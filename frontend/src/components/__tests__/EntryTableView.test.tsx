import { render, screen, fireEvent, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Entry, PriorityQueueRow, StoryThread } from "@/api/types";
import { useUIStore } from "@/stores/uiStore";

// jsdom gives the scroller no height, so the real virtualizer renders no body
// rows at all. Hand back every row instead — this suite is about what the cells
// of a thread row say, which is only observable once they exist.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({
    count,
    getItemKey,
  }: {
    count: number;
    getItemKey: (i: number) => string;
  }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        key: getItemKey(index),
        start: index * 34,
        size: 34,
      })),
    getTotalSize: () => count * 34,
    scrollToIndex: vi.fn(),
    measureElement: vi.fn(),
    measure: vi.fn(),
  }),
}));

import { EntryTableView } from "../EntryTableView";

function entry(overrides: Partial<Entry> = {}): Entry {
  return {
    id: "e-standalone",
    feed_id: "f1",
    feed_title: "BleepingComputer",
    feed_type: "rss",
    title: "Patch Tuesday lands",
    url: "https://example.com/patch-tuesday",
    author: "Staff",
    summary: "Ninety fixes.",
    published_at: "2026-09-20T00:00:00Z",
    is_read: false,
    tags: [],
    priority_score: 3.1,
    ...(overrides as Partial<Entry>),
  } as Entry;
}

function thread(overrides: Partial<StoryThread> = {}): StoryThread {
  return {
    id: "t1",
    slug: "bluemoon-exploit-kit",
    title: "BlueMoon exploit kit",
    summary: "A run of coverage of one intrusion set.",
    status: "open",
    entry_count: 23,
    source_count: 11,
    echo_count: 0,
    first_seen: null,
    last_seen: "2026-09-25T00:00:00Z",
    peak_at: null,
    key_entities: [{ entity_type: "threat_actor", entity_id: "a1", label: "Sandworm", count: 9 }],
    unread_count: 6,
    new_since_opened: 6,
    top_score: 7.4,
    top_entry_id: "e1",
    entry_ids: ["e1", "e2", "e3"],
    narrated_at: null,
    ...overrides,
  };
}

function queue(t = thread()): PriorityQueueRow[] {
  return [
    { kind: "thread", score: 8.8, entry: null, thread: t, absorbed_entry_ids: t.entry_ids },
    { kind: "entry", score: 3.1, entry: entry(), thread: null, absorbed_entry_ids: [] },
  ];
}

function renderTable(entries: Entry[], queueRows?: PriorityQueueRow[]) {
  return render(
    <EntryTableView
      entries={entries}
      queueRows={queueRows}
      hasNextPage={false}
      isFetchingNextPage={false}
      fetchNextPage={vi.fn()}
      isLoading={false}
    />,
  );
}

const renderQueue = (t = thread()) => renderTable([], queue(t));

/** The clickable row element containing the given text. */
function rowContaining(container: HTMLElement, text: string): HTMLElement {
  const wrap = Array.from(container.querySelectorAll('[class*="rowWrap"]')).find((el) =>
    el.textContent?.includes(text),
  );
  if (!wrap?.firstElementChild) throw new Error(`no row containing “${text}”`);
  return wrap.firstElementChild as HTMLElement;
}

describe("EntryTableView thread rows", () => {
  beforeEach(() => {
    useUIStore.setState({
      tables: {},
      selectedEntryId: null,
      selectedThreadSlug: null,
      selectedEntryIds: new Set<string>(),
    });
    // Source is hidden in the shipped default layout for this table.
    useUIStore.getState().setTableColumnVisible("entries", "source", true);
  });

  it("renders a story thread as a row beside the entries", () => {
    renderQueue();

    expect(screen.getByText("BlueMoon exploit kit")).toBeInTheDocument();
    expect(screen.getByText("Patch Tuesday lands")).toBeInTheDocument();
    expect(screen.getByText("2 entries loaded")).toBeInTheDocument();
  });

  it("fills the cells with thread-shaped values rather than an article's", () => {
    const { container } = renderQueue();
    const row = rowContaining(container, "BlueMoon exploit kit");

    // A thread has no single source, so Source counts them.
    expect(within(row).getByText("11 outlets")).toBeInTheDocument();
    // Signal is the best unread member's score, not the queue's ranking score.
    expect(within(row).getByText("◆ 7.4")).toBeInTheDocument();
    expect(within(row).getByText("Sandworm")).toBeInTheDocument();
    expect(within(row).getByTitle("11 outlets · 23 articles · 6 new")).toBeInTheDocument();
    expect(
      within(row).getByTitle("BlueMoon exploit kit — 11 outlets · 23 articles · 6 new"),
    ).toBeInTheDocument();
    // TTP / CVE counts belong to an article; the thread row must not invent them.
    expect(within(row).queryByText("23")).not.toBeInTheDocument();
  });

  it("opens the thread, not an entry, when the row is clicked", () => {
    const { container } = renderQueue();

    fireEvent.click(rowContaining(container, "BlueMoon exploit kit"));
    expect(useUIStore.getState().selectedThreadSlug).toBe("bluemoon-exploit-kit");
    expect(useUIStore.getState().selectedEntryId).toBeNull();

    fireEvent.click(rowContaining(container, "Patch Tuesday lands"));
    expect(useUIStore.getState().selectedEntryId).toBe("e-standalone");
    expect(useUIStore.getState().selectedThreadSlug).toBeNull();
  });

  it("checking a thread selects its articles, never the thread's own row id", () => {
    const { container } = renderQueue();
    const row = rowContaining(container, "BlueMoon exploit kit");

    fireEvent.click(within(row).getByLabelText("Select row"));

    const selected = useUIStore.getState().selectedEntryIds;
    expect([...selected].sort()).toEqual(["e1", "e2", "e3"]);
    expect([...selected].some((id) => id.startsWith("thread:"))).toBe(false);

    // ...and the row reads back as checked, because all of its members are.
    expect(
      within(rowContaining(container, "BlueMoon exploit kit")).getByLabelText("Select row"),
    ).toBeChecked();
  });

  it("keeps a thread's row id out of Select all", () => {
    const { container } = renderQueue();

    fireEvent.click(screen.getByLabelText("Select all loaded rows"));

    const selected = useUIStore.getState().selectedEntryIds;
    expect([...selected].sort()).toEqual(["e-standalone", "e1", "e2", "e3"]);
    expect(container.textContent).toContain("BlueMoon exploit kit");
  });

  it("unchecking a thread drops the articles it stood for", () => {
    const { container } = renderQueue();
    const checkbox = () =>
      within(rowContaining(container, "BlueMoon exploit kit")).getByLabelText("Select row");

    fireEvent.click(checkbox());
    fireEvent.click(checkbox());

    expect(useUIStore.getState().selectedEntryIds.size).toBe(0);
  });

  it("falls back to the plain entry list when no queue rows are given", () => {
    renderTable([entry()]);

    expect(screen.getByText("Patch Tuesday lands")).toBeInTheDocument();
    expect(screen.queryByText("BlueMoon exploit kit")).not.toBeInTheDocument();
  });
});
