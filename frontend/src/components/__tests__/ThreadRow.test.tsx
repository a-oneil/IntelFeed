import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ThreadRow } from "../ThreadRow";
import type { StoryThread, StoryThreadDetail } from "@/api/types";

const { threadDetail } = vi.hoisted(() => ({
  threadDetail: { current: null as StoryThreadDetail | null },
}));

vi.mock("@/hooks/useThreads", () => ({
  useThread: (slug: string | null) => ({
    data: slug ? threadDetail.current : undefined,
    isLoading: false,
  }),
}));

function thread(overrides: Partial<StoryThread> = {}): StoryThread {
  return {
    id: "t1",
    slug: "bluemoon-exploit-kit",
    title: "BlueMoon exploit kit",
    summary: null,
    status: "open",
    entry_count: 11,
    source_count: 7,
    echo_count: 2,
    first_seen: null,
    last_seen: null,
    peak_at: null,
    key_entities: [{ entity_type: "product", entity_id: "p1", label: "Chrome", count: 7 }],
    unread_count: 11,
    new_since_opened: 4,
    top_score: 6,
    top_entry_id: "e1",
    entry_ids: ["e1", "e2"],
    narrated_at: null,
    ...overrides,
  };
}

function detail(): StoryThreadDetail {
  return {
    ...thread(),
    beats: [
      {
        id: "b1",
        position: 0,
        occurred_at: "2026-09-09T00:00:00Z",
        kind: "first_disclosure",
        headline: "Volexity documents the chain",
        body: "Spear-phishing against NGOs.",
        lead_entry_id: "e1",
        entry_ids: ["e1"],
        collapsed_count: 2,
        is_ai: false,
      },
    ],
    members: [],
    thread_yield: { techniques: 0, cves: 3, products: 2, rules: 0, echoes_folded: 2 },
    nearest: [],
  };
}

function renderRow(props: Partial<Parameters<typeof ThreadRow>[0]> = {}) {
  const onOpenThread = vi.fn();
  const onEntryClick = vi.fn();
  const onToggle = vi.fn();
  render(
    <ThreadRow
      thread={thread()}
      score={9.2}
      expanded={false}
      onToggle={onToggle}
      onOpenThread={onOpenThread}
      onEntryClick={onEntryClick}
      onMarkRead={vi.fn()}
      selectedEntryId={null}
      {...props}
    />,
  );
  return { onOpenThread, onEntryClick, onToggle };
}

describe("ThreadRow", () => {
  it("replaces the pile with one line: score, name, and what it cost to read", () => {
    renderRow();

    expect(screen.getByText("BlueMoon exploit kit")).toBeInTheDocument();
    expect(screen.getByText("7 outlets · 11 articles · 4 new · 2 folded")).toBeInTheDocument();
    expect(screen.getByText("Chrome")).toBeInTheDocument();
    expect(screen.getByText("◆ 9.2")).toBeInTheDocument();
  });

  it("shows the spine when expanded, not the article list", () => {
    threadDetail.current = detail();
    renderRow({ expanded: true });

    expect(screen.getByText("Volexity documents the chain")).toBeInTheDocument();
    expect(screen.getByText("First")).toBeInTheDocument();
    expect(screen.getByText("2 re-reports folded")).toBeInTheDocument();
  });

  it("opens the thread on the title and the entry on a beat", () => {
    threadDetail.current = detail();
    const { onOpenThread, onEntryClick } = renderRow({ expanded: true });

    fireEvent.click(screen.getByText("BlueMoon exploit kit"));
    expect(onOpenThread).toHaveBeenCalled();

    fireEvent.click(screen.getByText("Volexity documents the chain"));
    expect(onEntryClick).toHaveBeenCalledWith("e1");
  });
});
