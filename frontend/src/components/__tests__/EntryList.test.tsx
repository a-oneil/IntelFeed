import { render, screen, fireEvent } from "@testing-library/react";
import { afterEach, describe, it, expect, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { Entry, CursorPaginatedResponse } from "@/api/types";

// Mock the hooks
vi.mock("@/hooks/useEntries", () => ({
  useEntries: vi.fn(),
  usePriorityQueue: vi.fn(() => ({ data: undefined, fetchNextPage: vi.fn(), hasNextPage: false })),
  useEntriesCount: vi.fn(() => ({ data: undefined })),
  useMarkRead: vi.fn(() => ({ mutate: vi.fn() })),
  useMarkAllRead: vi.fn(() => ({ mutate: vi.fn() })),
  useToggleStar: vi.fn(() => ({ mutate: vi.fn() })),
  useToggleBookmark: vi.fn(() => ({ mutate: vi.fn() })),
  useBulkAction: vi.fn(() => ({ mutate: vi.fn() })),
}));

vi.mock("@/hooks/useFeeds", () => ({
  useFeeds: vi.fn(() => ({ data: { items: [] } })),
}));


vi.mock("@/hooks/useEntryIntelBadges", () => ({
  useEntryIntelBadges: vi.fn(() => new Map()),
}));

vi.mock("@/hooks/usePullToRefresh", () => ({
  usePullToRefresh: vi.fn(() => ({ ref: { current: null }, isPulling: false, pullDistance: 0 })),
}));

vi.mock("@/components/SwipeableEntryRow", () => ({
  SwipeableEntryRow: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock("@/components/CVEGroupRow", () => ({
  CVEGroupRow: () => null,
}));

vi.mock("@/components/EntryIntelBadges", () => ({
  EntryIntelBadges: () => null,
}));

vi.mock("@/components/IntelLevelBadge", () => ({
  IntelLevelBadge: () => null,
}));

vi.mock("@/components/EditFeedModal", () => ({
  EditFeedModal: () => null,
}));

vi.mock("dompurify", () => ({
  default: { sanitize: (html: string) => html },
}));

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: () => ({
    getVirtualItems: () => [],
    getTotalSize: () => 0,
    scrollToIndex: vi.fn(),
    measureElement: vi.fn(),
    measure: vi.fn(),
  }),
}));

// Mock the UI store
const mockUiState: Record<string, unknown> = {};

vi.mock("@/stores/uiStore", () => ({
  useUIStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector(Object.assign({
      selectedFeedId: null,
      selectedCategoryId: null,
      showUnreadOnly: false,
      priorityShowUnreadOnly: true,
      unreadFallbackActive: false,
      setUnreadFallbackActive: vi.fn(),
      toggleUnreadOnly: vi.fn(),
      togglePriorityUnreadOnly: vi.fn(),
      setShowUnreadOnly: vi.fn(),
      setPriorityShowUnreadOnly: vi.fn(),
      setSelectedEntry: vi.fn(),
      selectedEntryId: null,
      viewMode: "expanded",
      setViewMode: vi.fn(),
      virtualFolder: null,
      markReadOnScroll: false,
      toggleMarkReadOnScroll: vi.fn(),
      readerOpen: false,
      sortOrder: "newest",
      setSortOrder: vi.fn(),
      groupByFeed: false,
      groupByCVE: false,
      selectedEntryIds: new Set(),
      toggleEntrySelection: vi.fn(),
      clearEntrySelection: vi.fn(),
      selectAllEntries: vi.fn(),
      setEntryNavigationIds: vi.fn(),
      entryNavigationIds: [],
      entryNavTrail: [],
      entryNavTrailIndex: -1,
    }, mockUiState))
  ),
}));

import { useEntries, usePriorityQueue } from "@/hooks/useEntries";
import { EntryList } from "@/components/EntryList";
import type { PriorityQueueRow, StoryThread } from "@/api/types";

const mockUseEntries = vi.mocked(useEntries);
const mockUsePriorityQueue = vi.mocked(usePriorityQueue);

function createQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
}

function renderEntryList(props: Parameters<typeof EntryList>[0] = {}) {
  const queryClient = createQueryClient();
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <EntryList {...props} />
      </QueryClientProvider>
    </MemoryRouter>
  );
}

const mockEntries: Entry[] = [
  {
    id: "entry-1",
    feed_id: "feed-1",
    guid: "guid-1",
    url: "https://example.com/article-1",
    title: "Critical CVE-2026-1234 in OpenSSL",
    translated_title: null,
    author: "John Doe",
    summary: "A critical vulnerability has been discovered in OpenSSL affecting all versions.",
    published_at: "2026-03-01T12:00:00Z",
    fetched_at: "2026-03-01T12:05:00Z",
    word_count: 800,
    content_hash: null,
    feed_title: "Krebs on Security",
    is_read: false,
    is_starred: true,
    is_bookmarked: false,
    tags: [],
    image_url: null,
    feed_type: "rss",
    metadata: {},
    media: [],
  },
  {
    id: "entry-2",
    feed_id: "feed-2",
    guid: "guid-2",
    url: "https://example.com/article-2",
    title: "New Ransomware Campaign Targets Healthcare",
    translated_title: null,
    author: "Jane Smith",
    summary: "A sophisticated ransomware group has shifted its focus to healthcare organizations.",
    published_at: "2026-03-02T10:00:00Z",
    fetched_at: "2026-03-02T10:05:00Z",
    word_count: 1200,
    content_hash: null,
    feed_title: "The Hacker News",
    is_read: true,
    is_starred: false,
    is_bookmarked: false,
    tags: [],
    image_url: null,
    feed_type: "rss",
    metadata: {},
    media: [],
  },
];

function makeInfiniteData(entries: Entry[]) {
  return {
    pages: [
      {
        items: entries,
        next_cursor: null,
        has_more: false,
      } as CursorPaginatedResponse<Entry>,
    ],
    pageParams: [undefined],
  };
}

describe("EntryList", () => {
  it("renders loading skeleton when loading", () => {
    mockUseEntries.mockReturnValue({
      data: undefined,
      isLoading: true,
      fetchNextPage: vi.fn(),
      hasNextPage: false,
      isFetchingNextPage: false,
    } as unknown as ReturnType<typeof useEntries>);

    const { container } = renderEntryList();
    // Loading state shows skeleton elements
    const skeleton = container.querySelector("[class*='skeleton'], [class*='Skeleton']");
    expect(skeleton || container.querySelector("[class*='entryList']")).toBeTruthy();
  });

  it("renders empty state when no entries exist", () => {
    mockUseEntries.mockReturnValue({
      data: makeInfiniteData([]),
      isLoading: false,
      fetchNextPage: vi.fn(),
      hasNextPage: false,
      isFetchingNextPage: false,
    } as unknown as ReturnType<typeof useEntries>);

    renderEntryList();
    expect(screen.getByText("No entries to display")).toBeInTheDocument();
  });

  it("lets Enter follow a focused internal link instead of using the article shortcut", () => {
    mockUseEntries.mockReturnValue({
      data: makeInfiniteData([]),
      isLoading: false,
      fetchNextPage: vi.fn(),
      hasNextPage: false,
      isFetchingNextPage: false,
    } as unknown as ReturnType<typeof useEntries>);

    renderEntryList();
    const link = document.createElement("a");
    link.href = "/settings";
    document.body.appendChild(link);
    try {
      expect(fireEvent.keyDown(link, { key: "Enter" })).toBe(true);
    } finally {
      link.remove();
    }
  });

  it("teaches how a zero-count folder earns a count instead of saying nothing", () => {
    mockUseEntries.mockReturnValue({
      data: makeInfiniteData([]),
      isLoading: false,
      fetchNextPage: vi.fn(),
      hasNextPage: false,
      isFetchingNextPage: false,
    } as unknown as ReturnType<typeof useEntries>);

    mockUiState.virtualFolder = "watched";
    renderEntryList();
    expect(screen.getByText("Nothing watched yet.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Browse entities to watch" })).toBeInTheDocument();
    delete mockUiState.virtualFolder;
  });

  it("explains why read entries are showing when Hide Read runs out of unread", () => {
    mockUseEntries.mockReturnValue({
      data: makeInfiniteData(mockEntries),
      isLoading: false,
      fetchNextPage: vi.fn(),
      hasNextPage: false,
      isFetchingNextPage: false,
    } as unknown as ReturnType<typeof useEntries>);

    mockUiState.showUnreadOnly = true;
    mockUiState.unreadFallbackActive = true;
    renderEntryList();

    expect(screen.getByText(/You.re all caught up\./)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Turn off Hide Read" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Hide Read (paused)" })).toBeInTheDocument();

    delete mockUiState.showUnreadOnly;
    delete mockUiState.unreadFallbackActive;
  });

  it("stays quiet when Hide Read is actually filtering", () => {
    mockUseEntries.mockReturnValue({
      data: makeInfiniteData(mockEntries),
      isLoading: false,
      fetchNextPage: vi.fn(),
      hasNextPage: false,
      isFetchingNextPage: false,
    } as unknown as ReturnType<typeof useEntries>);

    mockUiState.showUnreadOnly = true;
    renderEntryList();

    expect(screen.queryByText(/You.re all caught up\./)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Hide Read" })).toBeInTheDocument();

    delete mockUiState.showUnreadOnly;
  });

  it("renders magazine cards for the entries it is given", () => {
    mockUseEntries.mockReturnValue({
      data: makeInfiniteData(mockEntries),
      isLoading: false,
      fetchNextPage: vi.fn(),
      hasNextPage: false,
      isFetchingNextPage: false,
    } as unknown as ReturnType<typeof useEntries>);

    mockUiState.viewMode = "magazine";
    renderEntryList();

    expect(screen.getByText("Critical CVE-2026-1234 in OpenSSL")).toBeInTheDocument();
    delete mockUiState.viewMode;
  });

  it("prepares entries for virtualized rendering", () => {
    mockUseEntries.mockReturnValue({
      data: makeInfiniteData(mockEntries),
      isLoading: false,
      fetchNextPage: vi.fn(),
      hasNextPage: false,
      isFetchingNextPage: false,
    } as unknown as ReturnType<typeof useEntries>);

    // Component renders but entries are virtualized — only virtual items appear in DOM
    // This test verifies the component mounts without errors when entries are provided
    const { container } = renderEntryList();
    expect(container.firstChild).toBeTruthy();
  });
});

function storyThread(overrides: Partial<StoryThread> = {}): StoryThread {
  return {
    id: "t1",
    slug: "bluemoon-exploit-kit",
    title: "BlueMoon exploit kit",
    summary: null,
    status: "open",
    entry_count: 23,
    source_count: 11,
    echo_count: 0,
    first_seen: null,
    last_seen: null,
    peak_at: null,
    key_entities: [],
    unread_count: 6,
    new_since_opened: 6,
    top_score: 7.4,
    top_entry_id: "entry-1",
    entry_ids: ["entry-9"],
    narrated_at: null,
    ...overrides,
  };
}

function makeQueueData(items: PriorityQueueRow[]) {
  return {
    pages: [{ items, next_cursor: null, has_more: false, radar_threshold: null }],
    pageParams: [undefined],
  };
}

function mockQueue(items: PriorityQueueRow[]) {
  mockUsePriorityQueue.mockReturnValue({
    data: makeQueueData(items),
    isLoading: false,
    fetchNextPage: vi.fn(),
    hasNextPage: false,
    isFetchingNextPage: false,
  } as unknown as ReturnType<typeof usePriorityQueue>);
}

/**
 * The Priority Queue withholds every article a thread absorbed, so a magazine
 * grid built from the entry stream alone loses the story *and* its coverage —
 * a 23-article thread contributing nothing at all, with no gap to notice.
 */
describe("EntryList magazine view, Priority Queue", () => {
  const magazineQueue = { sortOverride: "radar" as const, withThreads: true, priorityMode: true };

  afterEach(() => {
    delete mockUiState.viewMode;
    delete mockUiState.setSelectedThread;
  });

  it("gives a story thread a card of its own beside the article cards", () => {
    mockQueue([
      {
        kind: "thread",
        score: 7.4,
        entry: null,
        thread: storyThread(),
        absorbed_entry_ids: ["entry-9"],
      },
      { kind: "entry", score: 6, entry: mockEntries[0], thread: null, absorbed_entry_ids: [] },
    ]);
    mockUiState.viewMode = "magazine";

    renderEntryList(magazineQueue);

    expect(screen.getByText("BlueMoon exploit kit")).toBeInTheDocument();
    expect(screen.getByText("11 outlets · 23 articles · 6 new")).toBeInTheDocument();
    expect(screen.getByText("◆ 7.4")).toBeInTheDocument();
    expect(screen.getByText("Critical CVE-2026-1234 in OpenSSL")).toBeInTheDocument();
  });

  it("opens the story when the card is clicked", () => {
    const setSelectedThread = vi.fn();
    mockQueue([
      {
        kind: "thread",
        score: 7.4,
        entry: null,
        thread: storyThread(),
        absorbed_entry_ids: [],
      },
    ]);
    mockUiState.viewMode = "magazine";
    mockUiState.setSelectedThread = setSelectedThread;

    renderEntryList(magazineQueue);
    fireEvent.click(screen.getByText("BlueMoon exploit kit"));

    expect(setSelectedThread).toHaveBeenCalledWith("bluemoon-exploit-kit");
  });

  it("does not claim to be empty when the queue is all threads", () => {
    mockQueue([
      {
        kind: "thread",
        score: 7.4,
        entry: null,
        thread: storyThread(),
        absorbed_entry_ids: [],
      },
    ]);
    mockUiState.viewMode = "magazine";

    renderEntryList(magazineQueue);

    expect(screen.queryByText("No entries to display")).not.toBeInTheDocument();
  });
});
