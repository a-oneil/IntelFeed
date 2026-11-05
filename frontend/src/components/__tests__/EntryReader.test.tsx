import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { EntryDetail } from "@/api/types";

// Mock react-router-dom
const mockNavigate = vi.fn();
vi.mock("react-router-dom", () => ({
  useNavigate: () => mockNavigate,
  // The reader's "open that other article" links route through useOpenEntry,
  // which asks the router where it is before choosing feed vs docked reader.
  useLocation: () => ({ pathname: "/" }),
}));

// Mock the hooks
vi.mock("@/hooks/useEntries", () => ({
  useEntry: vi.fn(),
  useToggleStar: vi.fn(() => ({ mutate: vi.fn() })),
  useToggleBookmark: vi.fn(() => ({ mutate: vi.fn() })),
  useMarkRead: vi.fn(() => ({ mutate: vi.fn() })),
  useMarkUnread: vi.fn(() => ({ mutate: vi.fn() })),
  useSimilarEntries: vi.fn(() => ({ data: [] })),
  useTranslateEntry: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useSetInfoRating: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
}));

vi.mock("@/hooks/useFeeds", () => ({
  useFeeds: vi.fn(() => ({ data: { items: [] } })),
}));

vi.mock("@/hooks/useExport", () => ({
  exportEntry: vi.fn(),
}));


vi.mock("@/hooks/useGlossary", () => ({
  useDetectGlossaryTerms: vi.fn(() => []),
}));

vi.mock("@/hooks/useSwipe", () => ({
  useSwipe: vi.fn(() => () => {}),
}));

vi.mock("@/components/SafeHTML", () => ({
  SafeHTML: ({ html, className }: { html: string; className?: string }) => (
    <div className={className} dangerouslySetInnerHTML={{ __html: html }} />
  ),
}));

vi.mock("@/components/YouTubePlayer", () => ({
  YouTubePlayer: () => null,
}));

vi.mock("@/components/EntryNotePanel", () => ({
  EntryNotePanel: () => null,
}));

vi.mock("@/components/TagInput", () => ({
  TagInput: () => null,
}));

vi.mock("@/components/ToolbarDropdown", () => ({
  ToolbarDropdown: () => null,
  DropdownItem: () => null,
}));

vi.mock("@/components/ResizeHandle", () => ({
  ResizeHandle: () => null,
}));

vi.mock("@/components/feedModal/EditFeedModal", () => ({
  EditFeedModal: () => null,
}));

vi.mock("@/components/WorkbenchPanel", () => ({
  default: () => null,
}));

vi.mock("@/components/GlossaryTooltip", () => ({
  GlossaryTooltip: () => null,
}));

vi.mock("@/components/GlossaryPanel", () => ({
  GlossaryPanel: () => null,
}));

vi.mock("@/components/InlineEntityHighlighter", () => ({
  InlineEntityHighlighter: () => null,
}));

vi.mock("@/components/RuleEntryCard", () => ({
  RuleEntryCard: () => null,
}));

vi.mock("@/components/IntelLevelBadge", () => ({
  IntelLevelBadge: () => null,
}));

vi.mock("@/components/EntryIntelBadges", () => ({
  EntryIntelBadges: () => null,
}));

vi.mock("@/components/SelectionContextMenu", () => ({
  SelectionContextMenu: () => null,
}));

vi.mock("@/components/CreateEntityPanel", () => ({
  CreateEntityPanel: () => null,
}));

vi.mock("@/components/AddAliasPanel", () => ({
  AddAliasPanel: () => null,
}));

vi.mock("@/components/LinkEntityPanel", () => ({
  LinkEntityPanel: () => null,
}));

vi.mock("@/components/FindInArticle", () => ({
  FindInArticle: () => null,
}));

vi.mock("@/components/ReaderTypography", () => ({
  ReaderTypography: () => null,
}));

vi.mock("@/components/SpeechHighlighter", () => ({
  SpeechHighlighter: () => null,
}));

vi.mock("@/hooks/useIntelligence", () => ({
  useEntryCVEs: vi.fn(() => ({ data: [] })),
  useEntryTTPs: vi.fn(() => ({ data: [] })),
  useEntryThreatActors: vi.fn(() => ({ data: [] })),
  useEntryMalware: vi.fn(() => ({ data: [] })),
  useEntryCountries: vi.fn(() => ({ data: [] })),
  useEntryVendors: vi.fn(() => ({ data: [] })),
  useEntryProducts: vi.fn(() => ({ data: [] })),
  useEntryTools: vi.fn(() => ({ data: [] })),
  useEntryMitigations: vi.fn(() => ({ data: [] })),
  useEntryCWEs: vi.fn(() => ({ data: [] })),
  useEntryObservables: vi.fn(() => ({ data: { items: [], candidates: [] } })),
}));

vi.mock("@/hooks/useEntryIntelBadges", () => ({
  useEntryIntelBadges: vi.fn(() => new Map()),
}));

vi.mock("@/stores/intelStore", () => ({
  useIntelStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      setPivotEntity: vi.fn(),
      autoOpenIntelPanel: false,
    })
  ),
}));

// Mock the stores
vi.mock("@/stores/uiStore", () => ({
  useUIStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      setSelectedEntry: vi.fn(),
      readerOpen: true,
      selectedEntryId: "entry-1",
      activeReaderPanel: null,
      setActiveReaderPanel: vi.fn(),
      entryListCollapsed: false,
      readerMaxWidth: 800,
      loadSavedSearch: vi.fn(),
      setEntryListCollapsed: vi.fn(),
      entryNavigationIds: ["entry-1"],
      entryNavTrail: [],
      entryNavTrailIndex: -1,
      navigateEntry: vi.fn(),
    })
  ),
}));

vi.mock("@/stores/playerStore", () => ({
  usePlayerStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      currentTrack: null,
      speechTrack: null,
      mode: "audio",
      isPlaying: false,
      speechPaused: false,
      play: vi.fn(),
      pause: vi.fn(),
      setTrack: vi.fn(),
    })
  ),
}));

import { useEntry } from "@/hooks/useEntries";
import { EntryReader } from "@/components/EntryReader";

const mockUseEntry = vi.mocked(useEntry);

function createQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
}

function renderEntryReader(entryId = "entry-1") {
  const queryClient = createQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <EntryReader entryId={entryId} />
    </QueryClientProvider>
  );
}

const mockEntry: EntryDetail = {
  id: "entry-1",
  feed_id: "feed-1",
  guid: "guid-1",
  url: "https://example.com/article-1",
  title: "APT29 Exploits New Zero-Day in Exchange Server",
  translated_title: null,
  author: "Threat Intel Team",
  summary: "Russian-linked threat actor APT29 has been observed exploiting a new zero-day.",
  published_at: "2026-03-01T12:00:00Z",
  fetched_at: "2026-03-01T12:05:00Z",
  word_count: 1400,
  content_hash: "abc123",
  feed_title: "Mandiant Blog",
  is_read: false,
  is_starred: false,
  is_bookmarked: false,
  tags: [],
  image_url: null,
  feed_type: "rss",
  metadata: {},
  media: [],
  content_html: "<p>Detailed analysis of APT29 activity targeting Exchange Server.</p>",
  content_text: "Detailed analysis of APT29 activity targeting Exchange Server.",
  duplicates: [],
  translated_html: null,
  translation_source_language: null,
  translation_target_language: null,
  translated_at: null,
};

describe("EntryReader", () => {
  it("renders loading state", () => {
    mockUseEntry.mockReturnValue({
      data: undefined,
      isLoading: true,
    } as ReturnType<typeof useEntry>);

    renderEntryReader();
    expect(screen.getByRole("status")).toHaveTextContent("Loading article…");
  });

  it("renders entry content when loaded", () => {
    mockUseEntry.mockReturnValue({
      data: mockEntry,
      isLoading: false,
    } as ReturnType<typeof useEntry>);

    renderEntryReader();

    // Title
    expect(
      screen.getByText("APT29 Exploits New Zero-Day in Exchange Server")
    ).toBeInTheDocument();

    // Author byline
    expect(screen.getByText(/Threat Intel Team/)).toBeInTheDocument();

    // Feed name
    expect(screen.getByText("Mandiant Blog")).toBeInTheDocument();

    // Read time (1400 words / 200 = 7 min)
    expect(screen.getByText("7 min read")).toBeInTheDocument();

    // Content rendered via SafeHTML
    expect(
      screen.getByText("Detailed analysis of APT29 activity targeting Exchange Server.")
    ).toBeInTheDocument();

    // Action buttons
    expect(screen.getByText("Star")).toBeInTheDocument();
    expect(screen.getByText("Bookmark")).toBeInTheDocument();
  });

  it("shows duplicates banner when duplicates exist", () => {
    const entryWithDuplicates: EntryDetail = {
      ...mockEntry,
      duplicates: [
        { entry_id: "dup-1", feed_title: "BleepingComputer", feed_id: "feed-10" },
        { entry_id: "dup-2", feed_title: "Dark Reading", feed_id: "feed-11" },
      ],
    };

    mockUseEntry.mockReturnValue({
      data: entryWithDuplicates,
      isLoading: false,
    } as ReturnType<typeof useEntry>);

    renderEntryReader();

    expect(
      screen.getByText(/Also reported by:/)
    ).toBeInTheDocument();
    expect(screen.getByText(/BleepingComputer/)).toBeInTheDocument();
    expect(screen.getByText(/Dark Reading/)).toBeInTheDocument();
  });
});
