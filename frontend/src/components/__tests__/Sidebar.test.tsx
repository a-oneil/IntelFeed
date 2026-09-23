import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { Feed, Category } from "@/api/types";

// Mock react-router-dom's useNavigate and useLocation
const mockNavigate = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: () => ({ pathname: "/", search: "", hash: "", state: null, key: "default" }),
  };
});

// Mock the hooks
vi.mock("@/hooks/useFeeds", () => ({
  useFeeds: vi.fn(),
  useCategories: vi.fn(),
  useAddFeed: vi.fn(),
  useDeleteFeed: vi.fn(() => ({ mutate: vi.fn() })),
  useRefreshFeed: vi.fn(() => ({ mutate: vi.fn() })),
  useUpdateFeed: vi.fn(() => ({ mutate: vi.fn() })),
  useCreateCategory: vi.fn(() => ({ mutate: vi.fn() })),
  useUpdateCategory: vi.fn(() => ({ mutate: vi.fn() })),
  useDeleteCategory: vi.fn(() => ({ mutate: vi.fn() })),
  useReorderCategories: vi.fn(() => ({ mutate: vi.fn() })),
}));

vi.mock("@/hooks/useEntries", () => ({
  useMarkAllRead: vi.fn(() => ({ mutate: vi.fn() })),
  useVirtualFolderCounts: vi.fn(() => ({})),
  usePriorityQueueCount: vi.fn(() => 0),
}));

vi.mock("@/hooks/useSearch", () => ({
  useSavedSearches: vi.fn(() => ({ data: [] })),
  useDeleteSavedSearch: vi.fn(() => ({ mutate: vi.fn() })),
  useUpdateSavedSearch: vi.fn(() => ({ mutate: vi.fn() })),
}));

vi.mock("@/hooks/useIntelligence", () => ({
  useBulkExtract: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useBulkTranslate: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
}));

vi.mock("@/hooks/useUndoableDelete", () => ({
  useUndoableDelete: vi.fn(() => vi.fn()),
}));

vi.mock("@/hooks/useSidebarCustomization", () => ({
  useSidebarCustomization: vi.fn(() => ({
    sectionOrder: ["nav", "saved_searches", "keywords", "feeds"],
    reorderSections: vi.fn(),
  })),
}));

vi.mock("@/hooks/useLongPress", () => ({
  useLongPress: vi.fn(() => ({})),
}));

vi.mock("@/components/AddFeedModal", () => ({
  AddFeedModal: () => null,
}));

vi.mock("@/components/EditFeedModal", () => ({
  EditFeedModal: () => null,
}));

vi.mock("@/components/EditCategoryModal", () => ({
  EditCategoryModal: () => null,
}));

vi.mock("@/components/Tooltip", () => ({
  Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));


vi.mock("@/components/FeedTypeIcon", () => ({
  FeedTypeIcon: () => <span>📄</span>,
}));

// Stub the badge component, but keep deriveIntelLevel: it is a pure helper
// the sidebar calls directly, not a rendering concern.
vi.mock("@/components/IntelLevelBadge", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/IntelLevelBadge")>()),
  IntelLevelBadge: () => null,
}));

// Mock the stores
vi.mock("@/stores/authStore", () => ({
  useAuthStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      user: { username: "testuser" },
      logout: vi.fn(),
    })
  ),
}));

const mockSidebarUIState: Record<string, unknown> = {
  setSelectedFeed: vi.fn(),
  setSelectedCategory: vi.fn(),
  selectedFeedId: null,
  selectedCategoryId: null,
  toggleUnreadOnly: vi.fn(),
  showUnreadOnly: false,
  unreadFallbackActive: false,
  virtualFolder: null,
  setVirtualFolder: vi.fn(),
  activePanel: "entries",
  setActivePanel: vi.fn(),
  loadSavedSearch: vi.fn(),
  sidebarCollapsed: false,
  toggleSidebar: vi.fn(),
  sidebarWidth: 280,
  setSidebarWidth: vi.fn(),
  navSectionCollapsed: false,
  setNavSectionCollapsed: vi.fn(),
  feedsSectionCollapsed: false,
  setFeedsSectionCollapsed: vi.fn(),
  toolsSectionCollapsed: false,
  setToolsSectionCollapsed: vi.fn(),
  savedSearchesSectionCollapsed: false,
  setSavedSearchesSectionCollapsed: vi.fn(),
  openReportWizard: vi.fn(),
  collapsedCategories: null,
  sidebarMode: "reading",
  setSidebarMode: vi.fn(),
};

vi.mock("@/stores/uiStore", () => ({
  useUIStore: Object.assign(
    vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
      selector(mockSidebarUIState)
    ),
    {
      getState: () => mockSidebarUIState,
      setState: (patch: Record<string, unknown>) =>
        Object.assign(mockSidebarUIState, patch),
    }
  ),
}));

import { useFeeds, useCategories, useAddFeed } from "@/hooks/useFeeds";
import { Sidebar } from "@/components/Sidebar";

const mockUseFeeds = vi.mocked(useFeeds);
const mockUseCategories = vi.mocked(useCategories);
const mockUseAddFeed = vi.mocked(useAddFeed);

function createQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
}

function renderSidebar() {
  const queryClient = createQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

const mockFeeds: Feed[] = [
  {
    id: "feed-1",
    title: "Krebs on Security",
    url: "https://krebsonsecurity.com/feed/",
    feed_type: "rss",
    site_url: "https://krebsonsecurity.com",
    icon_url: null,
    description: null,
    language: "en",
    last_fetched_at: null,
    fetch_interval_minutes: 60,
    error_count: 0,
    last_error: null,
    is_active: true,
    created_at: "2026-01-01T00:00:00Z",
    adapter_config: {},
    intel_extraction_mode: "selective" as const,
    auto_extract_on_ingest: false,
    extract_detection_rules: false,
    extract_tools: true,
    reliability_rating: null,
    timeliness_rating: null,
    relevance_rating: null,
    analyst_notes: null,
    last_reviewed_at: null,
    category_id: "cat-1",
    custom_title: null,
    is_muted: false,
    unread_count: 5,
    retention_days: 30,
  },
  {
    id: "feed-2",
    title: "The Hacker News",
    url: "https://thehackernews.com/feed/",
    feed_type: "rss",
    site_url: "https://thehackernews.com",
    icon_url: null,
    description: null,
    language: "en",
    last_fetched_at: null,
    fetch_interval_minutes: 60,
    error_count: 0,
    last_error: null,
    is_active: true,
    created_at: "2026-01-01T00:00:00Z",
    adapter_config: {},
    intel_extraction_mode: "selective" as const,
    auto_extract_on_ingest: false,
    extract_detection_rules: false,
    extract_tools: true,
    reliability_rating: null,
    timeliness_rating: null,
    relevance_rating: null,
    analyst_notes: null,
    last_reviewed_at: null,
    category_id: null,
    custom_title: "THN",
    is_muted: false,
    unread_count: 12,
    retention_days: 30,
  },
];

const mockCategories: Category[] = [
  {
    id: "cat-1",
    name: "Threat Intel",
    parent_id: null,
    position: 0,
    created_at: "2026-01-01T00:00:00Z",
    children: [],
    feed_count: 1,
  },
];

function setupMocks(
  feeds: Feed[] = mockFeeds,
  categories: Category[] = mockCategories
) {
  mockUseFeeds.mockReturnValue({
    data: { items: feeds, total: feeds.length, limit: 200, offset: 0, has_more: false },
  } as ReturnType<typeof useFeeds>);

  mockUseCategories.mockReturnValue({
    data: categories,
  } as ReturnType<typeof useCategories>);

  mockUseAddFeed.mockReturnValue({
    mutateAsync: vi.fn(),
    isPending: false,
  } as unknown as ReturnType<typeof useAddFeed>);
}

describe("Sidebar", () => {
  beforeEach(() => {
    setupMocks();
  });

  it("renders all navigation items", () => {
    renderSidebar();
    // The old "All Items" link is now a hero tile showing the unread total.
    expect(screen.getByText("Unread articles")).toBeInTheDocument();
    expect(screen.getByText("Last 24h")).toBeInTheDocument();
    expect(screen.getByText("This Week")).toBeInTheDocument();
    expect(screen.getByText("Watched")).toBeInTheDocument();
    expect(screen.getByText("Starred")).toBeInTheDocument();
    expect(screen.getByText("Bookmarked")).toBeInTheDocument();
  });

  it("renders Starred and Bookmarked virtual folders", () => {
    renderSidebar();
    expect(screen.getByText("Starred")).toBeInTheDocument();
    expect(screen.getByText("Bookmarked")).toBeInTheDocument();
  });

  it("renders feed items from mock data (categories default collapsed)", () => {
    renderSidebar();
    // Category should render even when collapsed
    expect(screen.getByText("Threat Intel")).toBeInTheDocument();
    // Uncategorized feeds always visible
    expect(screen.getByText("THN")).toBeInTheDocument();
    // Krebs on Security is inside collapsed category, not rendered
    expect(screen.queryByText("Krebs on Security")).not.toBeInTheDocument();
  });

  it("shows unread counts", () => {
    renderSidebar();
    // Total unread is 5 + 12 = 17
    expect(screen.getByText("17")).toBeInTheDocument();
    // "5" appears only on the category badge (feeds collapsed)
    expect(screen.getAllByText("5")).toHaveLength(1);
    expect(screen.getByText("12")).toBeInTheDocument();
  });
});
