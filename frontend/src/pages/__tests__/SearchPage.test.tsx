/**
 * Tests for /search — the one surface that renders search results.
 *
 * Two things it exists to get right, both of which the old split between the
 * header dropdown and the in-panel bar got wrong:
 *
 *  1. The `in:` chip is a **content** contract, not a routing one. `feeds`
 *     renders articles and no entities; `workbench` renders entities and no
 *     articles; `everything` renders both. Nothing else moves.
 *  2. Identity matches outrank incidental ones. Searching "lockbit" finds the
 *     LockBit actor *and* every actor whose prose cites LockBit; the backend
 *     labels which is which via `match_kind`, and the page has to keep them
 *     apart rather than interleaving them by relevance score.
 */
import { render, screen, fireEvent, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { EntitySearchResult, SavedSearch, UnifiedSearchResponse } from "@/api/types";
import { useUIStore } from "@/stores/uiStore";
import { SearchPage } from "@/pages/SearchPage";

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const unifiedMock = vi.fn();
vi.mock("@/hooks/useUnifiedSearch", () => ({
  useUnifiedSearch: (...args: unknown[]) => unifiedMock(...args),
}));

vi.mock("@/hooks/useMediaQuery", () => ({
  useIsMobile: () => false,
  useIsTablet: () => false,
  useMediaQuery: () => false,
}));

// The reader and the entry row pull a long tail of data hooks that say nothing
// about search; stub them at the component boundary.
vi.mock("@/components/EntryReader", () => ({
  EntryReader: ({ entryId }: { entryId: string }) => <div data-testid="reader">{entryId}</div>,
}));
vi.mock("@/components/EntryList", () => ({
  EntryRow: ({ entry }: { entry: { id: string; title: string } }) => (
    <div data-testid="entry-row">{entry.title}</div>
  ),
}));
vi.mock("@/components/BulkActionsToolbar", () => ({ BulkActionsToolbar: () => null }));
vi.mock("@/components/QueryBuilder", () => ({ QueryBuilder: () => null }));
vi.mock("@/hooks/useEntryIntelBadges", () => ({ useEntryIntelBadges: () => ({ data: {} }) }));
vi.mock("@/hooks/useSearch", () => ({
  useSavedSearches: () => ({ data: [] }),
  useCreateSavedSearch: () => ({ mutate: vi.fn() }),
  useDeleteSavedSearch: () => ({ mutate: vi.fn() }),
  useUpdateSavedSearch: () => ({ mutate: vi.fn() }),
}));
vi.mock("@/hooks/useUndoableDelete", () => ({ useUndoableDelete: () => vi.fn() }));
vi.mock("@/hooks/useEntries", () => ({ useMarkRead: () => ({ mutate: vi.fn() }) }));

function entity(partial: Partial<EntitySearchResult> & { id: string; type: string }): EntitySearchResult {
  return partial as EntitySearchResult;
}

const LOCKBIT_ACTOR = entity({
  id: "a1",
  type: "threat_actor",
  name: "LockBit",
  match_field: "name",
  match_kind: "direct",
  article_count: 761,
});
const LOCKBIT_MALWARE = entity({
  id: "m1",
  type: "malware",
  name: "LockBit",
  malware_type: "ransomware",
  match_field: "name",
  match_kind: "direct",
});
const DRAGONFORCE = entity({
  id: "a2",
  type: "threat_actor",
  name: "DragonForce",
  description: "Tooling is built on modified LockBit and Conti code.",
  match_field: "description",
  match_kind: "mention",
});
const KARAKURT = entity({
  id: "a3",
  type: "threat_actor",
  name: "Karakurt",
  description: "A component of the broader Conti organisation; LockBit lineage.",
  match_field: "description",
  match_kind: "mention",
});

function response(over: Partial<UnifiedSearchResponse> = {}): UnifiedSearchResponse {
  return {
    entries: {
      hits: [
        { id: "e1", title: "Ransomware Threats in Europe H1 2026", feed_title: "Cyble" },
        { id: "e2", title: "Lockbit5 publishes a new victim", feed_title: "Ransomware.live" },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ] as any,
      estimatedTotalHits: 414,
      facetDistribution: { feed_title: { Cyble: 12, "Ransomware.live": 300 }, feed_type: { rss: 400 } },
    },
    entities: {
      items: [LOCKBIT_ACTOR, LOCKBIT_MALWARE, DRAGONFORCE, KARAKURT],
      counts: { threat_actor: 33, malware: 1 },
    },
    query: "lockbit",
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ...(over as any),
  };
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/search"]}>
        <SearchPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Mount, then let the 300 ms query debounce fire so results render. */
function renderWithQuery(query = "lockbit") {
  useUIStore.setState({ headerSearchQuery: query });
  const utils = renderPage();
  act(() => {
    vi.advanceTimersByTime(300);
  });
  return utils;
}

beforeEach(() => {
  vi.useFakeTimers();
  navigateMock.mockReset();
  unifiedMock.mockReturnValue({ data: response(), isLoading: false });
  useUIStore.setState({
    headerSearchQuery: "",
    searchScope: "everything",
    searchFacetsCollapsed: false,
    selectedEntryId: null,
    selectedEntryIds: new Set(),
    showUnreadOnly: false,
    pendingSavedSearch: null,
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("SearchPage scope contract", () => {
  it("renders entities and articles under `everything`", () => {
    renderWithQuery();

    expect(screen.getByText("Direct matches")).toBeInTheDocument();
    expect(screen.getAllByTestId("entry-row")).toHaveLength(2);
  });

  it("renders only entities under `workbench`", () => {
    useUIStore.setState({ searchScope: "workbench" });
    renderWithQuery();

    expect(screen.getByText("Direct matches")).toBeInTheDocument();
    expect(screen.queryAllByTestId("entry-row")).toHaveLength(0);
    expect(screen.queryByText("Articles")).not.toBeInTheDocument();
  });

  it("renders only articles under `feeds`", () => {
    useUIStore.setState({ searchScope: "feeds" });
    renderWithQuery();

    expect(screen.getAllByTestId("entry-row")).toHaveLength(2);
    expect(screen.queryByText("Direct matches")).not.toBeInTheDocument();
    // The entity facets go with them — there is nothing left for them to filter.
    expect(screen.queryByText("Entity type")).not.toBeInTheDocument();
  });
});

describe("SearchPage identity vs mention", () => {
  it("separates name matches from prose mentions", () => {
    renderWithQuery();

    // The two LockBit rows are the direct ones; the two that merely cite it
    // are not in that section.
    const direct = screen.getByText("Direct matches").closest("section")!;
    expect(direct.textContent).toContain("LockBit");
    expect(direct.textContent).not.toContain("DragonForce");
    expect(direct.textContent).not.toContain("Karakurt");

    // ...and they are, in the mention group for their type.
    const mentions = screen.getByText("mentions your query").closest("section")!;
    expect(mentions.textContent).toContain("DragonForce");
    expect(mentions.textContent).toContain("Karakurt");

    // Direct matches lead the stream.
    expect(direct.compareDocumentPosition(mentions) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("hides mentions when the facet is unticked", () => {
    renderWithQuery();

    fireEvent.click(screen.getByText("Mentioned in text"));

    expect(screen.queryByText("DragonForce")).not.toBeInTheDocument();
    expect(screen.getByText("Direct matches")).toBeInTheDocument();
  });

  it("keeps the last match-kind checked rather than blanking the list", () => {
    renderWithQuery();

    fireEvent.click(screen.getByText("Mentioned in text"));
    fireEvent.click(screen.getByText("Name or alias"));

    // Unticking both would show nothing at all; the second click is a no-op.
    expect(screen.getByText("Direct matches")).toBeInTheDocument();
  });
});

describe("SearchPage facet counts", () => {
  it("shows the server's true per-type totals, not the trimmed payload length", () => {
    renderWithQuery();

    // Four entities came back; 33 actors matched. The rail reports 33 —
    // `getByText` would also hit the stream's own group heading, so scope to
    // the facet row, which is the only one that is a button.
    const actorRow = screen
      .getAllByText("Threat Actors")
      .map((el) => el.closest("button"))
      .find(Boolean)!;
    expect(actorRow.textContent).toContain("33");
  });

  it("asks the API for the same breadth the workbench does", () => {
    renderWithQuery();

    expect(unifiedMock).toHaveBeenCalledWith(
      "lockbit",
      expect.objectContaining({ entityLimit: 200, entityGroupLimit: 500 }),
    );
  });
});

describe("SearchPage entry facets", () => {
  it("writes a feed facet into the query as a quoted filter", () => {
    renderWithQuery();

    fireEvent.click(screen.getByText("Ransomware.live"));

    // Unquoted: the tokenizer splits on whitespace, and this value has none.
    expect(useUIStore.getState().headerSearchQuery).toBe("lockbit feed:Ransomware.live");
  });

  it("removes the filter again when the same row is clicked", () => {
    useUIStore.setState({ headerSearchQuery: "lockbit feed:Ransomware.live" });
    renderPage();
    act(() => {
      vi.advanceTimersByTime(300);
    });

    fireEvent.click(screen.getByText("Ransomware.live"));

    expect(useUIStore.getState().headerSearchQuery).toBe("lockbit");
  });

  it("writes a relative date window as an absolute date filter", () => {
    renderWithQuery();

    fireEvent.click(screen.getByText("Last 7 days"));

    expect(useUIStore.getState().headerSearchQuery).toMatch(/^lockbit date:>\d{4}-\d{2}-\d{2}$/);
  });

  it("clears every filter at once", () => {
    useUIStore.setState({ headerSearchQuery: "lockbit is:unread type:rss" });
    renderPage();
    act(() => {
      vi.advanceTimersByTime(300);
    });

    fireEvent.click(screen.getByText(/Clear 2 filters/));

    expect(useUIStore.getState().headerSearchQuery).toBe("lockbit");
  });
});

describe("SearchPage reader", () => {
  it("opens the reader beside the results when an entry is selected", () => {
    renderWithQuery();

    expect(screen.queryByTestId("reader")).not.toBeInTheDocument();

    act(() => {
      useUIStore.setState({ selectedEntryId: "e1" });
    });

    expect(screen.getByTestId("reader")).toHaveTextContent("e1");
  });

  it("keeps the reader out of the workbench scope, which has no entries", () => {
    useUIStore.setState({ searchScope: "workbench", selectedEntryId: "e1" });
    renderWithQuery();

    expect(screen.queryByTestId("reader")).not.toBeInTheDocument();
  });
});

describe("SearchPage saved search restore", () => {
  function savedSearch(over: Partial<SavedSearch> = {}): SavedSearch {
    return {
      id: "s1",
      name: "lockbit-actors",
      display_name: null,
      query: "lockbit",
      filters: {},
      unread_count: 0,
      total_count: 0,
      created_at: "2026-09-01T00:00:00Z",
      ...over,
    };
  }

  /** What every entry point does: park the saved search, then land on /search. */
  function openSaved(saved: SavedSearch) {
    useUIStore.setState({ pendingSavedSearch: saved, headerSearchQuery: "" });
    const utils = renderPage();
    act(() => {
      vi.advanceTimersByTime(300);
    });
    return utils;
  }

  it("restores the query and consumes the pending search", () => {
    openSaved(savedSearch());

    expect(useUIStore.getState().headerSearchQuery).toBe("lockbit");
    expect(useUIStore.getState().pendingSavedSearch).toBeNull();
  });

  it("restores the saved `search in` scope", () => {
    useUIStore.setState({ searchScope: "feeds" });
    openSaved(savedSearch({ filters: { scope: "workbench" } }));

    expect(useUIStore.getState().searchScope).toBe("workbench");
    expect(screen.queryAllByTestId("entry-row")).toHaveLength(0);
  });

  it("restores the entity type and match kind facets", () => {
    openSaved(
      savedSearch({ filters: { entity_type: "threat_actor", match_kinds: ["direct"] } }),
    );

    // `threat_actor` + direct-only leaves the LockBit actor and drops the
    // malware row and both mention-matched actors.
    expect(screen.getAllByText("LockBit").length).toBeGreaterThan(0);
    expect(screen.queryByText("DragonForce")).not.toBeInTheDocument();
    expect(screen.queryByText("Karakurt")).not.toBeInTheDocument();
  });

  it("expands the facet rail so the restored filters are visible", () => {
    useUIStore.setState({ searchFacetsCollapsed: true });
    openSaved(savedSearch());

    expect(useUIStore.getState().searchFacetsCollapsed).toBe(false);
  });

  it("folds a structured tag list into the query language", () => {
    openSaved(savedSearch({ query: "", filters: { tags: ["ransomware", "initial access"] } }));

    expect(useUIStore.getState().headerSearchQuery).toBe('tag:ransomware tag:"initial access"');
  });
});

describe("SearchPage unknown fields", () => {
  it("says a mistyped field was searched as text, not filtered on", () => {
    // `titel:ransomware` parses as a field the backend has never heard of. It
    // does not error and it does not filter — the value just goes to full-text
    // search. Without this notice the user reads the (wrong) count as truth.
    unifiedMock.mockReturnValue({
      data: response({ query: "titel:ransomware", unknown_fields: ["titel"] }),
      isLoading: false,
    });
    renderWithQuery("titel:ransomware");

    expect(screen.getByText("titel:")).toBeInTheDocument();
    expect(screen.getByText(/is not a search field/)).toBeInTheDocument();
    expect(screen.getByText(/searched as plain text instead/)).toBeInTheDocument();
  });

  it("pluralises when several fields are unrecognised", () => {
    unifiedMock.mockReturnValue({
      data: response({ query: "titel:x tags:y", unknown_fields: ["titel", "tags"] }),
      isLoading: false,
    });
    renderWithQuery("titel:x tags:y");

    expect(screen.getByText(/are not search fields/)).toBeInTheDocument();
  });

  it("stays quiet when every field is recognised", () => {
    renderWithQuery("lockbit");
    expect(screen.queryByText(/not a search field/)).not.toBeInTheDocument();
    expect(screen.queryByText(/not search fields/)).not.toBeInTheDocument();
  });
});

/**
 * Reading mode — the same shape the feed reader takes when an article opens:
 * the page's own nav folds away, the results become a narrow list column, and
 * the reader gets everything else, with a rail to hide the list entirely.
 */
describe("SearchPage reading mode", () => {
  const openEntry = (id = "e1") => {
    act(() => {
      useUIStore.getState().setSelectedEntry(id);
    });
  };

  it("folds the facet rail away when an article opens", () => {
    renderWithQuery();
    expect(useUIStore.getState().searchFacetsCollapsed).toBe(false);

    openEntry();

    expect(screen.getByTestId("reader")).toHaveTextContent("e1");
    expect(useUIStore.getState().searchFacetsCollapsed).toBe(true);
  });

  it("hands the rail back when the article closes", () => {
    renderWithQuery();
    openEntry();
    act(() => {
      useUIStore.getState().setSelectedEntry(null);
    });

    expect(screen.queryByTestId("reader")).not.toBeInTheDocument();
    expect(useUIStore.getState().searchFacetsCollapsed).toBe(false);
  });

  it("leaves a rail the user had already collapsed alone", () => {
    useUIStore.setState({ searchFacetsCollapsed: true });
    renderWithQuery();
    openEntry();
    act(() => {
      useUIStore.getState().setSelectedEntry(null);
    });

    expect(useUIStore.getState().searchFacetsCollapsed).toBe(true);
  });

  it("keeps the app sidebar folded after the article closes", () => {
    // Closing an entry hands the app sidebar back, which is right in the feed
    // reader and wrong here — it would land beside the facet rail.
    renderWithQuery();
    openEntry();
    act(() => {
      useUIStore.getState().setSelectedEntry(null);
    });

    expect(useUIStore.getState().sidebarCollapsed).toBe(true);
  });

  it("collapses the results column for a full-width read", () => {
    renderWithQuery();
    openEntry();

    fireEvent.click(screen.getByLabelText("Hide results"));

    expect(screen.queryAllByTestId("entry-row")).toHaveLength(0);
    expect(screen.getByTestId("reader")).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText("Show results"));
    expect(screen.getAllByTestId("entry-row")).toHaveLength(2);
  });

  it("offers no results rail until an article is open", () => {
    renderWithQuery();
    expect(screen.queryByLabelText("Hide results")).not.toBeInTheDocument();
  });
});
