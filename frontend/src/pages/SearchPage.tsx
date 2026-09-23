import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useAppSidebarAutoCollapse } from "@/hooks/useAppSidebarAutoCollapse";
import { useUnifiedSearch } from "@/hooks/useUnifiedSearch";
import { useDebouncedValue } from "@/components/search";
import { SearchFacetSidebar, type MatchKind } from "@/components/search/SearchFacetSidebar";
import { SearchResults } from "@/components/search/SearchResults";
import { EntryReader } from "@/components/EntryReader";
import { ResizeHandle } from "@/components/ResizeHandle";
import { RailToggle } from "@/components/primitives";
import { useRailWidth } from "@/hooks/useRailWidth";
import { parseQuery, extractFilters, removeFilterFromQuery } from "@/utils/queryParser";
import styles from "./SearchPage.module.css";

const ALL_MATCH_KINDS: MatchKind[] = ["direct", "mention"];

/** Days-ago windows the "Published" facet offers, for reading one back off the query. */
const DATE_WINDOWS = [1, 7, 30, 365];

function daysAgoISO(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().slice(0, 10);
}

/**
 * Turn a `date:>YYYY-MM-DD` filter back into the window that produced it, so the
 * radio row reads as selected. Tolerant by a day because the query is a fixed
 * date and "7 days ago" moves.
 */
function windowFromDateFilter(value: string | undefined): number | null {
  if (!value || !value.startsWith(">")) return null;
  const then = Date.parse(value.slice(1));
  if (Number.isNaN(then)) return null;
  const days = Math.round((Date.now() - then) / 86_400_000);
  return DATE_WINDOWS.find((w) => Math.abs(w - days) <= 1) ?? null;
}

/** `field:value`, quoting values the tokenizer would otherwise split. */
function filterToken(field: string, value: string): string {
  return /[\s:"]/.test(value) ? `${field}:"${value}"` : `${field}:${value}`;
}

/**
 * Fold a saved search's structured `tags` list into the query language.
 *
 * Tag pivots (the tag manager, the top-tags widget) and older API-created rows
 * carry tags as a list rather than as query tokens; the search page speaks only
 * the query language, so they are translated on the way in.
 */
function withTagFilters(query: string, tags: string[] | undefined): string {
  if (!tags?.length) return query;
  const tokens = tags.map((t) => filterToken("tag", t)).filter((t) => !query.includes(t));
  return [query, ...tokens].filter(Boolean).join(" ").trim();
}

/**
 * The one place search results are rendered.
 *
 * Its facet rail is a second sidebar inside the content area — the same shape as
 * the workbench and settings rails, and it folds the app sidebar away the same
 * way — so search can be entered from any route without stacking two navs.
 */
export function SearchPage() {
  // The facet rail is this page's nav; the app sidebar folds away beside it,
  // exactly as it does for the workbench and settings.
  useAppSidebarAutoCollapse();
  const isMobile = useIsMobile();
  const [searchParams, setSearchParams] = useSearchParams();

  const query = useUIStore((s) => s.headerSearchQuery);
  const setQuery = useUIStore((s) => s.setHeaderSearchQuery);
  const scope = useUIStore((s) => s.searchScope);
  const setScope = useUIStore((s) => s.setSearchScope);
  const facetsCollapsed = useUIStore((s) => s.searchFacetsCollapsed);
  const setFacetsCollapsed = useUIStore((s) => s.setSearchFacetsCollapsed);
  const selectedEntryId = useUIStore((s) => s.selectedEntryId);
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const entryListWidth = useUIStore((s) => s.entryListWidth);
  const setEntryListWidth = useUIStore((s) => s.setEntryListWidth);
  const entryListCollapsed = useUIStore((s) => s.entryListCollapsed);
  const setEntryListCollapsed = useUIStore((s) => s.setEntryListCollapsed);
  const pendingSavedSearch = useUIStore((s) => s.pendingSavedSearch);
  const clearPendingSavedSearch = useUIStore((s) => s.clearPendingSavedSearch);

  // The rail is a permanent column on desktop and a sheet on mobile, where
  // there is no room for both it and the results. Separate state because the
  // desktop collapse is a persisted preference and this is a transient sheet.
  const [filterSheetOpen, setFilterSheetOpen] = useState(false);
  const [entityTypeFilter, setEntityTypeFilter] = useState<string | null>(null);
  const [matchKinds, setMatchKinds] = useState<Set<MatchKind>>(new Set(ALL_MATCH_KINDS));
  const [offset, setOffset] = useState(0);
  // Hide Read is answered by the server: read state is per-user Postgres state
  // the index cannot filter on, and filtering the fetched page here instead
  // hid unread articles that ranked past the page break.
  const [hideRead, setHideRead] = useState(false);

  const debouncedQuery = useDebouncedValue(query, 300);

  // `?q=` deep links (bookmarks, the copilot, entity "find in IntelFeed").
  useEffect(() => {
    const seed = searchParams.get("q");
    if (seed) {
      setQuery(seed);
      setSearchParams({}, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // A saved search picked anywhere in the app lands here. It restores the whole
  // search UI, not just the text: the "Search in" scope, the entity-type facet
  // and the match kinds are part of what was saved, so reopening one reproduces
  // exactly the view it was saved from. The rail is expanded with it, so the
  // restored filters are visible rather than hidden behind a collapsed column.
  useEffect(() => {
    if (!pendingSavedSearch) return;
    const f = pendingSavedSearch.filters ?? {};

    setQuery(withTagFilters(pendingSavedSearch.query || "", f.tags));
    if (f.scope) setScope(f.scope);
    setEntityTypeFilter(f.entity_type ?? null);
    setMatchKinds(new Set(f.match_kinds?.length ? f.match_kinds : ALL_MATCH_KINDS));
    // Mobile shows the rail as a sheet over the results; popping it open would
    // hide the very results the saved search just fetched.
    if (!isMobile) setFacetsCollapsed(false);
    setOffset(0);
    clearPendingSavedSearch();
  }, [pendingSavedSearch, isMobile, setQuery, setScope, setFacetsCollapsed, clearPendingSavedSearch]);

  useEffect(() => {
    setOffset(0);
  }, [debouncedQuery, hideRead]);

  const { data: results, isLoading } = useUnifiedSearch(debouncedQuery, {
    limit: 100,
    offset,
    hideRead,
    // Matches what the workbench's own /intelligence/search asks for, so the
    // two can no longer disagree about how much of the graph matched. The
    // group cap is opted out of here: the facet rail needs the whole set to
    // count it, and the page caps groups itself at render time.
    entityLimit: 200,
    entityGroupLimit: 500,
  });

  const filters = useMemo(() => extractFilters(parseQuery(query)), [query]);
  const activeDateDays = useMemo(
    () => windowFromDateFilter(filters.find((f) => f.field === "date" && !f.negated)?.value),
    [filters],
  );

  const handleQueryChange = useCallback(
    (next: string) => {
      setQuery(next);
      setOffset(0);
    },
    [setQuery],
  );

  const handleToggleFilter = useCallback(
    (field: string, value: string) => {
      const existing = filters.find(
        (f) => f.field === field && !f.negated && f.value.toLowerCase() === value.toLowerCase(),
      );
      handleQueryChange(
        existing
          ? removeFilterFromQuery(query, existing.raw)
          : `${query} ${filterToken(field, value)}`.trim(),
      );
    },
    [filters, query, handleQueryChange],
  );

  const handleSetDateFilter = useCallback(
    (days: number | null) => {
      const existing = filters.find((f) => f.field === "date" && !f.negated);
      let next = existing ? removeFilterFromQuery(query, existing.raw) : query;
      if (days !== null) next = `${next} date:>${daysAgoISO(days)}`.trim();
      handleQueryChange(next);
    },
    [filters, query, handleQueryChange],
  );

  const handleClearFilters = useCallback(() => {
    let next = query;
    for (const f of filters) next = removeFilterFromQuery(next, f.raw);
    handleQueryChange(next.trim());
  }, [filters, query, handleQueryChange]);

  const toggleMatchKind = useCallback((kind: MatchKind) => {
    setMatchKinds((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      // Unchecking both would silently blank the intelligence half; the last
      // one standing stays checked.
      return next.size === 0 ? new Set([kind]) : next;
    });
  }, []);

  const entityCounts = results?.entities.counts ?? {};
  const items = useMemo(() => results?.entities.items ?? [], [results]);
  // The rail's entity value facets show what the stream shows: unticking
  // "Mentioned in text" has to remove those entities from the filter list too,
  // or the rail offers filters for rows that are not on screen.
  const visibleEntities = useMemo(
    () => items.filter((e) => matchKinds.has(e.match_kind === "direct" ? "direct" : "mention")),
    [items, matchKinds],
  );
  const directCount = items.filter(
    (e) => e.match_kind === "direct" && (entityTypeFilter === null || e.type === entityTypeFilter),
  ).length;
  const mentionCount = items.filter(
    (e) => e.match_kind !== "direct" && (entityTypeFilter === null || e.type === entityTypeFilter),
  ).length;

  const readerOpen = !!selectedEntryId && scope !== "workbench";

  // Reading mode, the same trade the feed reader makes: opening an article
  // folds the filter rail away so the results list and the reader get the
  // width, and closing it hands the rail back. Only what this took is given
  // back — a rail the user had already collapsed stays collapsed, and one they
  // re-open by hand while reading is theirs to keep.
  const facetsAutoCollapsedRef = useRef(false);
  useEffect(() => {
    if (isMobile) return;
    if (readerOpen) {
      if (!useUIStore.getState().searchFacetsCollapsed) {
        facetsAutoCollapsedRef.current = true;
        setFacetsCollapsed(true);
      }
      return;
    }
    if (facetsAutoCollapsedRef.current) {
      facetsAutoCollapsedRef.current = false;
      setFacetsCollapsed(false);
    }
    // Closing an entry hands the app sidebar back — the right move in the feed
    // reader, where it is the only nav, and the wrong one here, where it would
    // land beside the facet rail and stack two navs. Re-fold it as the page's
    // own auto-collapse did on the way in, still flagged so leaving the page
    // restores it.
    if (!useUIStore.getState().sidebarCollapsed) {
      useUIStore.setState({ sidebarCollapsed: true, sidebarAutoCollapsed: true });
    }
  }, [readerOpen, isMobile, setFacetsCollapsed]);

  // The results column collapses away entirely for a full-width read, exactly
  // as the entry list does; `entryListCollapsed` is that same shared pane
  // state, so the choice carries between the two surfaces.
  const listCollapsed = readerOpen && !isMobile && entryListCollapsed;
  const railHidden = isMobile ? !filterSheetOpen : facetsCollapsed;
  // The rail is a sized column only on desktop; on mobile it is a sheet whose
  // width the stylesheet owns.
  const facetRailWidth = useRailWidth("search-facets", { default: 232, min: 180, max: 480 });

  return (
    <div className={styles.container}>
      {isMobile && filterSheetOpen && (
        <div className={styles.sheetBackdrop} onClick={() => setFilterSheetOpen(false)} />
      )}
      <aside
        className={`${styles.facetRail} ${railHidden ? styles.facetRailCollapsed : ""} ${isMobile ? styles.facetSheet : ""}`}
        style={!isMobile && !railHidden ? facetRailWidth.style : undefined}
      >
        {isMobile && (
          <div className={styles.sheetHead}>
            <span className={styles.sheetTitle}>Filters</span>
            <button className={styles.sheetDone} onClick={() => setFilterSheetOpen(false)}>
              Done
            </button>
          </div>
        )}
        <SearchFacetSidebar
          scope={scope}
          onScopeChange={setScope}
          entityCounts={entityCounts}
          entities={visibleEntities}
          activeEntityType={entityTypeFilter}
          onEntityTypeChange={setEntityTypeFilter}
          matchKinds={matchKinds}
          onToggleMatchKind={toggleMatchKind}
          directCount={directCount}
          mentionCount={mentionCount}
          entryTotal={results?.entries.estimatedTotalHits ?? 0}
          facetDistribution={results?.entries.facetDistribution}
          filters={filters}
          onToggleFilter={handleToggleFilter}
          onSetDateFilter={handleSetDateFilter}
          activeDateDays={activeDateDays}
          onClearFilters={handleClearFilters}
        />
      </aside>

      {!isMobile && !facetsCollapsed && (
        <ResizeHandle label="search filters" {...facetRailWidth.handleProps} />
      )}

      {!isMobile && (
        <RailToggle
          side="left"
          collapsed={facetsCollapsed}
          onToggle={() => setFacetsCollapsed(!facetsCollapsed)}
          label="search filters"
          verbs={["Show", "Hide"]}
        />
      )}

      {!listCollapsed && (
        <div
          className={styles.stream}
          style={readerOpen && !isMobile ? { width: entryListWidth, flex: "none" } : undefined}
        >
          <SearchResults
            query={query}
            debouncedQuery={debouncedQuery}
            results={results}
            isLoading={isLoading}
            scope={scope}
            entityTypeFilter={entityTypeFilter}
            matchKinds={matchKinds}
            onQueryChange={handleQueryChange}
            onSelectEntry={setSelectedEntry}
            onOpenFilters={isMobile ? () => setFilterSheetOpen(true) : undefined}
            activeFilterCount={filters.length}
            offset={offset}
            onOffsetChange={setOffset}
            hideRead={hideRead}
            onHideReadChange={setHideRead}
            narrow={readerOpen && !isMobile}
          />
        </div>
      )}

      {readerOpen && !isMobile && !entryListCollapsed && (
        <ResizeHandle onResize={(delta) => setEntryListWidth(entryListWidth + delta)} />
      )}

      {readerOpen && !isMobile && (
        <RailToggle
          side="both"
          collapsed={entryListCollapsed}
          onToggle={() => setEntryListCollapsed(!entryListCollapsed)}
          label="results"
          verbs={["Show", "Hide"]}
        />
      )}

      {readerOpen && (
        <div className={styles.reader}>
          <EntryReader entryId={selectedEntryId!} />
        </div>
      )}
    </div>
  );
}
