import { useCallback, useEffect, useMemo, useState } from "react";
import { useMarkRead } from "@/hooks/useEntries";
import { useSavedSearches, useCreateSavedSearch, useDeleteSavedSearch, useUpdateSavedSearch } from "@/hooks/useSearch";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useOpenSavedSearch } from "@/hooks/useOpenSavedSearch";
import { useIntelStore } from "@/stores/intelStore";
import { useEntryIntelBadges } from "@/hooks/useEntryIntelBadges";
import { useUIStore, type SearchScope } from "@/stores/uiStore";
import { parseQuery, extractFilters, removeFilterFromQuery, type ParsedFilter } from "@/utils/queryParser";
import { getEntityColor } from "@/utils/entityTheme";
import type { Entry, EntitySearchResult, SavedSearchFilters, SearchHit, UnifiedSearchResponse } from "@/api/types";
import { EntryRow } from "@/components/EntryList";
import { BulkActionsToolbar } from "@/components/BulkActionsToolbar";
import FilterChips from "@/components/FilterChips";
import { QueryBuilder } from "@/components/QueryBuilder";
import { SearchSyntaxHelp } from "./SearchSyntaxHelp";
import { ENTITY_TYPE_LABELS, getSearchResultName, getSearchResultSubtext, useEntityResultNavigate } from "./EntityResults";
import type { MatchKind } from "./SearchFacetSidebar";
import styles from "./SearchResults.module.css";
import { promptDialog } from "@/utils/dialog";

/** Rows a mention group shows before its "Show all N". */
const GROUP_CAP = 10;

// Direct-match fields whose matched value is the name/identifier already
// printed on the row. Tagging these restates the obvious; the section header
// ("name, alias or identifier") covers them.
const SELF_EVIDENT_MATCH_FIELDS = new Set(["name", "title", "cve_id", "mitre_id", "technique"]);

const MATCH_FIELD_LABELS: Record<string, string> = {
  name: "Name",
  alias: "Alias",
  technique: "Technique",
  cve_id: "CVE ID",
  mitre_id: "MITRE ID",
  title: "Title",
  description: "in description",
  context: "in context",
  tactic: "tactic",
  tags: "in tags",
  notes: "in notes",
  content: "in body",
  rule_content: "in rule body",
  mitre_tactics: "ATT&CK tactic",
  malware_type: "type",
  tool_type: "type",
  vendor_type: "type",
  product_type: "type",
};

function searchHitToEntry(hit: SearchHit, markedReadIds: Set<string>): Entry {
  return {
    id: hit.id,
    feed_id: hit.feed_id || "",
    guid: null,
    url: hit.url,
    title: hit.title,
    translated_title: null,
    author: hit.author,
    summary: hit.summary || hit.content_text,
    published_at:
      typeof hit.published_at === "number" ? new Date(hit.published_at * 1000).toISOString() : hit.published_at,
    fetched_at: "",
    word_count: hit.word_count ?? null,
    content_hash: null,
    image_url: null,
    feed_title: hit.feed_title,
    feed_type: hit.feed_type,
    metadata: null,
    media: [],
    is_read: markedReadIds.has(hit.id) || (hit.is_read ?? false),
    is_starred: hit.is_starred ?? false,
    is_bookmarked: hit.is_bookmarked ?? false,
    tags: hit.tag_details ?? (hit.tags ?? []).map((t: string) => ({ name: t, color: "" })),
  };
}

/** Stable identity for a result across the two entity halves. */
function entityKey(e: EntitySearchResult): string {
  return `${e.type}-${e.id}`;
}

/** Wrap a multi-word term so it re-searches as a phrase, not as loose words. */
function quoteTerm(term: string): string {
  return term.includes(" ") ? `"${term}"` : term;
}

function entitySubtitle(e: EntitySearchResult): string {
  const parts: string[] = [];
  const sub = getSearchResultSubtext(e);
  if (sub) parts.push(sub);
  if (e.aliases?.length) parts.push(`aka ${e.aliases.slice(0, 4).join(", ")}${e.aliases.length > 4 ? ` +${e.aliases.length - 4}` : ""}`);
  return parts.join(" · ");
}

function entitySnippet(e: EntitySearchResult): string | null {
  const text = e.description || e.summary || null;
  if (!text) return null;
  return text.length > 190 ? `${text.slice(0, 190).trimEnd()}…` : text;
}

interface Props {
  query: string;
  debouncedQuery: string;
  results?: UnifiedSearchResponse;
  isLoading: boolean;
  scope: SearchScope;
  /** Sidebar's entity-type facet; null = all types. */
  entityTypeFilter: string | null;
  matchKinds: Set<MatchKind>;
  onQueryChange: (q: string) => void;
  onSelectEntry: (entryId: string) => void;
  offset: number;
  onOffsetChange: (offset: number) => void;
  /** Owned by the page because the server applies it to the whole match set. */
  hideRead: boolean;
  onHideReadChange: (hideRead: boolean) => void;
  /** Mobile only: the rail is a sheet there, so it needs a way in. */
  onOpenFilters?: () => void;
  activeFilterCount?: number;
  /** Sharing the pane with an open reader — same squeeze the entry list takes. */
  narrow?: boolean;
}

export function SearchResults({
  query,
  debouncedQuery,
  results,
  isLoading,
  scope,
  entityTypeFilter,
  matchKinds,
  onQueryChange,
  onSelectEntry,
  offset,
  onOffsetChange,
  hideRead,
  onHideReadChange,
  onOpenFilters,
  activeFilterCount = 0,
  narrow = false,
}: Props) {
  const navigateToEntity = useEntityResultNavigate();
  const [markedReadIds, setMarkedReadIds] = useState<Set<string>>(new Set());
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [showHelp, setShowHelp] = useState(false);
  const [showBuilder, setShowBuilder] = useState(false);
  // Which result is expanded into its preview card. Clicking a row opens its
  // preview rather than navigating, so the analyst can click down a list and
  // read each one in place; the card's own "Open profile" is the way out.
  const [previewKey, setPreviewKey] = useState<string | null>(null);

  const selectedEntryId = useUIStore((s) => s.selectedEntryId);
  // Search keeps its own Hide Read rather than sharing the feed reader's:
  // entering a search used to force that shared preference off, silently
  // changing the feed list behind you. Off by default — a search shows what
  // matched, read or not. The page owns the state because the filter is applied
  // server-side, across every match rather than the fetched page.
  const markReadOnScroll = useUIStore((s) => s.markReadOnScroll);
  const toggleMarkReadOnScroll = useUIStore((s) => s.toggleMarkReadOnScroll);
  const viewMode = useUIStore((s) => s.viewMode);
  const setViewMode = useUIStore((s) => s.setViewMode);
  const selectedEntryIds = useUIStore((s) => s.selectedEntryIds);
  const lastSelectedIndex = useUIStore((s) => s.lastSelectedIndex);
  const toggleEntrySelection = useUIStore((s) => s.toggleEntrySelection);
  const setEntrySelection = useUIStore((s) => s.setEntrySelection);
  const setLastSelectedIndex = useUIStore((s) => s.setLastSelectedIndex);
  const clearEntrySelection = useUIStore((s) => s.clearEntrySelection);

  const markRead = useMarkRead();
  const { data: savedSearches } = useSavedSearches();
  const createSaved = useCreateSavedSearch();
  const deleteSaved = useDeleteSavedSearch();
  const updateSaved = useUpdateSavedSearch();
  const undoableDelete = useUndoableDelete();
  const openSavedSearch = useOpenSavedSearch();
  const recentSearches = useIntelStore((s) => s.recentSearches);
  const addRecentSearch = useIntelStore((s) => s.addRecentSearch);

  // Recent searches are recorded from the debounced value, so a query is only
  // remembered once the user stops typing it — not once per keystroke.
  useEffect(() => {
    if (debouncedQuery.trim()) addRecentSearch(debouncedQuery.trim());
  }, [debouncedQuery, addRecentSearch]);

  // Saved alongside the query: the rail state the query language cannot say.
  // Without it a saved search reopens as bare text and quietly searches a
  // different scope than the one it was saved from.
  const handleSaveSearch = useCallback(async () => {
    if (!query.trim()) return;
    const name = await promptDialog({
      title: "Save search",
      message: "Save search as:",
      defaultValue: query,
      confirmLabel: "Save",
    });
    if (!name) return;
    const filters: SavedSearchFilters = {
      scope,
      entity_type: entityTypeFilter,
      match_kinds: [...matchKinds],
    };
    createSaved.mutate({ name, query, filters });
  }, [query, scope, entityTypeFilter, matchKinds, createSaved]);

  const showIntel = scope !== "feeds";
  const showEntries = scope !== "workbench";

  const parsedFilters = useMemo(() => extractFilters(parseQuery(query)), [query]);
  const didYouMean = results?.did_you_mean ?? null;
  const unknownFields = results?.unknown_fields ?? [];

  const entryHits = useMemo(() => (showEntries ? results?.entries.hits ?? [] : []), [results, showEntries]);
  const totalEntries = showEntries ? results?.entries.estimatedTotalHits ?? 0 : 0;

  const entities = useMemo(() => {
    if (!showIntel) return [];
    const items = results?.entities.items ?? [];
    return items.filter(
      (e) =>
        (entityTypeFilter === null || e.type === entityTypeFilter) &&
        matchKinds.has(e.match_kind === "direct" ? "direct" : "mention"),
    );
  }, [results, showIntel, entityTypeFilter, matchKinds]);

  const direct = useMemo(() => entities.filter((e) => e.match_kind === "direct"), [entities]);
  const mentions = useMemo(() => entities.filter((e) => e.match_kind !== "direct"), [entities]);

  // Mentions are grouped by type; direct matches are few and stay in one
  // relevance-ordered list, because splitting three rows by type is noise.
  const mentionGroups = useMemo(() => {
    const map = new Map<string, EntitySearchResult[]>();
    for (const e of mentions) {
      const list = map.get(e.type);
      if (list) list.push(e);
      else map.set(e.type, [e]);
    }
    return map;
  }, [mentions]);

  // The preview defaults to the best answer — the first direct match, or the
  // first result when nothing matched by name. Deriving it (rather than storing
  // a fallback) means a preview whose row is filtered away by the facet rail
  // quietly hands off to the new best answer instead of blanking.
  const previewEntity = useMemo(() => {
    if (entities.length === 0) return null;
    return entities.find((e) => entityKey(e) === previewKey) ?? direct[0] ?? entities[0];
  }, [entities, direct, previewKey]);

  const entries: Entry[] = useMemo(() => {
    const all = entryHits.map((hit) => searchHitToEntry(hit, markedReadIds));
    // The server already dropped what was read when the search ran; this only
    // clears the rows read since, without waiting for a refetch.
    return hideRead ? all.filter((e) => !e.is_read) : all;
  }, [entryHits, markedReadIds, hideRead]);

  const searchEntryIds = useMemo(() => entries.map((e) => e.id), [entries]);
  const { data: intelBadges } = useEntryIntelBadges(searchEntryIds);

  const snippetMap = useMemo(() => {
    const map: Record<string, string> = {};
    for (const hit of entryHits) {
      if (hit._formatted?.content_text) map[hit.id] = hit._formatted.content_text;
    }
    return map;
  }, [entryHits]);

  const currentSort = useMemo(
    () => parsedFilters.find((f) => f.field === "sort")?.value || "relevance",
    [parsedFilters],
  );

  const handleSortChange = useCallback(
    (newSort: string) => {
      let next = query.replace(/\bsort:\S+/g, "").trim();
      if (newSort !== "relevance") next = `${next} sort:${newSort}`.trim();
      onQueryChange(next);
    },
    [query, onQueryChange],
  );

  const handleRemoveFilter = useCallback(
    (filter: ParsedFilter) => onQueryChange(removeFilterFromQuery(query, filter.raw)),
    [query, onQueryChange],
  );

  const handleEntryClick = useCallback(
    (entry: Entry) => {
      onSelectEntry(entry.id);
      if (markReadOnScroll && !entry.is_read) {
        markRead.mutate(entry.id);
        setMarkedReadIds((prev) => new Set(prev).add(entry.id));
      }
    },
    [onSelectEntry, markRead, markReadOnScroll],
  );

  const handleCheckboxClick = useCallback(
    (index: number, entryId: string, e: React.MouseEvent) => {
      if (e.shiftKey && lastSelectedIndex !== null) {
        const start = Math.min(lastSelectedIndex, index);
        const end = Math.max(lastSelectedIndex, index);
        const merged = new Set(selectedEntryIds);
        entries.slice(start, end + 1).forEach((en) => merged.add(en.id));
        setEntrySelection(Array.from(merged));
      } else {
        toggleEntrySelection(entryId);
      }
      setLastSelectedIndex(index);
    },
    [entries, lastSelectedIndex, selectedEntryIds, toggleEntrySelection, setEntrySelection, setLastSelectedIndex],
  );

  const bulkMode = selectedEntryIds.size > 0;
  const handleSelectAll = useCallback(() => {
    if (selectedEntryIds.size === entries.length) clearEntrySelection();
    else setEntrySelection(entries.map((e) => e.id));
  }, [entries, selectedEntryIds.size, clearEntrySelection, setEntrySelection]);

  const toggleGroup = (type: string) =>
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });

  // Collapse expansions when the answer changes underneath them, and hand the
  // preview back to whatever the new best answer is.
  useEffect(() => {
    setExpandedGroups(new Set());
    setPreviewKey(null);
  }, [debouncedQuery, entityTypeFilter]);

  /** A result row, or its preview card when it is the one being previewed. */
  const renderEntity = (e: EntitySearchResult, showSnippet = false) => {
    const key = entityKey(e);
    if (previewEntity && entityKey(previewEntity) === key) {
      return (
        <FeaturedEntity
          key={key}
          entity={e}
          onOpen={() => navigateToEntity(e)}
          onScopeToEntity={() => onQueryChange(quoteTerm(getSearchResultName(e)))}
        />
      );
    }
    return (
      <EntityRow
        key={key}
        entity={e}
        onClick={() => setPreviewKey(key)}
        showSnippet={showSnippet}
      />
    );
  };

  const hasAnything = direct.length > 0 || mentions.length > 0 || entries.length > 0;

  if (!debouncedQuery.trim()) {
    const hasHistory = recentSearches.length > 0 || (savedSearches?.length ?? 0) > 0;
    const appendToken = (token: string) => onQueryChange(`${query} ${token}`.trimStart());
    return (
      <div className={styles.placeholder}>
        <div className={styles.placeholderHead}>
          <h2 className={styles.placeholderTitle}>Search IntelFeed</h2>
          <p>
            Look up an actor, malware family, CVE, technique, or search article text. Narrow the
            answer with the filters on the left — or say it directly in the query language.
          </p>
        </div>

        {hasHistory && (
          <div className={styles.historyGrid}>
            {recentSearches.length > 0 && (
              <section className={styles.savedBlock}>
                <div className={styles.savedHeader}>Recent</div>
                <div className={styles.chipRow}>
                  {recentSearches.map((q) => (
                    <button key={q} className={styles.queryChip} onClick={() => onQueryChange(q)}>
                      {q}
                    </button>
                  ))}
                </div>
              </section>
            )}

            {savedSearches && savedSearches.length > 0 && (
              <section className={styles.savedBlock}>
                <div className={styles.savedHeader}>Saved searches</div>
                <div className={styles.savedList}>
                  {savedSearches.map((sv) => (
                    <div key={sv.id} className={styles.savedItem}>
                      <button className={styles.savedName} onClick={() => openSavedSearch(sv)}>
                        <span className={styles.savedTitle}>{sv.name}</span>
                        {sv.query && <span className={styles.savedQuery}>{sv.query}</span>}
                      </button>
                      <button
                        className={styles.savedAction}
                        title="Rename"
                        onClick={async () => {
                          const newName = await promptDialog({
                            title: "Rename saved search",
                            message: "Rename saved search:",
                            defaultValue: sv.name,
                            confirmLabel: "Rename",
                          });
                          if (newName && newName !== sv.name) updateSaved.mutate({ id: sv.id, data: { name: newName } });
                        }}
                      >
                        Rename
                      </button>
                      <button
                        className={styles.savedAction}
                        title="Delete"
                        onClick={() =>
                          undoableDelete({
                            label: `Saved search "${sv.name}"`,
                            key: `saved-search-${sv.id}`,
                            onDelete: () => deleteSaved.mutate(sv.id),
                          })
                        }
                      >
                        Delete
                      </button>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </div>
        )}

        <SearchSyntaxHelp variant="card" onInsert={appendToken} onRunExample={onQueryChange} />
      </div>
    );
  }

  return (
    <div className={`${styles.results} ${narrow ? styles.narrow : ""}`}>
      {didYouMean && (
        // A value ends at the first space, so `country:North Korea` filters on
        // "North" and full-text searches "Korea" — a plausible wrong answer, not
        // an error. The server only offers this when the longer value is real.
        <div className={styles.didYouMean}>
          <span>
            Did you mean <code>{didYouMean}</code>?
          </span>
          <button type="button" className={styles.didYouMeanApply} onClick={() => onQueryChange(didYouMean)}>
            Apply
          </button>
        </div>
      )}
      {unknownFields.length > 0 && (
        // `titel:ransomware` is not a filter and never was — the value just gets
        // searched as text. Saying so is the difference between "no results
        // because nothing matched" and "no results because you typed it wrong".
        <div className={styles.unknownFields}>
          {unknownFields.map((f) => (
            <code key={f}>{f}:</code>
          ))}
          <span>
            {unknownFields.length === 1 ? "is not a search field" : "are not search fields"} — searched as plain text
            instead.
          </span>
        </div>
      )}
      <div className={styles.toolbar}>
        <div className={styles.toolbarLeft}>
          <span className={styles.summary}>
            {isLoading ? (
              "Searching…"
            ) : (
              <>
                {showIntel && (
                  <b>
                    {entities.length.toLocaleString()} {entities.length === 1 ? "entity" : "entities"}
                  </b>
                )}
                {showIntel && showEntries && <span className={styles.dot}>·</span>}
                {showEntries && <b>{totalEntries.toLocaleString()} articles</b>}
              </>
            )}
          </span>
          <FilterChips filters={parsedFilters} onRemove={handleRemoveFilter} variant="inline" />
        </div>
        <div className={styles.toolbarRight}>
          {onOpenFilters && (
            <button className={`${styles.toolbarBtn} ${activeFilterCount > 0 ? styles.toolbarBtnActive : ""}`} onClick={onOpenFilters}>
              Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ""}
            </button>
          )}
          <button
            className={`${styles.toolbarBtn} ${showBuilder ? styles.toolbarBtnActive : ""}`}
            onClick={() => { setShowBuilder(!showBuilder); if (!showBuilder) setShowHelp(false); }}
            title="Visual query builder"
          >
            Builder
          </button>
          <button
            className={`${styles.toolbarBtn} ${showHelp ? styles.toolbarBtnActive : ""}`}
            onClick={() => { setShowHelp(!showHelp); if (!showHelp) setShowBuilder(false); }}
            title="Query syntax help"
          >
            ?
          </button>
          <button className={styles.toolbarBtn} onClick={handleSaveSearch} disabled={!query.trim()}>
            Save
          </button>
        </div>
        {showEntries && (
          <div className={styles.toolbarRight}>
            <button
              className={`${styles.toolbarBtn} ${hideRead ? styles.toolbarBtnActive : ""}`}
              onClick={() => onHideReadChange(!hideRead)}
            >
              Hide Read
            </button>
            <button
              className={`${styles.toolbarBtn} ${markReadOnScroll ? styles.toolbarBtnActive : ""}`}
              onClick={toggleMarkReadOnScroll}
            >
              Auto-read
            </button>
            <select className={styles.select} value={currentSort} onChange={(e) => handleSortChange(e.target.value)}>
              <option value="relevance">Relevance</option>
              <option value="newest">Newest</option>
              <option value="oldest">Oldest</option>
              <option value="title_asc">Title A-Z</option>
              <option value="title_desc">Title Z-A</option>
              <option value="shortest">Shortest</option>
              <option value="longest">Longest</option>
            </select>
            <select
              className={styles.select}
              value={viewMode === "compact" ? "compact" : "expanded"}
              onChange={(e) => setViewMode(e.target.value as "compact" | "expanded")}
            >
              <option value="compact">Compact</option>
              <option value="expanded">Expanded</option>
            </select>
          </div>
        )}
      </div>

      {showHelp && <SearchSyntaxHelp />}
      {showBuilder && (
        <QueryBuilder
          currentQuery={query}
          onApply={(q) => {
            onQueryChange(q);
            setShowBuilder(false);
          }}
        />
      )}

      {bulkMode && (
        <BulkActionsToolbar
          selectedIds={selectedEntryIds}
          totalCount={entries.length}
          onSelectAll={handleSelectAll}
          onClearSelection={clearEntrySelection}
        />
      )}

      <div className={styles.scroll}>
        {!isLoading && !hasAnything && (
          <div className={styles.empty}>
            Nothing matched <b>{debouncedQuery}</b>
            {parsedFilters.length > 0 && " with these filters"}.
          </div>
        )}

        {showIntel && direct.length > 0 && (
          <section className={styles.section}>
            <SectionHeader title="Direct matches" count={direct.length} hint="name, alias or identifier" />
            {direct.map((e) => renderEntity(e))}
          </section>
        )}

        {showIntel &&
          Array.from(mentionGroups.entries()).map(([type, items]) => {
            const expanded = expandedGroups.has(type);
            const visible = expanded ? items : items.slice(0, GROUP_CAP);
            return (
              <section key={type} className={styles.section}>
                <SectionHeader
                  title={ENTITY_TYPE_LABELS[type] || type}
                  count={items.length}
                  hint="mentions your query"
                  color={getEntityColor(type)}
                />
                {visible.map((e) => renderEntity(e, true))}
                {items.length > GROUP_CAP && (
                  <button className={styles.showAll} onClick={() => toggleGroup(type)}>
                    {expanded ? "Show fewer" : `Show all ${items.length}`}
                  </button>
                )}
              </section>
            );
          })}

        {showEntries && entries.length > 0 && (
          <section className={styles.section}>
            <SectionHeader title="Articles" count={totalEntries} color="var(--accent)" />
            <div className={styles.entryList}>
              {entries.map((entry, i) => (
                <EntryRow
                  key={entry.id}
                  entry={entry}
                  isSelected={selectedEntryId === entry.id}
                  isChecked={selectedEntryIds.has(entry.id)}
                  bulkMode={bulkMode}
                  viewMode={viewMode === "compact" ? "compact" : "expanded"}
                  searchSnippet={snippetMap[entry.id]}
                  intelCounts={intelBadges?.[entry.id]}
                  undimRead
                  onClick={() => handleEntryClick(entry)}
                  onCheck={(e) => handleCheckboxClick(i, entry.id, e)}
                />
              ))}
            </div>
            {totalEntries > 100 && (
              <div className={styles.pagination}>
                <button disabled={offset === 0} onClick={() => onOffsetChange(Math.max(0, offset - 100))}>
                  Previous
                </button>
                <span>
                  {offset + 1}–{Math.min(offset + 100, totalEntries)} of {totalEntries.toLocaleString()}
                </span>
                <button disabled={offset + 100 >= totalEntries} onClick={() => onOffsetChange(offset + 100)}>
                  Next
                </button>
              </div>
            )}
          </section>
        )}
      </div>
    </div>
  );
}

function SectionHeader({
  title,
  count,
  hint,
  color,
}: {
  title: string;
  count: number;
  hint?: string;
  color?: string;
}) {
  return (
    <div className={styles.sectionHeader}>
      {color && <span className={styles.sectionSwatch} style={{ background: color }} />}
      <span className={styles.sectionTitle}>{title}</span>
      <span className={styles.sectionCount}>{count.toLocaleString()}</span>
      {hint && <span className={styles.sectionHint}>{hint}</span>}
      <span className={styles.sectionRule} />
    </div>
  );
}

/** The top direct match, given room to actually answer the question. */
function FeaturedEntity({
  entity,
  onOpen,
  onScopeToEntity,
}: {
  entity: EntitySearchResult;
  onOpen: () => void;
  onScopeToEntity: () => void;
}) {
  const color = getEntityColor(entity.type);
  const snippet = entitySnippet(entity);
  const articles = entity.article_count ?? null;
  return (
    <div className={styles.featured} style={{ borderLeftColor: color }}>
      <div className={styles.featuredBody}>
        <div className={styles.featuredHead}>
          <TypeBadge type={entity.type} />
          <span className={styles.featuredName}>{getSearchResultName(entity)}</span>
          {/* Reads the entity's own kind — any row can be previewed now, so a
              mention must not wear the direct-match badge. */}
          <MatchTag field={entity.match_field} kind={entity.match_kind} />
        </div>
        {entitySubtitle(entity) && <div className={styles.featuredSub}>{entitySubtitle(entity)}</div>}
        {snippet && <p className={styles.featuredDesc}>{snippet}</p>}
      </div>
      <div className={styles.featuredActions}>
        <button className={`${styles.action} ${styles.actionPrimary}`} onClick={onOpen}>
          {entity.type === "note" ? "Open note" : "Open profile"}
        </button>
        <button className={styles.action} onClick={onScopeToEntity}>
          Search this term only
        </button>
        {articles != null && articles > 0 && (
          <div className={styles.featuredStat}>
            <b>{articles.toLocaleString()}</b> linked article{articles === 1 ? "" : "s"}
          </div>
        )}
      </div>
    </div>
  );
}

function EntityRow({
  entity,
  onClick,
  showSnippet,
}: {
  entity: EntitySearchResult;
  onClick: () => void;
  showSnippet?: boolean;
}) {
  const sub = showSnippet ? entitySnippet(entity) || entitySubtitle(entity) : entitySubtitle(entity);
  const articles = entity.article_count ?? null;
  return (
    <button className={styles.row} onClick={onClick}>
      <TypeBadge type={entity.type} />
      <span className={styles.rowName}>{getSearchResultName(entity)}</span>
      {sub && <span className={styles.rowSub}>{sub}</span>}
      <MatchTag field={entity.match_field} kind={entity.match_kind} />
      {articles != null && articles > 0 && (
        <span className={styles.rowCount}>{articles.toLocaleString()}</span>
      )}
    </button>
  );
}

function TypeBadge({ type }: { type: string }) {
  const color = getEntityColor(type);
  const label = type === "detection_rule" ? "rule" : type === "threat_actor" ? "actor" : type;
  return (
    <span
      className={styles.badge}
      style={{ color, background: `color-mix(in srgb, ${color} 15%, transparent)` }}
    >
      {label}
    </span>
  );
}

function MatchTag({ field, kind }: { field?: string; kind?: string }) {
  if (!field) return null;
  const direct = kind === "direct";
  // The tag exists to explain a match the row does not already explain. When
  // the matched field IS the text on the row, saying so is noise on every
  // result — so only alias-style matches, where the query never appears in
  // what you can see, earn a tag.
  if (direct && SELF_EVIDENT_MATCH_FIELDS.has(field)) return null;
  // A title match is identity when the query opens the title and incidental
  // when it is merely somewhere inside it, so the same field reads two ways.
  const label = field === "title" && !direct ? "in title" : MATCH_FIELD_LABELS[field] ?? field.replace(/_/g, " ");
  return <span className={`${styles.matchTag} ${direct ? styles.matchTagDirect : ""}`}>{label}</span>;
}
