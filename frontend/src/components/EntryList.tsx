import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import DOMPurify from "dompurify";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  useEntries,
  useEntriesCount,
  usePriorityQueue,
  useMarkRead,
  useMarkAllRead,
  useToggleStar,
  useToggleBookmark,
  useBulkAction,
} from "@/hooks/useEntries";
import { useFeeds } from "@/hooks/useFeeds";
import { useEntryIntelBadges } from "@/hooks/useEntryIntelBadges";
import { previewSnippet } from "@/utils/previewText";
import { formatDate } from "@/utils/formatDate";
import { groupConsecutiveEntries } from "@/utils/groupEntries";
import { injectDayDividers, filterCollapsedDays, type DayDividerItem } from "@/utils/dayDividers";
import { DayDividerSummary } from "@/components/DayDividerSummary";
import { DayIntelChips, type DayFocus } from "@/components/DayIntelChips";
import { MarkDayReadButton } from "@/components/MarkDayReadButton";
import type { DailySummaryFilters } from "@/hooks/useDailySummary";
import { dayWindowIso } from "@/hooks/useDayIntel";
import { useUIStore, type SortOrder, type ViewMode } from "@/stores/uiStore";
import { useReadingPrefs } from "@/hooks/useReadingPrefs";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { usePullToRefresh } from "@/hooks/usePullToRefresh";
import { SwipeableEntryRow } from "@/components/SwipeableEntryRow";
import { CVEGroupRow } from "@/components/CVEGroupRow";
import { ThreadRow } from "@/components/ThreadRow";
import { queueItems, magazineQueueItems, type QueueItem, type MagazineItem } from "@/utils/threads";
import { MagazineThreadCard } from "@/components/MagazineThreadCard";
import { EntryIntelBadges } from "@/components/EntryIntelBadges";
import { EntryTableView } from "@/components/EntryTableView";
import { IntelLevelBadge } from "@/components/IntelLevelBadge";
import type { Entry } from "@/api/types";
import type { EntryIntelCounts } from "@/hooks/useEntryIntelBadges";
import { FeedNameMenuButton } from "@/components/FeedNameMenuButton";
import { Hint } from "@/components/primitives";
import { FeedTypeIcon } from "@/components/FeedTypeIcon";
import { EntryListSkeleton, MagazineSkeleton } from "@/components/Skeleton";
import { BulkActionsToolbar } from "@/components/BulkActionsToolbar";
import filterStyles from "./ContentTypeFilter.module.css";
import styles from "./EntryList.module.css";
import { SignalChip } from "./SignalChip";
import { ExposureChip } from "./ExposureChip";
import { ToolbarDropdown, DropdownItem } from "@/components/ToolbarDropdown";
import { DEFAULT_TABLE_LAYOUTS } from "@/components/table/defaultLayouts";
import { adjacentEntryId } from "@/utils/entryNavigation";
import { openExternalUrl } from "@/utils/openExternal";
import { isExternalWebUrl } from "@/utils/externalLinks";
import { useIsVisitor } from "@/stores/authStore";

function stripHtml(html: string): string {
  const doc = new DOMParser().parseFromString(html, "text/html");
  return doc.body.textContent || "";
}

function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

/* --------------------------------------------------------------------------
 * Narrow-pane fallback: the table's configured columns as the row's meta line
 * ------------------------------------------------------------------------ */

/** DataTable id the entry table registers under — see EntryTableView. */
const ENTRIES_TABLE_ID = "entries";
/** Most fields one squeezed row can carry before the line stops being readable. */
const MAX_META_FIELDS = 4;
/** Stable empty identity, so a non-fallback row's memo never breaks on it. */
const NO_META_COLUMNS: string[] = [];

interface MetaColumn {
  /** Mirrors the table column's `defaultHidden` — hidden until enabled. */
  defaultHidden?: boolean;
  /** Inline projection; null when this entry has nothing to say for the column. */
  render: (entry: Entry, counts?: EntryIntelCounts) => ReactNode;
}

/** Tags that stay a quiet label — the ones not promoted to a badge-row chip. */
function plainTagsOf(entry: Entry) {
  return (entry.tags ?? []).filter((t) => !t.display_as_chip);
}

function plainTagNames(entry: Entry): string | null {
  const names = plainTagsOf(entry).map((t) => t.name);
  return names.length ? names.join(", ") : null;
}

function domainOf(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}

/** Detection-opportunity tier label; mirrors EntryTableView's `opportunity` cell. */
function opportunityLabel(c?: EntryIntelCounts): string | null {
  if (!c) return null;
  const hot = !!c.has_detection_gap && !!c.has_high_risk_cve;
  if (hot && c.has_kev_cve) return "KEV";
  if (hot) return "high-risk";
  const tier =
    c.detection_opportunity !== undefined
      ? c.detection_opportunity
      : c.has_detection_gap
        ? "actionable_gap"
        : null;
  if (tier === "actionable_gap") return "gap";
  if (tier === "telemetry_gap") return "telemetry";
  return null;
}

/**
 * Inline projections of the entry table's columns, keyed by the same column
 * keys EntryTableView declares and listed in the same declaration order.
 *
 * EntryTableView's `COLUMNS` array isn't exported and isn't ours to change, so
 * this is a deliberately compact mirror of the *cells*. The visibility and
 * ordering decision is not mirrored — that still comes from the one source of
 * truth, `uiStore.tables["entries"]` layered over `DEFAULT_TABLE_LAYOUTS`
 * exactly the way DataTable layers them (see visibleMetaColumnKeys).
 *
 * Three declared columns are deliberately absent: `status` (the row already
 * shows read/starred/bookmarked state), `title` (it *is* the row heading), and
 * `summary` (a paragraph, not metadata). DataTable's checkbox column never
 * appears here — it isn't part of the declared column set at all.
 */
const META_COLUMNS: Record<string, MetaColumn> = {
  source: {
    render: (e) =>
      e.feed_title ? (
        <FeedNameMenuButton feedId={e.feed_id} className={styles.feedNameBtn}>
          {e.feed_type && <FeedTypeIcon type={e.feed_type} size={11} />}
          {e.feed_title}
        </FeedNameMenuButton>
      ) : null,
  },
  date: { render: (e) => formatDate(e.published_at, "") || null },
  signal: {
    render: (e) =>
      e.priority_score != null ? (
        <SignalChip score={e.priority_score} signals={e.top_signals ?? []} />
      ) : null,
  },
  pir: { render: (_e, c) => (c?.pir_matches?.length ? `${c.pir_matches.length} PIR` : null) },
  subject: {
    render: (_e, c) => {
      const names = [...(c?.actors ?? []), ...(c?.malware ?? [])];
      return names.length ? names.join(", ") : null;
    },
  },
  ttps: { render: (_e, c) => (c?.ttps ? `${c.ttps} TTP` : null) },
  cves: { render: (_e, c) => (c?.cves ? `${c.cves} CVE` : null) },
  rules: { render: (_e, c) => (c?.rules ? `${c.rules} rule${c.rules === 1 ? "" : "s"}` : null) },
  ai: { render: (_e, c) => (c?.ai_results ? `${c.ai_results} AI` : null) },
  opportunity: { defaultHidden: true, render: (_e, c) => opportunityLabel(c) },
  notes: {
    defaultHidden: true,
    render: (_e, c) => (c?.notes ? `${c.notes} note${c.notes === 1 ? "" : "s"}` : null),
  },
  // Chips already lead the badge row; this column carries the quiet tags.
  tags: { render: (e) => plainTagNames(e) },
  type: { defaultHidden: true, render: (e) => (e.feed_type ? e.feed_type.replace(/_/g, " ") : null) },
  domain: { defaultHidden: true, render: (e) => domainOf(e.url) },
  author: { defaultHidden: true, render: (e) => e.author || null },
  words: {
    defaultHidden: true,
    render: (e) => (e.word_count ? `${Math.ceil(e.word_count / 200)} min` : null),
  },
};

/**
 * The entry table's currently-visible columns, in the user's configured order.
 * Resolution follows DataTable's: the user's stored layout wins, then the
 * instance preset, then the column's own default.
 */
function visibleMetaColumnKeys(layout?: {
  columnVisibility: Record<string, boolean>;
  columnOrder: string[];
}): string[] {
  const preset = DEFAULT_TABLE_LAYOUTS[ENTRIES_TABLE_ID] ?? {};
  const order = (layout?.columnOrder.length ? layout.columnOrder : preset.order) ?? [];
  const arranged = order.filter((k) => k in META_COLUMNS);
  // Columns absent from the stored/preset order keep their declared position.
  for (const key of Object.keys(META_COLUMNS)) {
    if (!arranged.includes(key)) arranged.push(key);
  }
  return arranged.filter(
    (k) => layout?.columnVisibility[k] ?? preset.visibility?.[k] ?? !META_COLUMNS[k].defaultHidden,
  );
}

/**
 * "Mark read" split button: the primary half marks the whole view read, the ▾
 * half offers the same All plus Above (everything before the selected entry,
 * also on Shift+M). The menu is portalled because the toolbar clips its
 * overflow to pan horizontally in a narrow pane.
 */
function MarkReadSplitButton({
  onMarkAll,
  onMarkAbove,
  canMarkAbove,
}: {
  onMarkAll: () => void;
  onMarkAbove: () => void;
  canMarkAbove: boolean;
}) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [menuStyle, setMenuStyle] = useState<CSSProperties>({});

  useLayoutEffect(() => {
    if (!open) return;
    const update = () => {
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return;
      setMenuStyle({ position: "fixed", top: rect.bottom + 4, left: rect.left });
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (containerRef.current?.contains(target)) return;
      if (menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className={styles.splitBtn} ref={containerRef}>
      <button
        type="button"
        className={`${styles.toolbarBtn} ${styles.splitPrimary}`}
        onClick={onMarkAll}
        title="Mark every entry in this view as read"
      >
        Mark read
      </button>
      <button
        type="button"
        className={`${styles.toolbarBtn} ${styles.splitCaret} ${open ? styles.splitCaretOpen : ""}`}
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Mark read options"
      >
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
          <path d="M2.5 3.75L5 6.25L7.5 3.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open &&
        createPortal(
          <div ref={menuRef} className={styles.splitMenu} role="menu" style={menuStyle}>
            <button
              type="button"
              role="menuitem"
              className={styles.splitMenuItem}
              onClick={() => {
                setOpen(false);
                onMarkAll();
              }}
            >
              <span className={styles.splitMenuLabel}>All</span>
            </button>
            <button
              type="button"
              role="menuitem"
              className={styles.splitMenuItem}
              disabled={!canMarkAbove}
              title={
                canMarkAbove
                  ? "Mark all entries above the current one as read (Shift+M)"
                  : "Select an entry below the first one to use this"
              }
              onClick={() => {
                setOpen(false);
                onMarkAbove();
              }}
            >
              <span className={styles.splitMenuLabel}>Above</span>
              <span className={styles.splitMenuShortcut}>&#8679;M</span>
            </button>
          </div>,
          document.body,
        )}
    </div>
  );
}

// Memoized entry row — prevents re-renders when other rows' selection changes
// Exported for reuse in search results
export const EntryRow = memo(function EntryRow({
  entry,
  isSelected,
  isChecked,
  bulkMode,
  viewMode,
  onClick,
  onCheck,
  searchSnippet,
  intelCounts,
  intelMode,
  aiAnalysis,
  autoExtract,
  metaColumns,
  undimRead,
}: {
  entry: Entry;
  isSelected: boolean;
  isChecked: boolean;
  bulkMode: boolean;
  viewMode: "compact" | "expanded";
  onClick: () => void;
  onCheck: (e: React.MouseEvent) => void;
  /** HTML snippet from search highlighting showing why this entry matched */
  searchSnippet?: string;
  /**
   * Keep full title contrast on an already-read entry.
   *
   * In the feed list, dimming a read row is the point — it is a triage queue.
   * A search result is not: you asked for it, and whether you happened to read
   * it before says nothing about how legible it should be. The unread dot is
   * untouched, so read and unread are still distinguishable.
   */
  undimRead?: boolean;
  /** Intel badge data for this entry */
  intelCounts?: EntryIntelCounts;
  /** Feed-level intel extraction mode */
  intelMode?: string;
  aiAnalysis?: boolean;
  /** Whether feed auto-extracts on ingest */
  autoExtract?: boolean;
  /**
   * Table-view fallback only: the entry table's visible column keys, rendered
   * as the row's metadata line in place of the generic source + age header.
   * Empty/absent everywhere else, which keeps the row exactly as it was.
   */
  metaColumns?: string[];
}) {
  const isVisitor = useIsVisitor();
  // Settings → Reading → "Show entry previews".
  const showPreview = useReadingPrefs().show_entry_preview;
  const metaFields = useMemo(() => {
    if (!metaColumns?.length) return [];
    const out: { key: string; node: ReactNode }[] = [];
    for (const key of metaColumns) {
      const node = META_COLUMNS[key]?.render(entry, intelCounts);
      if (node == null || node === "") continue;
      out.push({ key, node });
      if (out.length >= MAX_META_FIELDS) break;
    }
    return out;
  }, [metaColumns, entry, intelCounts]);
  const useColumnMeta = metaFields.length > 0;
  const plainTags = plainTagsOf(entry);

  return (
    <div
      className={`${styles.entryItem} ${entry.is_read || isVisitor ? styles.read : ""} ${
        undimRead || isVisitor ? styles.undimRead : ""
      } ${isSelected ? styles.selected : ""} ${isChecked ? styles.checked : ""} ${
        styles[viewMode]
      } ${bulkMode ? styles.bulkMode : ""}`}
      onClick={onClick}
    >
      <div
        className={styles.checkboxWrapper}
        onClick={(e) => { e.stopPropagation(); onCheck(e); }}
      >
        <input
          type="checkbox"
          className={styles.checkbox}
          checked={isChecked}
          onChange={() => {}}
          tabIndex={-1}
        />
      </div>
      <div className={styles.entryContent}>
        {/* The column-meta line carries source/age/etc itself, so the generic
            header would only repeat (or contradict) the user's Columns choice. */}
        {!useColumnMeta && (
          <div className={styles.entryHeader}>
            <FeedNameMenuButton feedId={entry.feed_id} className={styles.feedNameBtn}>
              {intelMode && (
                <IntelLevelBadge
                  mode={intelMode}
                  aiAnalysis={aiAnalysis}
                  autoExtract={autoExtract ?? false}
                />
              )}
              {entry.feed_type && <FeedTypeIcon type={entry.feed_type} size={11} />}
              {entry.feed_title}
            </FeedNameMenuButton>
            {entry.priority_score != null && (
              <SignalChip score={entry.priority_score} signals={entry.top_signals ?? []} />
            )}
            {entry.exposure && <ExposureChip exposure={entry.exposure} />}
            <span className={styles.date}>{formatDate(entry.published_at, "")}</span>
          </div>
        )}
        <h3 className={styles.entryTitle}>{entry.translated_title || entry.title}</h3>
        {useColumnMeta && (
          <div className={styles.columnMeta}>
            {metaFields.map(({ key, node }, i) => (
              <span key={key} className={styles.columnMetaField}>
                {i > 0 && <span className={styles.columnMetaSep}>&middot;</span>}
                {node}
              </span>
            ))}
          </div>
        )}
        <EntryIntelBadges counts={intelCounts} starred={entry.is_starred} bookmarked={entry.is_bookmarked} echo={entry.is_echo} tags={entry.tags} entryId={entry.id} />
        {searchSnippet ? (
          <p className={styles.summary} dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(searchSnippet, { ALLOWED_TAGS: ["em", "mark", "strong", "b", "i", "span"], ALLOWED_ATTR: ["class"] }) }} />
        ) : (
          viewMode !== "compact" && showPreview && entry.summary && (
            <p className={styles.summary}>{previewSnippet(stripHtml(entry.summary), 200)}</p>
          )
        )}
        <div className={styles.entryMeta}>
          {entry.author && <span className={styles.author}>{entry.author}</span>}
          {entry.feed_type !== "youtube" && entry.feed_type !== "podcast" && entry.word_count && (
            <span className={styles.readTime}>
              {Math.ceil(entry.word_count / 200)} min read
            </span>
          )}
          {entry.media?.[0]?.duration_seconds && (
            <span className={styles.duration}>
              {formatDuration(entry.media[0].duration_seconds)}
            </span>
          )}
          {plainTags.length > 0 && (
            <span className={styles.tagList}>
              {plainTags.map((tag, i) => (
                <span key={tag.name} className={styles.tagInline}>
                  <span className={styles.tagDot} style={{ backgroundColor: tag.color }} />
                  {tag.name}
                  {i < plainTags.length - 1 && <span className={styles.tagSep}>·</span>}
                </span>
              ))}
            </span>
          )}
        </div>
      </div>
    </div>
  );
});

const MagazineCard = memo(function MagazineCard({
  entry,
  isSelected,
  isChecked,
  bulkMode,
  onClick,
  onCheck,
  intelCounts,
}: {
  entry: Entry;
  isSelected: boolean;
  isChecked: boolean;
  bulkMode: boolean;
  onClick: () => void;
  onCheck: (e: React.MouseEvent) => void;
  intelCounts?: EntryIntelCounts;
}) {
  const isVisitor = useIsVisitor();
  const plainSummary = entry.summary ? previewSnippet(stripHtml(entry.summary), 160) : "";
  const readTime = entry.word_count && entry.feed_type !== "youtube" && entry.feed_type !== "podcast"
    ? `${Math.ceil(entry.word_count / 200)} min`
    : null;
  const duration = entry.media?.[0]?.duration_seconds
    ? formatDuration(entry.media[0].duration_seconds)
    : null;

  return (
    <div
      className={`${styles.magazineCard} ${entry.is_read ? styles.magazineCardRead : ""} ${isVisitor ? styles.magazineCardVisitor : ""} ${isSelected ? styles.magazineCardSelected : ""} ${isChecked ? styles.magazineCardChecked : ""} ${bulkMode ? styles.magazineBulkMode : ""}`}
      onClick={onClick}
    >
      <div
        className={styles.magazineCheckbox}
        onClick={(e) => { e.stopPropagation(); onCheck(e); }}
      >
        <input
          type="checkbox"
          className={styles.checkbox}
          checked={isChecked}
          onChange={() => {}}
          tabIndex={-1}
        />
      </div>
      {entry.image_url && (
        <div className={styles.magazineImage}>
          <img
            src={entry.image_url}
            alt=""
            loading="lazy"
            onError={(e) => {
              const parent = (e.currentTarget.parentElement as HTMLElement | null);
              if (parent) parent.style.display = "none";
            }}
          />
        </div>
      )}
      <div className={styles.magazineBody}>
        <div className={styles.magazineSource}>
          <FeedNameMenuButton feedId={entry.feed_id}>
            {entry.feed_type && <FeedTypeIcon type={entry.feed_type} size={11} />}
            <span>{entry.feed_title}</span>
          </FeedNameMenuButton>
          {entry.priority_score != null && (
            <SignalChip score={entry.priority_score} signals={entry.top_signals ?? []} />
          )}
          {entry.exposure && <ExposureChip exposure={entry.exposure} />}
          <span className={styles.magazineDot}>&middot;</span>
          <span>{formatDate(entry.published_at, "")}</span>
        </div>
        <h3 className={styles.magazineTitle}>{entry.translated_title || entry.title}</h3>
        {plainSummary && <p className={styles.magazineSummary}>{plainSummary}</p>}
        <EntryIntelBadges counts={intelCounts} starred={entry.is_starred} bookmarked={entry.is_bookmarked} echo={entry.is_echo} tags={entry.tags} entryId={entry.id} />
        <div className={styles.magazineMeta}>
          {entry.author && <span>{entry.author}</span>}
          {readTime && <span>{readTime} read</span>}
          {duration && <span>{duration}</span>}
        </div>
      </div>
    </div>
  );
});

interface EntryListProps {
  // When set, pins the list to this sort order (e.g. the Priority Queue forces
  // "radar") without touching the user's persisted feed sort.
  sortOverride?: SortOrder;
  // When true, slots story-thread rows into the ranked list (Priority Queue
  // only), absorbing the loaded members each one folds.
  withThreads?: boolean;
  // Priority Queue mode: uses its own Hide Read preference (defaults on) kept
  // separate from the main feed's, so hiding read here doesn't affect the reader.
  priorityMode?: boolean;
}

export function EntryList({ sortOverride, withThreads = false, priorityMode = false }: EntryListProps = {}) {
  // Public read-only mode: no read state, no bulk actions, no AI day summaries.
  const isVisitor = useIsVisitor();
  const selectedFeedId = useUIStore((s) => s.selectedFeedId);
  const selectedCategoryId = useUIStore((s) => s.selectedCategoryId);
  const showUnreadOnly = useUIStore((s) => s.showUnreadOnly);
  const priorityShowUnreadOnly = useUIStore((s) => s.priorityShowUnreadOnly);
  const unreadFallbackActive = useUIStore((s) => s.unreadFallbackActive);
  const setUnreadFallbackActive = useUIStore((s) => s.setUnreadFallbackActive);
  // In Priority Queue mode, honor the queue's own Hide Read preference.
  const hideReadPref = priorityMode ? priorityShowUnreadOnly : showUnreadOnly;
  const effectiveShowUnreadOnly = hideReadPref && !unreadFallbackActive;
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const setSelectedThread = useUIStore((s) => s.setSelectedThread);
  const selectedEntryId = useUIStore((s) => s.selectedEntryId);
  const readerOpen = useUIStore((s) => s.readerOpen);
  const viewMode = useUIStore((s) => s.viewMode);
  const entryListWidth = useUIStore((s) => s.entryListWidth);
  const entryListCollapsed = useUIStore((s) => s.entryListCollapsed);
  const setViewMode = useUIStore((s) => s.setViewMode);
  const virtualFolder = useUIStore((s) => s.virtualFolder);
  const sortOrderPref = useUIStore((s) => s.sortOrder);
  const setSortOrder = useUIStore((s) => s.setSortOrder);
  const sortOrder = sortOverride ?? sortOrderPref;
  // Radar left the sort dropdown (the Priority Queue is its home now, via
  // sortOverride). A "radar" preference persisted before that change would
  // leave the select blank and the list silently signal-sorted — normalize it.
  useEffect(() => {
    if (sortOrderPref === "radar") setSortOrder("newest");
  }, [sortOrderPref, setSortOrder]);
  const markReadOnScroll = useUIStore((s) => s.markReadOnScroll);
  const toggleMarkReadOnScroll = useUIStore((s) => s.toggleMarkReadOnScroll);
  const toggleUnreadOnly = useUIStore((s) => s.toggleUnreadOnly);
  const togglePriorityUnreadOnly = useUIStore((s) => s.togglePriorityUnreadOnly);
  const toggleHideRead = priorityMode ? togglePriorityUnreadOnly : toggleUnreadOnly;
  const setShowUnreadOnly = useUIStore((s) => s.setShowUnreadOnly);
  const setPriorityShowUnreadOnly = useUIStore((s) => s.setPriorityShowUnreadOnly);
  const setHideRead = priorityMode ? setPriorityShowUnreadOnly : setShowUnreadOnly;
  const selectedEntryIds = useUIStore((s) => s.selectedEntryIds);
  const lastSelectedIndex = useUIStore((s) => s.lastSelectedIndex);
  const toggleEntrySelection = useUIStore((s) => s.toggleEntrySelection);
  const setEntrySelection = useUIStore((s) => s.setEntrySelection);
  const clearEntrySelection = useUIStore((s) => s.clearEntrySelection);
  const setLastSelectedIndex = useUIStore((s) => s.setLastSelectedIndex);
  const navTrail = useUIStore((s) => s.entryNavTrail);
  const navTrailIndex = useUIStore((s) => s.entryNavTrailIndex);
  const { data: feedsData } = useFeeds();
  const feedIntelMap = useMemo(() => {
    const map: Record<string, { mode: string; ai: boolean; auto: boolean }> = {};
    for (const sub of feedsData?.items ?? []) {
      map[sub.id] = {
        mode: sub.intel_extraction_mode || "selective",
        ai: sub.ai_analysis_enabled ?? true,
        auto: sub.auto_extract_on_ingest ?? false,
      };
    }
    return map;
  }, [feedsData]);
  const [changeTypeFilter, setChangeTypeFilter] = useState("");
  // The day-divider chip currently narrowing the list to its own day's articles.
  // Local rather than persisted: it is a "what is this?" drill-down on one
  // divider, not a view preference to come back to tomorrow.
  const [dayFocus, setDayFocus] = useState<DayFocus | null>(null);
  // The Priority Queue is served by its own ranking endpoint, which doesn't take
  // these filters — so its dividers show the chips as labels rather than
  // offering a toggle that would do nothing.
  const onDayFocus = priorityMode ? undefined : setDayFocus;

  const selectedFeed = feedsData?.items.find((s) => s.id === selectedFeedId);
  const isGitHubRepo = selectedFeed?.feed_type === "github_repo";
  const showChangeTypeFilter = isGitHubRepo;

  const isMobile = useIsMobile();
  // One-line keyboard hint under the list until the user dismisses it once.
  const [kbdHintDismissed, setKbdHintDismissed] = useState(
    () => localStorage.getItem("intelfeed-kbd-hint-dismissed") === "1",
  );
  const bulkMode = selectedEntryIds.size > 0;
  // Table view governs read/unread filtering itself via its State column
  // filter, so the global Hide Read toggle is hidden there and must not
  // silently shape the query behind an invisible control.
  // The table needs room for its columns, its header and its per-column filter
  // row. Opening the reader squeezes the list to `entryListWidth` (300px by
  // default), where the title column ends up ~60px wide and unreadable. Below
  // this threshold the list falls back to the compact rows instead. The stored
  // preference is untouched, so closing the reader restores the table.
  const TABLE_MIN_WIDTH = 520;
  // True whenever the list is sharing the pane with an open reader and has
  // been squeezed below the width its full chrome needs.
  const isNarrowPane =
    !isMobile && readerOpen && !entryListCollapsed && entryListWidth < TABLE_MIN_WIDTH;
  const tableTooNarrow = viewMode === "table" && isNarrowPane;
  const effectiveViewMode: typeof viewMode = tableTooNarrow ? "compact" : viewMode;
  const isTableView = effectiveViewMode === "table";

  // Fallback rows carry the table's configured columns as their metadata line,
  // so the Columns choice still means something when the table can't render.
  // Read-only consumption of the table's persisted layout — DataTable and
  // EntryTableView remain the owners of it.
  const entriesTableLayout = useUIStore((s) => s.tables?.[ENTRIES_TABLE_ID]);
  const metaColumnKeys = useMemo(
    () => (tableTooNarrow ? visibleMetaColumnKeys(entriesTableLayout) : NO_META_COLUMNS),
    [tableTooNarrow, entriesTableLayout],
  );

  const sinceDate = useMemo(() => {
    const now = new Date();
    if (virtualFolder === "today") {
      const start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      return start.toISOString();
    }
    if (virtualFolder === "last_24h") {
      return new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
    }
    if (virtualFolder === "this_week") {
      return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
    }
    return undefined;
  }, [virtualFolder]);

  // The engaged chip narrows to its own day, which is always inside whatever
  // window the folder already asked for — so the later of the two `since`
  // values wins rather than the day quietly widening a "last 24 hours" view.
  const focusWindow = useMemo(
    () => (dayFocus ? dayWindowIso(dayFocus.dayKey) : null),
    [dayFocus],
  );

  // Changing scope changes which days exist, so a chip engaged on a day that is
  // no longer in the list would leave an empty pane with nothing visible to
  // clear it.
  useEffect(() => {
    setDayFocus(null);
  }, [selectedFeedId, selectedCategoryId, virtualFolder]);

  const filters = {
    feed_id: selectedFeedId || undefined,
    category_id: selectedCategoryId || undefined,
    is_read: !isTableView && effectiveShowUnreadOnly ? false : undefined,
    is_starred: virtualFolder === "starred" ? true : undefined,
    is_bookmarked: virtualFolder === "bookmarked" ? true : undefined,
    watched: virtualFolder === "watched" ? true : undefined,
    change_type: changeTypeFilter || undefined,
    since:
      focusWindow && (!sinceDate || focusWindow.since > sinceDate) ? focusWindow.since : sinceDate,
    before: focusWindow?.before,
    ...(dayFocus?.filter ?? {}),
    sort: sortOrder,
    dedup: true,
  };

  // Filter subset that defines the daily-summary cache key. Excludes time-window
  // and sort fields (the divider's day_key captures the date) so navigating
  // between "today" / "last 24h" / "all time" doesn't blow the cache. Also
  // excludes `is_read` — the summary describes the day's intel regardless of
  // which entries the viewer has read, so the Hide Read toggle (and the act
  // of marking the day read) shouldn't move us to a different cache slot.
  const summaryFilters: DailySummaryFilters = useMemo(
    () => ({
      feed_id: selectedFeedId || undefined,
      category_id: selectedCategoryId || undefined,
      is_starred: virtualFolder === "starred" ? true : undefined,
      is_bookmarked: virtualFolder === "bookmarked" ? true : undefined,
      change_type: changeTypeFilter || undefined,
      dedup: true,
    }),
    [
      selectedFeedId,
      selectedCategoryId,
      virtualFolder,
      changeTypeFilter,
    ],
  );

  // Threads marked-read & cleared this session live in the UI store, so clearing
  // one from the reader's top bar drops its row here too — and hands its members
  // back to the queue as standalone entries.
  const dismissedThreadIds = useUIStore((s) => s.dismissedThreadIds);
  const dismissThread = useUIStore((s) => s.dismissThread);

  // Priority Queue mode is served by one endpoint that ranks entries and story
  // threads together; everywhere else uses the plain entry list. Only one of the
  // two queries runs.
  const priorityQuery = usePriorityQueue({
    enabled: priorityMode,
    unreadOnly: effectiveShowUnreadOnly,
    withThreads,
    excludeThreadIds: dismissedThreadIds,
  });
  const listQuery = useEntries(filters, { enabled: !priorityMode });
  const { fetchNextPage, hasNextPage, isFetchingNextPage, isLoading, refetch } = priorityMode
    ? priorityQuery
    : listQuery;

  const markRead = useMarkRead();
  const markAllRead = useMarkAllRead();
  const toggleStar = useToggleStar();
  const toggleBookmark = useToggleBookmark();
  const bulkAction = useBulkAction();
  const [batchResult, setBatchResult] = useState<{ type: string; content: string } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const savedScrollTopRef = useRef(0);

  const { pullDistance, isRefreshing } = usePullToRefresh({
    scrollRef,
    onRefresh: async () => { await refetch(); },
    enabled: isMobile,
  });

  // Flatten pages and drop duplicate IDs — cursor pagination can re-serve an
  // entry across page boundaries (ties / null published_at), and duplicate IDs
  // collide as React keys and as virtualizer position-cache keys, stacking two
  // copies of the row on top of each other.
  // Priority Queue rows, deduped by the id they carry — cursor pagination can
  // re-serve a row across a page boundary, and a duplicate collides as a React
  // key and as a virtualizer position-cache key, stacking two copies of the row
  // on top of each other. Deduping here (not separately in `entries`) keeps the
  // rendered rows and the flat entry stream indexed the same.
  const queueRows = useMemo(() => {
    if (!priorityMode) return [];
    const seen = new Set<string>();
    return (priorityQuery.data?.pages ?? [])
      .flatMap((p) => p.items)
      .filter((row) => {
        const id = row.kind === "thread" ? row.thread?.id : row.entry?.id;
        if (!id || seen.has(id)) return false;
        seen.add(id);
        return true;
      });
  }, [priorityMode, priorityQuery.data]);

  const entries = useMemo(() => {
    if (priorityMode) {
      return queueRows.flatMap((row) => (row.kind === "entry" && row.entry ? [row.entry] : []));
    }
    const raw = listQuery.data?.pages.flatMap((p) => p.items) ?? [];
    const seen = new Set<string>();
    return raw.filter((e) => (seen.has(e.id) ? false : (seen.add(e.id), true)));
  }, [priorityMode, queueRows, listQuery.data]);

  // When the current view has no unread entries, fall back to showing all
  // without overwriting the user's persisted "Hide Read" preference.
  useEffect(() => {
    if (!isTableView && !isLoading && entries.length === 0 && hideReadPref && !unreadFallbackActive) {
      setUnreadFallbackActive(true);
    }
  }, [isTableView, isLoading, entries.length, hideReadPref, unreadFallbackActive, setUnreadFallbackActive]);

  // Re-evaluate the fallback when the user navigates to a different scope.
  useEffect(() => {
    setUnreadFallbackActive(false);
  }, [selectedFeedId, selectedCategoryId, virtualFolder, setUnreadFallbackActive]);

  // Hide Read is on, but this scope has no unread left, so the list is showing
  // read entries anyway. Unannounced, that reads as a broken toggle — every
  // entry marked read, yet the list is still full.
  // `entries.length > 0` matters: a scope that is empty read-or-unread also
  // trips the fallback, and "you're all caught up" over an empty list is a lie.
  const caughtUpFallback =
    hideReadPref && unreadFallbackActive && !isTableView && !isLoading && entries.length > 0;

  // Mobile: continuously record list scroll position so we can restore it
  // when the reader closes (CSS display:none resets scrollTop on re-show).
  useEffect(() => {
    if (!isMobile) return;
    const el = scrollRef.current;
    if (!el) return;
    const handler = () => {
      if (!readerOpen) {
        savedScrollTopRef.current = el.scrollTop;
      }
    };
    el.addEventListener("scroll", handler, { passive: true });
    return () => el.removeEventListener("scroll", handler);
  }, [isMobile, readerOpen, effectiveViewMode]);

  // Mobile: restore scroll position after reader closes.
  useLayoutEffect(() => {
    if (!isMobile || readerOpen) return;
    const el = scrollRef.current;
    if (el && savedScrollTopRef.current > 0) {
      el.scrollTop = savedScrollTopRef.current;
    }
  }, [isMobile, readerOpen]);

  // Group consecutive CVE entries from the same feed
  const [expandedGroups, setExpandedGroups] = useState<Set<number>>(new Set());
  // Day-collapse state lives in uiStore so it persists across reload/navigation.
  // collapseAllMode keeps days that load in later collapsed too (see effect).
  const collapsedDaysArr = useUIStore((s) => s.collapsedDays);
  const collapseAllMode = useUIStore((s) => s.collapseAllMode);
  const toggleDayCollapsed = useUIStore((s) => s.toggleDayCollapsed);
  const collapseAllDays = useUIStore((s) => s.collapseAllDays);
  const expandAllDays = useUIStore((s) => s.expandAllDays);
  const mergeCollapsedDays = useUIStore((s) => s.mergeCollapsedDays);
  const collapsedDays = useMemo(() => new Set(collapsedDaysArr), [collapsedDaysArr]);
  const displayItems = useMemo(
    () => groupConsecutiveEntries(entries),
    [entries],
  );

  // Day dividers only make sense when entries are date-ordered
  const showDividers = sortOrder === "newest" || sortOrder === "oldest";
  const { data: totalCount } = useEntriesCount(filters);
  // Threads render collapsed: the row is the fold, and expanding it is a
  // deliberate "show me the spine" rather than the default state.
  const [expandedThreads, setExpandedThreads] = useState<Set<string>>(new Set());
  const virtualItems2D = useMemo<QueueItem[]>(() => {
    // The queue arrives already ranked and already folded — only the CVE
    // grouping is left to do. Day dividers don't apply: it isn't date-ordered.
    if (priorityMode) return queueItems(queueRows);
    const withDividers = injectDayDividers(displayItems, showDividers);
    return filterCollapsedDays(withDividers, collapsedDays);
  }, [priorityMode, queueRows, displayItems, showDividers, collapsedDays]);
  const magazineItems = useMemo<(MagazineItem | DayDividerItem)[]>(() => {
    if (effectiveViewMode !== "magazine") return [];
    // Built from the queue rows, not from `entries`: the endpoint withholds
    // every article a thread absorbed, so a grid mapped over the entry stream
    // drops a whole story — the thread card and the coverage behind it both.
    const items: MagazineItem[] = priorityMode
      ? magazineQueueItems(queueRows)
      : entries.map((entry, i) => ({ type: "single" as const, entry, flatIndex: i }));
    return filterCollapsedDays(
      injectDayDividers(items, showDividers),
      collapsedDays,
    );
  }, [priorityMode, queueRows, entries, effectiveViewMode, showDividers, collapsedDays]);

  // Every day key rendered by the *active* view — powers the collapse-all /
  // expand-all toolbar toggle. Derived from the same injected item list the
  // view renders (dividers survive collapse-filtering) so the key set matches
  // exactly what's on screen. Magazine renders ungrouped singles while the list
  // renders CVE-grouped items, and a group can straddle midnight — so the two
  // views can surface different day dividers, and reading from the wrong one
  // would leave some days uncollapsed. In the Priority Queue the list forgoes
  // dividers entirely (it isn't date-ordered) while magazine would date a
  // thread by its last beat — moot today, since the queue's forced "radar" sort
  // turns dividers off in both.
  const activeDividerItems = effectiveViewMode === "magazine" ? magazineItems : virtualItems2D;
  const allDayKeys = useMemo(
    () =>
      activeDividerItems
        .filter((it) => it.type === "divider")
        .map((it) => (it as { dayKey: string }).dayKey),
    [activeDividerItems],
  );
  const allDaysCollapsed =
    collapseAllMode ||
    (allDayKeys.length > 0 && allDayKeys.every((k) => collapsedDays.has(k)));
  const toggleAllDays = useCallback(() => {
    // Collapsed → expand all and leave the mode; otherwise enter collapse-all
    // mode and collapse every rendered day. The effect below keeps days that
    // stream in afterward collapsed while the mode stays on.
    if (allDaysCollapsed) expandAllDays();
    else collapseAllDays(allDayKeys);
  }, [allDaysCollapsed, allDayKeys, expandAllDays, collapseAllDays]);
  // While collapse-all is active, fold any newly-loaded days into the set.
  useEffect(() => {
    if (collapseAllMode) mergeCollapsedDays(allDayKeys);
  }, [collapseAllMode, allDayKeys, mergeCollapsedDays]);

  // Reset expanded groups when feed/category changes
  useEffect(() => {
    setExpandedGroups(new Set());
  }, [selectedFeedId, selectedCategoryId, virtualFolder]);

  // Fetch intel badges for all loaded entries (hook handles batching)
  const allEntryIds = useMemo(
    () => entries.map((e) => e.id),
    [entries]
  );
  const { data: intelBadges } = useEntryIntelBadges(allEntryIds);

  // Clear selection when feed/category/folder changes
  useEffect(() => {
    clearEntrySelection();
  }, [selectedFeedId, selectedCategoryId, virtualFolder, clearEntrySelection]);

  // Virtual scrolling for compact/expanded views
  const baseSize = effectiveViewMode === "compact" ? 56 : 130;
  const virtualizer = useVirtualizer({
    count: virtualItems2D.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (index) => {
      const item = virtualItems2D[index];
      if (!item) return baseSize;
      if (item.type === "divider") return 32;
      if (item.type === "thread") {
        // Collapsed the row is one line; expanded it is the spine, which is
        // roughly one beat per day of coverage rather than one per article.
        if (!expandedThreads.has(item.key)) return 46;
        return 44 + Math.min(item.thread.entry_count, 8) * 62;
      }
      if (item.type === "single") {
        const counts = intelBadges?.[item.entry.id];
        const hasIntel = !!(counts?.total || counts?.rules || counts?.pir_matches?.length);
        const intelHeight = hasIntel ? 24 : 0;
        if (effectiveViewMode === "compact") return 56 + intelHeight;
        // Estimate based on content: title length affects wrapping, summary adds ~40px
        const titleLen = item.entry.title?.length ?? 0;
        const hasSummary = !!item.entry.summary;
        // Base: header(20) + title(20) + meta(20) + padding(24) = ~84
        // Long titles (>80 chars) likely wrap: +20 per extra line
        const titleLines = Math.ceil(titleLen / 80);
        const titleHeight = titleLines * 20;
        const summaryHeight = hasSummary ? 40 : 0;
        return 64 + titleHeight + summaryHeight + intelHeight;
      }
      // Collapsed group row is slightly taller; expanded = bar + N entries
      if (expandedGroups.has(item.flatIndex)) {
        return 32 + item.entries.length * baseSize;
      }
      return 120;
    },
    overscan: isMobile ? 5 : 10,
    getItemKey: (index) => {
      const item = virtualItems2D[index];
      if (!item) return index;
      if (item.type === "divider") return `divider-${item.dayKey}`;
      if (item.type === "thread") return item.key;
      return item.type === "single" ? item.entry.id : `group-${item.flatIndex}`;
    },
  });

  // Re-measure all items when view mode, expanded groups/threads, or divider list change
  useEffect(() => {
    virtualizer.measure();
  }, [effectiveViewMode, expandedGroups, expandedThreads, virtualItems2D.length, virtualizer]);

  // When async content (intel badges) loads, force visible elements to re-measure
  // via the DOM. This is more reliable than measure() which only resets estimates.
  const scrollContainerRef = scrollRef;
  useLayoutEffect(() => {
    if (!intelBadges) return;
    const container = scrollContainerRef.current;
    if (!container) return;
    // Re-measure each visible virtual item by querying its DOM element
    const elements = container.querySelectorAll<HTMLElement>("[data-index]");
    elements.forEach((el) => {
      virtualizer.measureElement(el);
    });
  }, [intelBadges, virtualizer, scrollContainerRef]);


  // Infinite scroll: fetch more when nearing the end of the virtual list
  const virtualItems = virtualizer.getVirtualItems();
  useEffect(() => {
    const lastItem = virtualItems[virtualItems.length - 1];
    if (!lastItem) return;
    if (lastItem.index >= virtualItems2D.length - 5 && hasNextPage && !isFetchingNextPage) {
      fetchNextPage();
    }
  }, [virtualItems, virtualItems2D.length, hasNextPage, isFetchingNextPage, fetchNextPage]);

  // NOTE: auto-read (mark the previous entry read on selection change) lives in
  // MainLayout, not here — EntryList unmounts when the list is collapsed, so an
  // effect here misses reader-internal navigation. See MainLayout.

  const handleEntryClick = useCallback((entry: Entry) => {
    setSelectedEntry(entry.id);
  }, [setSelectedEntry]);

  const handleCheckboxClick = useCallback((index: number, entryId: string, e: React.MouseEvent) => {
    // Bulk actions all write; a visitor never enters bulk mode.
    if (isVisitor) return;
    if (e.shiftKey && lastSelectedIndex !== null) {
      // Range select
      const start = Math.min(lastSelectedIndex, index);
      const end = Math.max(lastSelectedIndex, index);
      const rangeIds = entries.slice(start, end + 1).map((en) => en.id);
      const merged = new Set(selectedEntryIds);
      rangeIds.forEach((id) => merged.add(id));
      setEntrySelection(Array.from(merged));
    } else {
      toggleEntrySelection(entryId);
    }
    setLastSelectedIndex(index);
  }, [isVisitor, entries, lastSelectedIndex, selectedEntryIds, toggleEntrySelection, setEntrySelection, setLastSelectedIndex]);

  const handleSelectAll = useCallback(() => {
    if (selectedEntryIds.size === entries.length) {
      clearEntrySelection();
    } else {
      setEntrySelection(entries.map((e) => e.id));
    }
  }, [entries, selectedEntryIds.size, clearEntrySelection, setEntrySelection]);

  // Mark all entries above the currently selected entry as read
  const handleMarkAboveAsRead = useCallback(() => {
    const currentIndex = entries.findIndex((e) => e.id === selectedEntryId);
    if (currentIndex <= 0) return; // Nothing above if first or not found
    const aboveIds = entries.slice(0, currentIndex).filter((e) => !e.is_read).map((e) => e.id);
    if (aboveIds.length === 0) return;
    bulkAction.mutate({ entry_ids: aboveIds, action: "read" });
  }, [entries, selectedEntryId, bulkAction]);

  // "Above" only means something with an entry selected that isn't the first.
  const canMarkAbove = !!selectedEntryId && entries.findIndex((e) => e.id === selectedEntryId) > 0;

  // Build a flat navigation list from display items (for keyboard nav)
  const navEntries = useMemo(() => {
    const result: Entry[] = [];
    for (const item of displayItems) {
      if (item.type === "single") {
        result.push(item.entry);
      } else {
        // For collapsed groups, use the first entry as representative;
        // for expanded groups, include all entries
        if (expandedGroups.has(item.flatIndex)) {
          result.push(...item.entries);
        } else {
          result.push(item.entries[0]);
        }
      }
    }
    return result;
  }, [displayItems, expandedGroups]);

  // Sync navigation list to store for prev/next buttons in reader
  const setEntryNavigationIds = useUIStore((s) => s.setEntryNavigationIds);
  useEffect(() => {
    const ids = navEntries.map((e) => e.id);
    setEntryNavigationIds(ids);
  }, [navEntries, setEntryNavigationIds]);

  // Keyboard navigation
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      // A <select> counts as typing too. Without it, every dropdown in every
      // modal above this list leaked its keystrokes through: with a feed's
      // "Poll interval" focused, j/k and the arrows navigated the list behind
      // the dialog, s starred, m marked read and Enter opened an article.
      if (
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        target?.isContentEditable
      ) return;

      // Enter on a focused OUTSIDE link means "follow it". Without this the
      // shortcut below preventDefault()s the keypress and opens the selected
      // entry's own URL instead — the link never fires, and neither does the
      // external-link confirmation that guards it. Links within the app are
      // left exactly as they were.
      if (e.key === "Enter") {
        const link = target?.closest("a[href]");
        if (link instanceof HTMLAnchorElement && isExternalWebUrl(link.getAttribute("href") ?? "")) return;
      }

      // Escape clears bulk selection
      if (e.key === "Escape" && bulkMode) {
        e.preventDefault();
        clearEntrySelection();
        return;
      }

      const currentIndex = navEntries.findIndex((en) => en.id === selectedEntryId);

      const findItemIdx = (entryId: string) =>
        virtualItems2D.findIndex((di) => {
          if (di.type === "single") return di.entry.id === entryId;
          if (di.type === "group") return di.entries.some((en) => en.id === entryId);
          return false;
        });

      // Step by list order, falling back to the visit trail — with auto-read on,
      // the article you just came from is already gone from a Hide-Read list, so
      // list indexes alone can't walk backwards.
      const step = (direction: "prev" | "next") => {
        const targetId = adjacentEntryId(
          direction,
          selectedEntryId,
          navEntries.map((en) => en.id),
          navTrail,
          navTrailIndex,
        );
        if (!targetId) return;
        setSelectedEntry(targetId);
        const diIdx = findItemIdx(targetId);
        if (diIdx >= 0) virtualizer.scrollToIndex(diIdx, { align: "auto" });
      };

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        step("next");
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        step("prev");
      } else if (e.key === "o" || e.key === "Enter") {
        e.preventDefault();
        const current = navEntries[currentIndex];
        // "noopener" only (no noreferrer): keeps the referrer this shortcut has always sent.
        if (current?.url) openExternalUrl(current.url, { features: "noopener" });
      } else if (e.key === "s") {
        e.preventDefault();
        if (selectedEntryId) toggleStar.mutate(selectedEntryId);
      } else if (e.key === "b") {
        e.preventDefault();
        if (selectedEntryId) toggleBookmark.mutate(selectedEntryId);
      } else if (e.key === "M" && e.shiftKey) {
        e.preventDefault();
        handleMarkAboveAsRead();
      } else if (e.key === "m") {
        e.preventDefault();
        if (selectedEntryId) markRead.mutate(selectedEntryId);
      } else if (e.key === "x") {
        // Toggle checkbox for current entry
        e.preventDefault();
        const current = navEntries[currentIndex];
        if (current) {
          toggleEntrySelection(current.id);
          setLastSelectedIndex(currentIndex);
        }
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  });

  return (
    <div className={styles.container} role="region" aria-label="Entry list">
      {bulkMode ? (
        <BulkActionsToolbar
          selectedIds={selectedEntryIds}
          totalCount={entries.length}
          onSelectAll={handleSelectAll}
          onClearSelection={() => { clearEntrySelection(); setBatchResult(null); }}
        />
      ) : (
        <div className={styles.toolbar}>
          <div className={styles.toolbarLeft}>
            {!isVisitor && <MarkReadSplitButton
              onMarkAll={() => markAllRead.mutate(
                sortOverride === "radar"
                  ? { radar_only: true }
                  : {
                      feed_id: selectedFeedId || undefined,
                      category_id: selectedCategoryId || undefined,
                    }
              )}
              onMarkAbove={handleMarkAboveAsRead}
              canMarkAbove={canMarkAbove}
            />}
            {!isNarrowPane && !isTableView && showDividers && allDayKeys.length > 0 && (
              <button
                className={styles.toolbarBtn}
                onClick={toggleAllDays}
                title={allDaysCollapsed ? "Expand all days" : "Collapse all days"}
              >
                {allDaysCollapsed ? "Expand All" : "Collapse All"}
              </button>
            )}
          </div>
          <div className={styles.toolbarRight}>
            {/* Narrow pane (reader open): the secondary controls move into a
                menu rather than panning off the edge of an invisible
                scroll strip, where they were effectively unreachable. */}
            {isNarrowPane ? (
              <ToolbarDropdown
                label="More"
                icon={
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <circle cx="12" cy="5" r="1" />
                    <circle cx="12" cy="12" r="1" />
                    <circle cx="12" cy="19" r="1" />
                  </svg>
                }
              >
                {/* "Mark above read" lives on the Mark read split button now,
                    at both widths — it isn't repeated here. */}
                {!isTableView && showDividers && allDayKeys.length > 0 && (
                  <DropdownItem
                    label={allDaysCollapsed ? "Expand all days" : "Collapse all days"}
                    onClick={toggleAllDays}
                  />
                )}
                {!isTableView && !isVisitor && (
                  <DropdownItem
                    label={
                      caughtUpFallback
                        ? "Hide read entries (paused — nothing unread)"
                        : effectiveShowUnreadOnly
                          ? "Show read entries"
                          : "Hide read entries"
                    }
                    onClick={toggleHideRead}
                  />
                )}
                {!isVisitor && (
                <DropdownItem
                  label={markReadOnScroll ? "Auto-read: on" : "Auto-read: off"}
                  onClick={toggleMarkReadOnScroll}
                />
                )}
                <div className={styles.toolbarMenuField}>
                  <label htmlFor="entrylist-sort-narrow">Sort</label>
                  <select
                    id="entrylist-sort-narrow"
                    value={sortOrder}
                    onChange={(e) => setSortOrder(e.target.value as SortOrder)}
                    className={styles.viewSelect}
                    disabled={sortOverride != null}
                  >
                    <option value="newest">Newest</option>
                    <option value="oldest">Oldest</option>
                    <option value="shortest">Shortest</option>
                    <option value="longest">Longest</option>
                    <option value="title_asc">Title A-Z</option>
                    <option value="title_desc">Title Z-A</option>
                  </select>
                </div>
                <div className={styles.toolbarMenuField}>
                  <label htmlFor="entrylist-view-narrow">View</label>
                  <select
                    id="entrylist-view-narrow"
                    value={viewMode}
                    onChange={(e) => setViewMode(e.target.value as ViewMode)}
                    className={styles.viewSelect}
                  >
                    <option value="compact">Compact</option>
                    <option value="expanded">Expanded</option>
                    <option value="magazine">Magazine</option>
                    <option value="table">Table</option>
                  </select>
                </div>
                {tableTooNarrow && (
                  <div className={styles.toolbarMenuNote}>
                    Table view resumes when the list is wider than {TABLE_MIN_WIDTH}px.
                  </div>
                )}
              </ToolbarDropdown>
            ) : (
              <>
            {/* Hide Read stays hidden in table view — the table's State column
                filter owns read/unread there. Auto-read applies everywhere. */}
            {!isTableView && !isVisitor && (
              <button
                className={`${styles.toolbarBtn} ${effectiveShowUnreadOnly ? styles.toolbarBtnActive : ""} ${caughtUpFallback ? styles.toolbarBtnPaused : ""}`}
                onClick={toggleHideRead}
                title={
                  caughtUpFallback
                    ? "Nothing unread here — paused so the list isn't empty"
                    : undefined
                }
              >
                Hide Read{caughtUpFallback ? " (paused)" : ""}
              </button>
            )}
            {!isVisitor && (
            <Hint
              title="Auto-read"
              body="Marks articles read as they scroll past you."
              aside="Off leaves everything unread until you say otherwise."
            >
              <button
                className={`${styles.toolbarBtn} ${markReadOnScroll ? styles.toolbarBtnActive : ""}`}
                onClick={toggleMarkReadOnScroll}
              >
                Auto-read
              </button>
            </Hint>
            )}
            <Hint
              title="Sort"
              body="How the list is ordered. Newest first by default."
              aside={
                sortOverride != null
                  ? "The Priority Queue sorts by signal score, so this is fixed here."
                  : "The Priority Queue ignores this and sorts by signal score."
              }
            >
              <select
                value={sortOrder}
                onChange={(e) => setSortOrder(e.target.value as SortOrder)}
                className={styles.viewSelect}
                disabled={sortOverride != null}
                aria-label="Sort order"
              >
                <option value="newest">Newest</option>
                <option value="oldest">Oldest</option>
                <option value="shortest">Shortest</option>
                <option value="longest">Longest</option>
                <option value="title_asc">Title A-Z</option>
                <option value="title_desc">Title Z-A</option>
              </select>
            </Hint>
            <Hint
              title="View"
              body="Compact, Expanded, Magazine or Table."
              aside="Table adds sortable columns, saved layouts and bulk actions."
              align="end"
            >
              <select
                value={viewMode}
                onChange={(e) => setViewMode(e.target.value as ViewMode)}
                className={styles.viewSelect}
                aria-label="View mode"
              >
                <option value="compact">Compact</option>
                <option value="expanded">Expanded</option>
                <option value="magazine">Magazine</option>
                <option value="table">Table</option>
              </select>
            </Hint>
              </>
            )}
          </div>
        </div>
      )}

      {caughtUpFallback && (
        <div className={styles.caughtUpBanner}>
          <svg className={styles.caughtUpIcon} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M20 6 9 17l-5-5" />
          </svg>
          <span className={styles.caughtUpText}>
            <strong>You&rsquo;re all caught up.</strong> Nothing is unread here, so
            Hide Read is paused and every entry is showing.
          </span>
          <button
            className={styles.caughtUpAction}
            onClick={() => setHideRead(false)}
          >
            Turn off Hide Read
          </button>
        </div>
      )}

      {batchResult && (
        <div className={styles.batchResultBanner}>
          <div className={styles.batchResultHeader}>
            <strong>{batchResult.type}</strong>
            <button
              className={styles.batchResultDismiss}
              onClick={() => setBatchResult(null)}
            >
              &times;
            </button>
          </div>
          <pre className={styles.batchResultContent}>{batchResult.content}</pre>
        </div>
      )}

      {/* A chip can filter its day down to nothing, which would take the divider
          — and the lit chip that clears it — off screen with it. This bar is the
          one control that is always there while a focus is engaged. */}
      {dayFocus && !priorityMode && (
        <div className={styles.dayFocusBar}>
          <span className={styles.dayFocusLabel}>
            Showing only {dayFocus.label}
          </span>
          <button
            type="button"
            className={styles.dayFocusClear}
            onClick={() => setDayFocus(null)}
          >
            Clear filter
          </button>
        </div>
      )}

      {showChangeTypeFilter && (
        <div className={filterStyles.filterBar}>
          <div className={filterStyles.filterGroup}>
            {[
              { value: "", label: "All Changes" },
              { value: "added", label: "New Files" },
              { value: "modified", label: "Modified" },
            ].map((f) => (
              <button
                key={f.value}
                className={`${filterStyles.chip} ${changeTypeFilter === f.value ? filterStyles.chipActive : ""}`}
                onClick={() => setChangeTypeFilter(f.value)}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* View-matched loading placeholders; table view renders its own
          skeleton rows under its sticky header instead. */}
      {isLoading && !isTableView && (
        effectiveViewMode === "magazine" ? <MagazineSkeleton /> : <EntryListSkeleton />
      )}

      {isTableView ? (
        /* Table view — flat, sortable, filterable grid of all entries */
        <EntryTableView
          entries={entries}
          // Priority mode: the table needs the queue rows, not the flattened
          // entries — `entries` drops the thread rows, and the server already
          // withheld the articles those threads absorbed.
          queueRows={priorityMode ? queueRows : undefined}
          intelBadges={intelBadges}
          totalCount={totalCount ?? undefined}
          hasNextPage={!!hasNextPage}
          isFetchingNextPage={isFetchingNextPage}
          fetchNextPage={fetchNextPage}
          isLoading={isLoading}
          uploadsFeed={selectedFeed?.feed_type === "manual"}
        />
      ) : effectiveViewMode === "magazine" ? (
        /* Magazine / card grid view */
        <div ref={scrollRef} className={styles.list} onScroll={() => {
          if (!scrollRef.current || !hasNextPage || isFetchingNextPage) return;
          const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
          if (scrollHeight - scrollTop - clientHeight < 400) fetchNextPage();
        }}>
          {pullDistance > 0 && (
            <div className={styles.pullIndicator} style={{ height: pullDistance }}>
              <div className={`${styles.pullSpinner} ${isRefreshing ? styles.pullSpinnerActive : ""}`}
                   style={{ opacity: Math.min(pullDistance / 64, 1) }}>
                {isRefreshing ? "Refreshing..." : pullDistance >= 64 ? "Release to refresh" : "Pull to refresh"}
              </div>
            </div>
          )}
          <div className={styles.magazineGrid}>
            {magazineItems.map((item) => {
              if (item.type === "divider") {
                const isCollapsed = collapsedDays.has(item.dayKey);
                return (
                  <div
                    key={`divider-${item.dayKey}`}
                    className={`${styles.dayDivider} ${styles.dayDividerMagazine}`}
                  >
                    <button
                      type="button"
                      className={styles.dayDividerToggle}
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleDayCollapsed(item.dayKey);
                      }}
                      title={isCollapsed ? "Expand day" : "Collapse day"}
                      aria-expanded={!isCollapsed}
                    >
                      <span className={isCollapsed ? styles.dayDividerCaretCollapsed : styles.dayDividerCaret}>▾</span>
                    </button>
                    <span className={styles.dayDividerLabel}>{item.label}</span>
                    <span className={styles.dayDividerDot}>·</span>
                    <span className={styles.dayDividerCount}>
                      {item.dayCount}
                      <span className={styles.dayDividerCountEntries}>
                        {" "}{item.dayCount === 1 ? "entry" : "entries"}
                      </span>
                    </span>
                    {totalCount != null && totalCount > 0 && item.cumulativeIndex > 0 && (
                      <>
                        <span className={styles.dayDividerDot}>·</span>
                        <span className={styles.dayDividerProgress}>
                          {item.cumulativeIndex.toLocaleString()} / {totalCount.toLocaleString()}
                        </span>
                      </>
                    )}
                    {/* Visitors: no read state to mark, no AI summary. */}
                    {!isVisitor && (<>
                    <MarkDayReadButton
                      dayKey={item.dayKey}
                      dayCount={item.dayCount}
                      feedId={summaryFilters.feed_id}
                      categoryId={summaryFilters.category_id}
                    />
                    <DayDividerSummary
                      dayKey={item.dayKey}
                      dayCount={item.dayCount}
                      filters={summaryFilters}
                      label={item.label}
                    />
                    </>)}
                    <DayIntelChips
                      dayKey={item.dayKey}
                      filters={summaryFilters}
                      focus={dayFocus}
                      onFocus={onDayFocus}
                    />
                  </div>
                );
              }
              if (item.type === "thread") {
                // No expand-in-place here: the spine is a stack of beats, a
                // row's shape rather than a card's. The card opens the story.
                return (
                  <MagazineThreadCard
                    key={item.key}
                    thread={item.thread}
                    score={item.score}
                    onOpen={() => setSelectedThread(item.thread.slug)}
                  />
                );
              }
              if (item.type !== "single") return null;
              return (
                <MagazineCard
                  key={item.entry.id}
                  entry={item.entry}
                  isSelected={selectedEntryId === item.entry.id}
                  isChecked={selectedEntryIds.has(item.entry.id)}
                  bulkMode={bulkMode}
                  onClick={() => handleEntryClick(item.entry)}
                  onCheck={(e) => handleCheckboxClick(item.flatIndex, item.entry.id, e)}
                  intelCounts={intelBadges?.[item.entry.id]}
                />
              );
            })}
          </div>
          {isFetchingNextPage && <div className={styles.loading}>Loading more...</div>}
          {/* Counted over the rendered cards, not over `entries` — a queue made
              entirely of story threads has no standalone entries and would
              otherwise claim it was empty underneath a full grid. */}
          {!isLoading && magazineItems.length === 0 && (
            <div className={styles.empty}>No entries to display</div>
          )}
        </div>
      ) : (
        /* Compact/Expanded: virtualized list */
        <div ref={scrollRef} className={styles.list}>
          {pullDistance > 0 && (
            <div className={styles.pullIndicator} style={{ height: pullDistance }}>
              <div className={`${styles.pullSpinner} ${isRefreshing ? styles.pullSpinnerActive : ""}`}
                   style={{ opacity: Math.min(pullDistance / 64, 1) }}>
                {isRefreshing ? "Refreshing..." : pullDistance >= 64 ? "Release to refresh" : "Pull to refresh"}
              </div>
            </div>
          )}
          <div style={{ height: virtualizer.getTotalSize(), width: "100%", position: "relative" }}>
            {virtualItems.map((virtualRow) => {
              const item = virtualItems2D[virtualRow.index];
              if (!item) return null;

              const key =
                item.type === "divider"
                  ? `divider-${item.dayKey}`
                  : item.type === "thread"
                    ? item.key
                    : item.type === "single"
                      ? item.entry.id
                      : `group-${item.flatIndex}`;

              return (
                <div
                  key={key}
                  data-index={virtualRow.index}
                  ref={virtualizer.measureElement}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    transform: `translateY(${virtualRow.start}px)`,
                  }}
                >
                  {item.type === "divider" ? (
                    (() => {
                      const isCollapsed = collapsedDays.has(item.dayKey);
                      return (
                        <div className={styles.dayDivider}>
                          <button
                            type="button"
                            className={styles.dayDividerToggle}
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleDayCollapsed(item.dayKey);
                            }}
                            title={isCollapsed ? "Expand day" : "Collapse day"}
                            aria-expanded={!isCollapsed}
                          >
                            <span className={isCollapsed ? styles.dayDividerCaretCollapsed : styles.dayDividerCaret}>▾</span>
                          </button>
                          <span className={styles.dayDividerLabel}>{item.label}</span>
                          <span className={styles.dayDividerDot}>·</span>
                          <span className={styles.dayDividerCount}>
                            {item.dayCount}
                            <span className={styles.dayDividerCountEntries}>
                              {" "}{item.dayCount === 1 ? "entry" : "entries"}
                            </span>
                          </span>
                          {totalCount != null && totalCount > 0 && item.cumulativeIndex > 0 && (
                            <>
                              <span className={styles.dayDividerDot}>·</span>
                              <span className={styles.dayDividerProgress}>
                                {item.cumulativeIndex.toLocaleString()} / {totalCount.toLocaleString()}
                              </span>
                            </>
                          )}
                          {/* Visitors: no read state to mark, no AI summary. */}
                          {!isVisitor && (<>
                          <MarkDayReadButton
                            dayKey={item.dayKey}
                            dayCount={item.dayCount}
                            feedId={summaryFilters.feed_id}
                            categoryId={summaryFilters.category_id}
                          />
                          <DayDividerSummary
                            dayKey={item.dayKey}
                            dayCount={item.dayCount}
                            filters={summaryFilters}
                            label={item.label}
                          />
                          </>)}
                          <DayIntelChips
                            dayKey={item.dayKey}
                            filters={summaryFilters}
                            focus={dayFocus}
                            onFocus={onDayFocus}
                          />
                        </div>
                      );
                    })()
                  ) : item.type === "thread" ? (
                    <ThreadRow
                      thread={item.thread}
                      score={item.score}
                      expanded={expandedThreads.has(item.key)}
                      onToggle={() => {
                        setExpandedThreads((prev) => {
                          const next = new Set(prev);
                          if (next.has(item.key)) next.delete(item.key);
                          else next.add(item.key);
                          return next;
                        });
                      }}
                      onOpenThread={() => setSelectedThread(item.thread.slug)}
                      onEntryClick={(id) => setSelectedEntry(id)}
                      onMarkRead={() => {
                        const ids = item.thread.entry_ids;
                        if (ids.length) bulkAction.mutate({ entry_ids: ids, action: "read" });
                        dismissThread(item.thread.id);
                      }}
                      isMarking={bulkAction.isPending}
                      selectedEntryId={selectedEntryId}
                    />
                  ) : item.type === "group" ? (
                    <CVEGroupRow
                      group={item}
                      expanded={expandedGroups.has(item.flatIndex)}
                      onToggleExpand={() => {
                        setExpandedGroups((prev) => {
                          const next = new Set(prev);
                          if (next.has(item.flatIndex)) next.delete(item.flatIndex);
                          else next.add(item.flatIndex);
                          return next;
                        });
                      }}
                      selectedEntryId={selectedEntryId}
                      selectedEntryIds={selectedEntryIds}
                      bulkMode={bulkMode}
                      viewMode={effectiveViewMode as "compact" | "expanded"}
                          onEntryClick={(id) => {
                        setSelectedEntry(id);
                        setExpandedGroups((prev) => new Set(prev).add(item.flatIndex));
                      }}
                      onCheckboxClick={handleCheckboxClick}
                      onMarkRead={() => {
                        const ids = item.entries
                          .filter((e) => !e.is_read)
                          .map((e) => e.id);
                        if (ids.length) bulkAction.mutate({ entry_ids: ids, action: "read" });
                      }}
                      isMarking={bulkAction.isPending}
                      intelBadges={intelBadges}
                      feedIntelMap={feedIntelMap}
                    />
                  ) : isMobile ? (
                    <SwipeableEntryRow
                      onStar={() => toggleStar.mutate(item.entry.id)}
                      onBookmark={() => toggleBookmark.mutate(item.entry.id)}
                      onMarkRead={() => markRead.mutate(item.entry.id)}
                    >
                      <EntryRow
                        entry={item.entry}
                        isSelected={selectedEntryId === item.entry.id}
                        isChecked={selectedEntryIds.has(item.entry.id)}
                        bulkMode={bulkMode}
                        viewMode={effectiveViewMode as "compact" | "expanded"}
                              onClick={() => handleEntryClick(item.entry)}
                        onCheck={(e) => handleCheckboxClick(item.flatIndex, item.entry.id, e)}
                          intelCounts={intelBadges?.[item.entry.id]}
                        intelMode={feedIntelMap[item.entry.feed_id]?.mode}
                        aiAnalysis={feedIntelMap[item.entry.feed_id]?.ai}
                        autoExtract={feedIntelMap[item.entry.feed_id]?.auto}
                        metaColumns={metaColumnKeys}
                      />
                    </SwipeableEntryRow>
                  ) : (
                    <EntryRow
                      entry={item.entry}
                      isSelected={selectedEntryId === item.entry.id}
                      isChecked={selectedEntryIds.has(item.entry.id)}
                      bulkMode={bulkMode}
                      viewMode={effectiveViewMode as "compact" | "expanded"}
                          onClick={() => handleEntryClick(item.entry)}
                      onCheck={(e) => handleCheckboxClick(item.flatIndex, item.entry.id, e)}
                      intelCounts={intelBadges?.[item.entry.id]}
                      intelMode={feedIntelMap[item.entry.feed_id]?.mode}
                        aiAnalysis={feedIntelMap[item.entry.feed_id]?.ai}
                      autoExtract={feedIntelMap[item.entry.feed_id]?.auto}
                      metaColumns={metaColumnKeys}
                    />
                  )}
                </div>
              );
            })}
          </div>
          {isFetchingNextPage && <div className={styles.loading}>Loading more...</div>}
          {!isLoading && entries.length === 0 && <EmptyFolderState folder={virtualFolder} />}
        </div>
      )}

      {!isMobile && !kbdHintDismissed && entries.length > 0 && (
        <div className={styles.kbdHint}>
          <span><kbd>j</kbd> <kbd>k</kbd> to move</span>
          <span><kbd>Enter</kbd> to read</span>
          <span><kbd>?</kbd> for every shortcut</span>
          <button
            className={styles.kbdHintDismiss}
            onClick={() => {
              localStorage.setItem("intelfeed-kbd-hint-dismissed", "1");
              setKbdHintDismissed(true);
            }}
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
}

/** Zero-count folders used to say "No entries to display", which reads as
    broken and teaches nothing. Each folder explains how it gets a count. */
function EmptyFolderState({ folder }: { folder: string | null }) {
  const navigate = useNavigate();
  if (folder === "watched") {
    return (
      <div className={styles.emptyTeach}>
        <strong>Nothing watched yet.</strong>
        <p>
          Watch a threat actor, malware family or CVE from its profile page, and
          every new article that mentions it lands here.
        </p>
        <button className={styles.emptyTeachBtn} onClick={() => navigate("/workbench/explore")}>
          Browse entities to watch
        </button>
      </div>
    );
  }
  if (folder === "bookmarked") {
    return (
      <div className={styles.emptyTeach}>
        <strong>No bookmarks yet.</strong>
        <p>
          Press <kbd>b</kbd> on any article — or click Bookmark in the reader —
          to save it here for later.
        </p>
      </div>
    );
  }
  if (folder === "starred") {
    return (
      <div className={styles.emptyTeach}>
        <strong>Nothing starred yet.</strong>
        <p>
          Press <kbd>s</kbd> on any article — or click Star in the reader — to
          keep your best finds here.
        </p>
      </div>
    );
  }
  return <div className={styles.empty}>No entries to display</div>;
}
