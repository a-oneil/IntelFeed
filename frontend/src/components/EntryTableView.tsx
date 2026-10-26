import { useCallback, useMemo } from "react";
import { formatDate } from "@/utils/formatDate";
import { useUIStore, type SortOrder } from "@/stores/uiStore";
import type { Entry, PriorityQueueRow, StoryThread } from "@/api/types";
import type { EntryIntelCounts } from "@/hooks/useEntryIntelBadges";
import { FeedTypeIcon } from "@/components/FeedTypeIcon";
import { DataTable, type DataTableColumn, type SortDir } from "@/components/table/DataTable";
import table from "@/components/table/DataTable.module.css";
import { threadSummaryLine } from "@/utils/threads";
import { SignalChip } from "./SignalChip";
import { Chip } from "@/components/primitives";
import { fileTypeLabel, formatBytes, ingestFileUrl, originalState, uploadMeta } from "@/utils/ingest";
import styles from "./EntryTableView.module.css";

/**
 * A row is an article, or a story thread standing in for the articles it
 * folded. The Priority Queue serves both, and the API withholds every member of
 * a live thread from the entry page — so a table that only knew about entries
 * would lose the thread row *and* the 23 articles behind it.
 */
type TableRow =
  | { kind: "entry"; entry: Entry; counts?: EntryIntelCounts }
  | { kind: "thread"; thread: StoryThread; score: number };

/**
 * Thread ids and entry ids are both UUIDs, so a thread row's id is namespaced
 * before anything can mistake one for the other. Keyed on the slug rather than
 * the id because `selectedThreadSlug` is what the store holds, which makes the
 * active-row highlight a comparison instead of a lookup.
 */
const threadRowId = (slug: string) => `thread:${slug}`;

/** What a cell shows for a value the row genuinely doesn't have. */
const ZERO_CELL = <span className={table.zero}>·</span>;

/** A thread has no one source, so the Source cell counts them instead. */
const outletLabel = (t: StoryThread) =>
  `${t.source_count} outlet${t.source_count === 1 ? "" : "s"}`;

const subjectNames = (r: TableRow) =>
  r.kind === "thread"
    ? r.thread.key_entities.map((e) => e.label)
    : [...(r.counts?.actors ?? []), ...(r.counts?.malware ?? [])];

// Regex-based strip is ~100× cheaper than DOMParser and runs on every row per
// filter keystroke; good enough for a one-line preview cell.
const stripCache = new Map<string, string>();
function stripHtmlFast(html: string): string {
  const cached = stripCache.get(html);
  if (cached !== undefined) return cached;
  const text = html
    .replace(/<[^>]+>/g, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
  if (stripCache.size > 2000) stripCache.clear();
  stripCache.set(html, text);
  return text;
}

const summaryText = (r: TableRow) => {
  const raw = r.kind === "thread" ? r.thread.summary : r.entry.summary;
  return raw ? stripHtmlFast(raw) : "";
};

const domainOf = (r: TableRow) => {
  if (r.kind === "thread" || !r.entry.url) return "";
  try {
    return new URL(r.entry.url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
};

/** Detection-opportunity tier, ranked for sorting: KEV > high-risk > gap > telemetry */
function opportunityRank(r: TableRow): number {
  if (r.kind === "thread") return 0;
  const c = r.counts;
  if (!c) return 0;
  const hot = !!c.has_detection_gap && !!c.has_high_risk_cve;
  if (hot && c.has_kev_cve) return 4;
  if (hot) return 3;
  const tier = c.detection_opportunity !== undefined
    ? c.detection_opportunity
    : c.has_detection_gap ? "actionable_gap" : null;
  if (tier === "actionable_gap") return 2;
  if (tier === "telemetry_gap") return 1;
  return 0;
}

/**
 * Per-entry intel tallies. A thread reports 0, not its members' sum: these
 * counts are what *this row's* article yielded, and a thread row has no article.
 */
const intelCount = (pick: (c: EntryIntelCounts) => number | undefined) => (r: TableRow) =>
  r.kind === "thread" || !r.counts ? 0 : (pick(r.counts) ?? 0);

function CountCell({ value, tone }: { value: number; tone?: string }) {
  if (!value) return <span className={table.zero}>·</span>;
  return <span className={`${table.count} ${tone ? table[tone] : ""}`}>{value}</span>;
}

/**
 * Server-sortable columns and the SortOrder values they map to. Everything else
 * sorts client-side over the loaded rows.
 *
 * These headers are inert in Priority Queue mode: /entries/priority-queue takes
 * no sort order, it always serves its own ranking with the thread rows already
 * slotted in by score. Clicking one moves the arrow and the stored preference
 * but not the queue — which predates threads and isn't changed here. What
 * matters for threads is the client sorts below: every `sortValue` answers for
 * a thread row, so a client sort can neither throw on one nor drop it.
 */
const SERVER_SORTS: Record<string, { asc: SortOrder; desc: SortOrder }> = {
  title: { asc: "title_asc", desc: "title_desc" },
  date: { asc: "oldest", desc: "newest" },
  words: { asc: "shortest", desc: "longest" },
};

/*
 * Client filters: a column's `textValue` is the text its cell shows, and a cell
 * showing the "·" placeholder contributes "". So a thread answers the filters it
 * has an answer for — title, summary, actors/malware, state, the outlet count
 * under Source — and drops out of the ones it doesn't, including every ">0"
 * toggle over per-entry intel counts. Surviving a filter it can't satisfy would
 * claim the row holds a value it doesn't have.
 */
const COLUMNS: DataTableColumn<TableRow>[] = [
  {
    key: "status", label: "State", width: 64, minWidth: 48, hideable: true,
    sortValue: (r) => r.kind === "thread"
      ? (r.thread.unread_count > 0 ? 0 : 1)
      : (r.entry.is_read ? 1 : 0) + (r.entry.is_starred ? -2 : 0),
    choices: [
      { value: "all", label: "All" },
      { value: "unread", label: "Unread" },
      { value: "read", label: "Read" },
      { value: "starred", label: "★" },
      { value: "bookmarked", label: "⚑" },
    ],
    choiceMatch: (r, v) => {
      // A thread is unread while any member is; it is never starred or
      // bookmarked — those are marks an analyst puts on an article.
      if (r.kind === "thread") {
        return v === "unread" ? r.thread.unread_count > 0
          : v === "read" ? r.thread.unread_count === 0
            : v === "all";
      }
      return v === "unread" ? !r.entry.is_read
        : v === "read" ? r.entry.is_read
          : v === "starred" ? !!r.entry.is_starred
            : v === "bookmarked" ? !!r.entry.is_bookmarked
              : true;
    },
    render: (r) => r.kind === "thread" ? (
      <span className={styles.statusCell}>
        {r.thread.unread_count > 0 && (
          <span
            className={styles.unreadDot}
            title={`${r.thread.unread_count} unread in this story`}
          />
        )}
      </span>
    ) : (
      <span className={styles.statusCell}>
        {!r.entry.is_read && <span className={styles.unreadDot} title="Unread" />}
        {r.entry.is_starred && <span className={styles.star} title="Starred">★</span>}
        {r.entry.is_bookmarked && <span className={styles.bookmark} title="Bookmarked">⚑</span>}
      </span>
    ),
  },
  {
    key: "source", label: "Source", width: 150, minWidth: 80, hideable: true,
    textValue: (r) => r.kind === "thread" ? outletLabel(r.thread) : r.entry.feed_title ?? "",
    sortValue: (r) =>
      (r.kind === "thread" ? outletLabel(r.thread) : r.entry.feed_title ?? "").toLowerCase(),
    render: (r) => r.kind === "thread" ? (
      <span className={styles.sourceCell} title={threadSummaryLine(r.thread)}>
        <span className={table.ellipsis}>{outletLabel(r.thread)}</span>
      </span>
    ) : (
      <span className={styles.sourceCell} title={r.entry.feed_title ?? ""}>
        {r.entry.feed_type && <FeedTypeIcon type={r.entry.feed_type} size={11} />}
        <span className={table.ellipsis}>{r.entry.feed_title}</span>
      </span>
    ),
  },
  {
    key: "title", label: "Title", width: 320, minWidth: 160, flex: true,
    textValue: (r) => r.kind === "thread" ? r.thread.title : r.entry.translated_title || r.entry.title,
    serverSort: true,
    render: (r) => {
      if (r.kind === "thread") {
        // The same ⟲ the compact list marks a thread with, so the row reads as
        // the same object in either view. "11 outlets · 23 articles · 6 new"
        // rides in the tooltip — the grid has no second line to put it on.
        return (
          <span
            className={styles.threadTitle}
            title={`${r.thread.title} — ${threadSummaryLine(r.thread)}`}
          >
            <span className={styles.threadGlyph} aria-hidden>⟲</span>
            <span className={`${table.strong} ${table.ellipsis}`}>{r.thread.title}</span>
          </span>
        );
      }
      const t = r.entry.translated_title || r.entry.title;
      return <span className={`${table.strong} ${table.ellipsis}`} title={t}>{t}</span>;
    },
  },
  {
    key: "summary", label: "Summary", width: 300, minWidth: 120, hideable: true,
    textValue: summaryText,
    render: (r) => {
      const s = summaryText(r);
      if (!s) return ZERO_CELL;
      return <span className={`${styles.summaryCell} ${table.ellipsis}`} title={s.slice(0, 500)}>{s}</span>;
    },
  },
  {
    key: "date", label: "Date", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (r) => {
      // A story has no publication date; `last_seen` is the closest thing —
      // when coverage of it last moved.
      const at = r.kind === "thread" ? r.thread.last_seen : r.entry.published_at;
      return (
        <span className={table.dateCell} title={at ? new Date(at).toLocaleString() : undefined}>
          {formatDate(at, "")}
        </span>
      );
    },
  },
  {
    key: "signal", label: "Signal", width: 76, minWidth: 56, hideable: true,
    // This column is the signal engine's score for the row's own content, which
    // for a thread is its best unread member (`top_score`) — not the queue's
    // ranking score, which can carry a read-time lift the entry column doesn't.
    sortValue: (r) => r.kind === "thread"
      ? (r.thread.top_score ?? r.score)
      : (r.entry.priority_score ?? -1),
    render: (r) => {
      if (r.kind === "thread") return <SignalChip score={r.thread.top_score ?? r.score} signals={[]} />;
      return r.entry.priority_score != null
        ? <SignalChip score={r.entry.priority_score} signals={r.entry.top_signals ?? []} />
        : ZERO_CELL;
    },
  },
  {
    key: "pir", label: "PIR", width: 60, minWidth: 48, hideable: true,
    numValue: intelCount((c) => c.pir_matches?.length),
    render: (r) => <CountCell value={intelCount((c) => c.pir_matches?.length)(r)} tone="pir" />,
  },
  {
    key: "subject", label: "Actors / Malware", width: 170, minWidth: 90, hideable: true,
    // A thread's key entities answer the same question this column asks of an
    // article: who or what is this about.
    textValue: (r) => subjectNames(r).join(", "),
    sortValue: (r) => (subjectNames(r)[0] ?? "￿").toLowerCase(),
    render: (r) => {
      const names = subjectNames(r);
      if (names.length === 0) return ZERO_CELL;
      return (
        <span className={`${styles.subjectCell} ${table.ellipsis}`} title={names.join(", ")}>
          {names.join(", ")}
        </span>
      );
    },
  },
  {
    key: "ttps", label: "TTPs", width: 60, minWidth: 48, hideable: true,
    numValue: intelCount((c) => c.ttps),
    render: (r) => <CountCell value={intelCount((c) => c.ttps)(r)} tone="ttp" />,
  },
  {
    key: "cves", label: "CVEs", width: 60, minWidth: 48, hideable: true,
    numValue: intelCount((c) => c.cves),
    render: (r) => {
      const sev = r.kind === "entry" ? r.counts?.cve_max_severity : undefined;
      return (
        <CountCell
          value={intelCount((c) => c.cves)(r)}
          tone={sev === "critical" || sev === "high" ? "cveHot" : "cve"}
        />
      );
    },
  },
  {
    key: "rules", label: "Rules", width: 62, minWidth: 48, hideable: true,
    numValue: intelCount((c) => c.rules),
    render: (r) => <CountCell value={intelCount((c) => c.rules)(r)} tone="rule" />,
  },
  {
    key: "ai", label: "AI", width: 52, minWidth: 44, hideable: true,
    numValue: intelCount((c) => c.ai_results),
    render: (r) => <CountCell value={intelCount((c) => c.ai_results)(r)} tone="ai" />,
  },
  {
    key: "opportunity", label: "Opportunity", width: 110, minWidth: 70, hideable: true, defaultHidden: true,
    numValue: opportunityRank,
    render: (r) => {
      const rank = opportunityRank(r);
      if (rank === 0) return ZERO_CELL;
      const label = rank === 4 ? "KEV" : rank === 3 ? "high-risk" : rank === 2 ? "gap" : "telemetry";
      const cls = rank >= 3 ? styles.oppHot : rank === 2 ? styles.oppGap : styles.oppTel;
      const tip =
        rank === 4
          ? "CISA KEV CVE (actively exploited) with no detection rules"
          : rank === 3
            ? "High-risk CVE (high EPSS / weaponized) with no detection rules"
            : rank === 2
              ? "No detection rule exists for the observed TTPs/CVEs"
              : "Library rules exist, but required data sources aren't in your telemetry";
      return <span className={`${styles.oppBadge} ${cls}`} title={tip}>{label}</span>;
    },
  },
  {
    key: "notes", label: "Notes", width: 62, minWidth: 48, hideable: true, defaultHidden: true,
    numValue: intelCount((c) => c.notes),
    render: (r) => <CountCell value={intelCount((c) => c.notes)(r)} />,
  },
  {
    key: "tags", label: "Tags", width: 150, minWidth: 80, hideable: true,
    textValue: (r) => r.kind === "thread" ? "" : r.entry.tags.map((t) => t.name).join(", "),
    render: (r) => {
      if (r.kind === "thread" || !r.entry.tags?.length) return ZERO_CELL;
      return (
        <span className={table.ellipsis} title={r.entry.tags.map((t) => t.name).join(", ")}>
          {r.entry.tags.map((tag) => (
            <span key={tag.name} className={styles.tagInline}>
              <span className={styles.tagDot} style={{ backgroundColor: tag.color }} />
              {tag.name}
            </span>
          ))}
        </span>
      );
    },
  },
  {
    key: "type", label: "Type", width: 90, minWidth: 60, hideable: true, defaultHidden: true,
    textValue: (r) => r.kind === "thread" ? "" : r.entry.feed_type ?? "",
    sortValue: (r) => r.kind === "thread" ? "￿" : r.entry.feed_type ?? "￿",
    render: (r) => r.kind === "entry" && r.entry.feed_type
      ? <span className={table.dateCell}>{r.entry.feed_type.replace(/_/g, " ")}</span>
      : ZERO_CELL,
  },
  {
    key: "domain", label: "Domain", width: 150, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: domainOf,
    sortValue: (r) => domainOf(r) || "￿",
    render: (r) => {
      const d = domainOf(r);
      if (!d) return ZERO_CELL;
      const href = r.kind === "entry" ? r.entry.url ?? "" : "";
      return <span className={`${table.dateCell} ${table.ellipsis}`} title={href}>{d}</span>;
    },
  },
  {
    key: "author", label: "Author", width: 130, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: (r) => r.kind === "thread" ? "" : r.entry.author ?? "",
    sortValue: (r) => (r.kind === "thread" ? "￿" : r.entry.author ?? "￿").toLowerCase(),
    render: (r) => r.kind === "thread"
      ? ZERO_CELL
      : <span className={table.ellipsis} title={r.entry.author ?? ""}>{r.entry.author}</span>,
  },
  {
    key: "words", label: "Read time", width: 90, minWidth: 60, hideable: true, defaultHidden: true,
    serverSort: true,
    render: (r) => r.kind === "entry" && r.entry.word_count
      ? <span className={table.dateCell}>{Math.ceil(r.entry.word_count / 200)} min</span>
      : ZERO_CELL,
  },
  /*
   * Manual Uploads only. Hidden everywhere else by default; the uploads feed
   * registers under its own table id (see `uploadsFeed`), whose default layout
   * turns them on, so a feed of files reads as a file table without a page of
   * its own.
   */
  {
    key: "file", label: "File", width: 240, minWidth: 120, hideable: true, defaultHidden: true,
    textValue: (r) => (r.kind === "entry" ? uploadMeta(r.entry.metadata)?.filename ?? "" : ""),
    sortValue: (r) => (r.kind === "entry" ? uploadMeta(r.entry.metadata)?.filename ?? "￿" : "￿").toLowerCase(),
    render: (r) => {
      const m = r.kind === "entry" ? uploadMeta(r.entry.metadata) : null;
      if (!m) return ZERO_CELL;
      if (!m.filename) {
        return <span className={table.dateCell}>{m.source === "url_ingest" ? "web page" : m.source === "github_repo" ? "repo file" : "·"}</span>;
      }
      return (
        <span className={styles.sourceCell} title={m.filename}>
          <Chip size="sm" tone="toned" tint="var(--accent-intel)">{fileTypeLabel(m.file_content_type, m.filename)}</Chip>
          <span className={table.ellipsis}>{m.filename}</span>
        </span>
      );
    },
  },
  {
    key: "size", label: "Size", width: 80, minWidth: 60, hideable: true, defaultHidden: true,
    numValue: (r) => (r.kind === "entry" ? uploadMeta(r.entry.metadata)?.size_bytes ?? 0 : 0),
    render: (r) => {
      const n = r.kind === "entry" ? uploadMeta(r.entry.metadata)?.size_bytes : null;
      return n != null ? <span className={table.dateCell}>{formatBytes(n)}</span> : ZERO_CELL;
    },
  },
  {
    key: "original", label: "Original", width: 110, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: (r) => (r.kind === "entry" ? originalState(uploadMeta(r.entry.metadata)).replace("_", " ") : ""),
    choices: [
      { value: "all", label: "All" },
      { value: "available", label: "Downloadable" },
      { value: "gone", label: "Not kept" },
    ],
    choiceMatch: (r, v) => {
      if (r.kind !== "entry") return v === "all";
      const s = originalState(uploadMeta(r.entry.metadata));
      return v === "available" ? s === "available" : v === "gone" ? s === "evicted" || s === "not_kept" : true;
    },
    render: (r) => {
      const m = r.kind === "entry" ? uploadMeta(r.entry.metadata) : null;
      const s = originalState(m);
      if (s === "available" && m?.ingest_file_id) {
        return (
          <a
            className={styles.downloadLink}
            href={ingestFileUrl(m.ingest_file_id)}
            download={m.filename ?? true}
            onClick={(e) => e.stopPropagation()}
            title={`Download ${m.filename ?? "original"}`}
          >
            Download
          </a>
        );
      }
      if (s === "evicted") return <span className={table.dateCell}>removed</span>;
      if (s === "not_kept") return <span className={table.dateCell}>not kept</span>;
      if (m && !m.ingest_file_id) return <span className={table.dateCell}>{m.source === "url_ingest" ? "link" : "text only"}</span>;
      return ZERO_CELL;
    },
  },
];

const rowClass = (r: TableRow) =>
  (r.kind === "thread"
    ? [styles.threadRow, r.thread.unread_count === 0 ? table.rowMuted : ""]
    : [r.entry.is_read ? table.rowMuted : "", r.entry.is_echo ? table.rowDim : ""]
  ).filter(Boolean).join(" ");

interface EntryTableViewProps {
  entries: Entry[];
  /**
   * Priority Queue rows, when the list is in priority mode. The queue
   * interleaves story threads with entries and the API withholds every article
   * a live thread absorbed, so `entries` alone is missing both the thread row
   * and the articles standing behind it. Omitted everywhere else: the plain
   * /entries list never carries a thread.
   */
  queueRows?: PriorityQueueRow[];
  intelBadges?: Record<string, EntryIntelCounts>;
  totalCount?: number;
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => void;
  isLoading: boolean;
  /**
   * The Manual Uploads feed is selected. The table registers under a second
   * id so its layout (File / Size / Original on, Source off) is remembered
   * apart from the ordinary entries table.
   */
  uploadsFeed?: boolean;
}

export function EntryTableView({
  entries,
  queueRows,
  intelBadges,
  totalCount,
  hasNextPage,
  isFetchingNextPage,
  fetchNextPage,
  isLoading,
  uploadsFeed = false,
}: EntryTableViewProps) {
  const tableId = uploadsFeed ? "entries-uploads" : "entries";
  const sortOrder = useUIStore((s) => s.sortOrder);
  const setSortOrder = useUIStore((s) => s.setSortOrder);
  const selectedEntryId = useUIStore((s) => s.selectedEntryId);
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const selectedThreadSlug = useUIStore((s) => s.selectedThreadSlug);
  const setSelectedThread = useUIStore((s) => s.setSelectedThread);
  const selectedEntryIds = useUIStore((s) => s.selectedEntryIds);
  const setEntrySelection = useUIStore((s) => s.setEntrySelection);

  // Defensive dedupe: a duplicate row id would collide as a React key and as a
  // virtualizer position-cache key, rendering stacked ghost rows.
  const rows: TableRow[] = useMemo(() => {
    const seen = new Set<string>();
    const out: TableRow[] = [];
    const pushEntry = (entry: Entry) => {
      if (seen.has(entry.id)) return;
      seen.add(entry.id);
      out.push({ kind: "entry", entry, counts: intelBadges?.[entry.id] });
    };
    if (queueRows) {
      for (const row of queueRows) {
        if (row.kind === "thread") {
          if (!row.thread) continue;
          const id = threadRowId(row.thread.slug);
          if (seen.has(id)) continue;
          seen.add(id);
          out.push({ kind: "thread", thread: row.thread, score: row.score });
        } else if (row.entry) {
          pushEntry(row.entry);
        }
      }
      return out;
    }
    for (const entry of entries) pushEntry(entry);
    return out;
  }, [queueRows, entries, intelBadges]);

  const threads = useMemo(
    () => rows.flatMap((r) => (r.kind === "thread" ? [r.thread] : [])),
    [rows],
  );

  /*
   * Selection is entry-scoped: it feeds bulk actions that POST `entry_ids`, so
   * a thread's row id must never reach `setEntrySelection` — the API would take
   * "thread:<slug>" for an article that doesn't exist. Checking a thread instead
   * selects the articles it folded, which is what the row stands for, and the
   * row reads back as checked once all of them are.
   *
   * Dropping the members again when the thread row comes back unchecked is safe
   * because the queue withholds a live thread's members from the entry rows —
   * they are never separately selectable while the thread row is on screen.
   */
  const tableSelection = useMemo(() => {
    if (threads.length === 0) return selectedEntryIds;
    const out = new Set(selectedEntryIds);
    for (const t of threads) {
      if (t.entry_ids.length > 0 && t.entry_ids.every((id) => selectedEntryIds.has(id))) {
        out.add(threadRowId(t.slug));
      }
    }
    return out;
  }, [threads, selectedEntryIds]);

  const handleSelectionChange = useCallback(
    (ids: string[]) => {
      if (threads.length === 0) {
        setEntrySelection(ids);
        return;
      }
      const next = new Set(ids);
      for (const t of threads) {
        if (next.delete(threadRowId(t.slug))) for (const id of t.entry_ids) next.add(id);
        else for (const id of t.entry_ids) next.delete(id);
      }
      setEntrySelection(Array.from(next));
    },
    [threads, setEntrySelection],
  );

  const sort = useMemo(() => {
    for (const [key, pair] of Object.entries(SERVER_SORTS)) {
      if (sortOrder === pair.desc) return { key, dir: "desc" as SortDir };
      if (sortOrder === pair.asc) return { key, dir: "asc" as SortDir };
    }
    return null;
  }, [sortOrder]);

  const handleSortChange = useCallback(
    ({ key, dir }: { key: string; dir: SortDir }) => {
      const pair = SERVER_SORTS[key];
      if (pair) setSortOrder(pair[dir]);
    },
    [setSortOrder]
  );

  return (
    <DataTable<TableRow>
      key={tableId}
      tableId={tableId}
      columns={COLUMNS}
      rows={rows}
      getRowId={(r) => (r.kind === "thread" ? threadRowId(r.thread.slug) : r.entry.id)}
      rowClass={rowClass}
      // The reader holds a thread or an article, never both — selecting either
      // clears the other — so exactly one of these is ever set.
      activeRowId={selectedThreadSlug ? threadRowId(selectedThreadSlug) : selectedEntryId}
      onRowClick={(r) =>
        r.kind === "thread" ? setSelectedThread(r.thread.slug) : setSelectedEntry(r.entry.id)
      }
      selectable
      selectedIds={tableSelection}
      onSelectionChange={handleSelectionChange}
      sort={sort}
      onSortChange={handleSortChange}
      isLoading={isLoading}
      hasNextPage={hasNextPage}
      isFetchingNextPage={isFetchingNextPage}
      fetchNextPage={fetchNextPage}
      totalCount={totalCount}
      noun="entry"
      nounPlural="entries"
      emptyMessage="No entries to display"
    />
  );
}
