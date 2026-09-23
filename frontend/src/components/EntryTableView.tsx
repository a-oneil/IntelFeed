import { useCallback, useMemo } from "react";
import { formatDate } from "@/utils/formatDate";
import { useUIStore, type SortOrder } from "@/stores/uiStore";
import type { Entry } from "@/api/types";
import type { EntryIntelCounts } from "@/hooks/useEntryIntelBadges";
import { FeedTypeIcon } from "@/components/FeedTypeIcon";
import { DataTable, type DataTableColumn, type SortDir } from "@/components/table/DataTable";
import table from "@/components/table/DataTable.module.css";
import { SignalChip } from "./SignalChip";
import styles from "./EntryTableView.module.css";

interface TableRow {
  entry: Entry;
  counts?: EntryIntelCounts;
}

const subjectNames = (r: TableRow) => [
  ...(r.counts?.actors ?? []),
  ...(r.counts?.malware ?? []),
];

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

const domainOf = (r: TableRow) => {
  if (!r.entry.url) return "";
  try {
    return new URL(r.entry.url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
};

/** Detection-opportunity tier, ranked for sorting: KEV > high-risk > gap > telemetry */
function opportunityRank(r: TableRow): number {
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

function CountCell({ value, tone }: { value: number; tone?: string }) {
  if (!value) return <span className={table.zero}>·</span>;
  return <span className={`${table.count} ${tone ? table[tone] : ""}`}>{value}</span>;
}

/**
 * Server-sortable columns and the SortOrder values they map to. Everything else
 * sorts client-side over the loaded rows.
 */
const SERVER_SORTS: Record<string, { asc: SortOrder; desc: SortOrder }> = {
  title: { asc: "title_asc", desc: "title_desc" },
  date: { asc: "oldest", desc: "newest" },
  words: { asc: "shortest", desc: "longest" },
};

const COLUMNS: DataTableColumn<TableRow>[] = [
  {
    key: "status", label: "State", width: 64, minWidth: 48, hideable: true,
    sortValue: (r) => (r.entry.is_read ? 1 : 0) + (r.entry.is_starred ? -2 : 0),
    choices: [
      { value: "all", label: "All" },
      { value: "unread", label: "Unread" },
      { value: "read", label: "Read" },
      { value: "starred", label: "★" },
      { value: "bookmarked", label: "⚑" },
    ],
    choiceMatch: (r, v) =>
      v === "unread" ? !r.entry.is_read
        : v === "read" ? r.entry.is_read
          : v === "starred" ? !!r.entry.is_starred
            : v === "bookmarked" ? !!r.entry.is_bookmarked
              : true,
    render: (r) => (
      <span className={styles.statusCell}>
        {!r.entry.is_read && <span className={styles.unreadDot} title="Unread" />}
        {r.entry.is_starred && <span className={styles.star} title="Starred">★</span>}
        {r.entry.is_bookmarked && <span className={styles.bookmark} title="Bookmarked">⚑</span>}
      </span>
    ),
  },
  {
    key: "source", label: "Source", width: 150, minWidth: 80, hideable: true,
    textValue: (r) => r.entry.feed_title ?? "",
    sortValue: (r) => (r.entry.feed_title ?? "").toLowerCase(),
    render: (r) => (
      <span className={styles.sourceCell} title={r.entry.feed_title ?? ""}>
        {r.entry.feed_type && <FeedTypeIcon type={r.entry.feed_type} size={11} />}
        <span className={table.ellipsis}>{r.entry.feed_title}</span>
      </span>
    ),
  },
  {
    key: "title", label: "Title", width: 320, minWidth: 160, flex: true,
    textValue: (r) => r.entry.translated_title || r.entry.title,
    serverSort: true,
    render: (r) => {
      const t = r.entry.translated_title || r.entry.title;
      return <span className={`${table.strong} ${table.ellipsis}`} title={t}>{t}</span>;
    },
  },
  {
    key: "summary", label: "Summary", width: 300, minWidth: 120, hideable: true,
    textValue: (r) => (r.entry.summary ? stripHtmlFast(r.entry.summary) : ""),
    render: (r) => {
      const s = r.entry.summary ? stripHtmlFast(r.entry.summary) : "";
      if (!s) return <span className={table.zero}>·</span>;
      return <span className={`${styles.summaryCell} ${table.ellipsis}`} title={s.slice(0, 500)}>{s}</span>;
    },
  },
  {
    key: "date", label: "Date", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (r) => (
      <span
        className={table.dateCell}
        title={r.entry.published_at ? new Date(r.entry.published_at).toLocaleString() : undefined}
      >
        {formatDate(r.entry.published_at, "")}
      </span>
    ),
  },
  {
    key: "signal", label: "Signal", width: 76, minWidth: 56, hideable: true,
    sortValue: (r) => r.entry.priority_score ?? -1,
    render: (r) => r.entry.priority_score != null
      ? <SignalChip score={r.entry.priority_score} signals={r.entry.top_signals ?? []} />
      : <span className={table.zero}>·</span>,
  },
  {
    key: "pir", label: "PIR", width: 60, minWidth: 48, hideable: true,
    numValue: (r) => r.counts?.pir_matches?.length ?? 0,
    render: (r) => <CountCell value={r.counts?.pir_matches?.length ?? 0} tone="pir" />,
  },
  {
    key: "subject", label: "Actors / Malware", width: 170, minWidth: 90, hideable: true,
    textValue: (r) => subjectNames(r).join(", "),
    sortValue: (r) => (subjectNames(r)[0] ?? "￿").toLowerCase(),
    render: (r) => {
      const names = subjectNames(r);
      if (names.length === 0) return <span className={table.zero}>·</span>;
      return (
        <span className={`${styles.subjectCell} ${table.ellipsis}`} title={names.join(", ")}>
          {names.join(", ")}
        </span>
      );
    },
  },
  {
    key: "ttps", label: "TTPs", width: 60, minWidth: 48, hideable: true,
    numValue: (r) => r.counts?.ttps ?? 0,
    render: (r) => <CountCell value={r.counts?.ttps ?? 0} tone="ttp" />,
  },
  {
    key: "cves", label: "CVEs", width: 60, minWidth: 48, hideable: true,
    numValue: (r) => r.counts?.cves ?? 0,
    render: (r) => {
      const sev = r.counts?.cve_max_severity;
      return <CountCell value={r.counts?.cves ?? 0} tone={sev === "critical" || sev === "high" ? "cveHot" : "cve"} />;
    },
  },
  {
    key: "rules", label: "Rules", width: 62, minWidth: 48, hideable: true,
    numValue: (r) => r.counts?.rules ?? 0,
    render: (r) => <CountCell value={r.counts?.rules ?? 0} tone="rule" />,
  },
  {
    key: "ai", label: "AI", width: 52, minWidth: 44, hideable: true,
    numValue: (r) => r.counts?.ai_results ?? 0,
    render: (r) => <CountCell value={r.counts?.ai_results ?? 0} tone="ai" />,
  },
  {
    key: "opportunity", label: "Opportunity", width: 110, minWidth: 70, hideable: true, defaultHidden: true,
    numValue: opportunityRank,
    render: (r) => {
      const rank = opportunityRank(r);
      if (rank === 0) return <span className={table.zero}>·</span>;
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
    numValue: (r) => r.counts?.notes ?? 0,
    render: (r) => <CountCell value={r.counts?.notes ?? 0} />,
  },
  {
    key: "tags", label: "Tags", width: 150, minWidth: 80, hideable: true,
    textValue: (r) => r.entry.tags.map((t) => t.name).join(", "),
    render: (r) => {
      if (!r.entry.tags?.length) return <span className={table.zero}>·</span>;
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
    textValue: (r) => r.entry.feed_type ?? "",
    sortValue: (r) => r.entry.feed_type ?? "￿",
    render: (r) => r.entry.feed_type
      ? <span className={table.dateCell}>{r.entry.feed_type.replace(/_/g, " ")}</span>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "domain", label: "Domain", width: 150, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: domainOf,
    sortValue: (r) => domainOf(r) || "￿",
    render: (r) => {
      const d = domainOf(r);
      if (!d) return <span className={table.zero}>·</span>;
      return <span className={`${table.dateCell} ${table.ellipsis}`} title={r.entry.url ?? ""}>{d}</span>;
    },
  },
  {
    key: "author", label: "Author", width: 130, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: (r) => r.entry.author ?? "",
    sortValue: (r) => (r.entry.author ?? "￿").toLowerCase(),
    render: (r) => <span className={table.ellipsis} title={r.entry.author ?? ""}>{r.entry.author}</span>,
  },
  {
    key: "words", label: "Read time", width: 90, minWidth: 60, hideable: true, defaultHidden: true,
    serverSort: true,
    render: (r) => r.entry.word_count
      ? <span className={table.dateCell}>{Math.ceil(r.entry.word_count / 200)} min</span>
      : <span className={table.zero}>·</span>,
  },
];

const rowClass = (r: TableRow) =>
  [r.entry.is_read ? table.rowMuted : "", r.entry.is_echo ? table.rowDim : ""].filter(Boolean).join(" ");

interface EntryTableViewProps {
  entries: Entry[];
  intelBadges?: Record<string, EntryIntelCounts>;
  totalCount?: number;
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => void;
  isLoading: boolean;
}

export function EntryTableView({
  entries,
  intelBadges,
  totalCount,
  hasNextPage,
  isFetchingNextPage,
  fetchNextPage,
  isLoading,
}: EntryTableViewProps) {
  const sortOrder = useUIStore((s) => s.sortOrder);
  const setSortOrder = useUIStore((s) => s.setSortOrder);
  const selectedEntryId = useUIStore((s) => s.selectedEntryId);
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const selectedEntryIds = useUIStore((s) => s.selectedEntryIds);
  const setEntrySelection = useUIStore((s) => s.setEntrySelection);

  // Defensive dedupe: duplicate entry IDs would collide as React keys and as
  // virtualizer position-cache keys, rendering stacked ghost rows.
  const rows: TableRow[] = useMemo(() => {
    const seen = new Set<string>();
    const out: TableRow[] = [];
    for (const entry of entries) {
      if (seen.has(entry.id)) continue;
      seen.add(entry.id);
      out.push({ entry, counts: intelBadges?.[entry.id] });
    }
    return out;
  }, [entries, intelBadges]);

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
      tableId="entries"
      columns={COLUMNS}
      rows={rows}
      getRowId={(r) => r.entry.id}
      rowClass={rowClass}
      activeRowId={selectedEntryId}
      onRowClick={(r) => setSelectedEntry(r.entry.id)}
      selectable
      selectedIds={selectedEntryIds}
      onSelectionChange={setEntrySelection}
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
