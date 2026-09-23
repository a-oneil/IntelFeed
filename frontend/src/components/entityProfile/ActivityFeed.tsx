/**
 * ActivityFeed — merged linked-entries + timeline events with an All / Articles /
 * Events filter and free-text search. Rendered at the bottom of the Overview tab
 * (replaces the old standalone Activity tab).
 *
 * Rows group under day dividers, and each day's catch-all relationship events
 * collapse to a single expandable summary row ("14 relationship changes · 6
 * tools · 4 CVEs") — bulk extraction runs stop drowning the articles. Rendering
 * caps at a page of rows with Show more; the feed no longer makes the profile
 * tens of thousands of pixels tall.
 */
import { useState, type ReactNode } from "react";
import { formatDate } from "@/utils/formatDate";
import { UnlinkArticleButton } from "@/components/UnlinkArticleButton";
import { RemoveFromCampaignButton } from "@/components/RemoveFromCampaignButton";
import type { EntityType } from "@/stores/intelStore";
import type { TimelineEvent } from "@/api/types";
import styles from "./entityProfile.module.css";

export const EVENT_COLORS: Record<string, string> = {
  correlation: "#f59e0b",
  enrichment: "#22c55e",
  detection_rule: "#ef4444",
  relationship: "#8b5cf6",
  campaign: "#ec4899",
  status_change: "#f97316",
  story: "#58a6ff",
};

const PAGE_SIZE = 50;
// A single day can carry thousands of articles (Chromium CVE dumps, Patch
// Tuesday) — cap them per day so other days and event rows stay reachable.
const ARTICLES_PER_DAY = 12;

type Filter = "all" | "articles" | "events";

interface EntryRow {
  id: string;
  title: string;
  published_at: string | null;
}

function sortByDateDesc<T extends { date: string | null }>(rows: T[]): T[] {
  return [...rows].sort((a, b) => {
    if (!b.date) return -1;
    if (!a.date) return 1;
    return new Date(b.date).getTime() - new Date(a.date).getTime();
  });
}

/** Day key for grouping (undated rows collect under "undated", listed last). */
function dayKey(date: string | null): string {
  if (!date) return "undated";
  const d = new Date(date);
  return isNaN(d.getTime()) ? "undated" : d.toISOString().slice(0, 10);
}

function dayLabel(key: string): string {
  if (key === "undated") return "No date";
  return new Date(`${key}T00:00:00`).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: new Date().getFullYear() !== Number(key.slice(0, 4)) ? "numeric" : undefined,
  });
}

/** Best-effort target-type from a relationship event title ("Uses tool "X""). */
const REL_TYPE_RE =
  /\b(tool|cve|actor|malware|vendor|product|country|ttp|technique|mitigation|cwe|weakness)\b/i;
const REL_TYPE_LABELS: Record<string, [singular: string, plural: string]> = {
  tool: ["tool", "tools"],
  cve: ["CVE", "CVEs"],
  actor: ["actor", "actors"],
  malware: ["malware", "malware"],
  vendor: ["vendor", "vendors"],
  product: ["product", "products"],
  country: ["country", "countries"],
  ttp: ["TTP", "TTPs"],
  technique: ["TTP", "TTPs"],
  mitigation: ["mitigation", "mitigations"],
  cwe: ["CWE", "CWEs"],
  weakness: ["CWE", "CWEs"],
};

function relationshipBreakdown(events: TimelineEvent[]): string {
  const byType = new Map<string, number>();
  for (const e of events) {
    const m = e.title.match(REL_TYPE_RE);
    const key = m ? m[1].toLowerCase() : "other";
    byType.set(key, (byType.get(key) ?? 0) + 1);
  }
  return [...byType.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([key, count]) => {
      const [singular, plural] = REL_TYPE_LABELS[key] ?? ["other", "other"];
      return `${count} ${count === 1 ? singular : plural}`;
    })
    .join(" · ");
}

export function ActivityFeed({
  entityType,
  entityId,
  entries,
  events,
  since,
  onOpenArticle,
  onOpenStory,
}: {
  entityType: EntityType;
  entityId: string;
  entries: EntryRow[];
  events: TimelineEvent[];
  /** Lower bound from the timeline's window picker — undated rows are kept. */
  since?: Date | null;
  onOpenArticle: (entryId: string) => void;
  /** Story rows are synthesized client-side; clicking one opens its thread. */
  onOpenStory?: (slug: string) => void;
}) {
  const [rawFilter, setRawFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE_SIZE);
  const [expandedDays, setExpandedDays] = useState<Set<string>>(new Set());
  const [expandedArticleDays, setExpandedArticleDays] = useState<Set<string>>(new Set());
  const q = query.trim().toLowerCase();
  const match = (t?: string | null) => !q || (t || "").toLowerCase().includes(q);
  const inWindow = (date: string | null) => !since || !date || new Date(date) >= since;

  const articleRows = sortByDateDesc(entries.map((e) => ({ ...e, date: e.published_at })))
    .filter((r) => inWindow(r.date))
    .filter((r) => match(r.title));
  const allEvents = sortByDateDesc(events.map((e) => ({ ...e })))
    .filter((r) => inWindow(r.date))
    .filter((r) => match(r.title));
  const nonArticleEvents = allEvents.filter((e) => e.event_type && e.event_type !== "article");

  // Some entity types (e.g. CVEs) never accrue non-article events — hide the
  // dead "Events (0)" filter instead of presenting an always-empty view.
  const hasAnyEvents = events.some((e) => e.event_type && e.event_type !== "article");
  const filters: Filter[] = hasAnyEvents ? ["all", "articles", "events"] : ["all", "articles"];
  let filter: Filter = !hasAnyEvents && rawFilter === "events" ? "all" : rawFilter;
  // A timeline with no events but linked articles still has an All view —
  // render (and count) the articles rather than claiming "No activity".
  if (filter === "all" && allEvents.length === 0 && articleRows.length > 0) filter = "articles";

  const counts = {
    all: allEvents.length || articleRows.length,
    articles: articleRows.length,
    events: nonArticleEvents.length,
  };

  const setFilter = (f: Filter) => {
    setRawFilter(f);
    setLimit(PAGE_SIZE);
  };

  const toggleArticleDay = (key: string) =>
    setExpandedArticleDays((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const toggleDay = (key: string) =>
    setExpandedDays((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const renderEventRow = (evt: TimelineEvent & { date: string | null }, key: string) => (
    <div
      key={key}
      className={`${styles.articleItem} ${evt.event_type !== "article" ? styles.nonArticleItem : ""}`}
      onClick={() => {
        // The article wins over the story it belongs to: a row with an entry
        // opens that entry in the workbench's docked reader, so the profile
        // stays on screen. Only an event with no article of its own (a story
        // beat, a relationship assertion) hands off to the thread reader.
        if (evt.entry_id) onOpenArticle(evt.entry_id);
        else if (evt.thread_slug && onOpenStory) onOpenStory(evt.thread_slug);
      }}
      style={!evt.entry_id && !evt.thread_slug ? { cursor: "default", opacity: 0.85 } : undefined}
    >
      {evt.event_type && evt.event_type !== "article" && (
        <span className={styles.eventBadge} style={{ color: EVENT_COLORS[evt.event_type] || "#6b7280" }}>
          {evt.event_type.replace(/_/g, " ")}
        </span>
      )}
      <a className={styles.articleTitle}>{evt.title}</a>
      <span className={styles.articleDate}>{formatDate(evt.date)}</span>
    </div>
  );

  /** Day-grouped event rows with per-day relationship collapsing and a row cap. */
  const renderGroupedEvents = (rows: Array<TimelineEvent & { date: string | null }>) => {
    if (rows.length === 0)
      return <div className={styles.emptySection}>{q ? "No matching activity" : "No activity recorded"}</div>;

    // Preserve the sorted order: collect day keys as they appear.
    const dayOrder: string[] = [];
    const byDay = new Map<string, Array<TimelineEvent & { date: string | null }>>();
    for (const row of rows) {
      const key = dayKey(row.date);
      if (!byDay.has(key)) {
        byDay.set(key, []);
        dayOrder.push(key);
      }
      byDay.get(key)!.push(row);
    }

    const out: ReactNode[] = [];
    let rendered = 0;
    let capped = false;
    for (const key of dayOrder) {
      if (rendered >= limit) {
        capped = true;
        break;
      }
      const dayRows = byDay.get(key)!;
      // Searching means the user wants the matching rows themselves — skip
      // collapsing and per-day caps so results are directly visible.
      const relRows = q ? [] : dayRows.filter((r) => r.event_type === "relationship");
      const collapse = relRows.length >= 3 && !expandedDays.has(key);
      const visible = collapse ? dayRows.filter((r) => r.event_type !== "relationship") : dayRows;
      const isArticle = (r: TimelineEvent) => !r.event_type || r.event_type === "article";
      const articleCap = q || expandedArticleDays.has(key) ? Infinity : ARTICLES_PER_DAY;
      const dayArticleTotal = visible.filter(isArticle).length;

      out.push(
        <div key={`day:${key}`} className={styles.feedDayRow}>
          <span className={styles.feedDayLabel}>{dayLabel(key)}</span>
          <span className={styles.feedDayRule} />
        </div>,
      );
      let dayArticles = 0;
      for (const [idx, row] of visible.entries()) {
        if (rendered >= limit) {
          capped = true;
          break;
        }
        if (isArticle(row)) {
          dayArticles += 1;
          // Skip past the cap but keep walking — event rows later in the day
          // must still render.
          if (dayArticles > articleCap) continue;
        }
        out.push(renderEventRow(row, `${key}:${idx}`));
        rendered += 1;
      }
      if (dayArticleTotal > articleCap && rendered < limit) {
        out.push(
          <button key={`arts:${key}`} className={styles.feedCollapseRow} onClick={() => toggleArticleDay(key)}>
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden>
              <path d="M3 1.5 L7 5 L3 8.5" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            </svg>
            {dayArticleTotal - articleCap} more article{dayArticleTotal - articleCap === 1 ? "" : "s"} this day
          </button>,
        );
        rendered += 1;
      }
      if (collapse && rendered < limit) {
        out.push(
          <button key={`rel:${key}`} className={styles.feedCollapseRow} onClick={() => toggleDay(key)}>
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden>
              <path d="M3 1.5 L7 5 L3 8.5" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            </svg>
            {relRows.length} relationship changes
            <span className={styles.feedCollapseDetail}> · {relationshipBreakdown(relRows)}</span>
          </button>,
        );
        rendered += 1;
      } else if (relRows.length >= 3 && expandedDays.has(key) && rendered < limit) {
        out.push(
          <button key={`relless:${key}`} className={styles.feedCollapseRow} onClick={() => toggleDay(key)}>
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden style={{ transform: "rotate(90deg)" }}>
              <path d="M3 1.5 L7 5 L3 8.5" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            </svg>
            collapse relationship changes
          </button>,
        );
      }
    }

    return (
      <div className={styles.entityList}>
        {out}
        {capped && (
          <button className={styles.feedShowMore} onClick={() => setLimit((l) => l + 2 * PAGE_SIZE)}>
            Show more
          </button>
        )}
      </div>
    );
  };

  return (
    <div>
      <div className={styles.filterRow}>
        {filters.map((f) => (
          <button
            key={f}
            className={`${styles.filterBtn} ${filter === f ? styles.filterBtnActive : ""}`}
            onClick={() => setFilter(f)}
          >
            {f[0].toUpperCase() + f.slice(1)} ({counts[f]})
          </button>
        ))}
        <input
          className={styles.filterSearch}
          placeholder="Search activity…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {filter === "articles" ? (
        articleRows.length > 0 ? (
          <div className={styles.entityList}>
            {articleRows.slice(0, limit).map((entry) => (
              <div key={entry.id} className={styles.articleItem} onClick={() => onOpenArticle(entry.id)}>
                <a className={styles.articleTitle}>{entry.title}</a>
                <span className={styles.articleDate}>{formatDate(entry.published_at)}</span>
                {entityType === "campaign" ? (
                  <RemoveFromCampaignButton campaignId={entityId} entryId={entry.id} />
                ) : (
                  <UnlinkArticleButton entryId={entry.id} entityId={entityId} entityType={entityType} />
                )}
              </div>
            ))}
            {articleRows.length > limit && (
              <button className={styles.feedShowMore} onClick={() => setLimit((l) => l + 2 * PAGE_SIZE)}>
                Show more
              </button>
            )}
          </div>
        ) : (
          <div className={styles.emptySection}>{q ? "No matching articles" : "No articles linked"}</div>
        )
      ) : (
        renderGroupedEvents(filter === "events" ? nonArticleEvents : allEvents)
      )}
    </div>
  );
}
