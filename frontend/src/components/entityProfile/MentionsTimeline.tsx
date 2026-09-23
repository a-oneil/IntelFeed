/**
 * MentionsTimeline — the profile's activity chart: mention counts over a
 * selectable window (24h → all time) with correlation events plotted on the
 * baseline. The selected window also scopes the ActivityFeed below it, so the
 * Overview reads as one time slice.
 */
import { useEffect, useMemo, useState } from "react";
import {
  MENTIONS_WINDOWS,
  useEntityEntriesWindow,
  useEntityMentionsTimeseries,
  type MentionsWindow,
} from "@/hooks/useEntityProfile";
import { getEntityColor } from "@/utils/entityTheme";
import type { EntityType } from "@/stores/intelStore";
import type { TimelineEvent } from "@/api/types";
import { EVENT_COLORS } from "./ActivityFeed";
import styles from "./entityProfile.module.css";

const WINDOW_LABELS: Record<MentionsWindow, string> = {
  "24h": "24H",
  "7d": "7D",
  "30d": "30D",
  "60d": "60D",
  "90d": "90D",
  all: "ALL",
};

/** Window → cutoff Date (null = unbounded). Shared with the ActivityFeed filter. */
export function windowCutoff(window: MentionsWindow): Date | null {
  const hours: Record<Exclude<MentionsWindow, "all">, number> = {
    "24h": 24,
    "7d": 7 * 24,
    "30d": 30 * 24,
    "60d": 60 * 24,
    "90d": 90 * 24,
  };
  if (window === "all") return null;
  return new Date(Date.now() - hours[window] * 3600_000);
}

function bucketLabel(
  date: string,
  bucket: "hour" | "day" | "week",
  withYear = false,
  withDay = false,
): string {
  const d = new Date(date.includes("T") ? date : `${date}T00:00:00`);
  if (bucket === "hour") {
    const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    // Anchor axis labels to a day — a 24h window straddles midnight.
    return withDay ? `${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })} ${time}` : time;
  }
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    ...(withYear ? { year: "numeric" } : {}),
  });
}

// Chart geometry: fixed virtual space, stretched to the container. The line
// keeps its width via vector-effect; dots/labels live in an HTML overlay so
// they never distort.
const VW = 100;
const VH = 100;
const TOP_PAD = 8;

export function MentionsTimeline({
  entityType,
  entityId,
  events,
  window,
  onWindowChange,
  onOpenArticle,
  onOpenEntity,
  onOpenStory,
  onCollapse,
}: {
  entityType: EntityType;
  entityId: string;
  events: TimelineEvent[];
  window: MentionsWindow;
  onWindowChange: (w: MentionsWindow) => void;
  onOpenArticle?: (entryId: string) => void;
  onOpenEntity?: (type: EntityType, id: string, label?: string) => void;
  /** Story rows (synthesized upstream) open their thread. */
  onOpenStory?: (slug: string) => void;
  /** Present when the timeline is the expanded state of the header pulse line. */
  onCollapse?: () => void;
}) {
  const { data, isLoading } = useEntityMentionsTimeseries(entityType, entityId, window);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [markerHover, setMarkerHover] = useState<number | null>(null);
  // Click selection: a chart bucket (→ fetch + list its articles) or an event
  // cluster (→ list its events). The timeline is an index into the reading.
  const [selection, setSelection] = useState<
    { kind: "bucket"; idx: number } | { kind: "cluster"; idx: number } | null
  >(null);
  useEffect(() => setSelection(null), [window, entityId]);
  const accent = getEntityColor(entityType);

  const points = useMemo(() => data?.points ?? [], [data]);
  const bucket = data?.bucket ?? "week";
  // Multi-year spans (the "all" window) need years on labels to be readable.
  const spansYears =
    points.length > 1 && points[0].date.slice(0, 4) !== points[points.length - 1].date.slice(0, 4);
  const counts = points.map((p) => p.count);
  const total = counts.reduce((a, b) => a + b, 0);
  const max = Math.max(...counts, 1);
  const n = points.length;

  const x = (i: number) => (n > 1 ? (i / (n - 1)) * VW : 0);
  const y = (c: number) => VH - (c / max) * (VH - TOP_PAD);

  // Sparse discrete counts (hourly/daily buckets) read as harsh sawteeth when
  // connected — draw those as bars; the aggregated weekly series keeps line+area.
  const asBars = bucket !== "week";
  const barW = n > 1 ? Math.max((VW / n) * 0.55, 0.35) : 2;

  const linePath = counts.map((c, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(2)},${y(c).toFixed(2)}`).join(" ");
  const areaPath = n > 1 ? `${linePath} L${VW},${VH} L0,${VH} Z` : "";

  // Non-article events inside the window, placed on the baseline by date and
  // clustered when they'd overlap — one legible marker per spot, not confetti.
  const markerClusters = useMemo(() => {
    if (n < 2) return [];
    const start = new Date(bucket === "hour" ? points[0].date : `${points[0].date}T00:00:00`).getTime();
    const span = Date.now() - start;
    if (span <= 0) return [];
    // Catch-all "Related to …" rows are machine-dated bulk-extraction noise —
    // annotations keep typed relationships, rules, campaigns. The cap keeps
    // the NEWEST events (ascending-then-slice used to keep the oldest 80 and
    // silently dropped every recent marker on busy entities); story rows ride
    // outside the cap — a busy week must not crowd a story off the chart.
    const dated = events
      .filter((e) => e.date && e.event_type && e.event_type !== "article")
      .filter((e) => !e.title.startsWith("Related to "))
      .map((e) => ({ event: e, t: new Date(e.date!).getTime() }))
      .filter(({ t }) => t >= start);
    const positioned = [
      ...dated.filter(({ event }) => event.event_type !== "story").sort((a, b) => b.t - a.t).slice(0, 80),
      ...dated.filter(({ event }) => event.event_type === "story"),
    ]
      .sort((a, b) => a.t - b.t)
      .map(({ event, t }) => ({ event, left: Math.min(((t - start) / span) * 100, 100) }));
    const clusters: Array<{ left: number; events: TimelineEvent[] }> = [];
    for (const { event, left } of positioned) {
      const last = clusters[clusters.length - 1];
      if (last && left - last.left < 1.6) last.events.push(event);
      else clusters.push({ left, events: [event] });
    }
    return clusters;
  }, [events, points, bucket, n]);

  // Coverage peak: the loudest bucket, annotated when the window is wide
  // enough for "peak" to mean something and the peak is a real spike.
  const peakIdx = useMemo(() => {
    if (n < 10 || max < 5) return null;
    const idx = counts.indexOf(max);
    return idx >= 0 ? idx : null;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [points, n, max]);
  const hasStoryMarkers = markerClusters.some((c) => c.events.some((e) => e.event_type === "story"));
  const hasMilestoneMarkers = markerClusters.some((c) => c.events.some((e) => e.event_type !== "story"));

  const handleMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (n < 2) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const frac = Math.min(Math.max((e.clientX - rect.left) / rect.width, 0), 1);
    setHoverIdx(Math.round(frac * (n - 1)));
  };

  const handleChartClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (n < 2) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const frac = Math.min(Math.max((e.clientX - rect.left) / rect.width, 0), 1);
    const idx = Math.round(frac * (n - 1));
    setSelection((s) => (s?.kind === "bucket" && s.idx === idx ? null : { kind: "bucket", idx }));
  };

  // Bucket boundaries in UTC — matches the server's date_trunc buckets.
  const bucketRange = (idx: number): { start: string; end: string } | null => {
    const p = points[idx];
    if (!p) return null;
    const startMs = new Date(p.date.includes("T") ? p.date : `${p.date}T00:00:00Z`).getTime();
    const dur = bucket === "hour" ? 3_600_000 : bucket === "day" ? 86_400_000 : 7 * 86_400_000;
    return { start: new Date(startMs).toISOString(), end: new Date(startMs + dur).toISOString() };
  };

  const selectedRange = selection?.kind === "bucket" ? bucketRange(selection.idx) : null;
  const { data: bucketEntries, isLoading: entriesLoading } = useEntityEntriesWindow(
    entityType,
    entityId,
    selectedRange?.start,
    selectedRange?.end,
  );

  const bucketNoun = bucket === "hour" ? "hr" : bucket === "day" ? "day" : "wk";

  return (
    <div className={styles.timelineSection}>
      <div className={styles.timelineHead}>
        <span className={styles.timelineTitle}>Mentions</span>
        {n > 0 && total > 0 && (
          <span className={styles.timelineMeta}>
            <b>{total}</b> article{total === 1 ? "" : "s"}
            {(data?.total_feeds ?? 0) > 0 && (
              <>
                {" "}
                · <b>{data!.total_feeds}</b> feed{data!.total_feeds === 1 ? "" : "s"}
              </>
            )}{" "}
            · peak <b>{Math.max(...counts, 0)}</b>/{bucketNoun}
          </span>
        )}
        <div className={styles.rangeGroup}>
          {MENTIONS_WINDOWS.map((w) => (
            <button
              key={w}
              className={`${styles.rangeBtn} ${w === window ? styles.rangeBtnActive : ""}`}
              onClick={() => onWindowChange(w)}
            >
              {WINDOW_LABELS[w]}
            </button>
          ))}
        </div>
        {onCollapse && (
          <button className={styles.pulseCtl} onClick={onCollapse} title="Collapse to the pulse line">
            <svg width="9" height="9" viewBox="0 0 10 10" aria-hidden>
              <path
                d="M9 4 L6 4 L6 1 M6 4 L9.5 0.5 M1 6 L4 6 L4 9 M4 6 L0.5 9.5"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.3"
                strokeLinecap="round"
              />
            </svg>
            Collapse
          </button>
        )}
      </div>

      {n < 2 || total === 0 ? (
        <div className={styles.timelineEmpty}>
          {isLoading ? "Loading…" : "No mentions in this window"}
        </div>
      ) : (
        <>
          <div
            className={styles.chartWrap}
            onMouseMove={handleMove}
            onMouseLeave={() => setHoverIdx(null)}
            onClick={handleChartClick}
          >
            <svg
              className={styles.chartSvg}
              viewBox={`0 0 ${VW} ${VH}`}
              preserveAspectRatio="none"
              role="img"
              aria-label={`Mentions over the last ${WINDOW_LABELS[window]}: ${total} total, peak ${max} per ${bucketNoun}`}
            >
              <defs>
                <linearGradient id="mentionsAreaFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0" stopColor={accent} stopOpacity="0.26" />
                  <stop offset="1" stopColor={accent} stopOpacity="0" />
                </linearGradient>
              </defs>
              {[0.25, 0.5, 0.75].map((f) => (
                <line
                  key={f}
                  x1={0}
                  y1={TOP_PAD + (VH - TOP_PAD) * f}
                  x2={VW}
                  y2={TOP_PAD + (VH - TOP_PAD) * f}
                  className={styles.chartGrid}
                  vectorEffect="non-scaling-stroke"
                />
              ))}
              <line x1={0} y1={VH} x2={VW} y2={VH} className={styles.chartBaseline} vectorEffect="non-scaling-stroke" />
              {asBars ? (
                counts.map((c, i) =>
                  c > 0 ? (
                    <rect
                      key={i}
                      x={Math.min(Math.max(x(i) - barW / 2, 0), VW - barW)}
                      y={y(c)}
                      width={barW}
                      height={VH - y(c)}
                      fill={accent}
                      opacity={hoverIdx === i ? 1 : 0.75}
                    />
                  ) : null,
                )
              ) : (
                <>
                  <path d={areaPath} fill="url(#mentionsAreaFill)" />
                  <path
                    d={linePath}
                    fill="none"
                    stroke={accent}
                    strokeWidth={2}
                    strokeLinejoin="round"
                    vectorEffect="non-scaling-stroke"
                  />
                </>
              )}
            </svg>

            {/* HTML overlay: crosshair, endpoint, event markers — undistorted */}
            {hoverIdx != null && markerHover == null && (
              <>
                <div className={styles.chartCrosshair} style={{ left: `${x(hoverIdx)}%` }} />
                {!asBars && (
                  <div
                    className={styles.chartHoverDot}
                    style={{
                      left: `${x(hoverIdx)}%`,
                      top: `${y(counts[hoverIdx])}%`,
                      borderColor: accent,
                    }}
                  />
                )}
                <div
                  className={styles.chartTooltip}
                  style={{ left: `${Math.min(Math.max(x(hoverIdx), 8), 92)}%` }}
                >
                  {bucketLabel(points[hoverIdx].date, bucket, spansYears)} · <b>{counts[hoverIdx]}</b>{" "}
                  mention{counts[hoverIdx] === 1 ? "" : "s"}
                  {points[hoverIdx].feeds > 0 && <> · {points[hoverIdx].feeds} feed{points[hoverIdx].feeds === 1 ? "" : "s"}</>}
                  {counts[hoverIdx] > 0 && <span className={styles.tooltipHint}> · click to read</span>}
                </div>
              </>
            )}
            {selection?.kind === "bucket" && (
              <div className={styles.chartSelectLine} style={{ left: `${x(selection.idx)}%` }} />
            )}
            {!asBars && (
              <div
                className={styles.chartEndDot}
                style={{ top: `${y(counts[n - 1])}%`, background: accent }}
              />
            )}
            {peakIdx != null && (
              <div
                className={styles.chartPeakMarker}
                style={{ left: `${x(peakIdx)}%`, top: `${y(counts[peakIdx])}%` }}
                title={`Coverage peak — ${counts[peakIdx]} article${counts[peakIdx] === 1 ? "" : "s"}/${bucketNoun}${
                  points[peakIdx].feeds > 0 ? ` across ${points[peakIdx].feeds} feeds` : ""
                } · ${bucketLabel(points[peakIdx].date, bucket, spansYears)}`}
              >
                ▲
              </div>
            )}
            {markerClusters.map((cluster, i) => (
              <button
                key={i}
                className={styles.chartEventMarker}
                style={{
                  left: `${cluster.left}%`,
                  background:
                    EVENT_COLORS[
                      (cluster.events.find((e) => e.event_type === "story") ?? cluster.events[0]).event_type!
                    ] || "var(--text-muted)",
                }}
                onMouseEnter={() => setMarkerHover(i)}
                onMouseLeave={() => setMarkerHover(null)}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelection((s) => (s?.kind === "cluster" && s.idx === i ? null : { kind: "cluster", idx: i }));
                }}
                aria-label={`${cluster.events.length} event${cluster.events.length === 1 ? "" : "s"}`}
              >
                {cluster.events.length > 1 ? cluster.events.length : ""}
              </button>
            ))}
            {markerHover != null && markerClusters[markerHover] && (
              <div
                className={styles.markerTooltip}
                style={{ left: `${Math.min(Math.max(markerClusters[markerHover].left, 14), 86)}%` }}
              >
                {markerClusters[markerHover].events.slice(0, 4).map((e, j) => (
                  <div key={j} className={styles.markerTooltipRow}>
                    <span
                      className={styles.eventLegendDot}
                      style={{ background: EVENT_COLORS[e.event_type!] || "var(--text-muted)" }}
                    />
                    <span className={styles.markerTooltipText}>
                      {e.date ? `${bucketLabel(e.date, "day", spansYears)} — ` : ""}
                      {e.title.length > 70 ? `${e.title.slice(0, 70)}…` : e.title}
                    </span>
                  </div>
                ))}
                {markerClusters[markerHover].events.length > 4 && (
                  <div className={styles.markerTooltipMore}>
                    +{markerClusters[markerHover].events.length - 4} more
                  </div>
                )}
              </div>
            )}
          </div>
          <div className={styles.chartXLabels}>
            {(() => {
              const slots = Math.min(7, n);
              const idxs = [...new Set(
                Array.from({ length: slots }, (_, i) => Math.round((i * (n - 1)) / (slots - 1))),
              )];
              return idxs.map((idx, i) => (
                <span key={idx}>
                  {bucketLabel(
                    points[idx].date,
                    bucket,
                    spansYears,
                    bucket === "hour" && (i === 0 || i === idxs.length - 1),
                  )}
                </span>
              ));
            })()}
          </div>

          {selection && (
            <div className={styles.bucketPanel}>
              <div className={styles.bucketPanelHead}>
                <span className={styles.bucketPanelTitle}>
                  {selection.kind === "bucket"
                    ? `${bucketLabel(points[selection.idx]?.date ?? "", bucket, true)} · ${counts[selection.idx] ?? 0} mention${(counts[selection.idx] ?? 0) === 1 ? "" : "s"}`
                    : `${markerClusters[selection.idx]?.events.length ?? 0} event${(markerClusters[selection.idx]?.events.length ?? 0) === 1 ? "" : "s"}`}
                </span>
                <button className={styles.bucketPanelClose} onClick={() => setSelection(null)} aria-label="Close">
                  ×
                </button>
              </div>
              {selection.kind === "bucket" ? (
                entriesLoading ? (
                  <div className={styles.bucketPanelEmpty}>Loading…</div>
                ) : bucketEntries && bucketEntries.length > 0 ? (
                  bucketEntries.map((item) => (
                    <button
                      key={item.entry_id}
                      className={styles.bucketPanelRow}
                      onClick={() => onOpenArticle?.(item.entry_id)}
                    >
                      <span className={styles.bucketPanelRowTitle}>{item.title}</span>
                      <span className={styles.bucketPanelRowSrc}>
                        {item.feed_title}
                        {item.published_at
                          ? ` · ${new Date(item.published_at).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}`
                          : ""}
                      </span>
                    </button>
                  ))
                ) : (
                  <div className={styles.bucketPanelEmpty}>No articles in this bucket</div>
                )
              ) : (
                markerClusters[selection.idx]?.events.map((e, j) => (
                  <button
                    key={j}
                    className={styles.bucketPanelRow}
                    disabled={!e.entry_id && !e.nav_context?.entity_id && !e.thread_slug}
                    onClick={() => {
                      // Article first — see ActivityFeed.renderEventRow: an
                      // event with an entry opens in the docked reader rather
                      // than leaving the profile for the feed's thread reader.
                      if (e.entry_id) onOpenArticle?.(e.entry_id);
                      else if (e.thread_slug) onOpenStory?.(e.thread_slug);
                      else if (e.nav_context?.entity_id && e.nav_context.entity_type)
                        onOpenEntity?.(e.nav_context.entity_type as EntityType, e.nav_context.entity_id);
                    }}
                  >
                    <span
                      className={styles.eventLegendDot}
                      style={{ background: EVENT_COLORS[e.event_type!] || "var(--text-muted)" }}
                    />
                    <span className={styles.bucketPanelRowTitle}>
                      {e.date ? `${bucketLabel(e.date, "day", true)} — ` : ""}
                      {e.title}
                    </span>
                  </button>
                ))
              )}
            </div>
          )}

          {(markerClusters.length > 0 || peakIdx != null) && (
            <div className={styles.eventLegend}>
              {/* Class key, not an event list — the markers themselves carry
                  the details (hover a dot; click for the full cluster). */}
              <span className={styles.eventLegendItem}>
                <span className={styles.eventLegendSwatch} style={{ background: accent }} />
                articles
              </span>
              {hasMilestoneMarkers && (
                <span className={styles.eventLegendItem}>
                  <span className={styles.eventLegendDot} style={{ background: EVENT_COLORS.relationship || "var(--text-muted)" }} />
                  milestones
                </span>
              )}
              {hasStoryMarkers && (
                <span className={styles.eventLegendItem}>
                  <span className={styles.eventLegendDot} style={{ background: EVENT_COLORS.story || "var(--text-muted)" }} />
                  stories
                </span>
              )}
              {peakIdx != null && (
                <span className={styles.eventLegendItem}>
                  <span className={styles.eventLegendPeak}>▲</span>
                  coverage peak
                </span>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
