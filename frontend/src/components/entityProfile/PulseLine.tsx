/**
 * PulseLine — the header's collapsed activity readout: a bare sparkline plus
 * one quiet line of type (totals, trend vs the prior window, coverage quality)
 * with the window picker and an Expand control that unfolds the full
 * MentionsTimeline in place. No cards, no chrome — it reads like a vital sign
 * under the entity name.
 */
import { useMemo } from "react";
import {
  MENTIONS_WINDOWS,
  useEntityMentionsTimeseries,
  type MentionsWindow,
} from "@/hooks/useEntityProfile";
import { getEntityColor } from "@/utils/entityTheme";
import type { EntityType } from "@/stores/intelStore";
import styles from "./entityProfile.module.css";

const WINDOW_LABELS: Record<MentionsWindow, string> = {
  "24h": "24H",
  "7d": "7D",
  "30d": "30D",
  "60d": "60D",
  "90d": "90D",
  all: "ALL",
};

const SPARK_W = 300;
const SPARK_H = 30;

export function PulseLine({
  entityType,
  entityId,
  window,
  onWindowChange,
  onExpand,
}: {
  entityType: EntityType;
  entityId: string;
  window: MentionsWindow;
  onWindowChange: (w: MentionsWindow) => void;
  onExpand: () => void;
}) {
  const { data } = useEntityMentionsTimeseries(entityType, entityId, window);
  const accent = getEntityColor(entityType);

  const points = useMemo(() => data?.points ?? [], [data]);
  const counts = points.map((p) => p.count);
  const total = counts.reduce((a, b) => a + b, 0);
  const max = Math.max(...counts, 1);
  const n = points.length;
  const bucketNoun = data?.bucket === "hour" ? "hr" : data?.bucket === "day" ? "day" : "wk";

  // Trend vs the immediately-prior window. Suppressed for "all" (no prior
  // window exists) and when both windows are empty.
  const prev = data?.previous_total ?? null;
  const trend = useMemo(() => {
    if (prev == null || (prev === 0 && total === 0)) return null;
    if (prev === 0) return { dir: "up" as const, label: "new this window" };
    const pct = Math.round(((total - prev) / prev) * 100);
    if (pct === 0) return null;
    return {
      dir: pct > 0 ? ("up" as const) : ("down" as const),
      label: `${Math.abs(pct) > 999 ? ">999" : Math.abs(pct)}% vs prior ${WINDOW_LABELS[window].toLowerCase()}`,
    };
  }, [prev, total, window]);

  // Coverage quality: breadth of independent feeds vs one outlet echoing.
  const feeds = data?.total_feeds ?? 0;
  const echoShare = data?.top_feed_share ?? null;
  const quality = useMemo(() => {
    if (total === 0 || feeds === 0) return null;
    // One outlet dominating outranks raw feed count — 48 feeds where one
    // carries 73% of mentions is an echo chamber, not broad coverage.
    if (echoShare != null && echoShare >= 0.6 && total >= 4)
      return {
        tone: "warn" as const,
        label: `echo-heavy · one outlet is ${Math.round(echoShare * 100)}%`,
      };
    if (feeds >= 10) return { tone: "good" as const, label: `broad coverage · ${feeds} independent feeds` };
    return { tone: "flat" as const, label: `${feeds} feed${feeds === 1 ? "" : "s"}` };
  }, [total, feeds, echoShare]);

  const barW = n > 0 ? Math.max((SPARK_W / n) * 0.62, 1.2) : 2;

  return (
    <div className={styles.pulseLine}>
      <svg
        className={styles.pulseSpark}
        width={SPARK_W}
        height={SPARK_H}
        viewBox={`0 0 ${SPARK_W} ${SPARK_H}`}
        role="img"
        aria-label={`Mentions sparkline, last ${WINDOW_LABELS[window]}: ${total} articles`}
        onClick={onExpand}
      >
        <line x1={0} y1={SPARK_H - 0.5} x2={SPARK_W} y2={SPARK_H - 0.5} className={styles.pulseSparkBase} />
        {counts.map((c, i) =>
          c > 0 ? (
            <rect
              key={i}
              x={n > 1 ? (i / (n - 1)) * (SPARK_W - barW) : 0}
              y={SPARK_H - (c / max) * (SPARK_H - 2)}
              width={barW}
              height={(c / max) * (SPARK_H - 2)}
              rx={1}
              fill={accent}
              opacity={0.5 + 0.5 * (n > 1 ? i / (n - 1) : 1)}
            />
          ) : null,
        )}
      </svg>

      {total > 0 ? (
        <span className={styles.pulseStats}>
          <b>{total}</b> article{total === 1 ? "" : "s"}
          {feeds > 0 && (
            <>
              {" "}· <b>{feeds}</b> feed{feeds === 1 ? "" : "s"}
            </>
          )}{" "}
          · peak <b>{Math.max(...counts, 0)}</b>/{bucketNoun}
        </span>
      ) : (
        <span className={styles.pulseStats}>No mentions in this window</span>
      )}

      {trend && (
        <span className={trend.dir === "up" ? styles.pulseDeltaUp : styles.pulseDeltaDown}>
          {trend.dir === "up" ? "▲" : "▼"} {trend.label}
        </span>
      )}

      {quality && (
        <span
          className={styles.pulseQuality}
          title="Coverage quality: independent feeds carrying this vs one outlet echoing"
        >
          <span
            className={styles.pulseQualityDot}
            data-tone={quality.tone}
          />
          {quality.label}
        </span>
      )}

      <span className={styles.pulseCtls}>
        <select
          className={styles.pulseSelect}
          value={window}
          onChange={(e) => onWindowChange(e.target.value as MentionsWindow)}
          aria-label="Mentions window"
        >
          {MENTIONS_WINDOWS.map((w) => (
            <option key={w} value={w}>
              {WINDOW_LABELS[w]}
            </option>
          ))}
        </select>
        <button className={styles.pulseCtl} onClick={onExpand} title="Expand the full timeline">
          <svg width="9" height="9" viewBox="0 0 10 10" aria-hidden>
            <path
              d="M6 1 L9 1 L9 4 M9 1 L5.5 4.5 M4 9 L1 9 L1 6 M1 9 L4.5 5.5"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.3"
              strokeLinecap="round"
            />
          </svg>
          Expand
        </button>
      </span>
    </div>
  );
}
