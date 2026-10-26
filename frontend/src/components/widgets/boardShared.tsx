/**
 * Shared primitives for the board widgets.
 *
 * House style: no chart library — everything is inline SVG or CSS, matching
 * the existing widgets. Series colors come from a CVD-validated ordering
 * checked against the card surface (#161b22); the raw --rgroup-* theme hues
 * fail adjacent-pair colorblind separation when stacked.
 */
import { useCallback, useLayoutEffect, useState } from "react";
import styles from "./widgets.module.css";

/**
 * Pixel width of the element the ref lands on, for an inline-SVG chart.
 *
 * A chart drawn on a fixed viewBox and stretched to `width: 100%` scales its
 * text and height with the card: on a wide board a 10px label renders at 35px
 * and the plot runs taller than the card. Drawing the viewBox at the measured
 * width keeps one SVG unit to one pixel. `fallback` covers the first paint and
 * environments without ResizeObserver.
 */
export function useChartWidth<T extends Element>(fallback: number) {
  const [el, setEl] = useState<T | null>(null);
  const [width, setWidth] = useState(fallback);
  // A callback ref, not useRef: the chart mounts only once data has loaded,
  // after the skeleton, so the element must be able to arrive late.
  const ref = useCallback((node: T | null) => setEl(node), []);
  useLayoutEffect(() => {
    if (!el || typeof ResizeObserver === "undefined") return;
    const measure = () => {
      const w = Math.round(el.getBoundingClientRect().width);
      if (w > 0) setWidth(w);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [el]);
  return [ref, width] as const;
}

/** Categorical series slots, validated for adjacent-pair CVD separation. */
export const SERIES_COLORS = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"];
export const SERIES_OTHER = "#8b94a3";

export function seriesColor(index: number): string {
  return index < SERIES_COLORS.length ? SERIES_COLORS[index] : SERIES_OTHER;
}

/** CSS variable for an entity type's theme color, e.g. "var(--entity-actor)". */
export function entityColorVar(entityType: string): string {
  const slug = entityType === "threat_actor" ? "actor" : entityType;
  return `var(--entity-${slug})`;
}

const ENTITY_LABELS: Record<string, string> = {
  threat_actor: "TAs",
  malware: "Malware",
  tool: "Tools",
  cve: "CVEs",
  ttp: "TTPs",
  vendor: "Vendors",
  product: "Products",
  country: "Countries",
  sector: "Sectors",
};

export function entityLabel(entityType: string): string {
  return ENTITY_LABELS[entityType] ?? entityType.replace(/_/g, " ");
}

/** Signed delta with an arrow. `goodWhenDown` flips the coloring (e.g. unread). */
export function DeltaText({
  value,
  suffix = "",
  goodWhenDown = false,
}: {
  value: number | null | undefined;
  suffix?: string;
  goodWhenDown?: boolean;
}) {
  if (value === null || value === undefined) return null;
  const rounded = Math.round(value * 10) / 10;
  if (rounded === 0) {
    return <span className={styles.deltaFlat}>— no change</span>;
  }
  const up = rounded > 0;
  const good = goodWhenDown ? !up : up;
  return (
    <span className={good ? styles.deltaUp : styles.deltaDown}>
      {up ? "▲" : "▼"} {Math.abs(rounded)}
      {suffix}
    </span>
  );
}

/** Compact sparkline: gray line, accent endpoint dot. */
export function Sparkline({
  points,
  width = 88,
  height = 22,
  color = "var(--text-muted)",
}: {
  points: number[];
  width?: number;
  height?: number;
  color?: string;
}) {
  if (points.length === 0) return null;
  const max = Math.max(...points);
  const min = Math.min(...points);
  const span = max - min || 1;
  const pad = 3;
  const step = points.length > 1 ? width / (points.length - 1) : 0;
  const coords = points.map((v, i) => {
    const x = i * step;
    const y = height - pad - (height - pad * 2) * ((v - min) / span);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const last = coords[coords.length - 1].split(",");
  return (
    <svg
      className={styles.miniSpark}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden="true"
    >
      <polyline
        points={coords.join(" ")}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
      <circle cx={last[0]} cy={last[1]} r="2.6" fill="var(--accent)" stroke="var(--card-bg)" strokeWidth="1.5" />
    </svg>
  );
}

/**
 * Clamp the dashboard's injected `days` into an endpoint's supported band.
 *
 * The global range maps "all" to 36500 and "24h" to 1; day-series endpoints
 * can serve neither (one would build a 100-year grid, the other is below the
 * minimum window). Clamping keeps the widget following the global range
 * without tripping the API's bounds — an out-of-range value 422s and the
 * widget silently falls back to its empty state.
 */
export function clampDays(days: unknown, min: number, max: number): number | undefined {
  if (typeof days !== "number" || Number.isNaN(days)) return undefined;
  return Math.min(max, Math.max(min, Math.round(days)));
}

/** Relative day count, e.g. "62d ago" / "today". */
export function daysAgo(iso: string | null | undefined): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "never";
  const days = Math.floor((Date.now() - then) / 86400000);
  if (days <= 0) return "today";
  if (days === 1) return "1d ago";
  return `${days}d ago`;
}
