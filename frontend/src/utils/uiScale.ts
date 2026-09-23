/**
 * Interface scale.
 *
 * `--ui-scale` in index.css multiplies every geometry token (type, spacing,
 * control heights, layout widths), so CSS scales on its own. A handful of
 * sizes live in JS instead — fixed virtualizer row heights, which have to be
 * numbers because the virtualizer does translateY math with them — and those
 * would stay pinned at their 1.0 values while the text inside them grew.
 * Run those through `scalePx()`.
 */

let cached: number | null = null;

/**
 * The live `--ui-scale`, or 1 outside a browser / if the token is missing.
 * Cached after the first read: the token is authored, not toggled at runtime,
 * and callers sit on render paths where a forced style read would cost.
 */
export function getUiScale(): number {
  if (cached !== null) return cached;
  if (typeof window === "undefined") return 1;
  const raw = getComputedStyle(document.documentElement).getPropertyValue("--ui-scale");
  const n = Number.parseFloat(raw);
  cached = Number.isFinite(n) && n > 0 ? n : 1;
  return cached;
}

/** Scale a px length authored at 1.0, rounded to a whole pixel. */
export function scalePx(px: number): number {
  return Math.round(px * getUiScale());
}
