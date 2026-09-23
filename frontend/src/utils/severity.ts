/**
 * One source of truth for severity chip colours.
 *
 * Five widgets had independently-written versions of this and they disagreed:
 * three used white on every fill (failing WCAG AA on `high` at 2.26:1 and
 * `low` at 2.54:1), and one used `--text-secondary` on every fill, which fails
 * on all four between 1.21:1 and 1.57:1 — grey text on saturated orange.
 *
 * The paired `--severity-*-fg` tokens are measured against their fills; use
 * this helper rather than picking a foreground at the call site.
 */
export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export interface SeverityChipColors {
  tint?: string;
  fg?: string;
}

const LEVELS: Record<SeverityLevel, SeverityChipColors> = {
  critical: { tint: "var(--severity-critical)", fg: "var(--severity-critical-fg)" },
  high: { tint: "var(--severity-high)", fg: "var(--severity-high-fg)" },
  medium: { tint: "var(--severity-medium)", fg: "var(--severity-medium-fg)" },
  low: { tint: "var(--severity-low)", fg: "var(--severity-low-fg)" },
  info: { tint: "var(--severity-info)", fg: "var(--severity-info-fg)" },
};

/** Colours for a named severity. Unknown/null returns `{}` (neutral chip). */
export function severityChipColors(level: string | null | undefined): SeverityChipColors {
  if (!level) return {};
  return LEVELS[level.toLowerCase() as SeverityLevel] ?? {};
}

/** Colours for a CVSS base score, using the standard NVD bands. */
export function cvssChipColors(score: number | string | null | undefined): SeverityChipColors {
  const n = typeof score === "string" ? Number.parseFloat(score) : score;
  if (n == null || Number.isNaN(n)) return {};
  if (n >= 9.0) return LEVELS.critical;
  if (n >= 7.0) return LEVELS.high;
  if (n >= 4.0) return LEVELS.medium;
  return LEVELS.low;
}
