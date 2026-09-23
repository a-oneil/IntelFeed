// ATT&CK matrix view — shared types and pure helpers (heat ramp + Navigator
// layer export). Kept out of the component so they can be unit tested.

export type AttackDomain = "enterprise" | "mobile" | "ics";
export type MatrixLayerMode = "heat" | "coverage" | "combined";
export type CoverageStatus = "covered" | "library_only" | "no_rule";

export interface MatrixTechnique {
  id: string;
  technique_id: string;
  name: string;
  article_count: number;
  rule_count: number;
  has_rule: boolean;
  coverage: CoverageStatus;
  deployable: boolean;
  missing_data_sources: string[];
  is_deprecated: boolean;
  subtechniques?: MatrixTechnique[];
  rollup_article_count?: number;
}

export interface MatrixTactic {
  id: string;
  name: string;
  techniques: MatrixTechnique[];
}

export interface AttackMatrixData {
  domain: AttackDomain;
  days: number | null;
  generated_at: string;
  technique_count: number;
  max_article_count: number;
  coverage_summary: {
    total: number;
    covered: number;
    library_only: number;
    no_rule: number;
    coverage_percentage: number;
  };
  tactics: MatrixTactic[];
}

/**
 * Heat opacity for a cell (0 when unseen). Square-root ramp so low-volume
 * techniques stay visible next to the handful of very hot ones.
 */
export function heatAlpha(count: number, max: number): number {
  if (count <= 0 || max <= 0) return 0;
  return Math.min(1, 0.15 + 0.75 * Math.sqrt(count / max));
}

export interface NavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: string;
  description: string;
  gradient: { colors: string[]; minValue: number; maxValue: number };
  techniques: Array<{
    techniqueID: string;
    tactic: string;
    score: number;
    comment: string;
    metadata: Array<{ name: string; value: string }>;
  }>;
}

const COVERAGE_LABELS: Record<CoverageStatus, string> = {
  covered: "rule with telemetry available",
  library_only: "rule blocked by missing telemetry",
  no_rule: "no rule",
};

/**
 * Build an ATT&CK Navigator layer from matrix data (same shape as the
 * campaign attack-layer export; score = article count within the window).
 */
export function buildNavigatorLayer(matrix: AttackMatrixData): NavigatorLayer {
  const windowLabel = matrix.days ? `last ${matrix.days} days` : "all time";
  const techniques: NavigatorLayer["techniques"] = [];

  const pushCell = (tactic: string, t: MatrixTechnique) => {
    techniques.push({
      techniqueID: t.technique_id,
      tactic,
      score: t.article_count,
      comment: `${t.article_count} article${t.article_count === 1 ? "" : "s"} (${windowLabel}); ${t.rule_count} rule${t.rule_count === 1 ? "" : "s"} — ${COVERAGE_LABELS[t.coverage]}`,
      metadata: [
        { name: "articles", value: String(t.article_count) },
        { name: "rules", value: String(t.rule_count) },
        { name: "coverage", value: t.coverage },
      ],
    });
  };

  for (const tactic of matrix.tactics) {
    for (const tech of tactic.techniques) {
      pushCell(tactic.id, tech);
      for (const sub of tech.subtechniques ?? []) pushCell(tactic.id, sub);
    }
  }

  return {
    name: `IntelFeed - ATT&CK Matrix (${matrix.domain}, ${windowLabel})`,
    versions: { attack: "15", navigator: "4.9.5", layer: "4.5" },
    domain: `${matrix.domain}-attack`,
    description: `Feed frequency and detection coverage across ${matrix.technique_count} techniques (${windowLabel})`,
    gradient: {
      colors: ["#ffffff", "#ff6666"],
      minValue: 0,
      maxValue: Math.max(1, matrix.max_article_count),
    },
    techniques,
  };
}
