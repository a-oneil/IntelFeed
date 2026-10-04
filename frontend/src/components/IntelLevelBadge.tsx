import styles from "./IntelLevelBadge.module.css";

/**
 * How much of the extraction pipeline a feed actually runs, as a fill level.
 *
 * This used to be a five-way enum — full / selective / known_only / manual /
 * none — derived from `intel_extraction_mode` + `auto_extract_on_ingest`. Two
 * of those names described a pipeline that stopped existing: "known entities
 * only" claimed nothing new would be created and "manual" claimed nothing ran
 * automatically, while the one-pass AI read both and minted entities from
 * them. The Pipeline pane in the edit modal was rebuilt around the real
 * switches; this is the same model, compressed to a rail.
 *
 * Three per-feed stages can be on, so the rail has four states: empty (the
 * feed is processed but every extraction stage is off), a third, two thirds,
 * and full. A feed with `intel_extraction_mode = "none"` renders nothing.
 */
export interface IntelLevelInput {
  mode: string;
  /** `ai_analysis_enabled` — whether the one-pass AI reads this feed. */
  aiAnalysis?: boolean;
  /** `auto_extract_on_ingest` — the NVD/CVE lookup pass. */
  autoExtract?: boolean;
}

interface Props extends IntelLevelInput {
  size?: "sm" | "md";
}

export interface IntelLevel {
  /** 0–1, or -1 when the feed is out of the intel system entirely. */
  fill: number;
  label: string;
  /** Which stages are running, for the tooltip. */
  stages: string[];
}

export function deriveIntelLevel({
  mode,
  aiAnalysis = true,
  autoExtract = false,
}: IntelLevelInput): IntelLevel {
  if (mode === "none") {
    return { fill: -1, label: "", stages: [] };
  }

  const stages: string[] = [];
  // "manual" is the one mode that turns autolinking off; the rest leave it on.
  if (mode !== "manual") {
    stages.push(mode === "selective" ? "autolinks relevant articles" : "autolinks everything");
  }
  if (aiAnalysis) stages.push("AI analysis");
  if (autoExtract) stages.push("NVD lookups");

  const label = stages.length
    ? `Extraction: ${stages.join(", ")}`
    : "Processed, but no extraction stage is on";

  return { fill: stages.length / 3, label, stages };
}

/** Extraction intensity as a small vertical fill bar. */
export function IntelLevelBadge({ mode, aiAnalysis, autoExtract, size = "sm" }: Props) {
  const level = deriveIntelLevel({ mode, aiAnalysis, autoExtract });
  if (level.fill < 0) return null;

  return (
    <span
      className={`${styles.rail} ${level.fill === 1 ? styles.full : ""} ${
        level.fill === 0 ? styles.empty : ""
      } ${size === "md" ? styles.md : ""}`}
      data-tooltip={level.label}
      role="img"
      aria-label={level.label}
    >
      {level.fill > 0 && (
        <span className={styles.fill} style={{ height: `${level.fill * 100}%` }} />
      )}
    </span>
  );
}
