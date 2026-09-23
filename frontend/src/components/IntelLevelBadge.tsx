import styles from "./IntelLevelBadge.module.css";

export type IntelLevel = "full" | "selective" | "known_only" | "manual" | "none";

interface Props {
  mode: string;
  autoExtract: boolean;
  size?: "sm" | "md";
}

// Extraction intensity as a fill fraction: empty (manual) → quarter (known-only)
// → half (selective) → solid (full). "none" isn't shown. Rendered as a small
// vertical fill bar — the same waterline metaphor as the sidebar's level rail.
export const INTEL_LEVEL_CONFIG: Record<IntelLevel, { fill: number; label: string; className: string }> = {
  full: { fill: 1, label: "Full — extract all intelligence automatically", className: "full" },
  selective: { fill: 0.5, label: "Selective — security-relevant articles only", className: "selective" },
  known_only: { fill: 0.25, label: "Known entities only — match against existing database", className: "knownOnly" },
  manual: { fill: 0, label: "Manual — only when triggered", className: "manual" },
  none: { fill: -1, label: "", className: "" },
};

export function deriveIntelLevel(mode: string, autoExtract: boolean): IntelLevel {
  if (mode === "none") return "none";
  if (mode === "manual") return "manual";
  if (mode === "full" && autoExtract) return "full";
  if (mode === "selective" && autoExtract) return "selective";
  if ((mode === "full" || mode === "selective") && !autoExtract) return "known_only";
  return "selective";
}

export function IntelLevelBadge({ mode, autoExtract, size = "sm" }: Props) {
  const level = deriveIntelLevel(mode, autoExtract);
  if (level === "none") return null;

  const { fill, label } = INTEL_LEVEL_CONFIG[level];

  return (
    <span
      className={`${styles.rail} ${level === "full" ? styles.full : ""} ${fill === 0 ? styles.empty : ""} ${size === "md" ? styles.md : ""}`}
      data-tooltip={label}
      role="img"
      aria-label={label}
    >
      {fill > 0 && <span className={styles.fill} style={{ height: `${fill * 100}%` }} />}
    </span>
  );
}
