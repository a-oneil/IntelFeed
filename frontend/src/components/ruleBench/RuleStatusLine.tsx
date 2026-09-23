import type { RuleValidationResult } from "@/api/types";
import bench from "./bench.module.css";
import styles from "./RuleStatusLine.module.css";

interface RuleStatusLineProps {
  validation: RuleValidationResult | null;
  ruleTypeLabel: string;
  /** Fields the rule needs vs fields the inventory actually collects. */
  telemetry: { required: number; collected: number } | null;
  nearDupeCount: number;
  freshIntelCount: number;
  issuesOpen: boolean;
  onToggleIssues: () => void;
}

/**
 * One line, four facts, no gates. Syntax validation reports here and nowhere
 * else — it never blocks a save, because a rule the analyst is mid-thought on
 * is supposed to be invalid.
 */
export function RuleStatusLine({
  validation,
  ruleTypeLabel,
  telemetry,
  nearDupeCount,
  freshIntelCount,
  issuesOpen,
  onToggleIssues,
}: RuleStatusLineProps) {
  const errors = validation?.errors.filter((e) => e.severity === "error").length ?? 0;
  const warnings = validation?.errors.filter((e) => e.severity !== "error").length ?? 0;
  const issueCount = errors + warnings + (validation?.suggestions.length ?? 0);

  return (
    <div className={styles.line}>
      <button
        type="button"
        className={styles.item}
        onClick={onToggleIssues}
        disabled={issueCount === 0}
        aria-expanded={issuesOpen}
      >
        <b>{ruleTypeLabel}</b>{" "}
        {!validation ? (
          "not checked"
        ) : errors > 0 ? (
          <span className={bench.bad}>{errors} error{errors !== 1 ? "s" : ""}</span>
        ) : warnings > 0 ? (
          <span className={bench.warn}>{warnings} warning{warnings !== 1 ? "s" : ""}</span>
        ) : (
          "parses"
        )}
      </button>
      {telemetry && telemetry.required > 0 && (
        <span className={styles.item}>
          {telemetry.required} field{telemetry.required !== 1 ? "s" : ""} ·{" "}
          <b className={telemetry.collected === telemetry.required ? bench.ok : bench.warn}>
            {telemetry.collected} collected
          </b>
        </span>
      )}
      {nearDupeCount > 0 && (
        <span className={styles.item}>
          {nearDupeCount} near-duplicate{nearDupeCount !== 1 ? "s" : ""}
        </span>
      )}
      {freshIntelCount > 0 && (
        <span className={`${styles.item} ${bench.accent}`}>
          {freshIntelCount} new article{freshIntelCount !== 1 ? "s" : ""} since last save
        </span>
      )}
    </div>
  );
}
