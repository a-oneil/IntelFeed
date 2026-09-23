import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useDetectionRule } from "@/hooks/useIntelligence";
import { AsyncStateLoading } from "@/components/AsyncState";
import { lineDiff } from "./lineDiff";
import { DiffView } from "./DiffView";
import bench from "./bench.module.css";
import styles from "./RuleCompare.module.css";

interface RuleCompareProps {
  otherRuleId: string;
  currentContent: string;
}

/** Diff this rule against a near-duplicate. No endpoint — the bodies are short. */
export function RuleCompare({ otherRuleId, currentContent }: RuleCompareProps) {
  const navigate = useNavigate();
  const { data: other, isLoading } = useDetectionRule(otherRuleId);
  const lines = useMemo(
    () => (other ? lineDiff(other.rule_content, currentContent) : []),
    [other, currentContent],
  );

  if (isLoading) return <AsyncStateLoading label="Loading rule…" />;
  if (!other) return <div className={bench.empty}>That rule is no longer available.</div>;

  const changed = lines.filter((l) => l.op !== "same").length;

  return (
    <>
      <div className={bench.railLabel}>
        {other.title}
        <b>{changed} differing line{changed !== 1 ? "s" : ""}</b>
      </div>
      <div className={styles.legend}>
        <span className={styles.theirs}>− {other.rule_type}{other.source_repo ? ` · ${other.source_repo}` : ""}</span>
        <span className={styles.mine}>+ this rule</span>
        <button type="button" className={bench.btn} onClick={() => navigate(`/workbench/rule/${other.id}`)}>
          Open that rule
        </button>
      </div>
      <DiffView lines={lines} />
    </>
  );
}
