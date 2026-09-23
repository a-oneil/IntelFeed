import { useMemo } from "react";
import type { DetectionRule } from "@/api/types";
import { formatDateTime } from "@/utils/formatDate";
import { parseRuleOutline } from "./ruleOutline";
import bench from "./bench.module.css";
import styles from "./RuleStructureRail.module.css";

interface RuleStructureRailProps {
  ruleContent: string;
  ruleType: string;
  rule?: DetectionRule;
  activeLine: number | null;
  onSelectLine: (line: number) => void;
}

/** Left column: the rule's own outline, plus where the rule came from. */
export function RuleStructureRail({
  ruleContent,
  ruleType,
  rule,
  activeLine,
  onSelectLine,
}: RuleStructureRailProps) {
  const outline = useMemo(() => parseRuleOutline(ruleContent, ruleType), [ruleContent, ruleType]);
  const hasAttribution = !!(rule?.source_repo || rule?.license || rule?.upstream_updated_at || rule?.source_author);

  return (
    <>
      <div className={bench.railLabel}>
        Structure
        {outline.length > 0 && <b>{outline.length}</b>}
      </div>
      {outline.length === 0 ? (
        <div className={bench.empty}>No outline for this format.</div>
      ) : (
        <nav className={styles.outline} aria-label="Rule structure">
          {outline.map((node) => (
            <button
              key={node.id}
              type="button"
              className={`${styles.node} ${activeLine === node.line ? styles.nodeActive : ""}`}
              onClick={() => onSelectLine(node.line)}
              title={`Line ${node.line}`}
            >
              <span className={node.depth === 1 ? styles.indent : undefined}>{node.label}</span>
              {node.count != null && <em>{node.count}</em>}
            </button>
          ))}
        </nav>
      )}

      {hasAttribution && (
        <>
          <div className={bench.railLabel}>Attribution</div>
          <div className={bench.card}>
            <div className={bench.cardBody}>
              {rule?.source_repo && (
                <div className={bench.kv}>
                  <span>{rule.source_repo}</span>
                  {rule.license && <span className={`${bench.kvStatus} ${bench.ok}`}>{rule.license}</span>}
                </div>
              )}
              {!rule?.source_repo && rule?.license && (
                <div className={bench.kv}>
                  <span>licence</span>
                  <span className={`${bench.kvStatus} ${bench.ok}`}>{rule.license}</span>
                </div>
              )}
              {rule?.source_author && (
                <div className={bench.kv}>
                  <span>{rule.source_author}</span>
                </div>
              )}
              {rule?.upstream_updated_at && (
                <div className={bench.kv}>
                  <span>upstream {formatDateTime(rule.upstream_updated_at)}</span>
                </div>
              )}
              {rule?.is_authored_local && (
                <div className={`${bench.kv} ${bench.accent}`}>
                  <span>authored here</span>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </>
  );
}
