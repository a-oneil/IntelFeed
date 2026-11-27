import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import type { DetectionRule } from "@/api/types";
import type { CommitTimeline } from "@/hooks/useDetectionRules";
import { formatDateTime } from "@/utils/formatDate";
import { parseRuleOutline } from "./ruleOutline";
import bench from "./bench.module.css";
import styles from "./RuleStructureRail.module.css";

interface RuleStructureRailProps {
  ruleContent: string;
  ruleType: string;
  rule?: DetectionRule;
  commitTimeline?: CommitTimeline;
  activeLine: number | null;
  onSelectLine: (line: number) => void;
}

/** Left column: the rule's own outline, where the rule came from, and what it is about. Provenance is read-only, so it sits beside attribution rather than in the Details tab. */
export function RuleStructureRail({
  ruleContent,
  ruleType,
  rule,
  commitTimeline,
  activeLine,
  onSelectLine,
}: RuleStructureRailProps) {
  const navigate = useNavigate();
  const outline = useMemo(() => parseRuleOutline(ruleContent, ruleType), [ruleContent, ruleType]);
  const hasAttribution = !!(rule?.source_repo || rule?.license || rule?.upstream_updated_at || rule?.source_author);

  const techniques = ((rule?.source_ttps as string[] | undefined) ?? []).filter(Boolean);
  const cve = (rule?.source_cves as string[] | undefined)?.[0];
  const affected = (rule?.source_products as string[] | undefined)?.[0];
  const latestCommit = commitTimeline?.commits?.[0];
  const references = rule?.references ?? [];

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
                  <span>license</span>
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

      {rule && (
        <>
          <div className={bench.railLabel}>Provenance</div>
          <div className={bench.card}>
            <div className={bench.cardBody}>
              <dl className={styles.dl}>
                {techniques.length > 0 && (
                  <>
                    <dt>Technique</dt>
                    <dd>
                      {techniques.slice(0, 4).map((t, i) => (
                        <span key={t}>
                          {i > 0 && " "}
                          <button type="button" className={styles.link} onClick={() => navigate(`/workbench/ttp/${t}`)}>
                            {t}
                          </button>
                        </span>
                      ))}
                      {techniques.length > 4 && <span className={styles.more}> +{techniques.length - 4}</span>}
                    </dd>
                  </>
                )}
                {cve && (
                  <>
                    <dt>CVE</dt>
                    <dd>
                      <button type="button" className={styles.link} onClick={() => navigate(`/workbench/cve/${cve}`)}>
                        {cve}
                      </button>
                    </dd>
                  </>
                )}
                {affected && (
                  <>
                    <dt>Affected</dt>
                    <dd>{affected}</dd>
                  </>
                )}
                <dt>Created</dt>
                <dd>{formatDateTime(rule.created_at)}</dd>
                <dt>Updated</dt>
                <dd>{formatDateTime(rule.updated_at)}</dd>
                {latestCommit && (
                  <>
                    <dt>Commit</dt>
                    <dd>
                      {latestCommit.url ? (
                        <a className={styles.link} href={latestCommit.url} target="_blank" rel="noopener noreferrer">
                          {latestCommit.short_sha}
                        </a>
                      ) : (
                        latestCommit.short_sha
                      )}
                      {commitTimeline?.owner && commitTimeline?.repo && (
                        <span className={styles.more}> {commitTimeline.owner}/{commitTimeline.repo}</span>
                      )}
                    </dd>
                  </>
                )}
              </dl>
              {references.length > 0 && (
                <div className={styles.refs}>
                  {references.map((r) => (
                    <a key={r} className={styles.ref} href={r} target="_blank" rel="noopener noreferrer" title={r}>
                      ↗ {r.replace(/^https?:\/\//, "")}
                    </a>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </>
  );
}
