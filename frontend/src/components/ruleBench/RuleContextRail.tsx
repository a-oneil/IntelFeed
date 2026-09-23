import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useIntelStore } from "@/stores/intelStore";
import type { DetectionRule, FeasibilityResult } from "@/api/types";
import type { RelatedRules, RuleFreshIntel } from "@/hooks/useDetectionRules";
import { useEntryTTPs } from "@/hooks/useIntelligence";
import { formatDateTime } from "@/utils/formatDate";
import bench from "./bench.module.css";
import styles from "./RuleContextRail.module.css";

const RULE_TYPE_SHORT: Record<string, string> = {
  sigma: "sigma",
  splunk_spl: "spl",
  kql: "kql",
  elastic_ql: "eql",
  crowdstrike_ql: "cql",
  snort_suricata: "snort",
  yara: "yara",
  nuclei: "nuclei",
  panther: "panther",
};

interface RuleContextRailProps {
  rule?: DetectionRule;
  freshIntel?: RuleFreshIntel;
  related?: RelatedRules;
  feasibility: FeasibilityResult | null;
  onDiff: (ruleId: string) => void;
}

/**
 * Right column: why the rule exists, what has landed since, whether the fields
 * are actually collected, and what already covers the same ground. Every card
 * is an endpoint that used to render inside a collapsed tab.
 */
export function RuleContextRail({ rule, freshIntel, related, feasibility, onDiff }: RuleContextRailProps) {
  const navigate = useNavigate();
  const { data: entryTtps } = useEntryTTPs(rule?.entry_id || undefined);

  // The quote is the entry_ttps match text for a technique this rule claims —
  // the sentence that caused the rule, not the article's first paragraph.
  // Autolinked rows store a marker (`auto_link:T1059.001`) rather than prose,
  // so anything without a space in it is a token, not a quote.
  const quote = useMemo(() => {
    if (!entryTtps?.length) return null;
    const isProse = (t: string | null | undefined) => !!t && t.trim().length > 24 && /\s/.test(t.trim());
    const claimed = new Set((rule?.source_ttps as string[] | undefined) ?? []);
    const hit =
      entryTtps.find((t) => claimed.has(t.technique_id) && isProse(t.source_text)) ??
      entryTtps.find((t) => isProse(t.source_text));
    return hit?.source_text ? { text: hit.source_text, technique: hit.technique_id } : null;
  }, [entryTtps, rule?.source_ttps]);

  const telemetry = rule?.telemetry;
  const telemetryRows = telemetry?.required.length
    ? telemetry.required.map((t) => ({ name: t, have: telemetry.collected.includes(t) }))
    : feasibility
      ? [
          ...feasibility.feasible.map((t) => ({ name: t, have: true })),
          ...feasibility.missing.map((t) => ({ name: t, have: false })),
        ]
      : [];

  const nearDupes = related?.near_duplicate ?? [];
  const otherRelated = related
    ? [...related.other_format, ...related.same_cve, ...related.same_technique]
    : [];

  return (
    <>
      {(rule?.entry_id || quote) && (
        <>
          <div className={bench.railLabel}>Why this rule exists</div>
          <div className={bench.card}>
            {rule?.entry_id && (
              <a
                className={`${bench.cardHead} ${styles.articleLink}`}
                href={`/?entry=${rule.entry_id}`}
                onClick={(e) => {
                  e.preventDefault();
                  useIntelStore.getState().openWorkbenchReader(rule.entry_id!);
                }}
              >
                {rule.entry_title || "View source article"}
              </a>
            )}
            {quote && (
              <div className={bench.cardBody}>
                <blockquote className={styles.quote}>
                  {quote.text}
                  <cite>{quote.technique}</cite>
                </blockquote>
              </div>
            )}
          </div>
        </>
      )}

      {freshIntel && freshIntel.total > 0 && (
        <>
          <div className={bench.railLabel}>
            Fresh intel<b>{freshIntel.total} new</b>
          </div>
          <div className={bench.card}>
            <div className={bench.cardBody}>
              {freshIntel.items.slice(0, 5).map((e) => (
                <a
                  key={e.id}
                  className={styles.freshItem}
                  href={`/?entry=${e.id}`}
                  onClick={(ev) => {
                    ev.preventDefault();
                    useIntelStore.getState().openWorkbenchReader(e.id);
                  }}
                >
                  <span className={styles.freshDate}>{e.published_at ? formatDateTime(e.published_at) : "—"}</span>
                  <span className={styles.freshTitle}>{e.title}</span>
                </a>
              ))}
            </div>
          </div>
        </>
      )}

      {telemetryRows.length > 0 && (
        <>
          <div className={bench.railLabel}>
            Fields vs inventory
            <b>
              {telemetryRows.filter((r) => r.have).length}/{telemetryRows.length} collected
            </b>
          </div>
          <div className={bench.card}>
            <div className={bench.cardBody}>
              {telemetryRows.map((r) => (
                <div key={r.name} className={bench.kv}>
                  <span>{r.name}</span>
                  <span className={`${bench.kvStatus} ${r.have ? bench.ok : bench.warn}`}>
                    {r.have ? "collected" : "missing"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {(nearDupes.length > 0 || otherRelated.length > 0) && (
        <>
          <div className={bench.railLabel}>
            Near-duplicates{nearDupes.length > 0 && <b>{nearDupes.length}</b>}
          </div>
          {nearDupes.slice(0, 3).map((r) => (
            <div key={r.id} className={bench.card}>
              <div className={bench.cardHead}>{r.title}</div>
              <div className={bench.cardBody}>
                <div className={bench.kv}>
                  <span>{RULE_TYPE_SHORT[r.rule_type] || r.rule_type}</span>
                  {r.similarity != null && (
                    <span className={bench.kvStatus}>{Math.round(r.similarity * 100)}% similar</span>
                  )}
                </div>
              </div>
              <div className={bench.cardFoot}>
                <button type="button" className={bench.btn} onClick={() => onDiff(r.id)}>Diff</button>
                <button type="button" className={bench.btn} onClick={() => navigate(`/workbench/rule/${r.id}`)}>Open</button>
              </div>
            </div>
          ))}
          {otherRelated.length > 0 && (
            <div className={bench.card}>
              <div className={bench.cardBody}>
                {otherRelated.slice(0, 6).map((r) => (
                  <button
                    key={r.id}
                    type="button"
                    className={styles.relatedRow}
                    onClick={() => navigate(`/workbench/rule/${r.id}`)}
                  >
                    <span className={styles.relatedTitle}>{r.title}</span>
                    <span className={styles.relatedMeta}>{RULE_TYPE_SHORT[r.rule_type] || r.rule_type}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
}
