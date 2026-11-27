import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useIntelStore } from "@/stores/intelStore";
import type { DetectionRule, FeasibilityResult } from "@/api/types";
import type { RelatedRules, RuleFreshIntel } from "@/hooks/useDetectionRules";
import { useEntryTTPs } from "@/hooks/useIntelligence";
import DataSourcePicker from "@/components/DataSourcePicker";
import { TelemetrySourceDrawer } from "@/components/telemetry/TelemetrySourceDrawer";
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
  yaral: "yara-l",
  aql: "aql",
  sumo: "sumo",
  sql: "sql",
};

interface RuleContextRailProps {
  rule?: DetectionRule;
  freshIntel?: RuleFreshIntel;
  related?: RelatedRules;
  feasibility: FeasibilityResult | null;
  /** The rule's declared data sources, editable in place. */
  dataSources: string[];
  onDataSourcesChange?: (value: string[]) => void;
  onDiff: (ruleId: string) => void;
}

/** Right column: why the rule exists, what new intel has arrived since, whether the fields are actually collected, and which rules already cover the same ground. The telemetry card is also where data sources are edited, the only place the page shows them. */
export function RuleContextRail({
  rule,
  freshIntel,
  related,
  feasibility,
  dataSources,
  onDataSourcesChange,
  onDiff,
}: RuleContextRailProps) {
  const navigate = useNavigate();
  const { data: entryTtps } = useEntryTTPs(rule?.entry_id || undefined);
  const [editingSources, setEditingSources] = useState(false);
  const [openSource, setOpenSource] = useState<string | null>(null);

  // The quote is the entry_ttps match text for a technique this rule claims (the sentence that led to the rule, not the article's first paragraph), falling back to any technique's match text. Autolinked rows store a marker (`auto_link:T1059.001`) rather than prose, so only text longer than 24 characters that contains whitespace counts as a quote.
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
  const collected = telemetryRows.filter((r) => r.have).length;
  const coverage = telemetryRows.length ? collected / telemetryRows.length : null;
  const showTelemetry = telemetryRows.length > 0 || !!onDataSourcesChange;

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

      {showTelemetry && (
        <>
          <div className={bench.railLabel}>
            Fields vs inventory
            {telemetryRows.length > 0 && (
              <b>
                {collected}/{telemetryRows.length} collected
              </b>
            )}
          </div>
          <div className={bench.card}>
            {telemetryRows.length > 0 ? (
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
            ) : (
              <div className={bench.cardBody}>
                <span className={styles.noSources}>No data sources declared</span>
              </div>
            )}
            {editingSources && onDataSourcesChange && (
              <div className={bench.cardBody}>
                <DataSourcePicker value={dataSources} onChange={onDataSourcesChange} />
              </div>
            )}
            {onDataSourcesChange && (
              <div className={bench.cardFoot}>
                <button type="button" className={bench.btn} onClick={() => setEditingSources((v) => !v)}>
                  {editingSources ? "Done" : dataSources.length ? "Edit sources" : "+ Add source"}
                </button>
                {coverage !== null && (
                  <span
                    className={`${styles.coverage} ${coverage >= 0.8 ? bench.ok : coverage >= 0.5 ? bench.warn : bench.bad}`}
                  >
                    {Math.round(coverage * 100)}% collected
                  </span>
                )}
              </div>
            )}
          </div>
        </>
      )}

      {telemetry?.sources && telemetry.sources.length > 0 && (
        <>
          <div className={bench.railLabel}>Log sources for this rule</div>
          <div className={bench.card}>
            <div className={bench.cardBody}>
              {telemetry.sources.map((src) => (
                <button
                  key={src.name}
                  type="button"
                  className={styles.sourceRow}
                  onClick={() => setOpenSource(src.name)}
                  title="Notes and links about this source"
                >
                  <span className={styles.sourceName}>{src.name}</span>
                  <span className={styles.sourceMeta}>
                    {src.provides.join(", ")}
                    {src.note_count > 0 && (
                      <b>
                        {" "}
                        · {src.note_count} {src.note_count === 1 ? "note" : "notes"}
                      </b>
                    )}
                  </span>
                </button>
              ))}
            </div>
          </div>
          {openSource && <TelemetrySourceDrawer source={{ name: openSource }} onClose={() => setOpenSource(null)} />}
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
