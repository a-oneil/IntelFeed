import { useNavigate } from "react-router-dom";
import type { DetectionRule, FeasibilityResult } from "@/api/types";
import type { CommitTimeline } from "@/hooks/useDetectionRules";
import SimpleTagEditor from "@/components/SimpleTagEditor";
import DataSourcePicker from "@/components/DataSourcePicker";
import { formatDateTime } from "@/utils/formatDate";
import styles from "./RuleDetailsForm.module.css";

const SEVERITY_OPTIONS = ["informational", "low", "medium", "high", "critical"];
// Hyphenated to match what the backend stores — these are ATT&CK's own slugs
// (`kill_chain_phases.phase_name`), the same ones `TTP.tactic` holds. An
// underscored copy here would leave every chip unselected on rules that use
// them, and saving would appear to do nothing once the API folded the spelling
// back. `stealth` and `defense-impairment` are the v18 split of defense-evasion,
// which is kept for rules written before it.
const TACTIC_OPTIONS = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "stealth",
  "defense-impairment", "credential-access", "discovery", "lateral-movement",
  "collection", "command-and-control", "exfiltration", "impact",
];

const META_DISPLAY_KEYS: Record<string, string> = {
  rule_author: "Author",
  rule_date: "Date",
  rule_modified: "Modified",
  rule_status: "Status",
  rule_level: "Level",
  rule_severity: "Severity",
  rule_name: "Name",
  rule_reference: "Reference",
  detection_name: "Detection",
  detection_type: "Type",
  template_author: "Author",
  template_severity: "Severity",
  template_id: "Template ID",
  mitre_attack_ids: "ATT&CK IDs",
  mitre_tactics: "Tactics",
  false_positives: "False Positives",
  analytic_stories: "Analytic Stories",
  log_source: "Log Source",
  log_types: "Log Types",
  rule_tags: "YARA Tags",
  rule_risk_score: "Risk Score",
  rule_index: "Indices",
  required_data_connectors: "Data Connectors",
  data_models: "Data Models",
  cvss_score: "CVSS Score",
  cve_ids: "CVEs",
};

// Duplicates rule_content or is internal bookkeeping — never worth a row.
const META_HIDDEN_KEYS = new Set([
  "search_query", "rule_query", "commit_history", "file_path", "owner", "repo",
  "commit_sha", "commit_author", "commit_message", "commit_date", "change_type",
  "content_subtype", "has_title_function", "ai_chat_history", "rule_conversions",
]);

export interface RuleFormValues {
  severity: string;
  description: string;
  tags: string[];
  mitreTactics: string[];
  dataSources: string[];
  notes: string;
}

interface RuleDetailsFormProps {
  rule?: DetectionRule;
  values: RuleFormValues;
  onChange: <K extends keyof RuleFormValues>(key: K, value: RuleFormValues[K]) => void;
  extractedMeta: Record<string, unknown> | null;
  extracting: boolean;
  mappedFields: Record<string, unknown> | null;
  onAutoFill: () => void;
  feasibility: FeasibilityResult | null;
  commitTimeline?: CommitTimeline;
}

/** The former Details tab, now the slide-over's default pane. */
export function RuleDetailsForm({
  rule,
  values,
  onChange,
  extractedMeta,
  extracting,
  mappedFields,
  onAutoFill,
  feasibility,
  commitTimeline,
}: RuleDetailsFormProps) {
  const navigate = useNavigate();

  const renderMetaValue = (key: string, value: unknown): React.ReactNode => {
    if (key === "mitre_attack_ids" && Array.isArray(value) && value.length > 0) {
      return value.map((tid, i) => (
        <span key={String(tid)}>
          {i > 0 && ", "}
          <button className={styles.metaLink} onClick={() => navigate(`/workbench/ttp/${tid}`)} type="button">
            {String(tid)}
          </button>
        </span>
      ));
    }
    if (Array.isArray(value)) return value.join(", ");
    if (typeof value === "object" && value !== null) {
      return Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v)
        .map(([k, v]) => `${k}: ${v}`)
        .join(", ");
    }
    return String(value || "");
  };

  const metaRows = Object.entries(extractedMeta || {}).filter(([k, v]) => {
    if (v === "" || v === null || v === undefined) return false;
    if (Array.isArray(v) && v.length === 0) return false;
    if (typeof v === "object" && !Array.isArray(v) && Object.values(v as Record<string, unknown>).every((x) => !x)) return false;
    return !META_HIDDEN_KEYS.has(k);
  });

  const classification = rule
    ? [
        ["Technique", (rule.source_ttps as string[] | undefined)?.[0], "ttp"],
        ["CVE", (rule.source_cves as string[] | undefined)?.[0], "cve"],
        ["Affected", (rule.source_products as string[] | undefined)?.[0], null],
      ].filter((row) => row[1])
    : [];

  const hasProvenance =
    classification.length > 0 ||
    metaRows.length > 0 ||
    (rule?.references?.length ?? 0) > 0 ||
    (commitTimeline?.commits.length ?? 0) > 0 ||
    !!rule;

  return (
    <div className={styles.root}>
      {/* ── Authoring: the fields that define what this rule is ── */}
      <section className={styles.group}>
        <div className={styles.groupHead}>Authoring</div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="rule-severity">Severity</label>
          <div className={styles.sevRow}>
            <select
              id="rule-severity"
              className={styles.select}
              value={values.severity}
              onChange={(e) => onChange("severity", e.target.value)}
            >
              <option value="">None</option>
              {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            {values.severity && (
              <span className={styles.sevDot} data-sev={values.severity} aria-hidden="true" />
            )}
          </div>
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="rule-description">Description</label>
          <textarea
            id="rule-description"
            className={styles.textarea}
            value={values.description}
            onChange={(e) => onChange("description", e.target.value)}
            rows={3}
            placeholder="What this rule detects…"
          />
        </div>

        <div className={styles.field}>
          <label className={styles.label}>Tags</label>
          <SimpleTagEditor tags={values.tags} onChange={(t) => onChange("tags", t)} />
        </div>

        <div className={styles.field}>
          <label className={styles.label}>MITRE Tactics</label>
          <div className={styles.tacticGrid}>
            {TACTIC_OPTIONS.map((t) => (
              <button
                key={t}
                type="button"
                className={`${styles.tacticChip} ${values.mitreTactics.includes(t) ? styles.tacticActive : ""}`}
                aria-pressed={values.mitreTactics.includes(t)}
                onClick={() =>
                  onChange(
                    "mitreTactics",
                    values.mitreTactics.includes(t)
                      ? values.mitreTactics.filter((x) => x !== t)
                      : [...values.mitreTactics, t],
                  )
                }
              >
                {t.replace(/-/g, " ")}
              </button>
            ))}
          </div>
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="rule-notes">Analyst notes</label>
          <textarea
            id="rule-notes"
            className={styles.textarea}
            value={values.notes}
            onChange={(e) => onChange("notes", e.target.value)}
            rows={3}
            placeholder="Anything the next reader should know…"
          />
        </div>
      </section>

      {/* ── Telemetry: what this rule needs, against what's collected ── */}
      <section className={styles.group}>
        <div className={styles.groupHead}>
          Telemetry
          {feasibility && (
            <span
              className={styles.groupBadge}
              style={{
                color: feasibility.coverage_pct >= 0.8 ? "var(--success)"
                  : feasibility.coverage_pct >= 0.5 ? "var(--warning)" : "var(--danger)",
              }}
            >
              {Math.round(feasibility.coverage_pct * 100)}% collected
            </span>
          )}
        </div>
        <div className={styles.field}>
          <DataSourcePicker value={values.dataSources} onChange={(ds) => onChange("dataSources", ds)} />
          {feasibility && feasibility.missing.length > 0 && (
            <div className={styles.missing}>Missing: {feasibility.missing.join(", ")}</div>
          )}
        </div>
      </section>

      {/* ── Provenance: read-only, where this rule came from ── */}
      {hasProvenance && (
        <section className={`${styles.group} ${styles.provenance}`}>
          <div className={styles.groupHead}>Provenance</div>

          {(classification.length > 0 || rule) && (
            <dl className={styles.defList}>
              {classification.map(([label, value, kind]) => (
                <div key={label as string} className={styles.defRow}>
                  <dt>{label as string}</dt>
                  <dd>
                    {kind ? (
                      <button
                        type="button"
                        className={styles.metaLink}
                        onClick={() => navigate(`/workbench/${kind}/${value}`)}
                      >
                        {value as string}
                      </button>
                    ) : (
                      (value as string)
                    )}
                  </dd>
                </div>
              ))}
              {rule && (
                <>
                  <div className={styles.defRow}>
                    <dt>Created</dt>
                    <dd>{formatDateTime(rule.created_at)}</dd>
                  </div>
                  <div className={styles.defRow}>
                    <dt>Updated</dt>
                    <dd>{formatDateTime(rule.updated_at)}</dd>
                  </div>
                </>
              )}
            </dl>
          )}

          {rule?.references && rule.references.length > 0 && (
            <div className={styles.field}>
              <span className={styles.subLabel}>References</span>
              <div className={styles.refList}>
                {rule.references.map((r) => (
                  <a key={r} className={styles.refLink} href={r} target="_blank" rel="noopener noreferrer">
                    ↗ {r.replace(/^https?:\/\//, "")}
                  </a>
                ))}
              </div>
            </div>
          )}

          {metaRows.length > 0 && (
            <div className={styles.field}>
              <span className={styles.subLabel}>
                Extracted metadata
                {extracting && <span className={styles.extracting}> · extracting…</span>}
              </span>
              <div className={styles.metaTable}>
                {metaRows.map(([key, value]) => (
                  <div key={key} className={styles.metaRow}>
                    <span className={styles.metaKey}>{META_DISPLAY_KEYS[key] || key.replace(/_/g, " ")}</span>
                    <span className={styles.metaValue}>{renderMetaValue(key, value)}</span>
                  </div>
                ))}
              </div>
              {mappedFields && Object.keys(mappedFields).length > 0 && (
                <button type="button" className={styles.autoFill} onClick={onAutoFill}>
                  Auto-fill fields from content
                </button>
              )}
            </div>
          )}

      {commitTimeline && commitTimeline.commits.length > 0 && (
        <div className={styles.field}>
          <span className={styles.subLabel}>
            Commit history
            {commitTimeline.file_path && <span className={styles.filePath}> · {commitTimeline.file_path}</span>}
          </span>
          <div className={styles.commits}>
            {commitTimeline.commits.map((commit, idx) => (
              <div key={commit.sha || idx} className={styles.commit}>
                <div className={styles.commitDot} />
                {idx < commitTimeline.commits.length - 1 && <div className={styles.commitLine} />}
                <div className={styles.commitHead}>
                  <span className={styles.commitType}>{commit.change_type}</span>
                  {commit.url ? (
                    <a href={commit.url} target="_blank" rel="noopener noreferrer" className={styles.commitSha}>
                      {commit.short_sha}
                    </a>
                  ) : (
                    <span className={styles.commitSha}>{commit.short_sha}</span>
                  )}
                  {commit.date && <span className={styles.commitDate}>{formatDateTime(commit.date)}</span>}
                </div>
                {commit.message && <div className={styles.commitMessage}>{commit.message.split("\n")[0]}</div>}
                <div className={styles.commitAuthor}>{commit.author}</div>
              </div>
            ))}
          </div>
          {commitTimeline.owner && commitTimeline.repo && (
            <a
              className={styles.refLink}
              href={`https://github.com/${commitTimeline.owner}/${commitTimeline.repo}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              {commitTimeline.owner}/{commitTimeline.repo}
            </a>
          )}
        </div>
      )}
        </section>
      )}
    </div>
  );
}
