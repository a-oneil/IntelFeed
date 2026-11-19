import SimpleTagEditor from "@/components/SimpleTagEditor";
import bench from "./bench.module.css";
import styles from "./RuleDetailsForm.module.css";

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

export interface RuleFormValues {
  severity: string;
  description: string;
  tags: string[];
  mitreTactics: string[];
  dataSources: string[];
  notes: string;
}

interface RuleDetailsFormProps {
  values: RuleFormValues;
  onChange: <K extends keyof RuleFormValues>(key: K, value: RuleFormValues[K]) => void;
  /** Fields the metadata extractor read out of the rule body, when it found any. */
  mappedFields: Record<string, unknown> | null;
  onAutoFill: () => void;
}

/**
 * The Details tab: the four fields you type into. Severity lives in the
 * headline row, telemetry in the right rail's "Fields vs inventory" card and
 * provenance in the left rail, so nothing here repeats what the page already
 * shows. Status, level, log source and ATT&CK ids are in the rule body in the
 * editor above; "Auto-fill" is how they get into these fields.
 */
export function RuleDetailsForm({ values, onChange, mappedFields, onAutoFill }: RuleDetailsFormProps) {
  const canAutoFill = !!mappedFields && Object.keys(mappedFields).length > 0;

  return (
    <div className={styles.root}>
      <div className={bench.railLabel}>
        Fields
        {canAutoFill && (
          <b>
            <button
              type="button"
              className={bench.btn}
              onClick={onAutoFill}
              title="Reads status, level, log source, tactics and ATT&CK ids out of the rule body and fills the fields below"
            >
              Auto-fill from rule body
            </button>
          </b>
        )}
      </div>

      <div className={styles.grid}>
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
          <span className={styles.label}>Tags</span>
          <SimpleTagEditor tags={values.tags} onChange={(t) => onChange("tags", t)} />
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

        <div className={styles.field}>
          <span className={styles.label}>MITRE tactics</span>
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
      </div>
    </div>
  );
}
