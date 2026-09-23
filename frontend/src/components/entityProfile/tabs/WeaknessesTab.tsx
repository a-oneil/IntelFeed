/**
 * WeaknessesTab — how NVD classified this CVE, and how good that classification is.
 *
 * One section per weakness assignment, and deliberately only three things in it:
 * the weakness itself (the heading, linked), what it means (its description),
 * and where it sits on the abstraction ladder (one breadcrumb line).
 *
 * Everything else is a chip on the heading. MITRE's mapping guidance was a
 * full-width banner and read as an alert, which it isn't — it is a qualifier on
 * the classification, so it belongs on the line the classification is stated.
 * Sibling weaknesses and an "open the profile" row were cut outright: the
 * heading is already the link, and neighbours are a question the CWE profile
 * answers, not one a reader of a single CVE is asking.
 */
import { Link } from "react-router-dom";
import { Chip } from "@/components/primitives";
import { useCVEWeaknesses, useCWEFamily } from "@/hooks/useIntelligence";
import type { CVEWeaknessRow } from "@/api/types";
import { AsyncStateLoading } from "@/components/AsyncState";
import { entityProfilePath } from "../entityProfileConfig";
import styles from "../entityProfile.module.css";

/** Why MITRE's guidance matters for an assignment that isn't plain "Allowed". */
const MAPPING_NOTES: Record<string, string> = {
  Prohibited:
    "MITRE marks this a prohibited mapping target — categories and retired entries were never meant to be assigned to a CVE.",
  Discouraged:
    "MITRE discourages this id: it sits high on the abstraction ladder, so the classification is imprecise rather than wrong.",
  "Allowed-with-Review":
    "MITRE allows this id but asks for review — a more specific weakness may fit better.",
};

function WeaknessSection({ row }: { row: CVEWeaknessRow }) {
  // Only fetch a family for refs that resolved — the sentinels have none.
  const { data: family } = useCWEFamily(row.cwe_id ?? undefined);
  const note = row.mapping_usage ? MAPPING_NOTES[row.mapping_usage] : undefined;

  if (!row.cwe_id) {
    return (
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          {row.cwe_ref === "NVD-CWE-noinfo" ? "Unclassified by NVD" : "Classified as Other by NVD"}
        </div>
        <div className={styles.description}>
          NVD recorded <span className={styles.mono}>{row.cwe_ref}</span> instead of a weakness. The
          vulnerability is real; the classification is missing.
        </div>
      </div>
    );
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <Link className={styles.familyLink} to={entityProfilePath("cwe", row.cwe_id)}>
          <span className={styles.mono}>{row.cwe_ref}</span> {row.name}
        </Link>
        <span
          className={styles.sectionCount}
          title={row.assigner ? `Assigned by ${row.assigner}` : undefined}
        >
          {[row.is_primary ? "primary" : "secondary", row.abstraction, row.kind === "category" ? "category" : null]
            .filter(Boolean)
            .join(" · ")}
        </span>
        {note && (
          <Chip tone="toned" tint="var(--warning)" title={note}>
            {row.mapping_usage}
          </Chip>
        )}
      </div>

      {row.description && <div className={styles.description}>{row.description}</div>}

      {family && family.lineage.length > 0 && (
        <div className={styles.tagRow}>
          {/* The ladder reads as a path, not as rows — root-first, ending on
              this weakness, which is where the reader already is. */}
          <span className={styles.metaLabel}>Ladder</span>
          {family.lineage.map((a) => (
            <span key={a.cwe_id}>
              <Link className={styles.familyLink} to={a.id ? entityProfilePath("cwe", a.id) : "#"} title={a.name}>
                <span className={styles.mono}>{a.cwe_id}</span>
              </Link>
              <span className={styles.metaLabel}> › </span>
            </span>
          ))}
          <span className={styles.mono}>{row.cwe_ref}</span>
        </div>
      )}

    </div>
  );
}

export function WeaknessesTab({ entityId }: { entityId: string }) {
  const { data: rows, isLoading } = useCVEWeaknesses(entityId);

  if (isLoading) {
    return (
      <div className={styles.tabPanel}>
        <AsyncStateLoading label="Loading weaknesses…" />
      </div>
    );
  }

  if (!rows || rows.length === 0) {
    return (
      <div className={styles.tabPanel}>
        <div className={styles.section}>
          <div className={styles.sectionHeader}>Weaknesses</div>
          <div className={styles.emptySection}>
            NVD has published no weakness data for this CVE. It arrives with the NVD enrichment pass, so a
            very new CVE is often blank here for a day or two.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.tabPanel}>
      {rows.map((r) => (
        <WeaknessSection key={r.cwe_ref} row={r} />
      ))}
    </div>
  );
}
