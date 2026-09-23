/**
 * DetectionGapsTab — prioritized punch-list of this entity's techniques with
 * NO covering detection rule. DetectionTab already shows the full
 * covered/library-only/gap breakdown; this tab is deliberately narrower — just
 * the actionable gaps, ready to generate a rule for, for a detection engineer
 * triaging "what should I build next".
 */
import { useState } from "react";
import { toast } from "sonner";
import type { EntityType } from "@/stores/intelStore";
import { useEntityDetectionGaps } from "@/hooks/useEntityProfile";
import { useGenerateEntityRules } from "@/hooks/useIntelligence";
import styles from "../entityProfile.module.css";

const DEFAULT_RULE_TYPES = ["sigma", "splunk_spl"];

export function DetectionGapsTab({
  entityType,
  entityId,
  onOpenEntity,
}: {
  entityType: EntityType;
  entityId: string;
  onOpenEntity: (type: EntityType, id: string, label: string) => void;
}) {
  const { data: gaps, isLoading } = useEntityDetectionGaps(entityType, entityId);
  const generateRules = useGenerateEntityRules();
  const [generatingFor, setGeneratingFor] = useState("");

  const handleGenerate = (technique: { ttp_id: string; technique_id: string }) => {
    if (generateRules.isPending) return;
    setGeneratingFor(technique.ttp_id);
    generateRules.mutate(
      { entityType: "ttp", entityId: technique.ttp_id, ruleTypes: DEFAULT_RULE_TYPES },
      {
        onSuccess: (created) => {
          if (created.length > 0) {
            toast.success(`Generated ${created.length} draft rule${created.length === 1 ? "" : "s"} for ${technique.technique_id}`);
          } else {
            toast.info(`No new rules generated for ${technique.technique_id}`);
          }
        },
        onError: () => toast.error("Rule generation failed"),
        onSettled: () => setGeneratingFor(""),
      },
    );
  };

  if (isLoading) return <div className={styles.tabPanel}>Loading…</div>;

  if (!gaps || gaps.total_ttps === 0) {
    return (
      <div className={styles.tabPanel}>
        <div className={styles.emptySection}>No ATT&CK techniques mapped to this entity yet.</div>
      </div>
    );
  }

  if (gaps.gaps.length === 0) {
    return (
      <div className={styles.tabPanel}>
        <div className={styles.statGrid}>
          <span className={styles.statChip}>
            <span className={styles.statDot} style={{ background: "#38a169" }} />
            {gaps.covered_count}/{gaps.total_ttps} covered ({gaps.coverage_percentage}%)
          </span>
        </div>
        <div className={styles.emptySection}>
          No gaps — every technique either has a satisfiable rule or is library-only (see Detection tab).
        </div>
      </div>
    );
  }

  return (
    <div className={styles.tabPanel}>
      <div className={styles.statGrid}>
        <span className={styles.statChip}>
          <span className={styles.statDot} style={{ background: "#e53e3e" }} />
          {gaps.gaps.length} gap{gaps.gaps.length === 1 ? "" : "s"}
        </span>
        <span className={styles.statChip}>
          {gaps.covered_count}/{gaps.total_ttps} covered ({gaps.coverage_percentage}%)
        </span>
      </div>

      <div className={styles.covTrack}>
        <div className={styles.covSegCovered} style={{ width: `${(gaps.covered_count / gaps.total_ttps) * 100}%` }} />
        <div className={styles.covSegLibrary} style={{ width: `${(gaps.library_only_count / gaps.total_ttps) * 100}%` }} />
        <div className={styles.covSegGap} style={{ width: `${(gaps.no_rule_count / gaps.total_ttps) * 100}%` }} />
      </div>

      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          No detection rule <span className={styles.sectionCount}>{gaps.gaps.length}</span>
        </div>
        {gaps.gaps.map((g) => (
          <div key={g.ttp_id} className={styles.covRow}>
            <button
              className={styles.ttpBadge}
              title={g.technique_name}
              onClick={() => onOpenEntity("ttp", g.ttp_id, g.technique_id)}
            >
              {g.technique_id}
              {g.technique_name && <span className={styles.ttpName}>{g.technique_name}</span>}
            </button>
            <span className={styles.covRowActions}>
              <button
                className={styles.ctaBtnMini}
                disabled={generateRules.isPending}
                onClick={() => handleGenerate(g)}
              >
                {generateRules.isPending && generatingFor === g.ttp_id ? "Generating…" : "Generate rule"}
              </button>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
