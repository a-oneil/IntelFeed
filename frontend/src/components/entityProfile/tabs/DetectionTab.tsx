/**
 * DetectionTab — one question, one answer.
 *
 * For anything the coverage workspace understands (actors, malware, CVEs,
 * techniques, campaigns) this tab is the workspace: a verdict sentence, a
 * ladder of behaviours ordered by what to do next, and folded provenance. The
 * old Build|Coverage segmented pair is gone — they were two designs answering
 * the same question, and the ladder answers it once.
 *
 * A CWE has no extracted behaviours to build a workspace from, so it keeps the
 * plain list it always had: the rules that cover it, and the way into the
 * library to find more.
 */
import { Link } from "react-router-dom";
import { toast } from "sonner";
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult, PivotResponse } from "@/api/types";
import { useGenerateEntityRules } from "@/hooks/useIntelligence";
import { WORKSPACE_TYPES } from "@/hooks/useCoverageWorkspace";
import { CoverageWorkspace } from "@/components/coverageWorkspace";
import { useState } from "react";
import styles from "../entityProfile.module.css";

/** Entity types the entity-scoped generation endpoint supports. */
const GENERATABLE_TYPES = ["threat_actor", "malware", "cve", "ttp"] as const;
type GeneratableType = (typeof GENERATABLE_TYPES)[number];

/** A guard rather than a Set membership test, so the narrowing survives to the
 * call: the generation endpoint is typed to the extraction types, and a
 * campaign — which nothing extracts — is not one of them. */
function isGeneratable(type: EntityType): type is GeneratableType {
  return (GENERATABLE_TYPES as readonly string[]).includes(type);
}

/** Default formats — mirrors the entry intel panel's "Gen Rules" action. */
const DEFAULT_RULE_TYPES = ["sigma", "splunk_spl"];

function libraryPath(query: string): string {
  return `/workbench/explore?section=rules&rules_q=${encodeURIComponent(query)}`;
}

export function DetectionTab({
  entityType,
  entityId,
  entity,
  related,
  onNavigateRule,
}: {
  entityType: EntityType;
  entityId: string;
  entity: EntitySearchResult;
  related: PivotResponse["related"];
  onNavigateRule: (ruleId: string) => void;
}) {
  const searchTerm = entity.cve_id || entity.technique_id || entity.name || "";

  if (WORKSPACE_TYPES.has(entityType)) {
    return (
      <div className={styles.tabPanel}>
        <CoverageWorkspace
          entityType={entityType}
          entityKey={entityId}
          label={entity.name || searchTerm}
          onNavigateRule={onNavigateRule}
        />
      </div>
    );
  }

  return (
    <RuleListFallback
      entityType={entityType}
      entityId={entityId}
      searchTerm={searchTerm}
      related={related}
      onNavigateRule={onNavigateRule}
    />
  );
}

/** The no-workspace face. A CWE has covering rules but no extracted behaviours,
    so there is no coverage to judge — only a list and a way to add to it. */
function RuleListFallback({
  entityType,
  entityId,
  searchTerm,
  related,
  onNavigateRule,
}: {
  entityType: EntityType;
  entityId: string;
  searchTerm: string;
  related: PivotResponse["related"];
  onNavigateRule: (ruleId: string) => void;
}) {
  const rules = related.detection_rules || [];
  const generateRules = useGenerateEntityRules();
  const [generating, setGenerating] = useState(false);

  const handleGenerate = (targetType: GeneratableType) => {
    if (generateRules.isPending) return;
    setGenerating(true);
    generateRules.mutate(
      { entityType: targetType, entityId, ruleTypes: DEFAULT_RULE_TYPES },
      {
        onSuccess: (created) => {
          if (created.length > 0) {
            toast.success(`Generated ${created.length} draft rule${created.length === 1 ? "" : "s"}`);
          } else {
            toast.info("No new rules generated — matching rules may already exist");
          }
        },
        onError: (err) => {
          const detail = (err as { response?: { data?: { detail?: { message?: string } | string } } })?.response?.data
            ?.detail;
          toast.error((typeof detail === "string" ? detail : detail?.message) || "Rule generation failed");
        },
        onSettled: () => setGenerating(false),
      }
    );
  };

  return (
    <div className={styles.tabPanel}>
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          Detection Rules <span className={styles.sectionCount}>{rules.length}</span>
        </div>
        {rules.length > 0 ? (
          <div className={styles.entityList}>
            {rules.map((rule) => (
              <div key={rule.id} className={styles.entityItem}>
                <button className={styles.entityItemInner} onClick={() => onNavigateRule(rule.id)}>
                  <span className={styles.entityBadge}>{rule.rule_type}</span>
                  <span className={styles.entityLabel}>{rule.title}</span>
                  {rule.severity && <span className={styles.entityMeta}>{rule.severity}</span>}
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className={styles.emptySection}>No detection rules cover this entity yet</div>
        )}
        <div className={styles.ctaRow}>
          {isGeneratable(entityType) && (
            <button
              className={styles.ctaBtn}
              disabled={generateRules.isPending}
              onClick={() => handleGenerate(entityType)}
            >
              {generating ? "Generating…" : "Generate rule"}
            </button>
          )}
          {searchTerm && (
            <Link
              className={styles.ctaBtnSecondary}
              to={libraryPath(searchTerm)}
              title={`Search the rules library for "${searchTerm}"`}
            >
              Search library
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}
