/**
 * NextActions — the "Next steps" panel that closes the Overview's brief.
 * Computed, not curated: every line is a signal the backend already emits.
 * Actors and malware lead with their detection coverage (techniques with a
 * rule, with a rule whose log source isn't collected, with none) and the
 * Review gaps / Build hunt package buttons; a KEV CVE leads with its patch
 * deadline and rule count. Under that, one line per remaining job (claims to
 * corroborate, a missing assessment, a campaign's suggestions and standing
 * searches), each with its explanation and a text link. Lines disappear as the
 * work gets done.
 */
import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import api from "@/api/client";
import { formatDate } from "@/utils/formatDate";
import { useEntityDetectionGaps } from "@/hooks/useEntityProfile";
import {
  useAddCampaignEntries,
  useCampaignSavedSearches,
  useCampaignSuggestions,
  useUpdateCampaign,
} from "@/hooks/useCampaigns";
import { groupSuggestions } from "@/utils/campaignSuggestions";
import { daysQuiet, isCampaignQuiet } from "@/utils/campaignActivity";
import { isConfirmed } from "@/utils/relationshipBrowser";
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult, PivotResponse } from "@/api/types";
import styles from "./entityProfile.module.css";

type RelatedEntities = PivotResponse["related"];

const ENTITY_RELATED_KEYS: Array<keyof RelatedEntities> = [
  "threat_actors",
  "malwares",
  "ttps",
  "cves",
  "tools",
  "vendors",
  "products",
  "countrys",
  "sectors",
  "mitigations",
];

/** Types the detection-gaps endpoint serves (mirrors the tabs config). */
const GAPPED_TYPES: EntityType[] = ["threat_actor", "malware"];

const BUNDLE_ENTRY_CAP = 100;

type Tone = "hot" | "warm" | "cool";

interface Action {
  key: string;
  tone: Tone;
  label: string;
  why: ReactNode;
  button?: { label: string; onClick: () => void; disabled?: boolean };
}

export function NextActions({
  entityType,
  entityId,
  entity,
  displayName,
  related,
  entries,
  onShowRelationships,
  onShowDetectionGaps,
  onDraftAssessment,
  draftPending,
}: {
  entityType: EntityType;
  entityId: string;
  entity: EntitySearchResult;
  displayName: string;
  related: RelatedEntities;
  entries: Array<{ id: string; published_at: string | null }>;
  onShowRelationships: () => void;
  onShowDetectionGaps: () => void;
  onDraftAssessment: () => void;
  draftPending: boolean;
}) {
  const hasGaps = GAPPED_TYPES.includes(entityType);
  const { data: gaps } = useEntityDetectionGaps(
    hasGaps ? entityType : undefined,
    hasGaps ? entityId : undefined,
  );
  const [exporting, setExporting] = useState(false);

  // A campaign's next actions are the two tabs it used to carry — Suggestions
  // and Searches — plus the one thing nothing ever told you: that it has gone
  // quiet. All three are work, which is what this row is for.
  const isCampaign = entityType === "campaign";
  const campaignId = isCampaign ? entityId : undefined;
  const { data: campaignSuggestions } = useCampaignSuggestions(campaignId);
  const { data: campaignSearches } = useCampaignSavedSearches(campaignId);
  const addEntries = useAddCampaignEntries();
  const updateCampaign = useUpdateCampaign();

  const topStory = isCampaign
    ? groupSuggestions(campaignSuggestions ?? []).find((g) => g.kind === "story")
    : undefined;
  const syncingSearches = isCampaign ? (campaignSearches ?? []).filter((x) => x.auto_sync) : [];
  const campaignQuiet =
    isCampaign && isCampaignQuiet(entity.status ?? "", entity.last_activity_at)
      ? daysQuiet(entity.last_activity_at)
      : null;

  const unconfirmed = ENTITY_RELATED_KEYS.flatMap(
    (k) => (related[k] as EntitySearchResult[] | undefined) ?? [],
  ).filter((e) => e.relationship_id && !isConfirmed(e));

  const exportBundle = async () => {
    setExporting(true);
    try {
      const entryIds = [...entries]
        .sort((a, b) => (b.published_at || "").localeCompare(a.published_at || ""))
        .slice(0, BUNDLE_ENTRY_CAP)
        .map((e) => e.id);
      const res = await api.post(
        "/export/research-bundle",
        { entry_ids: entryIds, name: displayName },
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${displayName.replace(/[^\w.-]+/g, "_").toLowerCase()}-bundle.zip`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(
        entries.length > BUNDLE_ENTRY_CAP
          ? `Bundle exported (${BUNDLE_ENTRY_CAP} most recent of ${entries.length} articles)`
          : "Research bundle exported",
      );
    } catch {
      toast.error("Could not export the bundle");
    } finally {
      setExporting(false);
    }
  };

  const coverage = gaps && gaps.total_ttps > 0 ? gaps : null;
  const gapCount = coverage?.gap_count ?? 0;
  const kevDue = entityType === "cve" ? entity.kev_due_date : null;
  const ruleCount = related.detection_rules?.length ?? 0;
  const needsAssessment = !entity.description;
  const canBundle = entries.length > 0;

  const actions: Action[] = [];

  if (topStory && topStory.kind === "story") {
    actions.push({
      key: "story",
      tone: "hot",
      label: `${topStory.items.length} more article${topStory.items.length === 1 ? "" : "s"} in a story you track`,
      why: `${topStory.title}${topStory.held > 0 ? `: ${topStory.held} of ${topStory.total} already in the campaign` : ""}`,
      button: {
        label: addEntries.isPending ? "Adding…" : `Add all ${topStory.items.length}`,
        disabled: addEntries.isPending,
        onClick: () =>
          addEntries.mutate(
            { campaignId: entityId, entryIds: topStory.items.map((i) => i.entry_id) },
            {
              onSuccess: (r) => toast.success(`Added ${r.added} articles`),
              onError: () => toast.error("Could not add the story's articles"),
            },
          ),
      },
    });
  }

  if (syncingSearches.length > 0) {
    const added = syncingSearches.reduce((n, x) => n + x.entries_added, 0);
    actions.push({
      key: "searches",
      tone: "cool",
      label: `${syncingSearches.length} saved search${syncingSearches.length === 1 ? " adds" : "es add"} matching articles automatically`,
      why:
        [syncingSearches.map((x) => x.saved_search_name).filter(Boolean).slice(0, 2).join(", "), added > 0 ? `${added} added so far.` : null]
          .filter(Boolean)
          .join(". "),
    });
  }

  if (campaignQuiet !== null) {
    actions.push({
      key: "quiet",
      tone: "warm",
      label: `No new articles in ${campaignQuiet} days`,
      why: `The campaign is still marked ${entity.status}. Closing it sets its end date to the last article.`,
      button: {
        label: updateCampaign.isPending ? "Closing…" : "Close campaign",
        disabled: updateCampaign.isPending,
        onClick: () =>
          updateCampaign.mutate(
            { id: entityId, status: "closed", end_date: entity.last_activity_at?.slice(0, 10) },
            {
              onSuccess: () => toast.success("Campaign closed"),
              onError: () => toast.error("Could not close the campaign"),
            },
          ),
      },
    });
  }

  if (unconfirmed.length > 0) {
    actions.push({
      key: "claims",
      tone: "warm",
      label: `${unconfirmed.length} relationship${unconfirmed.length === 1 ? " is" : "s are"} not confirmed yet`,
      why: "AI checks them every night. To settle one now, confirm or reject it in Relationships.",
      button: { label: "Open Relationships", onClick: onShowRelationships },
    });
  }

  if (needsAssessment) {
    actions.push({
      key: "assessment",
      tone: "cool",
      label: "No assessment yet",
      why: "AI can write one from the linked articles.",
      button: {
        label: draftPending ? "Writing…" : "Write with AI",
        disabled: draftPending,
        onClick: onDraftAssessment,
      },
    });
  }

  if (!coverage && !kevDue && actions.length === 0 && !canBundle) return null;

  return (
    <div className={styles.move} aria-label="Next steps">
      <div className={styles.moveMain}>
        <span className={styles.sectionLabel}>Next steps</span>
        {coverage && (
          <div>
            <div className={styles.moveHead}>
              How your detection rules cover its {coverage.total_ttps} known techniques
            </div>
            {/* Proportions by count, not a percentage: tag equality reads
                88-90% for every actor, so the missing counts are the point. */}
            <div className={styles.meter} aria-hidden="true">
              <i className={styles.meterCovered} style={{ flexGrow: coverage.covered_count }} />
              <i className={styles.meterBlind} style={{ flexGrow: coverage.library_only_count }} />
              <i className={styles.meterGap} style={{ flexGrow: coverage.no_rule_count }} />
            </div>
            <div className={styles.meterLegend}>
              <span>
                <i className={styles.meterCovered} />
                <b>{coverage.covered_count}</b> have a rule
              </span>
              {coverage.library_only_count > 0 && (
                <span>
                  <i className={styles.meterBlind} />
                  <b>{coverage.library_only_count}</b> have a rule that can't run, because the logs it needs aren't collected
                </span>
              )}
              <span>
                <i className={styles.meterGap} />
                <b>{coverage.no_rule_count}</b> have no rule
              </span>
            </div>
          </div>
        )}
        {kevDue && (
          <div className={styles.moveHead}>
            CISA requires this to be patched or mitigated by <b>{formatDate(kevDue)}</b>.{" "}
            <span className={styles.moveWhy}>
              {ruleCount > 0
                ? `${ruleCount} detection rule${ruleCount === 1 ? "" : "s"} linked.`
                : "No detection rules cover this CVE yet."}
            </span>
          </div>
        )}
        {actions.map((a) => (
          <div key={a.key} className={styles.moveRow}>
            <span className={`${styles.moveDot} ${styles[`moveDot_${a.tone}`]}`} aria-hidden="true" />
            <span className={styles.moveLabel}>{a.label}.</span>
            <span className={styles.moveWhy}>{a.why}</span>
            {a.button && (
              <button type="button" className={styles.factLink} onClick={a.button.onClick} disabled={a.button.disabled}>
                {a.button.label}
              </button>
            )}
          </div>
        ))}
      </div>
      {(gapCount > 0 || canBundle) && (
        <div className={styles.moveActs}>
          {gapCount > 0 && (
            <button className={styles.primaryBtn} onClick={onShowDetectionGaps}>
              See the {gapCount} technique{gapCount === 1 ? "" : "s"} with no rule
            </button>
          )}
          {canBundle && (
            <button
              className={`${styles.primaryBtn} ${styles.moveGo}`}
              onClick={exportBundle}
              disabled={exporting}
              title="One zip with the most recent articles, the entities in them, their IOCs as CSV, and an ATT&CK Navigator layer"
            >
              {exporting ? "Preparing…" : "Download hunt package"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
