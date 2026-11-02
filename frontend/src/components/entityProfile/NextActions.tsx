/**
 * NextActions — computed, not curated: each chip is a signal the backend
 * already emits (detection gaps, unconfirmed relationship suggestions, bundle
 * export, missing assessment, a campaign's suggestions and standing searches).
 * One row under the assessment; each chip's explanation lives in its hover
 * card. Chips disappear as the work gets done.
 */
import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import api from "@/api/client";
import { Hint } from "@/components/primitives";
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

type Tone = "hot" | "warm" | "cool" | "calm";

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
      toast.error("Failed to export bundle");
    } finally {
      setExporting(false);
    }
  };

  const coverage = gaps && gaps.total_ttps > 0 ? gaps : null;
  const gapCount = coverage?.gap_count ?? 0;
  const gapTechniques = (coverage?.gaps ?? []).slice(0, 3).map((g) => g.technique_id);
  const needsAssessment = !entity.description;
  const canBundle = entries.length > 0;

  const actions: Action[] = [];

  // No coverage percentage: source_ttps tag equality reads 88-90% for every
  // actor, so a ring measured nothing. The honest numbers are the Threats
  // board's: techniques on record, and the gap chip beside it.
  if (coverage) {
    actions.push({
      key: "coverage",
      tone: "cool",
      label: `${coverage.total_ttps} techniques on record`,
      why: "Build coverage from the Detection tab.",
    });
  }

  if (topStory && topStory.kind === "story") {
    actions.push({
      key: "story",
      tone: "hot",
      label: `${topStory.items.length} more article${topStory.items.length === 1 ? "" : "s"} in a story you track`,
      why: `${topStory.title}${topStory.held > 0 ? ` — you have ${topStory.held} of ${topStory.total}` : ""}`,
      button: {
        label: addEntries.isPending ? "Adding…" : `Add all ${topStory.items.length}`,
        disabled: addEntries.isPending,
        onClick: () =>
          addEntries.mutate(
            { campaignId: entityId, entryIds: topStory.items.map((i) => i.entry_id) },
            {
              onSuccess: (r) => toast.success(`Added ${r.added} articles`),
              onError: () => toast.error("Failed to add story"),
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
      label: `${syncingSearches.length} standing search${syncingSearches.length === 1 ? "" : "es"}`,
      why:
        (syncingSearches.map((x) => x.saved_search_name).filter(Boolean).slice(0, 2).join(" · ") ||
          "Pulling matching articles in automatically") + (added > 0 ? ` — ${added} added so far` : ""),
    });
  }

  if (campaignQuiet !== null) {
    actions.push({
      key: "quiet",
      tone: "warm",
      label: `No new coverage in ${campaignQuiet} days`,
      why: `Status still says ${entity.status} — closing it stamps the end date from the last article.`,
      button: {
        label: updateCampaign.isPending ? "Closing…" : "Close it",
        disabled: updateCampaign.isPending,
        onClick: () =>
          updateCampaign.mutate(
            { id: entityId, status: "closed", end_date: entity.last_activity_at?.slice(0, 10) },
            {
              onSuccess: () => toast.success("Campaign closed"),
              onError: () => toast.error("Failed to close campaign"),
            },
          ),
      },
    });
  }

  if (gapCount > 0) {
    actions.push({
      key: "gaps",
      tone: "hot",
      label: `Close ${gapCount} detection gap${gapCount === 1 ? "" : "s"}`,
      why: (
        <>
          No rule for{" "}
          {gapTechniques.map((t) => (
            <code key={t} className={styles.actionCode}>
              {t}
            </code>
          ))}
          {gapCount > 3 ? ` +${gapCount - 3} more` : ""}
        </>
      ),
      button: { label: "Review gaps", onClick: onShowDetectionGaps },
    });
  }

  if (unconfirmed.length > 0) {
    actions.push({
      key: "claims",
      tone: "warm",
      label: `${unconfirmed.length} claim${unconfirmed.length === 1 ? "" : "s"} to corroborate`,
      why: "The AI adjudicator reviews these nightly — pin or reject to settle one now.",
      button: { label: "Review", onClick: onShowRelationships },
    });
  }

  if (needsAssessment) {
    actions.push({
      key: "assessment",
      tone: "cool",
      label: "No assessment yet",
      why: "Draft one from linked reporting with AI.",
      button: {
        label: draftPending ? "Drafting…" : "Draft with AI",
        disabled: draftPending,
        onClick: onDraftAssessment,
      },
    });
  }

  if (canBundle) {
    actions.push({
      key: "bundle",
      tone: "calm",
      label: "Hunt package",
      why: "Articles, entities, IOC CSV and ATT&CK Navigator layer as one bundle.",
      button: { label: exporting ? "Building…" : "Build", disabled: exporting, onClick: exportBundle },
    });
  }

  if (actions.length === 0) return null;

  return (
    <div className={styles.nextActions} role="group" aria-label="Next actions">
      <span className={styles.sectionLabel}>Next</span>
      {actions.map((a) => (
        <Hint key={a.key} title={a.label} body={a.why}>
          <span className={`${styles.actionChip} ${styles[`actionTone_${a.tone}`]}`}>
            <span className={styles.actionDot} aria-hidden="true" />
            {a.label}
            {a.button && (
              <button
                type="button"
                className={styles.actionChipBtn}
                onClick={a.button.onClick}
                disabled={a.button.disabled}
              >
                {a.button.label}
              </button>
            )}
          </span>
        </Hint>
      ))}
    </div>
  );
}
