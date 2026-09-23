/**
 * NextActionsRail — computed, not curated: each card is a signal the backend
 * already emits (detection gaps, unconfirmed relationship suggestions, bundle
 * export, missing assessment). Cards disappear as the work gets done; a clean
 * profile shows only the coverage ring.
 */
import { useState } from "react";
import { toast } from "sonner";
import api from "@/api/client";
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
  "mitigations",
];

/** Types the detection-gaps endpoint serves (mirrors the tabs config). */
const GAPPED_TYPES: EntityType[] = ["threat_actor", "malware"];

const BUNDLE_ENTRY_CAP = 100;

export function NextActionsRail({
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
  // quiet. All three are work, which is what this rail is for.
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

  const hasCampaignWork = !!topStory || syncingSearches.length > 0 || campaignQuiet !== null;
  if (!coverage && unconfirmed.length === 0 && !needsAssessment && !canBundle && !hasCampaignWork) return null;

  return (
    <div className={styles.rail}>
      <div className={styles.railTitle}>Next actions</div>

      {/* No coverage percentage: source_ttps tag equality reads 88-90% for
          every actor, so the ring measured nothing. The honest numbers are the
          Threats board's: techniques on record, and the gap list below. */}
      {coverage && (
        <div className={styles.posture}>
          <div>
            <div className={styles.postureValue}>{coverage.total_ttps} techniques on record</div>
            <div className={styles.postureLabel}>build coverage from the Detection tab</div>
          </div>
        </div>
      )}

      {topStory && topStory.kind === "story" && (
        <div className={`${styles.actionCard} ${styles.actionHot}`}>
          <div className={styles.actionTitle}>
            {topStory.items.length} more article{topStory.items.length === 1 ? "" : "s"} in a story you track
          </div>
          <div className={styles.actionWhy}>
            {topStory.title}
            {topStory.held > 0 ? ` — you have ${topStory.held} of ${topStory.total}` : ""}
          </div>
          <button
            className={styles.actionBtn}
            disabled={addEntries.isPending}
            onClick={() =>
              addEntries.mutate(
                { campaignId: entityId, entryIds: topStory.items.map((i) => i.entry_id) },
                {
                  onSuccess: (r) => toast.success(`Added ${r.added} articles`),
                  onError: () => toast.error("Failed to add story"),
                },
              )
            }
          >
            {addEntries.isPending ? "Adding…" : `Add all ${topStory.items.length}`}
          </button>
        </div>
      )}

      {syncingSearches.length > 0 && (
        <div className={`${styles.actionCard} ${styles.actionCool}`}>
          <div className={styles.actionTitle}>
            {syncingSearches.length} standing search{syncingSearches.length === 1 ? "" : "es"}
          </div>
          <div className={styles.actionWhy}>
            {syncingSearches.map((x) => x.saved_search_name).filter(Boolean).slice(0, 2).join(" · ") ||
              "Pulling matching articles in automatically"}
            {syncingSearches.some((x) => x.entries_added > 0)
              ? ` — ${syncingSearches.reduce((n, x) => n + x.entries_added, 0)} added so far`
              : ""}
          </div>
        </div>
      )}

      {campaignQuiet !== null && (
        <div className={`${styles.actionCard} ${styles.actionWarm}`}>
          <div className={styles.actionTitle}>No new coverage in {campaignQuiet} days</div>
          <div className={styles.actionWhy}>
            Status still says {entity.status} — closing it stamps the end date from the last article
          </div>
          <button
            className={styles.actionBtn}
            disabled={updateCampaign.isPending}
            onClick={() =>
              updateCampaign.mutate(
                {
                  id: entityId,
                  status: "closed",
                  end_date: entity.last_activity_at?.slice(0, 10),
                },
                {
                  onSuccess: () => toast.success("Campaign closed"),
                  onError: () => toast.error("Failed to close campaign"),
                },
              )
            }
          >
            {updateCampaign.isPending ? "Closing…" : "Close it"}
          </button>
        </div>
      )}

      {gapCount > 0 && (
        <div className={`${styles.actionCard} ${styles.actionHot}`}>
          <div className={styles.actionTitle}>
            Close {gapCount} detection gap{gapCount === 1 ? "" : "s"}
          </div>
          <div className={styles.actionWhy}>
            No rule for{" "}
            {gapTechniques.map((t) => (
              <code key={t} className={styles.actionCode}>
                {t}
              </code>
            ))}
            {gapCount > 3 ? ` +${gapCount - 3} more` : ""}
          </div>
          <button className={styles.actionBtn} onClick={onShowDetectionGaps}>
            Review gaps
          </button>
        </div>
      )}

      {unconfirmed.length > 0 && (
        <div className={`${styles.actionCard} ${styles.actionWarm}`}>
          <div className={styles.actionTitle}>
            {unconfirmed.length} claim{unconfirmed.length === 1 ? "" : "s"} awaiting corroboration
          </div>
          <div className={styles.actionWhy}>
            The AI adjudicator reviews these nightly — pin or reject to settle one now
          </div>
          <button className={styles.actionBtn} onClick={onShowRelationships}>
            Review
          </button>
        </div>
      )}

      {needsAssessment && (
        <div className={`${styles.actionCard} ${styles.actionCool}`}>
          <div className={styles.actionTitle}>No assessment yet</div>
          <div className={styles.actionWhy}>Draft one from linked reporting with AI</div>
          <button className={styles.actionBtn} onClick={onDraftAssessment} disabled={draftPending}>
            {draftPending ? "Drafting…" : "Draft with AI"}
          </button>
        </div>
      )}

      {canBundle && (
        <div className={`${styles.actionCard} ${styles.actionCalm}`}>
          <div className={styles.actionTitle}>Export hunt package</div>
          <div className={styles.actionWhy}>
            Articles, entities, IOC CSV and ATT&CK Navigator layer as one bundle
          </div>
          <button className={styles.actionBtn} onClick={exportBundle} disabled={exporting}>
            {exporting ? "Building…" : "Build package"}
          </button>
        </div>
      )}
    </div>
  );
}

