/**
 * CampaignIntake — what feeds this campaign, and what it could take next.
 *
 * These were three surfaces (a Searches tab, a Suggestions tab, and a rail
 * card) answering one question, and splitting them made each one too small to
 * be legible: the rail in particular could show that something *would* be added
 * without ever showing *what*. One section in the main column, wide enough to
 * name the articles before you commit to them.
 *
 * Two halves, because they are two different commitments:
 *
 * * **Feeding it** — standing intake. A saved search catches things nobody has
 *   named yet; a followed entity or story reads the campaign's own curation and
 *   so doesn't drift the way a parallel query does.
 * * **Could take** — offers. Each expands to the articles it would actually
 *   add, and carries both verbs: take these once, or follow it so later waves
 *   arrive on their own.
 */
import { useState } from "react";
import { toast } from "sonner";
import {
  useAddCampaignEntries,
  useAddCampaignSavedSearch,
  useAddCampaignSource,
  useCampaignSavedSearches,
  useCampaignSources,
  useCampaignSuggestions,
  useRemoveCampaignSavedSearch,
  useRemoveCampaignSource,
  useSuggestedCampaignSources,
  useSyncCampaignSavedSearch,
  useSyncCampaignSource,
  useUpdateCampaignSavedSearch,
  useUpdateCampaignSource,
} from "@/hooks/useCampaigns";
import { useSavedSearches } from "@/hooks/useSearch";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { groupSuggestions } from "@/utils/campaignSuggestions";
import { formatDate } from "@/utils/formatDate";
import styles from "./entityProfile.module.css";

/** One row in either half — the shape the list renders, whatever produced it. */
interface IntakeOffer {
  key: string;
  kind: "story" | "entity" | "article";
  label: string;
  why: string;
  count: number;
  /** Articles it would add, by name. Empty for an offer we can only count. */
  preview: Array<{ entry_id: string; title: string; published_at?: string | null }>;
  /** Present when the offer can also be followed as a standing source. */
  follow?: { kind: "entity" | "story"; entityType: string | null; refId: string };
  /** Present when the offer's articles can be taken in one go. */
  entryIds?: string[];
}

export function CampaignIntake({
  campaignId,
  onOpenArticle,
}: {
  campaignId: string;
  onOpenArticle?: (entryId: string) => void;
}) {
  const { data: sources } = useCampaignSources(campaignId);
  const { data: searches } = useCampaignSavedSearches(campaignId);
  const { data: allSearches } = useSavedSearches();
  const { data: sourceOffers } = useSuggestedCampaignSources(campaignId);
  const { data: suggestions } = useCampaignSuggestions(campaignId, { limit: 200 });

  const addSource = useAddCampaignSource();
  const updateSource = useUpdateCampaignSource();
  const removeSource = useRemoveCampaignSource();
  const syncSource = useSyncCampaignSource();
  const addSearch = useAddCampaignSavedSearch();
  const updateSearch = useUpdateCampaignSavedSearch();
  const removeSearch = useRemoveCampaignSavedSearch();
  const syncSearch = useSyncCampaignSavedSearch();
  const addEntries = useAddCampaignEntries();
  const undoableDelete = useUndoableDelete();

  const [open, setOpen] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);

  const sourceRows = sources ?? [];
  const searchRows = searches ?? [];
  const linkedSearchIds = new Set(searchRows.map((r) => r.saved_search_id));
  const availableSearches = (allSearches ?? []).filter((s) => !linkedSearchIds.has(s.id));

  // Offers from both directions, in one list. A story the campaign part-holds
  // shows up in each — as something to take now (/suggest) and as something to
  // follow (sources) — so they are merged on the thread id rather than listed
  // twice saying almost the same thing.
  const followedRefs = new Set(sourceRows.map((s) => `${s.kind}:${s.ref_id}`));
  const storyGroups = groupSuggestions(suggestions ?? []).filter((g) => g.kind === "story");
  const looseCount = groupSuggestions(suggestions ?? []).filter((g) => g.kind === "entry").length;

  const offers: IntakeOffer[] = [];

  for (const group of storyGroups) {
    if (group.kind !== "story") continue;
    const threadId = group.items[0]?.thread_id ?? null;
    offers.push({
      key: `story-${group.slug}`,
      kind: "story",
      label: group.title,
      why:
        group.held > 0
          ? `you hold ${group.held} of ${group.total}`
          : `${group.items.length} articles, one story`,
      count: group.items.length,
      preview: group.items.slice(0, 5),
      follow:
        threadId && !followedRefs.has(`story:${threadId}`)
          ? { kind: "story", entityType: null, refId: threadId }
          : undefined,
      entryIds: group.items.map((i) => i.entry_id),
    });
  }

  for (const offer of sourceOffers ?? []) {
    // A story already listed above from /suggest — don't repeat it.
    if (offer.kind === "story" && offers.some((o) => o.follow?.refId === offer.ref_id)) continue;
    offers.push({
      key: `${offer.kind}-${offer.ref_id}`,
      kind: offer.kind,
      label: offer.label,
      why: offer.why,
      count: offer.would_add,
      preview: offer.preview ?? [],
      follow: { kind: offer.kind, entityType: offer.entity_type, refId: offer.ref_id },
      entryIds: undefined,
    });
  }

  const nothingFeeding = sourceRows.length === 0 && searchRows.length === 0;
  if (nothingFeeding && offers.length === 0 && availableSearches.length === 0) return null;

  return (
    <div className={`${styles.panel} ${styles.intakePanel}`}>
      <div className={styles.panelTitle}>Feeding this campaign</div>

      {nothingFeeding && (
        <p className={styles.intakeEmpty}>
          Nothing arrives on its own — every article here was added by hand.
        </p>
      )}

      {sourceRows.map((source) => (
        <div key={source.id} className={styles.intakeRow}>
          <span className={styles.intakeKind}>{source.kind}</span>
          <span className={styles.intakeLabel}>{source.label}</span>
          <span className={styles.intakeMeta}>
            {source.entries_added} added
            {source.last_synced_at && ` · ran ${formatDate(source.last_synced_at)}`}
            {!source.auto_sync && " · paused"}
          </span>
          <span className={styles.intakeControls}>
            <button
              className={styles.intakeBtn}
              onClick={() =>
                updateSource.mutate({ campaignId, sourceId: source.id, autoSync: !source.auto_sync })
              }
            >
              {source.auto_sync ? "Pause" : "Resume"}
            </button>
            <button
              className={styles.intakeBtn}
              disabled={syncSource.isPending}
              onClick={() =>
                syncSource.mutate(
                  { campaignId, sourceId: source.id },
                  {
                    onSuccess: (r) =>
                      toast.success(r.entries_added > 0 ? `Added ${r.entries_added}` : "Nothing new"),
                    onError: () => toast.error("Sync failed"),
                  },
                )
              }
            >
              Run
            </button>
            <button
              className={styles.intakeBtn}
              title="Articles already added stay in the campaign"
              onClick={() =>
                undoableDelete({
                  label: `${source.kind} source`,
                  key: `campaign-source-${source.id}`,
                  onDelete: () => removeSource.mutate({ campaignId, sourceId: source.id }),
                })
              }
            >
              Unfollow
            </button>
          </span>
        </div>
      ))}

      {searchRows.map((row) => (
        <div key={row.id} className={styles.intakeRow}>
          <span className={styles.intakeKind}>search</span>
          <span className={styles.intakeLabel} title={row.saved_search_query ?? undefined}>
            {row.saved_search_name}
          </span>
          <span className={styles.intakeMeta}>
            {row.entries_added} added
            {row.last_synced_at && ` · ran ${formatDate(row.last_synced_at)}`}
            {!row.auto_sync && " · paused"}
          </span>
          <span className={styles.intakeControls}>
            <button
              className={styles.intakeBtn}
              onClick={() =>
                updateSearch.mutate({ campaignId, cssId: row.id, autoSync: !row.auto_sync })
              }
            >
              {row.auto_sync ? "Pause" : "Resume"}
            </button>
            <button
              className={styles.intakeBtn}
              disabled={syncSearch.isPending}
              onClick={() =>
                syncSearch.mutate(
                  { campaignId, cssId: row.id },
                  {
                    onSuccess: (r) =>
                      toast.success(
                        r.new_entries_added > 0 ? `Added ${r.new_entries_added}` : "Nothing new matched",
                      ),
                    onError: () => toast.error("Sync failed"),
                  },
                )
              }
            >
              Run
            </button>
            <button
              className={styles.intakeBtn}
              onClick={() =>
                undoableDelete({
                  label: "Search link",
                  key: `campaign-search-${row.id}`,
                  onDelete: () => removeSearch.mutate({ campaignId, cssId: row.id }),
                })
              }
            >
              Unlink
            </button>
          </span>
        </div>
      ))}

      {/* --- Offers --- */}

      {(offers.length > 0 || availableSearches.length > 0) && (
        <div className={styles.intakeOffers}>
          <div className={styles.intakeOffersHead}>
            <span>Could take</span>
            {availableSearches.length > 0 && (
              <button className={styles.intakeBtn} onClick={() => setPicking((p) => !p)}>
                {picking ? "Cancel" : "Link a saved search"}
              </button>
            )}
          </div>

          {picking && (
            <div className={styles.intakePicker}>
              {availableSearches.map((s) => (
                <button
                  key={s.id}
                  className={styles.intakePick}
                  disabled={addSearch.isPending}
                  onClick={() => {
                    addSearch.mutate(
                      { campaignId, savedSearchId: s.id },
                      {
                        onSuccess: () => toast.success(`Linked "${s.display_name || s.name}"`),
                        onError: () => toast.error("Failed to link search"),
                      },
                    );
                    setPicking(false);
                  }}
                >
                  <span className={styles.intakeLabel}>{s.display_name || s.name}</span>
                  {s.query && <span className={styles.intakeQuery}>{s.query}</span>}
                </button>
              ))}
            </div>
          )}

          {offers.map((offer) => {
            const isOpen = open === offer.key;
            return (
              <div key={offer.key} className={styles.intakeOffer}>
                <div className={styles.intakeRow}>
                  <span className={styles.intakeKind}>{offer.kind}</span>
                  <button
                    className={styles.intakeLabelBtn}
                    onClick={() => setOpen(isOpen ? null : offer.key)}
                    aria-expanded={isOpen}
                    title="Show the articles this would add"
                  >
                    {offer.label}
                  </button>
                  <span className={styles.intakeMeta}>
                    {offer.why} · adds {offer.count}
                  </span>
                  <span className={styles.intakeControls}>
                    {offer.entryIds && (
                      <button
                        className={styles.intakePrimary}
                        disabled={addEntries.isPending}
                        onClick={() =>
                          addEntries.mutate(
                            { campaignId, entryIds: offer.entryIds! },
                            {
                              onSuccess: (r) => toast.success(`Added ${r.added} articles`),
                              onError: () => toast.error("Failed to add"),
                            },
                          )
                        }
                      >
                        Add {offer.count}
                      </button>
                    )}
                    {offer.follow && (
                      <button
                        className={styles.intakeBtn}
                        disabled={addSource.isPending}
                        title="Take these and every later one, without being asked again"
                        onClick={() =>
                          addSource.mutate(
                            {
                              campaignId,
                              kind: offer.follow!.kind,
                              entityType: offer.follow!.entityType,
                              refId: offer.follow!.refId,
                            },
                            {
                              onSuccess: (s) => toast.success(`Following ${s.label}`),
                              onError: () => toast.error("Failed to follow"),
                            },
                          )
                        }
                      >
                        Follow
                      </button>
                    )}
                    <button
                      className={styles.intakeBtn}
                      onClick={() => setOpen(isOpen ? null : offer.key)}
                    >
                      {isOpen ? "Hide" : "What?"}
                    </button>
                  </span>
                </div>

                {isOpen && (
                  <div className={styles.intakePreview}>
                    {offer.preview.length === 0 && (
                      <div className={styles.intakePreviewNote}>Nothing new to show.</div>
                    )}
                    {offer.preview.map((item) => (
                      <button
                        key={item.entry_id}
                        className={styles.intakePreviewRow}
                        onClick={() => onOpenArticle?.(item.entry_id)}
                      >
                        {item.title}
                      </button>
                    ))}
                    {offer.count > offer.preview.length && (
                      <div className={styles.intakePreviewNote}>
                        + {offer.count - offer.preview.length} more
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {looseCount > 0 && (
            <div className={`${styles.intakePreviewNote} ${styles.intakeFootnote}`}>
              {looseCount} further article{looseCount === 1 ? "" : "s"} match this campaign's entities but
              never clustered into a story.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
