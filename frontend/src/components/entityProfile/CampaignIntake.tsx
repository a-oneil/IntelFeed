/**
 * CampaignIntake — what feeds this campaign, and what it could take next.
 *
 * One section in the main column covers what separate Searches and Suggestions tabs and a rail card covered, because split up each was too small to read: the rail card could say that something would be added but not which articles. The section is wide enough to list the articles before you add them.
 *
 * Two halves, because they are two different commitments:
 *
 * * **Standing intake** — sources that keep adding articles. A followed entity or story adds from the campaign's own curation; a typed query catches articles about something nobody has named yet. Both belong to the campaign, so a teammate can see and pause either.
 * * **Suggested intake** — offers. Each expands to the articles it would add and has two actions: add these articles once, or follow the source so later articles arrive on their own.
 *
 * The section renders even when nothing is held and nothing is offered, because that is a new campaign, the one that most needs to be told what to collect. "Add intake" (CampaignIntakeComposer) points the campaign at any query, entity, story or saved search by hand, so intake is not limited to what the backend has proposed.
 */
import { useRef, useState } from "react";
import { toast } from "sonner";
import {
  useAddCampaignEntries,
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
import { CampaignIntakeComposer } from "./CampaignIntakeComposer";
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
  const updateSearch = useUpdateCampaignSavedSearch();
  const removeSearch = useRemoveCampaignSavedSearch();
  const syncSearch = useSyncCampaignSavedSearch();
  const addEntries = useAddCampaignEntries();
  const undoableDelete = useUndoableDelete();

  const [open, setOpen] = useState<string | null>(null);
  const [composing, setComposing] = useState(false);
  /** Which query source is being rewritten in place, and to what. */
  const [editing, setEditing] = useState<{ id: string; text: string } | null>(null);
  /** Set by Escape so the blur that follows discards rather than saves. */
  const abandonEdit = useRef(false);

  const sourceRows = sources ?? [];
  const searchRows = searches ?? [];
  const linkedSearchIds = new Set(searchRows.map((r) => r.saved_search_id));
  const availableSearches = (allSearches ?? []).filter((s) => !linkedSearchIds.has(s.id));

  // Offers from both directions, in one list. A story the campaign part-holds shows up in each — as something to take now (/suggest) and as something to follow (sources) — so they are merged on the thread id rather than listed twice.
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
          ? `${group.held} of ${group.total} already in the campaign`
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

  return (
    <div className={`${styles.panel} ${styles.intakePanel}`}>
      <div className={styles.intakeHead}>
        <div className={styles.panelTitle}>Campaign intake</div>
        {!composing && (
          <button className={styles.intakeBtn} onClick={() => setComposing(true)}>
            Add intake
          </button>
        )}
      </div>

      {nothingFeeding && !composing && (
        <p className={styles.intakeEmpty}>
          No automatic intake is set up. Every article here was added by hand. Add intake to follow a query, an
          entity or a story, and new matching articles are added automatically.
        </p>
      )}

      {composing && (
        <CampaignIntakeComposer
          campaignId={campaignId}
          availableSearches={availableSearches}
          onClose={() => setComposing(false)}
          onOpenArticle={onOpenArticle}
        />
      )}

      {sourceRows.map((source) => (
        <div key={source.id} className={styles.intakeRow}>
          <span className={styles.intakeKind}>{source.kind}</span>
          {editing?.id === source.id ? (
            <input
              className={styles.intakeQueryInput}
              value={editing.text}
              autoFocus
              spellCheck={false}
              aria-label="Rewrite this query"
              onChange={(e) => setEditing({ id: source.id, text: e.target.value })}
              onKeyDown={(e) => {
                // Both exits go through blur so there is one save path. Escape marks the intent first, because by the time blur runs the difference between "left it alone" and "changed my mind" is no longer visible in the value.
                if (e.key === "Escape") abandonEdit.current = true;
                if (e.key === "Escape" || e.key === "Enter") e.currentTarget.blur();
              }}
              onBlur={(e) => {
                const text = e.target.value.trim();
                const abandoned = abandonEdit.current;
                abandonEdit.current = false;
                setEditing(null);
                if (abandoned || !text || text === source.query) return;
                updateSource.mutate(
                  { campaignId, sourceId: source.id, query: text },
                  {
                    onSuccess: () => toast.success("Query rewritten"),
                    onError: (err) =>
                      toast.error(
                        (err as { response?: { data?: { error?: { message?: string } } } })?.response?.data
                          ?.error?.message || "Could not save the query",
                      ),
                  },
                );
              }}
            />
          ) : (
            <span
              className={source.kind === "query" ? styles.intakeLabelQuery : styles.intakeLabel}
              title={source.query ?? undefined}
            >
              {source.label}
            </span>
          )}
          <span className={styles.intakeMeta}>
            {source.entries_added} added
            {source.last_synced_at && ` · ran ${formatDate(source.last_synced_at)}`}
            {!source.auto_sync && " · paused"}
          </span>
          <span className={styles.intakeControls}>
            {source.kind === "query" && editing?.id !== source.id && (
              <button
                className={styles.intakeBtn}
                title="Rewrite the query, keeping what it has already added"
                onClick={() => setEditing({ id: source.id, text: source.query ?? "" })}
              >
                Edit
              </button>
            )}
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
                    onError: () => toast.error("Could not run the source"),
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
                    onError: () => toast.error("Could not run the source"),
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

      {(offers.length > 0 || looseCount > 0) && (
        <div className={styles.intakeOffers}>
          {/* Linking a saved search lives in the composer's own tab: it is one of four ways to add intake, not an action on offers. */}
          <div className={styles.intakeOffersHead}>
            <span>Suggested intake</span>
          </div>

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
                              onError: () => toast.error("Could not add the articles"),
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
                        title="Add these articles and every later match automatically"
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
                              onError: () => toast.error("Could not follow"),
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
                      {isOpen ? "Hide" : "Articles"}
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
              {looseCount} more article{looseCount === 1 ? "" : "s"} match this campaign's entities but
              are not part of a story.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
