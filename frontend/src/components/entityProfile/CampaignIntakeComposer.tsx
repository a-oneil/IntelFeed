/**
 * CampaignIntakeComposer — pointing a campaign at something by hand.
 *
 * Before this, standing intake could only be *accepted*: the section listed
 * what the backend had already proposed from what the campaign held, so an
 * entity the campaign had never named could never be followed, and a query had
 * to exist as somebody's personal saved search before it could be linked. A new
 * campaign — the case that most needs intake — was offered nothing at all.
 *
 * Four tabs, because they are four different reaches:
 *
 * * **Query** — the one intake that catches something nobody has named yet. It
 *   belongs to the campaign rather than to whoever typed it, so a teammate can
 *   read it, fix it or pause it.
 * * **Entity** — any actor, malware, CVE or other entity, not only the ones the
 *   campaign already names. The type list comes from the server: a type with no
 *   article junction would make a source that is created and never adds
 *   anything, and only the backend knows which those are.
 * * **Story** — a thread by name, including a dormant one. Reached by title,
 *   because a story you want on a campaign is one you can already name.
 * * **Saved search** — the old path, kept for the searches that already exist.
 *
 * Nothing commits without a dry run first: every tab previews "adds N" with the
 * article titles, the same information the offers have always carried, because
 * a count tells you the size of a decision but not whether to make it.
 */
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { SearchSyntaxHelp } from "@/components/search/SearchSyntaxHelp";
import { Segmented, type SegmentedOption } from "@/components/primitives";
import {
  useAddCampaignSavedSearch,
  useAddCampaignSource,
  useCampaignSourceOptions,
  useCampaignSourcePreview,
} from "@/hooks/useCampaigns";
import { useEntitySearch } from "@/hooks/useCorrelation";
import { useThreadSearch } from "@/hooks/useThreads";
import type { CampaignSourceKind, EntitySearchResult, SavedSearch } from "@/api/types";
// Two near-identical EntityType unions exist: the theming one (which also
// covers notes) and the pivot one the row helpers key on. Kept distinct here
// rather than widened, since the server hands us a plain slug either way.
import type { EntityType as PivotEntityType } from "@/stores/intelStore";
import { getEntityLabel, type EntityType } from "@/utils/entityTheme";
import { rowLabel, rowMeta } from "@/utils/relationshipBrowser";
import styles from "./entityProfile.module.css";

type Tab = "query" | "entity" | "story" | "search";

/**
 * The `{error: {code, message, details}}` envelope every AppError comes back
 * in. Worth surfacing verbatim here: the refusals are specific ("'detection_rule'
 * owns no articles", "Query does not parse: Unexpected token") and a generic
 * "failed" would hide the one sentence that says what to change.
 */
function appErrorMessage(err: unknown): string | undefined {
  return (err as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message;
}

/** What the composer has aimed at, once it is specific enough to dry-run. */
interface Target {
  kind: CampaignSourceKind;
  entityType?: string | null;
  refId?: string | null;
  query?: string | null;
  /** How to name it in the confirm button and the toast. */
  label: string;
}

/** Debounce a value so typing previews once, not once per keystroke. */
function useSettled(value: string, ms = 350): string {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setSettled(value.trim()), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return settled;
}

export function CampaignIntakeComposer({
  campaignId,
  availableSearches,
  onClose,
  onOpenArticle,
}: {
  campaignId: string;
  /** Saved searches not already linked — the old path, offered when there are any. */
  availableSearches: SavedSearch[];
  onClose: () => void;
  onOpenArticle?: (entryId: string) => void;
}) {
  const { data: options } = useCampaignSourceOptions();
  const addSource = useAddCampaignSource();
  const addSearch = useAddCampaignSavedSearch();

  const [tab, setTab] = useState<Tab>("query");
  const [showSyntax, setShowSyntax] = useState(false);

  const [query, setQuery] = useState("");
  const settledQuery = useSettled(query);

  const pickable = useMemo(() => options?.pickable_entity_types ?? [], [options]);
  const [entityType, setEntityType] = useState("threat_actor");
  const [entityTerm, setEntityTerm] = useState("");
  const settledEntityTerm = useSettled(entityTerm, 250);
  const [picked, setPicked] = useState<Target | null>(null);

  const [storyTerm, setStoryTerm] = useState("");
  const settledStoryTerm = useSettled(storyTerm, 250);

  // The server's list is authoritative; a stale default (a type that stopped
  // being followable) would otherwise silently search nothing.
  useEffect(() => {
    if (pickable.length > 0 && !pickable.includes(entityType)) setEntityType(pickable[0]);
  }, [pickable, entityType]);

  const { data: entityHits, isFetching: entitySearching } = useEntitySearch(
    tab === "entity" ? settledEntityTerm : "",
    25,
    entityType,
  );
  const { data: storyHits, isFetching: storySearching } = useThreadSearch(
    tab === "story" ? settledStoryTerm : "",
  );

  // Switching tabs drops the aim rather than previewing a target the visible
  // tab cannot explain.
  const switchTab = (next: Tab) => {
    setTab(next);
    setPicked(null);
  };

  const target: Target | null = useMemo(() => {
    if (tab === "query") return settledQuery ? { kind: "query", query: settledQuery, label: settledQuery } : null;
    if (tab === "entity" || tab === "story") return picked;
    return null;
  }, [tab, settledQuery, picked]);

  const { data: preview, isFetching: previewing } = useCampaignSourcePreview(
    campaignId,
    target ? { kind: target.kind, entityType: target.entityType, refId: target.refId, query: target.query } : null,
  );

  const follow = () => {
    if (!target) return;
    addSource.mutate(
      {
        campaignId,
        kind: target.kind,
        entityType: target.entityType ?? null,
        refId: target.refId ?? null,
        query: target.query ?? null,
      },
      {
        onSuccess: (s) => {
          toast.success(`Following ${s.label}`, {
            description: s.entries_added > 0 ? `Added ${s.entries_added} articles` : "Nothing to add yet",
          });
          onClose();
        },
        onError: (err) => toast.error(appErrorMessage(err) || "Failed to follow"),
      },
    );
  };

  const tabs: SegmentedOption<Tab>[] = [
    { value: "query", label: "Query", title: "Take everything matching a query, from now on" },
    { value: "entity", label: "Entity", title: "Follow an actor, malware family, CVE or other entity" },
    { value: "story", label: "Story", title: "Follow a story thread by name" },
  ];
  if (availableSearches.length > 0) {
    tabs.push({ value: "search", label: "Saved search", title: "Link a search you already saved" });
  }

  const blocked = !target || !!preview?.error || addSource.isPending;

  return (
    <div className={styles.intakeComposer}>
      <div className={styles.intakeComposerHead}>
        <Segmented options={tabs} value={tab} onChange={switchTab} label="Intake kind" role="tablist" size="sm" />
        <button type="button" className={styles.intakeBtn} onClick={onClose}>
          Cancel
        </button>
      </div>

      {tab === "query" && (
        <>
          <div className={styles.intakeComposerRow}>
            <input
              className={styles.intakeQueryInput}
              value={query}
              autoFocus
              spellCheck={false}
              placeholder='threat_actor:"Scattered Spider" OR malware:Akira'
              onChange={(e) => setQuery(e.target.value)}
            />
            <button
              type="button"
              className={styles.intakeBtn}
              aria-pressed={showSyntax}
              title="Query language reference"
              onClick={() => setShowSyntax((v) => !v)}
            >
              ?
            </button>
          </div>
          <p className={styles.intakeComposerNote}>
            The campaign owns this query, not you — anyone on it can read, pause or rewrite it. It re-runs every
            15 minutes and takes whatever is new.
          </p>
          {showSyntax && (
            <SearchSyntaxHelp
              variant="card"
              onInsert={(token) => setQuery((q) => (q ? `${q} ${token}` : token))}
              onRunExample={(q) => setQuery(q)}
            />
          )}
        </>
      )}

      {tab === "entity" && (
        <>
          <div className={styles.intakeComposerRow}>
            <select
              className={styles.intakeSelect}
              value={entityType}
              aria-label="Entity type"
              onChange={(e) => {
                setEntityType(e.target.value);
                setPicked(null);
              }}
            >
              {pickable.map((t) => (
                <option key={t} value={t}>
                  {getEntityLabel(t as EntityType)}
                </option>
              ))}
            </select>
            <input
              className={styles.intakeSearchInput}
              value={entityTerm}
              autoFocus
              placeholder={`Search ${getEntityLabel(entityType as EntityType).toLowerCase()} by name…`}
              onChange={(e) => {
                setEntityTerm(e.target.value);
                setPicked(null);
              }}
            />
          </div>
          {!picked && (
            <HitList
              empty={
                settledEntityTerm.length === 0
                  ? "Type a name. Any entity works here, not only the ones this campaign already lists."
                  : entitySearching
                    ? "Searching…"
                    : `No ${getEntityLabel(entityType as EntityType).toLowerCase()} matched.`
              }
              busy={entitySearching}
              hits={(entityHits?.results ?? []).map((hit: EntitySearchResult) => {
                const name = rowLabel(entityType as PivotEntityType, hit);
                return {
                  key: hit.id,
                  label: name,
                  meta: rowMeta(entityType as PivotEntityType, hit),
                  onPick: () =>
                    setPicked({ kind: "entity", entityType, refId: hit.id, label: name }),
                };
              })}
            />
          )}
        </>
      )}

      {tab === "story" && (
        <>
          <div className={styles.intakeComposerRow}>
            <input
              className={styles.intakeSearchInput}
              value={storyTerm}
              autoFocus
              placeholder="Search story threads by title…"
              onChange={(e) => {
                setStoryTerm(e.target.value);
                setPicked(null);
              }}
            />
          </div>
          {!picked && (
            <HitList
              empty={
                settledStoryTerm.length === 0
                  ? "Type part of a story's title. Dormant stories count — following one picks up its next wave."
                  : storySearching
                    ? "Searching…"
                    : "No story matched that title."
              }
              busy={storySearching}
              hits={(storyHits?.threads ?? []).map((thread) => ({
                key: thread.id,
                label: thread.title,
                meta: `${thread.entry_count} article${thread.entry_count === 1 ? "" : "s"} · ${thread.status}`,
                onPick: () => setPicked({ kind: "story", refId: thread.id, label: thread.title }),
              }))}
            />
          )}
        </>
      )}

      {tab === "search" && (
        <div className={styles.intakePicker}>
          {availableSearches.map((s) => (
            <button
              key={s.id}
              type="button"
              className={styles.intakePick}
              disabled={addSearch.isPending}
              onClick={() =>
                addSearch.mutate(
                  { campaignId, savedSearchId: s.id },
                  {
                    onSuccess: () => {
                      toast.success(`Linked "${s.display_name || s.name}"`);
                      onClose();
                    },
                    onError: () => toast.error("Failed to link search"),
                  },
                )
              }
            >
              <span className={styles.intakeLabel}>{s.display_name || s.name}</span>
              {s.query && <span className={styles.intakeQuery}>{s.query}</span>}
            </button>
          ))}
        </div>
      )}

      {/* --- The dry run. Same shape for all three, because it is one question. --- */}
      {tab !== "search" && (
        <div className={styles.intakeDryRun}>
          {picked && (
            <div className={styles.intakeComposerRow}>
              <span className={styles.intakeLabel}>{picked.label}</span>
              <button type="button" className={styles.intakeBtn} onClick={() => setPicked(null)}>
                Change
              </button>
            </div>
          )}

          {!target && <div className={styles.intakePreviewNote}>Nothing aimed at yet.</div>}

          {target && preview?.error && (
            <div className={styles.intakeDryRunError}>{preview.error}</div>
          )}

          {target && !preview?.error && (
            <>
              <div className={styles.intakeDryRunHead}>
                <span className={styles.intakeDryRunCount}>
                  {previewing || !preview
                    ? "Checking…"
                    : preview.would_add === 0
                      ? "Adds nothing right now"
                      : `Adds ${preview.would_add} article${preview.would_add === 1 ? "" : "s"}`}
                </span>
                {preview && preview.already_held > 0 && (
                  <span className={styles.intakeMeta}>{preview.already_held} already here</span>
                )}
                <button
                  type="button"
                  className={styles.intakePrimary}
                  disabled={blocked}
                  title="Take these and every later one, without being asked again"
                  onClick={follow}
                >
                  {addSource.isPending ? "Following…" : "Follow"}
                </button>
              </div>

              {preview && preview.unknown_fields.length > 0 && (
                <div className={styles.intakeDryRunWarn}>
                  {preview.unknown_fields.map((f) => `${f}:`).join(", ")}{" "}
                  {preview.unknown_fields.length === 1 ? "is not a field" : "are not fields"} — matched as plain
                  text. Check the reference before following this.
                </div>
              )}

              {preview && preview.preview.length > 0 && (
                <div className={styles.intakePreview}>
                  {preview.preview.map((item) => (
                    <button
                      key={item.entry_id}
                      type="button"
                      className={styles.intakePreviewRow}
                      onClick={() => onOpenArticle?.(item.entry_id)}
                    >
                      {item.title || "Untitled"}
                    </button>
                  ))}
                  {preview.would_add > preview.preview.length && (
                    <div className={styles.intakePreviewNote}>
                      + {preview.would_add - preview.preview.length} more
                    </div>
                  )}
                </div>
              )}

              {preview && preview.would_add === 0 && !previewing && (
                <div className={styles.intakePreviewNote}>
                  {preview.already_held > 0
                    ? "Everything it matches is already in this campaign. Following it still catches what comes next."
                    : "Following it anyway is fine — it will take whatever starts matching."}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

/** The one result list the entity and story tabs share. */
function HitList({
  hits,
  empty,
  busy,
}: {
  hits: Array<{ key: string; label: string; meta?: string; onPick: () => void }>;
  empty: string;
  busy: boolean;
}) {
  if (hits.length === 0) {
    return <div className={styles.intakePreviewNote}>{empty}</div>;
  }
  return (
    <div className={styles.intakePicker} aria-busy={busy}>
      {hits.map((hit) => (
        <button key={hit.key} type="button" className={styles.intakePick} onClick={hit.onPick}>
          <span className={styles.intakeLabel}>{hit.label}</span>
          {hit.meta && <span className={styles.intakeQuery}>{hit.meta}</span>}
        </button>
      ))}
    </div>
  );
}
