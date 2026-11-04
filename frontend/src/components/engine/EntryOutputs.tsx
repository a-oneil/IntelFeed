import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import api from "@/api/client";

import { entityProfilePath } from "@/components/entityProfile/entityProfileConfig";
import { useAllRelationships, useEntityLinks, useUnlink } from "@/hooks/useAutolinking";
import { useEntryAdjudication, type EntryAdjudicationVerdict } from "@/hooks/useEngine";
import { useConfirmExtraction, useDeleteExtractionEntity, useExtractionEntities } from "@/hooks/useExtraction";
import {
  useConfirmRelationship,
  useDeleteRelationship,
  useRejectRelationship,
} from "@/hooks/useRelationships";
import type { EntityType } from "@/stores/intelStore";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";

import styles from "./EngineMatrix.module.css";
import { skipReason } from "./adjudicationCopy";
import { confirmDialog } from "@/utils/dialog";

const SOURCE_LABELS: Record<string, string> = {
  auto_link: "Autolinker",
  ai: "AI extraction",
  ai_reconcile: "AI reconcile",
  auto_extracted: "Auto-extracted",
  manual: "Analyst",
  co_occurrence: "Co-occurrence",
  analyst_created: "Analyst",
  analyst_confirmed: "Confirmed",
};

function srcClass(source: string | null): string {
  if (source === "auto_link") return styles.srcAuto;
  if (source === "ai" || source === "ai_reconcile") return styles.srcAi;
  return styles.srcNeutral;
}

function EntityChip({ type, id, name }: { type: string; id: string; name: string | null | undefined }) {
  const navigate = useNavigate();
  return (
    <button
      type="button"
      className={styles.entChip}
      title={`Open ${getEntityLabel(type)} profile`}
      onClick={() => navigate(entityProfilePath(type as EntityType, id))}
    >
      <span className={styles.entDot} style={{ background: getEntityCssVar(type) }} />
      <span className={styles.entName}>{name ?? "(unknown)"}</span>
      <span className={styles.entType}>{getEntityLabel(type)}</span>
    </button>
  );
}

const LIST_LIMIT = 25;

function fmtDuration(ms: number | null | undefined): string {
  if (ms == null) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

/** `ioc:<kind>:<value>` — the value may itself contain colons (URLs, IPv6). */
function parseIocItemId(itemId: string): { kind: string; value: string } {
  const m = /^ioc:([^:]*):(.*)$/.exec(itemId);
  return m ? { kind: m[1], value: m[2] } : { kind: "", value: itemId };
}

const VERDICT_LABEL: Record<string, string> = {
  keep: "keep",
  remove: "remove",
  reclassify: "reclassify",
  veto: "veto",
  merge: "merge",
  demote: "demote",
  drop: "drop",
  link: "link",
  capture: "capture",
};

/** The adjudicate stage's verdict for one drawer row, as a badge with the
 *  matching action: Apply while it is a shadow proposal, Restore once it was
 *  applied. Dashed = proposed; solid = applied. */
function VerdictBadge({ verdict, entryId }: { verdict: EntryAdjudicationVerdict | undefined; entryId: string }) {
  const qc = useQueryClient();
  if (!verdict || verdict.verdict === "keep") return null;
  const [logSource, logId] = verdict.log.split(":");
  const maint = logSource === "entity_maintenance";
  const canApply = !verdict.applied && !verdict.restored && verdict.kind !== "assessment";
  // Merges are undone from the merge engine's tombstone, not from here.
  const canRestore = verdict.applied && !verdict.restored && verdict.verdict !== "merge";
  const run = async (what: "apply" | "restore") => {
    try {
      if (maint) {
        const res = await api.post<{ applied: boolean; restored: boolean; reason: string | null }>(
          `/admin/hygiene/adjudication/${logId}/${what}`,
        );
        const ok = what === "apply" ? res.data.applied : res.data.restored;
        if (ok) toast.success(what === "apply" ? "Applied" : "Restored");
        else toast.message(res.data.reason ?? "Nothing to do");
      } else {
        await api.post(`/admin/hygiene/link-log/${logId}/${what === "apply" ? "apply-removal" : "restore"}`);
        toast.success(what === "apply" ? "Link removed" : "Link restored");
      }
      qc.invalidateQueries({ queryKey: ["engine", "adjudication", entryId] });
      qc.invalidateQueries({ queryKey: ["hygiene"] });
      qc.invalidateQueries({ queryKey: ["entity-links"] });
      qc.invalidateQueries({ queryKey: ["relationships"] });
      qc.invalidateQueries({ queryKey: ["extraction"] });
    } catch (e) {
      toast.error(`${what === "apply" ? "Apply" : "Restore"} failed: ${(e as Error).message}`);
    }
  };
  const label = VERDICT_LABEL[verdict.verdict] ?? verdict.verdict;
  const detail =
    verdict.verdict === "merge" && verdict.merge_into
      ? `${label} → ${verdict.merge_into}`
      : verdict.verdict === "reclassify" && verdict.suggested_type
        ? `${label} → ${verdict.suggested_type}`
        : label;
  const state = verdict.restored
    ? " (applied, then restored by an analyst)"
    : verdict.applied
      ? " (applied)"
      : " (proposed, not applied)";
  const title = `AI review: ${detail}${state}${verdict.reason ? ` — ${verdict.reason}` : ""}`;
  return (
    <>
      <span className={`${styles.verdictPill} ${verdict.applied ? styles.verdictApplied : styles.verdictShadow}`} title={title}>
        {detail}
      </span>
      {canApply && (
        <button type="button" className={styles.verdictBtn} title="Apply this verdict now" onClick={() => run("apply")}>
          apply
        </button>
      )}
      {canRestore && (
        <button type="button" className={styles.verdictBtn} title="Undo this applied verdict" onClick={() => run("restore")}>
          restore
        </button>
      )}
    </>
  );
}

/** Drawer zone: everything the engine produced for one entry — links,
 *  relationships, created entities — each manageable in place. */
export function EntryOutputs({ entryId }: { entryId: string }) {
  const linksQ = useEntityLinks({ entry_id: entryId, limit: LIST_LIMIT, offset: 0 });
  const relsQ = useAllRelationships({ evidence_entry_id: entryId, limit: LIST_LIMIT, offset: 0 });
  const createdQ = useExtractionEntities({ source_entry_id: entryId, window: "all", limit: LIST_LIMIT, offset: 0 });

  const unlink = useUnlink();
  const confirmRel = useConfirmRelationship();
  const rejectRel = useRejectRelationship();
  const deleteRel = useDeleteRelationship();
  const confirmEntity = useConfirmExtraction();
  const deleteEntity = useDeleteExtractionEntity();
  const navigate = useNavigate();

  const links = linksQ.data?.items ?? [];
  const rels = relsQ.data?.items ?? [];
  const created = createdQ.data?.items ?? [];
  const loading = linksQ.isLoading || relsQ.isLoading || createdQ.isLoading;

  const adjQ = useEntryAdjudication(entryId);
  const verdictById = new Map<string, EntryAdjudicationVerdict>();
  for (const v of adjQ.data?.verdicts ?? []) verdictById.set(v.item_id, v);
  const adjRun = adjQ.data?.run;
  const adjDetail = adjRun?.detail as
    | { mode?: string; items?: number; verdicts?: Record<string, number>; skipped?: string }
    | null
    | undefined;
  const adjStatus = adjQ.data?.status;
  const adjMode = adjRun?.mode ?? adjDetail?.mode;
  const adjDur = fmtDuration(adjRun?.duration_ms);
  const adjSummary =
    adjStatus === "completed" && adjDetail
      ? adjDetail.skipped
        ? `AI review: skipped — ${skipReason(adjDetail.skipped)}`
        : `AI review: ${[adjDur ? `reviewed in ${adjDur}` : "reviewed", adjMode ?? "shadow"].join(" · ")} · ${
            adjDetail.items ?? 0
          } items · ${
            Object.entries(adjDetail.verdicts ?? {})
              .filter(([k]) => k !== "keep")
              .map(([k, n]) => `${n} ${k}`)
              .join(", ") || "all kept"
          }${adjMode === "apply" ? " · applied" : " · proposals only"}`
      : adjStatus === "pending"
        ? "AI review: queued"
        : adjStatus === "recheck"
          ? "AI review: reviewed; queued again to check held matches settled since"
          : adjStatus?.startsWith("skipped_")
            ? `AI review: skipped — ${skipReason(adjStatus.replace("skipped_", ""))}`
            : null;
  const iocVerdicts = (adjQ.data?.verdicts ?? []).filter((v) => v.kind === "ioc");
  const heldVerdicts = (adjQ.data?.verdicts ?? []).filter((v) => v.kind === "held");
  const assessment = (adjQ.data?.verdicts ?? []).find((v) => v.kind === "assessment");

  return (
    <div className={styles.outputsZone}>
      {adjSummary && <p className={styles.ozAdj}>{adjSummary}</p>}
      <p className={styles.ozSub}>Links — entry → entity ({linksQ.data?.total ?? "…"})</p>
      {links.map((l) => (
        <div key={`${l.entity_type}|${l.entity_id}`} className={styles.orow}>
          <EntityChip type={l.entity_type} id={l.entity_id} name={l.entity_name} />
          <VerdictBadge verdict={verdictById.get(`link:${l.entity_type}:${l.entity_id}`)} entryId={entryId} />
          {l.matched_names?.length ? <span className={styles.surf}>{l.matched_names[0]}</span> : null}
          <span className={`${styles.srcPill} ${srcClass(l.source)}`}>
            {SOURCE_LABELS[l.source ?? ""] ?? l.source ?? "unattributed"}
          </span>
          {l.confidence && <span className={styles.popMuted}>{l.confidence}</span>}
          <span className={styles.oActs}>
            <button
              type="button"
              className={`${styles.iact} ${styles.iactDanger}`}
              title="Unlink from this entry"
              onClick={async () => {
                await unlink.mutateAsync({
                  entity_type: l.entity_type,
                  entity_id: l.entity_id,
                  entry_id: l.entry_id,
                });
                toast.success("Link removed");
              }}
            >
              ✕
            </button>
          </span>
        </div>
      ))}
      {!loading && links.length === 0 && <div className={styles.ozEmpty}>No entity links.</div>}
      {(linksQ.data?.total ?? 0) > LIST_LIMIT && (
        <div className={styles.ozMore}>+{(linksQ.data?.total ?? 0) - LIST_LIMIT} more — see Links browser</div>
      )}

      <p className={styles.ozSub}>Relationships evidenced here ({relsQ.data?.total ?? "…"})</p>
      {rels.map((r) => (
        <div key={r.id} className={styles.orow}>
          <EntityChip type={r.source_type} id={r.source_id} name={r.source_name} />
          <span className={styles.verb}>{r.relationship_type}</span>
          <EntityChip type={r.target_type} id={r.target_id} name={r.target_name} />
          <VerdictBadge verdict={verdictById.get(`edge:${r.id}`)} entryId={entryId} />
          <span className={`${styles.srcPill} ${srcClass(r.source)}`}>
            {SOURCE_LABELS[r.source ?? ""] ?? r.source ?? "—"}
          </span>
          <span className={styles.oActs}>
            <button
              type="button"
              className={`${styles.iact} ${styles.iactGood}`}
              title="Confirm relationship"
              onClick={async () => {
                await confirmRel.mutateAsync(r.id);
                toast.success("Relationship confirmed");
              }}
            >
              ✓
            </button>
            <button
              type="button"
              className={styles.iact}
              title="Reject relationship"
              onClick={async () => {
                await rejectRel.mutateAsync(r.id);
                toast.success("Relationship rejected");
              }}
            >
              ∅
            </button>
            <button
              type="button"
              className={`${styles.iact} ${styles.iactDanger}`}
              title="Delete relationship"
              onClick={async () => {
                await deleteRel.mutateAsync(r.id);
                toast.success("Relationship deleted");
              }}
            >
              ✕
            </button>
          </span>
        </div>
      ))}
      {!loading && rels.length === 0 && <div className={styles.ozEmpty}>No relationships cite this entry.</div>}

      <p className={styles.ozSub}>Entities created by this entry ({createdQ.data?.total ?? "…"})</p>
      {created.map((e) => (
        <div key={e.id} className={styles.orow}>
          <EntityChip type={e.entity_type} id={e.id} name={e.name} />
          <span className={styles.newTag}>NEW</span>
          <VerdictBadge verdict={verdictById.get(`link:${e.entity_type}:${e.id}`)} entryId={entryId} />
          <span className={styles.popMuted}>
            {e.article_count} linked {e.article_count === 1 ? "entry" : "entries"}
            {e.created_confidence ? ` · ${e.created_confidence}` : ""}
          </span>
          <span className={styles.oActs}>
            {e.needs_review && (
              <button
                type="button"
                className={`${styles.iact} ${styles.iactGood}`}
                title="Confirm entity"
                onClick={async () => {
                  await confirmEntity.mutateAsync({ entityType: e.entity_type, ids: [e.id] });
                  toast.success(`Confirmed "${e.name}"`);
                }}
              >
                ✓
              </button>
            )}
            <button
              type="button"
              className={styles.iact}
              title="Open profile"
              onClick={() => navigate(`/workbench/${e.entity_type}/${e.id}`)}
            >
              ↗
            </button>
            <button
              type="button"
              className={`${styles.iact} ${styles.iactDanger}`}
              title={
                e.entity_type === "observable"
                  ? "Remove this article's sighting (the ledger row stays)"
                  : "Delete entity and all its links"
              }
              onClick={async () => {
                // Per-entry context: an observable ✕ removes THIS article's
                // sighting only. The global tombstone lives on the ledger row
                // (Extraction tab / profile), where its blast radius is clear.
                const obs = e.entity_type === "observable";
                if (
                  !(await confirmDialog({
                    title: obs ? "Remove sighting" : "Delete entity",
                    message: obs
                      ? `Remove this article's sighting of "${e.name}"? The ledger row and its other sightings stay.`
                      : `Delete "${e.name}"? This removes the entity and all links. This cannot be undone.`,
                    confirmLabel: obs ? "Remove sighting" : "Delete",
                    destructive: true,
                  }))
                )
                  return;
                try {
                  await deleteEntity.mutateAsync({ entityType: e.entity_type, id: e.id, entryId });
                  toast.success(obs ? `Removed the sighting of "${e.name}"` : `Deleted "${e.name}"`);
                } catch {
                  toast.error(obs ? "No sighting to remove for this article" : `Failed to delete "${e.name}"`);
                }
              }}
            >
              ✕
            </button>
          </span>
        </div>
      ))}
      {!loading && created.length === 0 && <div className={styles.ozEmpty}>No entities were created from this entry.</div>}

      {/* The review's observable verdicts. The drawer has no sightings list of
          its own, so each ioc verdict is its own row: kind · value, the badge
          (Apply while proposed, Restore once applied), and the reason. */}
      {iocVerdicts.length > 0 && (
        <>
          <p className={styles.ozSub}>Observables — review verdicts ({iocVerdicts.length})</p>
          {iocVerdicts.map((v) => {
            const { kind, value } = parseIocItemId(v.item_id);
            return (
              <div key={v.item_id} className={styles.orow} data-testid="ioc-verdict">
                {kind && <span className={styles.surf}>{kind}</span>}
                {v.entity_id ? (
                  <EntityChip type="observable" id={v.entity_id} name={value} />
                ) : (
                  <span className={styles.entName} title={value}>
                    {value}
                  </span>
                )}
                <VerdictBadge verdict={v} entryId={entryId} />
                {v.reason && <span className={styles.popMuted}>{v.reason}</span>}
              </div>
            );
          })}
        </>
      )}

      {/* Held matches the analysis rejected and the review would link. Until
          the verdict is applied there is no link row to badge, so each gets
          its own row: the entity, the badge and the reason. */}
      {heldVerdicts.length > 0 && (
        <>
          <p className={styles.ozSub}>Held matches — review verdicts ({heldVerdicts.length})</p>
          {heldVerdicts.map((v) => (
            <div key={v.item_id} className={styles.orow} data-testid="held-verdict">
              {v.entity_type && v.entity_id && <EntityChip type={v.entity_type} id={v.entity_id} name={v.name} />}
              <VerdictBadge verdict={v} entryId={entryId} />
              {v.reason && <span className={styles.popMuted}>{v.reason}</span>}
            </div>
          ))}
        </>
      )}

      {/* The review's read on the analysis itself — logged, never applied. */}
      {assessment && (
        <>
          <p className={styles.ozSub}>Assessment</p>
          <div className={styles.orow} data-testid="assessment-verdict">
            <span className={styles.entName}>severity/summary</span>
            <span
              className={`${styles.verdictPill} ${assessment.verdict === "ok" ? styles.verdictOk : styles.verdictShadow}`}
              title={`AI review: the analysis's severity/summary reads as ${assessment.verdict}`}
            >
              {assessment.verdict}
            </span>
            {assessment.reason && <span className={styles.popMuted}>{assessment.reason}</span>}
            <span className={styles.loggedOnly} title="Assessment verdicts are recorded for the record; nothing is changed">
              logged only
            </span>
          </div>
        </>
      )}
    </div>
  );
}
