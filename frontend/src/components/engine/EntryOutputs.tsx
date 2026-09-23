import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { entityProfilePath } from "@/components/entityProfile/entityProfileConfig";
import { useAllRelationships, useEntityLinks, useUnlink } from "@/hooks/useAutolinking";
import { useConfirmExtraction, useDeleteExtractionEntity, useExtractionEntities } from "@/hooks/useExtraction";
import {
  useConfirmRelationship,
  useDeleteRelationship,
  useRejectRelationship,
} from "@/hooks/useRelationships";
import type { EntityType } from "@/stores/intelStore";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";

import styles from "./EngineMatrix.module.css";

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

  return (
    <div className={styles.outputsZone}>
      <p className={styles.ozSub}>Links — entry → entity ({linksQ.data?.total ?? "…"})</p>
      {links.map((l) => (
        <div key={`${l.entity_type}|${l.entity_id}`} className={styles.orow}>
          <EntityChip type={l.entity_type} id={l.entity_id} name={l.entity_name} />
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
                  !window.confirm(
                    obs
                      ? `Remove this article's sighting of "${e.name}"? The ledger row and its other sightings stay.`
                      : `Delete "${e.name}"? This removes the entity and all links. This cannot be undone.`,
                  )
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
    </div>
  );
}
