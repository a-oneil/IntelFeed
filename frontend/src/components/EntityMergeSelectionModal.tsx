/**
 * EntityMergeSelectionModal — fold the rows checked in a workbench entity table
 * into one profile. Same engine as EntityMergeIntoModal (one
 * POST /entities/{type}/merge carrying the keeper plus every target), differing
 * only in where the candidates come from — an existing selection instead of a
 * search — so it shares that modal's stylesheet.
 */
import { useState } from "react";
import { toast } from "sonner";
import { useMergeEntities } from "@/hooks/useEntityProfile";
import { getEntityPluralLabel, getEntityLabel } from "@/utils/entityTheme";
import styles from "./EntityMergeIntoModal.module.css";

export interface MergeSelectionEntity {
  id: string;
  name: string;
  aliases?: string[] | null;
  article_count?: number | null;
}

function mergeErrorMessage(err: unknown): string {
  const data = (err as { response?: { data?: { error?: { message?: string }; message?: string } } })?.response?.data;
  return data?.error?.message || data?.message || (err as Error)?.message || "Unknown error";
}

/** The richest profile is the sane default keeper — it has the most to lose. */
function defaultKeeper(entities: MergeSelectionEntity[]): string {
  return entities.reduce((best, e) =>
    (e.article_count ?? 0) > (best.article_count ?? 0) ? e : best,
  ).id;
}

export function EntityMergeSelectionModal({
  entityType,
  entities,
  onClose,
  onMerged,
}: {
  entityType: string;
  /** The checked rows, in table order. Two or more. */
  entities: MergeSelectionEntity[];
  onClose: () => void;
  /** Called after a successful merge, so the table can drop its selection. */
  onMerged?: () => void;
}) {
  const [keeperId, setKeeperId] = useState(() => defaultKeeper(entities));
  const mergeMutation = useMergeEntities();

  const keeper = entities.find((e) => e.id === keeperId) ?? entities[0];
  const losers = entities.filter((e) => e.id !== keeper.id);
  const typeLabel = getEntityLabel(entityType).toLowerCase();

  const handleMerge = async () => {
    try {
      await mergeMutation.mutateAsync({
        entityType,
        keeperId: keeper.id,
        mergeIds: losers.map((e) => e.id),
      });
      toast.success(
        `Merged ${losers.length} ${losers.length === 1 ? typeLabel : `${typeLabel}s`} into "${keeper.name}"`,
      );
      onMerged?.();
      onClose();
    } catch {
      // surfaced via mergeMutation.isError below
    }
  };

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div
        className={styles.modal}
        role="dialog"
        aria-label="Merge selected entities"
        onClick={(e) => e.stopPropagation()}
      >
        <div className={styles.modalHeader}>
          <h3>
            Merge {entities.length} {getEntityPluralLabel(entityType).toLowerCase()}
          </h3>
          <button className={styles.closeBtn} onClick={onClose}>
            &times;
          </button>
        </div>

        <div className={styles.body}>
          {mergeMutation.isError && (
            <div className={styles.errorMsg}>Merge failed: {mergeErrorMessage(mergeMutation.error)}</div>
          )}

          <div className={styles.confirmTitle}>Which profile should be kept?</div>
          <div className={styles.results}>
            {entities.map((e) => (
              <label
                key={e.id}
                className={`${styles.resultRow} ${e.id === keeper.id ? styles.keepOptionSelected : ""}`}
              >
                <input
                  type="radio"
                  name="merge-keeper"
                  checked={e.id === keeper.id}
                  onChange={() => setKeeperId(e.id)}
                />
                <div className={styles.resultInfo}>
                  <div className={styles.resultName}>{e.name}</div>
                  {e.aliases && e.aliases.length > 0 && (
                    <div className={styles.resultMeta}>Aliases: {e.aliases.join(", ")}</div>
                  )}
                </div>
                <span className={styles.articleCount}>
                  {e.article_count ?? 0} article{(e.article_count ?? 0) === 1 ? "" : "s"}
                </span>
              </label>
            ))}
          </div>

          <div className={styles.warning}>
            <strong>{losers.map((e) => e.name).join(", ")}</strong>
            {losers.length === 1 ? " will be deleted. Its" : " will be deleted. Their"} article links,
            aliases, and relationships will be merged into <strong>{keeper.name}</strong>. This cannot
            be undone.
          </div>

          <div className={styles.confirmActions}>
            <button className={styles.secondaryBtn} onClick={onClose} disabled={mergeMutation.isPending}>
              Cancel
            </button>
            <button className={styles.mergeBtn} onClick={handleMerge} disabled={mergeMutation.isPending}>
              {mergeMutation.isPending ? "Merging…" : `Merge ${losers.length} into "${keeper.name}"`}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
