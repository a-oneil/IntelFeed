/**
 * EntityMergeIntoModal — search for another profile of the same type and merge
 * it with the one currently being viewed. The user chooses which profile is
 * kept; the other is absorbed (entry links, aliases, relationships) and deleted.
 */
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  useEntitySearch,
  useMergeEntities,
  type MergeCandidate,
} from "@/hooks/useEntityProfile";
import { getEntityLabel } from "@/utils/entityTheme";
import { Chip } from "@/components/primitives/Chip";
import styles from "./EntityMergeIntoModal.module.css";

function mergeErrorMessage(err: unknown): string {
  const detail = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
  return detail || (err as Error)?.message || "Unknown error";
}

interface Props {
  entityType: string;
  keeperId: string;
  keeperName: string;
  onClose: () => void;
  /** Called after a successful merge (the current profile may have been merged away). */
  onMerged?: () => void;
}

export function EntityMergeIntoModal({ entityType, keeperId, keeperName, onClose, onMerged }: Props) {
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [selected, setSelected] = useState<MergeCandidate | null>(null);
  // Which profile survives: the one being viewed, or the searched one.
  const [keepCurrent, setKeepCurrent] = useState(true);

  const mergeMutation = useMergeEntities();

  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 250);
    return () => clearTimeout(t);
  }, [query]);

  const { data: results, isFetching } = useEntitySearch(
    entityType,
    debounced,
    debounced.length > 0,
  );

  const candidates = (results ?? []).filter((c) => c.id !== keeperId);

  const typeLabel = getEntityLabel(entityType);

  const handleMerge = async () => {
    if (!selected) return;
    const keeperFinalId = keepCurrent ? keeperId : selected.id;
    const mergedId = keepCurrent ? selected.id : keeperId;
    const keptName = keepCurrent ? keeperName : selected.name;
    const removedName = keepCurrent ? selected.name : keeperName;
    try {
      await mergeMutation.mutateAsync({
        entityType,
        keeperId: keeperFinalId,
        mergeIds: [mergedId],
      });
      toast.success(`Merged "${removedName}" into "${keptName}"`);
      onMerged?.();
      onClose();
    } catch {
      // surfaced via mergeMutation.isError below
    }
  };

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <h3>Merge {typeLabel}</h3>
          <button className={styles.closeBtn} onClick={onClose}>
            &times;
          </button>
        </div>

        <div className={styles.body}>
          <div className={styles.currentRow}>
            <span className={styles.currentLabel}>Current profile</span>
            <span className={styles.currentName}>{keeperName}</span>
          </div>

          {mergeMutation.isError && (
            <div className={styles.errorMsg}>
              Merge failed: {mergeErrorMessage(mergeMutation.error)}
            </div>
          )}

          <label className={styles.searchLabel}>
            Find a {typeLabel.toLowerCase()} to merge with
          </label>
          <input
            className={styles.searchInput}
            type="text"
            value={query}
            autoFocus
            placeholder={`Search ${typeLabel.toLowerCase()} by name…`}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelected(null);
            }}
          />

          {!selected && (
            <div className={styles.results}>
              {debounced.length === 0 ? (
                <div className={styles.hint}>Start typing to search.</div>
              ) : isFetching ? (
                <div className={styles.hint}>Searching…</div>
              ) : candidates.length === 0 ? (
                <div className={styles.hint}>No other {typeLabel.toLowerCase()} matched.</div>
              ) : (
                candidates.map((c) => (
                  <button
                    key={c.id}
                    className={styles.resultRow}
                    onClick={() => setSelected(c)}
                  >
                    <div className={styles.resultInfo}>
                      <div className={styles.resultName}>
                        {c.name}
                        {c.mitre_id && (
                          <Chip tone="toned" tint="var(--accent)" className={styles.badge}>
                            {c.mitre_id}
                          </Chip>
                        )}
                      </div>
                      {c.aliases && c.aliases.length > 0 && (
                        <div className={styles.resultMeta}>Aliases: {c.aliases.join(", ")}</div>
                      )}
                    </div>
                    <span className={styles.articleCount}>{c.article_count ?? 0} articles</span>
                  </button>
                ))
              )}
            </div>
          )}

          {selected && (
            <div className={styles.confirmBox}>
              <div className={styles.confirmTitle}>Which profile should be kept?</div>
              <label className={`${styles.keepOption} ${keepCurrent ? styles.keepOptionSelected : ""}`}>
                <input
                  type="radio"
                  name="keep"
                  checked={keepCurrent}
                  onChange={() => setKeepCurrent(true)}
                />
                <span className={styles.keepName}>{keeperName}</span>
                <span className={styles.keepNote}>current</span>
              </label>
              <label className={`${styles.keepOption} ${!keepCurrent ? styles.keepOptionSelected : ""}`}>
                <input
                  type="radio"
                  name="keep"
                  checked={!keepCurrent}
                  onChange={() => setKeepCurrent(false)}
                />
                <span className={styles.keepName}>{selected.name}</span>
                <span className={styles.keepNote}>{selected.article_count ?? 0} articles</span>
              </label>

              <div className={styles.warning}>
                <strong>{keepCurrent ? selected.name : keeperName}</strong> will be deleted. Its
                article links, aliases, and relationships will be merged into{" "}
                <strong>{keepCurrent ? keeperName : selected.name}</strong>. This cannot be undone.
              </div>

              <div className={styles.confirmActions}>
                <button
                  className={styles.secondaryBtn}
                  onClick={() => setSelected(null)}
                  disabled={mergeMutation.isPending}
                >
                  Back
                </button>
                <button
                  className={styles.mergeBtn}
                  onClick={handleMerge}
                  disabled={mergeMutation.isPending}
                >
                  {mergeMutation.isPending ? "Merging…" : "Merge profiles"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
