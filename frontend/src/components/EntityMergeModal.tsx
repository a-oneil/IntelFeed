import { useState } from "react";
import {
  useDismissMergeSuggestion,
  useFindDuplicates,
  useMergeEntities,
  useMergeSuggestions,
  type DuplicateGroup,
  type MergeSuggestion,
} from "@/hooks/useEntityProfile";
import { Chip } from "./primitives";
import styles from "./EntityMergeModal.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

const ENTITY_TYPE_LABELS: Record<string, string> = {
  threat_actor: "Threat Actors",
  malware: "Malware Families",
  country: "Countries",
  tool: "Tools",
};

const REASON_LABELS: Record<string, string> = {
  name_substring: "Name substring match",
  name_in_aliases: "Name found in aliases",
  name_after_normalization: "Same name after normalization",
  primary: "Primary entity",
};

interface Props {
  entityType: string;
  onClose: () => void;
}

export function EntityMergeModal({ entityType, onClose }: Props) {
  const { data, isLoading } = useFindDuplicates(entityType, true);
  const suggestionsQuery = useMergeSuggestions(entityType, true);
  const mergeMutation = useMergeEntities();
  const dismissMutation = useDismissMergeSuggestion();
  const [selectedKeepers, setSelectedKeepers] = useState<
    Record<number, string>
  >({});
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const handleMergeSuggestion = async (suggestion: MergeSuggestion) => {
    try {
      const result = await mergeMutation.mutateAsync({
        entityType,
        keeperId: suggestion.keeper.id,
        mergeIds: [suggestion.candidate.id],
      });
      setSuccessMsg(
        `Merged "${suggestion.candidate.name}" into "${result.keeper.name}"`
      );
    } catch {
      // error handled by mutation state
    }
  };

  const handleDismissSuggestion = (suggestion: MergeSuggestion) => {
    dismissMutation.mutate(suggestion);
  };

  const handleSelectKeeper = (groupIndex: number, entityId: string) => {
    setSelectedKeepers((prev) => ({ ...prev, [groupIndex]: entityId }));
  };

  const handleMerge = async (groupIndex: number, group: DuplicateGroup) => {
    const keeperId = selectedKeepers[groupIndex];
    if (!keeperId) return;

    const mergeIds = group.entities
      .map((e) => e.id)
      .filter((id) => id !== keeperId);

    try {
      const result = await mergeMutation.mutateAsync({
        entityType,
        keeperId,
        mergeIds,
      });
      setSuccessMsg(
        `Merged ${result.merged_count} entities into "${result.keeper.name}"`
      );
      // Clear selection for this group
      setSelectedKeepers((prev) => {
        const next = { ...prev };
        delete next[groupIndex];
        return next;
      });
    } catch {
      // error handled by mutation state
    }
  };

  const formatReason = (reason: string) => {
    if (reason.startsWith("shared_aliases:")) {
      return reason;
    }
    return REASON_LABELS[reason] || reason;
  };

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <h3>
            Find Duplicates:{" "}
            {ENTITY_TYPE_LABELS[entityType] || entityType}
          </h3>
          <button className={styles.closeBtn} onClick={onClose}>
            &times;
          </button>
        </div>

        <div className={styles.body}>
          {successMsg && (
            <div className={styles.successMsg}>{successMsg}</div>
          )}
          {mergeMutation.isError && (
            <div className={styles.errorMsg}>
              Merge failed:{" "}
              {(mergeMutation.error as Error)?.message || "Unknown error"}
            </div>
          )}

          {(suggestionsQuery.data?.suggestions.length ?? 0) > 0 && (
            <div className={styles.suggestionsSection}>
              <div className={styles.suggestionsHeader}>
                <span className={styles.groupLabel}>
                  Suggestions ({suggestionsQuery.data!.total})
                </span>
                <span className={styles.suggestionsHint}>
                  Ranked by name similarity, alias overlap, shared
                  relationships, and co-mentions
                </span>
              </div>
              {suggestionsQuery.data!.suggestions.map((s) => (
                <SuggestionRow
                  key={`${s.keeper.id}-${s.candidate.id}`}
                  suggestion={s}
                  busy={mergeMutation.isPending || dismissMutation.isPending}
                  onMerge={handleMergeSuggestion}
                  onDismiss={handleDismissSuggestion}
                />
              ))}
            </div>
          )}

          {isLoading ? (
            <AsyncStateLoading label="Scanning for duplicates…" compact />
          ) : !data?.groups.length ? (
            <div className={styles.empty}>
              <div className={styles.emptyTitle}>No duplicates found</div>
              <div>
                All {ENTITY_TYPE_LABELS[entityType]?.toLowerCase() || "entities"}{" "}
                appear to be unique.
              </div>
            </div>
          ) : (
            data.groups.map((group, gi) => (
              <div key={gi} className={styles.group}>
                <div className={styles.groupHeader}>
                  <span className={styles.groupLabel}>
                    Potential duplicate group ({group.entities.length} entities)
                  </span>
                  <button
                    className={styles.mergeBtn}
                    disabled={
                      !selectedKeepers[gi] || mergeMutation.isPending
                    }
                    onClick={() => handleMerge(gi, group)}
                  >
                    {mergeMutation.isPending
                      ? "Merging..."
                      : "Merge into selected"}
                  </button>
                </div>
                {group.entities.map((entity) => {
                  const isKeeper = selectedKeepers[gi] === entity.id;
                  return (
                    <div
                      key={entity.id}
                      className={`${styles.entityRow} ${isKeeper ? styles.entityRowSelected : ""}`}
                      onClick={() => handleSelectKeeper(gi, entity.id)}
                    >
                      <div
                        className={`${styles.radio} ${isKeeper ? styles.radioSelected : ""}`}
                      />
                      <div className={styles.entityInfo}>
                        <div className={styles.entityName}>
                          {entity.name}
                          {entity.mitre_id && (
                            <Chip
                              tone="toned"
                              tint="var(--accent)"
                              className={styles.badge}
                            >
                              {entity.mitre_id}
                            </Chip>
                          )}
                        </div>
                        {entity.aliases?.length > 0 && (
                          <div className={styles.entityMeta}>
                            Aliases: {entity.aliases.join(", ")}
                          </div>
                        )}
                        {entity.description && (
                          <div className={styles.entityMeta}>
                            {entity.description}
                          </div>
                        )}
                        <div className={styles.reasons}>
                          {entity.match_reasons.map((r, ri) => (
                            <Chip
                              key={ri}
                              tone="toned"
                              tint="var(--warning)"
                              truncate
                              title={formatReason(r)}
                            >
                              {formatReason(r)}
                            </Chip>
                          ))}
                        </div>
                      </div>
                      <div className={styles.articleCount}>
                        {entity.article_count} articles
                      </div>
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className={styles.footer}>
          <span className={styles.footerInfo}>
            {data?.total_groups
              ? `${data.total_groups} duplicate group${data.total_groups !== 1 ? "s" : ""} found`
              : ""}
          </span>
          <button
            className={styles.mergeBtn}
            onClick={onClose}
            style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border)" }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function SuggestionRow({
  suggestion,
  busy,
  onMerge,
  onDismiss,
}: {
  suggestion: MergeSuggestion;
  busy: boolean;
  onMerge: (s: MergeSuggestion) => void;
  onDismiss: (s: MergeSuggestion) => void;
}) {
  const { keeper, candidate, score, reasons, cross_type: crossType } = suggestion;
  return (
    <div className={styles.suggestionRow}>
      <span
        className={styles.suggestionScore}
        title="Merge confidence based on name similarity, alias overlap, shared relationships, and co-mentions"
      >
        {Math.round(score * 100)}%
      </span>
      <div className={styles.entityInfo}>
        <div className={styles.entityName}>
          {candidate.name}
          <span className={styles.suggestionArrow}> → </span>
          {keeper.name}
          {crossType && (
            <Chip
              tone="toned"
              tint="var(--warning)"
              truncate
              className={`${styles.badge} ${styles.badgeCrossType}`}
            >
              possible cross-type duplicate
            </Chip>
          )}
        </div>
        <div className={styles.entityMeta}>
          {candidate.article_count} → {keeper.article_count} articles
          {crossType && ` · ${candidate.entity_type} vs ${keeper.entity_type}`}
        </div>
        <div className={styles.reasons}>
          {reasons.map((r, ri) => (
            <Chip key={ri} tone="toned" tint="var(--warning)" truncate title={r}>
              {r}
            </Chip>
          ))}
        </div>
      </div>
      <div className={styles.suggestionActions}>
        {crossType ? (
          <span
            className={styles.crossTypeNote}
            title="Cross-type pairs can't be merged directly — use Convert on the entity profile to reclassify one side first"
          >
            convert to resolve
          </span>
        ) : (
          <button
            className={styles.mergeBtn}
            disabled={busy}
            onClick={() => onMerge(suggestion)}
            title={`Merge "${candidate.name}" into "${keeper.name}" — the merged name becomes an alias of the keeper`}
          >
            Merge
          </button>
        )}
        <button
          className={styles.dismissBtn}
          disabled={busy}
          onClick={() => onDismiss(suggestion)}
          title="Not a duplicate — never suggest this pair again"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}
