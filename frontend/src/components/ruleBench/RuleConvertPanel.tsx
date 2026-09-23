import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import api from "@/api/client";
import RuleBuilderShell from "@/components/RuleBuilderShell";
import { formatDateTime } from "@/utils/formatDate";
import bench from "./bench.module.css";
import styles from "./RuleConvertPanel.module.css";

export interface RuleConversion {
  content: string;
  converted_at: string;
  model: string;
  tokens_used?: number;
  cost?: number;
}

/** A converted rule, now a real row of its own hanging off `derived_from`. */
interface ConversionSibling {
  id: string;
  rule_type: string;
  title: string;
  rule_content: string;
  is_draft: boolean;
  updated_at: string;
  metadata: Record<string, unknown> | null;
}

interface RuleConvertPanelProps {
  ruleId?: string;
  ruleType: string;
  typeLabels: Record<string, string>;
  /** Legacy `metadata.rule_conversions` blob — read-only fallback, see below. */
  conversions: Record<string, RuleConversion>;
  activeType: string | null;
  /** The target format currently converting, or null. Only that button reads
      "Converting…" — the rest stay labelled (though disabled) so the panel
      doesn't look like it's converting to every format at once. */
  convertingType: string | null;
  onSelect: (type: string | null) => void;
  onConvert: (type: string) => void;
  onRemove: (type: string) => void;
  onUpdateContent: (type: string, content: string) => void;
}

/** Provenance the convert endpoint records on the sibling it writes. */
function conversionMeta(sibling: ConversionSibling): RuleConversion | null {
  const meta = sibling.metadata?.conversion as Record<string, unknown> | undefined;
  if (!meta) return null;
  return {
    content: sibling.rule_content,
    converted_at: (meta.converted_at as string) || sibling.updated_at,
    model: (meta.model as string) || "unknown",
    tokens_used: meta.tokens_used as number | undefined,
    cost: meta.cost as number | undefined,
  };
}

/**
 * Conversions are sibling rules, not a blob on the parent — searchable,
 * versioned, exportable and no longer deleted along with what they came from.
 *
 * The old `metadata.rule_conversions` blob is still read for anything the
 * backfill has not promoted yet, and a sibling always wins over a blob entry of
 * the same format. Blob entries stay editable through the parent's autosave
 * (the props below); siblings save as themselves.
 */
export function RuleConvertPanel({
  ruleId,
  ruleType,
  typeLabels,
  conversions,
  activeType,
  convertingType,
  onSelect,
  onConvert,
  onRemove,
  onUpdateContent,
}: RuleConvertPanelProps) {
  const qc = useQueryClient();
  const siblingsKey = ["rule-conversions", ruleId];

  const siblings = useQuery({
    queryKey: siblingsKey,
    enabled: Boolean(ruleId),
    queryFn: async () => {
      const { data } = await api.get<ConversionSibling[]>(`/detection-rules/${ruleId}/conversions`);
      return data;
    },
  });

  const byType = new Map((siblings.data ?? []).map((s) => [s.rule_type, s]));
  // Blob entries the backfill has not reached; siblings shadow their own format.
  const legacyTypes = Object.keys(conversions).filter((t) => !byType.has(t));
  const existing = [...byType.keys(), ...legacyTypes].sort();

  // A conversion writes a new sibling server-side, so the list is stale the
  // moment the mutation the parent owns settles.
  useEffect(() => {
    if (convertingType === null && ruleId) qc.invalidateQueries({ queryKey: siblingsKey });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [convertingType, ruleId]);

  const activeSibling = activeType ? byType.get(activeType) : undefined;
  const activeLegacy = activeType && !activeSibling ? conversions[activeType] : undefined;

  const [draft, setDraft] = useState<string | null>(null);
  useEffect(() => setDraft(null), [activeSibling?.id]);

  const save = useMutation({
    mutationFn: async ({ id, content }: { id: string; content: string }) => {
      await api.put(`/detection-rules/${id}`, { rule_content: content });
    },
    onSuccess: () => {
      setDraft(null);
      qc.invalidateQueries({ queryKey: siblingsKey });
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
      toast.success("Conversion saved");
    },
    onError: () => toast.error("Could not save the conversion"),
  });

  const remove = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/detection-rules/${id}`);
    },
    onSuccess: (_data, id) => {
      const removed = (siblings.data ?? []).find((s) => s.id === id);
      if (removed && activeType === removed.rule_type) onSelect(null);
      qc.invalidateQueries({ queryKey: siblingsKey });
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
      toast.success("Conversion deleted");
    },
    onError: () => toast.error("Could not delete the conversion"),
  });

  const meta = activeSibling ? conversionMeta(activeSibling) : activeLegacy;
  const body = draft ?? activeSibling?.rule_content ?? activeLegacy?.content ?? "";

  return (
    <>
      <div className={bench.railLabel}>Convert this {typeLabels[ruleType] || ruleType} rule</div>
      <div className={styles.grid}>
        {Object.entries(typeLabels)
          .filter(([k]) => k !== ruleType)
          .map(([k, v]) => (
            <button
              key={k}
              type="button"
              className={styles.option}
              onClick={() => onConvert(k)}
              disabled={convertingType !== null}
            >
              {convertingType === k ? "Converting…" : `→ ${v}`}
            </button>
          ))}
      </div>

      {existing.length > 0 && (
        <>
          <div className={bench.railLabel}>
            Existing conversions<b>{existing.length}</b>
          </div>
          <div className={styles.tabs}>
            {existing.map((type) => (
              <button
                key={type}
                type="button"
                className={`${styles.tab} ${activeType === type ? styles.tabActive : ""}`}
                onClick={() => onSelect(activeType === type ? null : type)}
              >
                {typeLabels[type] || type}
                {!byType.has(type) && <span className={styles.legacyDot} title="Not yet a rule of its own" />}
              </button>
            ))}
          </div>
        </>
      )}

      {activeType && (activeSibling || activeLegacy) && (
        <div className={styles.editor}>
          <div className={styles.editorHead}>
            <span className={styles.editorMeta}>
              {meta?.model}
              {meta?.tokens_used != null && <> &middot; {meta.tokens_used.toLocaleString()} tokens</>}
              {meta?.cost != null && meta.cost > 0 && <> &middot; ${meta.cost.toFixed(4)}</>}
              {meta?.converted_at && <> &middot; {formatDateTime(meta.converted_at)}</>}
            </span>
            {activeSibling && (
              <Link className={bench.btn} to={`/workbench/rule/${activeSibling.id}`}>
                Open rule
              </Link>
            )}
            <button type="button" className={bench.btn} onClick={() => onConvert(activeType)} disabled={convertingType !== null}>
              {convertingType === activeType ? "Converting…" : "Re-convert"}
            </button>
            {activeSibling ? (
              <>
                <button
                  type="button"
                  className={bench.btn}
                  disabled={draft === null || save.isPending}
                  onClick={() => save.mutate({ id: activeSibling.id, content: draft ?? "" })}
                >
                  {save.isPending ? "Saving…" : "Save"}
                </button>
                <button
                  type="button"
                  className={bench.btn}
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(activeSibling.id)}
                >
                  Delete
                </button>
              </>
            ) : (
              <button type="button" className={bench.btn} onClick={() => onRemove(activeType)}>
                Remove
              </button>
            )}
          </div>
          {activeSibling && (
            <div className={styles.editorNote}>
              {activeSibling.is_draft ? "Draft" : "Published"} rule &middot; {activeSibling.title}
            </div>
          )}
          <div className={styles.editorBody}>
            <RuleBuilderShell
              ruleType={activeType}
              value={body}
              onChange={(content) =>
                activeSibling ? setDraft(content) : onUpdateContent(activeType, content)
              }
            />
          </div>
        </div>
      )}
    </>
  );
}
