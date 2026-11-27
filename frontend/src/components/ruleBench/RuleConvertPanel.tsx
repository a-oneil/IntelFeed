import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import api from "@/api/client";
import RuleBuilderShell from "@/components/RuleBuilderShell";
import { useReadingPrefs } from "@/hooks/useReadingPrefs";
import { formatDateTime } from "@/utils/formatDate";
import { QUERY_LANGUAGES } from "@/utils/queryLanguage";
import bench from "./bench.module.css";
import styles from "./RuleConvertPanel.module.css";

export interface RuleConversion {
  content: string;
  converted_at: string;
  model: string;
  tokens_used?: number;
  cost?: number;
}

/** What a convert button asks for: the stored format, and the exact language where one format holds several (elastic_ql is ES|QL and EQL). */
export interface ConvertTarget {
  type: string;
  dialect: string | null;
}

/** A converted rule: a rule row of its own, linked to its source through `derived_from`. */
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
  /** Legacy `metadata.rule_conversions` blob, read as a fallback for conversions not yet promoted to sibling rules; see below. */
  conversions: Record<string, RuleConversion>;
  /** The selected conversion: a sibling's id, or `legacy:<type>` for a blob entry. */
  activeKey: string | null;
  /** The target currently converting, or null. Only that button reads "Converting…"; the rest keep their labels (though disabled) so the panel doesn't look like it's converting to every format at once. */
  converting: ConvertTarget | null;
  onSelect: (key: string | null) => void;
  onConvert: (target: ConvertTarget, notes: string) => void;
  onRemove: (type: string) => void;
  onUpdateContent: (type: string, content: string) => void;
}

/** Provenance the convert endpoint records on the sibling it writes. */
function conversionMeta(sibling: ConversionSibling): (RuleConversion & { dialect: string | null }) | null {
  const meta = sibling.metadata?.conversion as Record<string, unknown> | undefined;
  if (!meta) return null;
  return {
    content: sibling.rule_content,
    converted_at: (meta.converted_at as string) || sibling.updated_at,
    model: (meta.model as string) || "unknown",
    tokens_used: meta.tokens_used as number | undefined,
    cost: meta.cost as number | undefined,
    dialect: (meta.dialect as string | null | undefined) ?? null,
  };
}

const LEGACY = "legacy:";

/**
 * Conversions are sibling rules, not a blob on the parent, so they are searchable, versioned, exportable and not deleted along with the rule they came from.
 *
 * The legacy `metadata.rule_conversions` blob is still read for anything the backfill has not promoted yet, and a sibling always wins over a blob entry of the same format. Blob entries stay editable through the parent's autosave (the props below); siblings save as themselves.
 */
export function RuleConvertPanel({
  ruleId,
  ruleType,
  typeLabels,
  conversions,
  activeKey,
  converting,
  onSelect,
  onConvert,
  onRemove,
  onUpdateContent,
}: RuleConvertPanelProps) {
  const qc = useQueryClient();
  const siblingsKey = ["rule-conversions", ruleId];
  const preferred = useReadingPrefs().query_language;
  const [notes, setNotes] = useState("");

  const siblings = useQuery({
    queryKey: siblingsKey,
    enabled: Boolean(ruleId),
    queryFn: async () => {
      const { data } = await api.get<ConversionSibling[]>(`/detection-rules/${ruleId}/conversions`);
      return data;
    },
  });

  // Every query language from Settings › Reading is a target, except the one this rule already is. Formats the library stores but no SIEM queries in (Snort, YARA, Nuclei) are listed separately.
  const languageTargets = QUERY_LANGUAGES.filter((q) => q.ruleType && q.ruleType !== ruleType);
  const languageTypes = new Set(QUERY_LANGUAGES.map((q) => q.ruleType));
  const formatTargets = Object.entries(typeLabels).filter(([k]) => k !== ruleType && !languageTypes.has(k));

  const siblingRows = siblings.data ?? [];
  const siblingTypes = new Set(siblingRows.map((s) => s.rule_type));
  // Blob entries the backfill has not promoted; a sibling hides the blob entry of its own format.
  const legacyTypes = Object.keys(conversions).filter((t) => !siblingTypes.has(t));

  const labelFor = (type: string, dialect: string | null) =>
    (dialect && QUERY_LANGUAGES.find((q) => q.value === dialect)?.short) || typeLabels[type] || type;

  const existing: { key: string; label: string; legacy: boolean }[] = [
    ...siblingRows.map((s) => ({ key: s.id, label: labelFor(s.rule_type, conversionMeta(s)?.dialect ?? null), legacy: false })),
    ...legacyTypes.map((t) => ({ key: `${LEGACY}${t}`, label: typeLabels[t] || t, legacy: true })),
  ].sort((a, b) => a.label.localeCompare(b.label));

  // A conversion writes a new sibling server-side, so refetch the list as soon as the parent's convert mutation settles.
  useEffect(() => {
    if (converting === null && ruleId) qc.invalidateQueries({ queryKey: siblingsKey });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [converting, ruleId]);

  const activeSibling = activeKey && !activeKey.startsWith(LEGACY) ? siblingRows.find((s) => s.id === activeKey) : undefined;
  const activeLegacyType = activeKey?.startsWith(LEGACY) ? activeKey.slice(LEGACY.length) : null;
  const activeLegacy = activeLegacyType ? conversions[activeLegacyType] : undefined;

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
      if (activeKey === id) onSelect(null);
      qc.invalidateQueries({ queryKey: siblingsKey });
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
      toast.success("Conversion deleted");
    },
    onError: () => toast.error("Could not delete the conversion"),
  });

  const meta = activeSibling ? conversionMeta(activeSibling) : activeLegacy;
  const body = draft ?? activeSibling?.rule_content ?? activeLegacy?.content ?? "";
  const activeTarget: ConvertTarget | null = activeSibling
    ? { type: activeSibling.rule_type, dialect: conversionMeta(activeSibling)?.dialect ?? null }
    : activeLegacyType
      ? { type: activeLegacyType, dialect: null }
      : null;
  const isConverting = (t: ConvertTarget) =>
    converting !== null && converting.type === t.type && (converting.dialect ?? null) === (t.dialect ?? null);
  const preferredShort = QUERY_LANGUAGES.find((q) => q.value === preferred)?.short;

  return (
    <>
      <div className={bench.railLabel}>
        Convert this {typeLabels[ruleType] || ruleType} rule
        {preferredShort && <b>preferred: {preferredShort} · Settings › Reading</b>}
      </div>

      <div className={styles.group}>
        <span className={styles.groupLabel}>Query languages</span>
        <div className={styles.grid}>
          {languageTargets.map((q) => {
            const target: ConvertTarget = { type: q.ruleType!, dialect: q.value };
            return (
              <button
                key={q.value}
                type="button"
                className={styles.option}
                onClick={() => onConvert(target, notes)}
                disabled={converting !== null}
                title={q.label}
              >
                <span>{isConverting(target) ? "Converting…" : `→ ${q.short}`}</span>
                <small className={q.value === preferred ? styles.preferred : undefined}>
                  {q.value === preferred ? "preferred" : q.label.replace(/^[^(]*\(|\)$/g, "")}
                </small>
              </button>
            );
          })}
        </div>
      </div>

      {formatTargets.length > 0 && (
        <div className={styles.group}>
          <span className={styles.groupLabel}>Rule formats</span>
          <div className={styles.grid}>
            {formatTargets.map(([k, v]) => {
              const target: ConvertTarget = { type: k, dialect: null };
              return (
                <button
                  key={k}
                  type="button"
                  className={styles.option}
                  onClick={() => onConvert(target, notes)}
                  disabled={converting !== null}
                >
                  <span>{isConverting(target) ? "Converting…" : `→ ${v}`}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      <div className={styles.group}>
        <label className={styles.groupLabel} htmlFor="conversion-notes">
          Notes for the conversion
          <span className={styles.groupHint}>optional · added to the prompt</span>
        </label>
        <input
          id="conversion-notes"
          className={styles.notes}
          type="text"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Anything the converted rule should account for"
          maxLength={2000}
        />
      </div>

      {existing.length > 0 && (
        <>
          <div className={bench.railLabel}>
            Existing conversions<b>{existing.length}</b>
          </div>
          <div className={styles.tabs}>
            {existing.map((c) => (
              <button
                key={c.key}
                type="button"
                className={`${styles.tab} ${activeKey === c.key ? styles.tabActive : ""}`}
                onClick={() => onSelect(activeKey === c.key ? null : c.key)}
              >
                {c.label}
                {c.legacy && <span className={styles.legacyDot} title="Not yet a rule of its own" />}
              </button>
            ))}
          </div>
        </>
      )}

      {activeTarget && (activeSibling || activeLegacy) && (
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
            <button
              type="button"
              className={bench.btn}
              onClick={() => onConvert(activeTarget, notes)}
              disabled={converting !== null}
            >
              {isConverting(activeTarget) ? "Converting…" : "Re-convert"}
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
              <button type="button" className={bench.btn} onClick={() => onRemove(activeTarget.type)}>
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
              ruleType={activeTarget.type}
              value={body}
              onChange={(content) =>
                activeSibling ? setDraft(content) : onUpdateContent(activeTarget.type, content)
              }
            />
          </div>
        </div>
      )}
    </>
  );
}
