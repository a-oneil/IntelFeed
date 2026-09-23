/**
 * KnownAssociates — the hero strip of the entity's best-evidenced CLAIMS,
 * reading the same way the Relationships tab does: a typed verb, the other
 * entity, and a mark only when the mark says something (corroborated by an
 * authority / analyst / adjudicator, or recurring across separate stories).
 *
 * Deliberately NOT co-mention strength: the old "STRONG" tiers ranked by raw
 * co-occurrence, which put reporting vendors and countries alongside real
 * tradecraft with no way to explain why. Rows here must be asserted claims
 * that earned their place under the evidence-structure rules (see
 * relationshipBrowser), so every chip is explainable from its tooltip.
 */
import { useMemo } from "react";
import { getEntityColor } from "@/utils/entityTheme";
import type { EntityType } from "@/stores/intelStore";
import type { PivotResponse } from "@/api/types";
import {
  flattenRelated,
  isEarnedRow,
  isEverydaySoftware,
  isImplausibleCveId,
  REGION_NAMES,
  rowKey,
  shapeRank,
  splitAssertedContext,
  structurePhrase,
  trustOf,
  verbChipLabel,
  verbSentence,
  type RelRow,
} from "@/utils/relationshipBrowser";
import styles from "./entityProfile.module.css";

const STRIP_LIMIT = 5;
/** At most two chips per entity type — without this the strip fills with five
 * ATT&CK techniques on every actor (MITRE corroborates them all), which the
 * ATT&CK tab already covers and which says nothing about who the entity runs
 * with. The cap makes the strip read across the diamond: capability, tooling,
 * victim. */
const TYPE_CAP = 2;
const TRUST_RANK: Record<string, number> = { corroborated: 2, reported: 1, signal: 0 };

/** The chip's trailing mark — shown only when it carries information.
 * Corroboration provenance first, then a recurring evidence shape. */
function markOf(row: RelRow): { text: string; kind: "corroborated" | "recurring" } | null {
  const trust = trustOf(row.item);
  if (trust?.tier === "corroborated") {
    return { text: trust.provenance ?? "corroborated", kind: "corroborated" };
  }
  if (row.item.evidence_structure?.shape === "recurring") return { text: "recurring", kind: "recurring" };
  return null;
}

export function KnownAssociates({
  entityType,
  entityLabel,
  related,
  onOpenEntity,
  onShowRelationships,
}: {
  entityType: EntityType;
  entityLabel: string;
  related: PivotResponse["related"];
  onOpenEntity: (type: EntityType, id: string, label?: string) => void;
  onShowRelationships: () => void;
}) {
  const { top, claimCount, relatedCount } = useMemo(() => {
    const { asserted } = splitAssertedContext(flattenRelated(related, entityType));
    // Same gates the tab folds on, so the hero never promotes what the tab
    // hides: junk ids, ubiquitous software, regions mis-filed as countries,
    // and claims whose evidence carries no story.
    const eligible = asserted.filter(
      (r) =>
        isEarnedRow(r) &&
        !isEverydaySoftware(r) &&
        !(r.type === "cve" && isImplausibleCveId(r.label)) &&
        !(r.type === "country" && REGION_NAMES.has(r.label.toLowerCase())),
    );
    const ranked = [...eligible].sort((a, b) => {
      const t =
        (TRUST_RANK[trustOf(b.item)?.tier ?? "signal"] ?? 0) -
        (TRUST_RANK[trustOf(a.item)?.tier ?? "signal"] ?? 0);
      if (t !== 0) return t;
      const s = shapeRank(a.item) - shapeRank(b.item);
      if (s !== 0) return s;
      return (b.item.strength?.articles ?? 0) - (a.item.strength?.articles ?? 0);
    });
    const perType = new Map<EntityType, number>();
    const picked: RelRow[] = [];
    for (const pass of [0, 1]) {
      for (const r of ranked) {
        if (picked.length >= STRIP_LIMIT) break;
        if (picked.includes(r)) continue;
        const n = perType.get(r.type) ?? 0;
        // Second pass relaxes the cap so a sparse profile still fills the strip.
        if (pass === 0 && n >= TYPE_CAP) continue;
        perType.set(r.type, n + 1);
        picked.push(r);
      }
    }
    return { top: picked, claimCount: eligible.length, relatedCount: flattenRelated(related, entityType).length };
  }, [related, entityType]);

  // No claims worth standing behind → no chip strip; co-mentions stay in the
  // tab, where they are labeled as context. But keep the escape hatch: on
  // profiles whose related set is all co-mention (typical vendor / product /
  // country / CVE), a slim link is the header's only way into Relationships
  // besides the tab itself.
  if (top.length === 0) {
    if (relatedCount === 0) return null;
    return (
      <div className={styles.associates}>
        <div className={styles.associatesTitle}>No corroborated claims yet</div>
        <div className={styles.associatesRow}>
          <button className={styles.associateMore} onClick={onShowRelationships}>
            all {relatedCount} related entities →
          </button>
        </div>
      </div>
    );
  }

  // Chip economy: when every chip carries the SAME mark (an actor whose top
  // claims are all MITRE), five identical badges say nothing — say it once in
  // the title and let the chips be names.
  const marks = top.map(markOf);
  const uniform =
    marks.every((m) => m && m.text === marks[0]?.text) && marks[0] ? marks[0] : null;
  const title = uniform
    ? uniform.kind === "corroborated"
      ? `Best-evidenced claims · all corroborated by ${uniform.text}`
      : "Best-evidenced claims · all recurring across separate stories"
    : "Best-evidenced claims · corroborated first";

  return (
    <div className={styles.associates}>
      <div className={styles.associatesTitle}>{title}</div>
      <div className={styles.associatesRow}>
        {top.map((row, i) => {
          const { type, item, label } = row;
          const mark = uniform ? null : marks[i];
          const phrase = structurePhrase(item);
          const rowMark = marks[i];
          const why = rowMark?.kind === "corroborated" ? `corroborated by ${rowMark.text}` : null;
          return (
            <button
              key={rowKey(row)}
              className={styles.associateChip}
              onClick={() => onOpenEntity(type, item.id, label)}
              title={[
                verbSentence(item, label, entityLabel),
                why,
                phrase ? `${phrase.lead} ${phrase.rest}`.trim() : null,
              ]
                .filter(Boolean)
                .join(" — ")}
            >
              <span className={styles.associateDot} style={{ background: getEntityColor(type) }} />
              <span className={styles.associateVerb}>{verbChipLabel(item)}</span>
              <span className={styles.associateName}>{label}</span>
              {mark && (
                <span className={`${styles.associateMark} ${styles[`associateMark_${mark.kind}`]}`}>
                  {mark.text}
                </span>
              )}
            </button>
          );
        })}
        {claimCount > top.length && (
          <button className={styles.associateMore} onClick={onShowRelationships}>
            all {claimCount} claims →
          </button>
        )}
      </div>
    </div>
  );
}
