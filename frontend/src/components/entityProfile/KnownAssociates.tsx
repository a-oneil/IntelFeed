/**
 * KnownAssociates — the entity's best-evidenced CLAIMS as rows of the Overview's key facts table: one row per verb (targets, uses, attributed to…), keyed by the verb, naming the other entities. Who stands behind each name (MITRE ATT&CK, an analyst, AI review, several separate stories) is in its tooltip, in plain words; the row carries no source tag, because one row mixes sources.
 *
 * Deliberately not ranked by co-mention strength: ranking by raw co-occurrence (the "STRONG" tiers) put reporting vendors and countries next to real techniques and tools with no way to explain why. Rows here must be asserted claims that earned their place under the evidence-structure rules (see relationshipBrowser), so every chip is explainable from its tooltip.
 */
import { useMemo } from "react";
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
import { Row as FactRow } from "./SnapshotCard";
import styles from "./entityProfile.module.css";

const LIMIT = 12;
/** At most four names per entity type — without this the rows fill with ATT&CK techniques on every actor (MITRE corroborates them all), which the ATT&CK tab already covers and which says nothing about the entity's other associations. The cap mixes types so the rows cover capability, tooling and victims. */
const TYPE_CAP = 4;
const TRUST_RANK: Record<string, number> = { corroborated: 2, reported: 1, signal: 0 };

/** A claim's mark — present only when it carries information. Corroboration provenance first, then a recurring evidence shape. */
function markOf(row: RelRow): { text: string; kind: "corroborated" | "recurring" } | null {
  const trust = trustOf(row.item);
  if (trust?.tier === "corroborated") {
    return { text: trust.provenance ?? "corroborated", kind: "corroborated" };
  }
  if (row.item.evidence_structure?.shape === "recurring") return { text: "recurring", kind: "recurring" };
  return null;
}

/** The mark in plain words, for a name's tooltip. */
function markSentence(mark: { text: string; kind: "corroborated" | "recurring" }): string {
  if (mark.kind === "recurring") return "Reported in several separate stories";
  if (mark.text === "MITRE") return "Confirmed by MITRE ATT&CK";
  if (mark.text === "you") return "Confirmed by an analyst";
  const n = mark.text.match(/×(\d+)/)?.[1];
  return n ? `Confirmed by AI review of ${n} article${n === "1" ? "" : "s"}` : "Confirmed by AI";
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
    // Same gates the tab folds on, so the Overview never promotes what the tab hides: junk ids, ubiquitous software, regions mis-filed as countries, and claims whose evidence carries no story.
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
        if (picked.length >= LIMIT) break;
        if (picked.includes(r)) continue;
        const n = perType.get(r.type) ?? 0;
        // Second pass relaxes the cap so a sparse profile still fills the rows.
        if (pass === 0 && n >= TYPE_CAP) continue;
        perType.set(r.type, n + 1);
        picked.push(r);
      }
    }
    return { top: picked, claimCount: eligible.length, relatedCount: flattenRelated(related, entityType).length };
  }, [related, entityType]);

  // No eligible claims → no claim rows; co-mentions stay in the tab, where they are labeled as context. Profiles whose related set is all co-mentions (typical for vendor / product / country / CVE) still get a short link, because it is the Overview's only way into Relationships besides the tab itself.
  if (top.length === 0) {
    if (relatedCount === 0) return null;
    return (
      <FactRow
        k="Relationships"
        v={
          <>
            <span className={styles.claimsNone}>None confirmed yet. </span>
            <button className={styles.factLink} onClick={onShowRelationships}>
              See all {relatedCount} related entities
            </button>
          </>
        }
      />
    );
  }

  // Rows in first-seen order, which is rank order: the best-evidenced verb leads. The verb is the row's key; the names read as a sentence.
  const groups = new Map<string, RelRow[]>();
  for (const row of top) {
    const verb = verbChipLabel(row.item);
    groups.set(verb, [...(groups.get(verb) ?? []), row]);
  }

  return (
    <>
      {[...groups].map(([verb, rows]) => (
          <FactRow
            key={verb}
            k={verb.charAt(0).toUpperCase() + verb.slice(1)}
            v={rows.map((row, i) => {
              const { type, item, label } = row;
              const mark = markOf(row);
              const phrase = structurePhrase(item);
              return (
                <span key={rowKey(row)}>
                  {i > 0 && ", "}
                  <button
                    className={styles.factLink}
                    onClick={() => onOpenEntity(type, item.id, label)}
                    title={[
                      verbSentence(item, label, entityLabel),
                      mark ? markSentence(mark) : null,
                      phrase ? `${phrase.lead} ${phrase.rest}`.trim() : null,
                    ]
                      .filter(Boolean)
                      .join(". ")}
                  >
                    {label}
                  </button>
                </span>
              );
            })}
          />
      ))}
      {claimCount > top.length && (
        <FactRow
          k=""
          v={
            <button className={styles.factLink} onClick={onShowRelationships}>
              See all {claimCount} relationships
            </button>
          }
        />
      )}
    </>
  );
}
