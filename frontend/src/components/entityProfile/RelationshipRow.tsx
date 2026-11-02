/**
 * RelationshipRow — one relationship on the trust ladder: entity identity +
 * trust chip (corroborated · MITRE / AI ×N / you, reported, signal) + plain
 * evidence facts (articles · feeds · recency) with a quiet bar, expandable
 * into the contributing articles (with the co-mention trend), and pin /
 * reject / unlink actions on hover. Strength words never appear — evidence
 * volume is shown as what it is.
 */
import { useState } from "react";
import type { EntityType } from "@/stores/intelStore";
import { getEntityColor, getEntityLabel } from "@/utils/entityTheme";
import { formatDate } from "@/utils/formatDate";
import { structurePhrase, timeAgo, trustOf, verbChipLabel, verbSentence, type RelRow } from "@/utils/relationshipBrowser";
import styles from "./entityProfile.module.css";
import { useIsVisitor } from "@/stores/authStore";

function Spark({ trend }: { trend: number[] }) {
  const max = Math.max(...trend, 1);
  return (
    <span className={styles.spark} title={`Co-mentions per month (last ${trend.length} months)`}>
      {trend.map((v, i) => (
        <span
          key={i}
          className={styles.sparkBar}
          style={{ height: `${Math.max(10, (v / max) * 100)}%`, opacity: v ? 1 : 0.2 }}
        />
      ))}
    </span>
  );
}

const scoreClass = (s: number) =>
  s >= 0.7 ? styles.proximityStrong : s >= 0.3 ? styles.proximityModerate : styles.proximityWeak;

const TRUST_CLASS: Record<string, string> = {
  corroborated: styles.trustCorroborated,
  reported: styles.trustReported,
  signal: styles.trustSignal,
};

export function RelationshipRow({
  row,
  viewedLabel,
  onOpen,
  onOpenArticle,
  onConfirm,
  onReject,
  onUnlink,
  claimSources,
}: {
  row: RelRow;
  viewedLabel: string;
  /** The enrichment sources that claim this connection, as labels. */
  claimSources?: (row: RelRow) => string[];
  onOpen: (type: EntityType, id: string, label: string) => void;
  onOpenArticle?: (entryId: string) => void;
  onConfirm?: (relationshipId: string) => void;
  onReject?: (relationshipId: string) => void;
  onUnlink?: (row: RelRow) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [expandedStories, setExpandedStories] = useState<Set<number>>(new Set());
  const { type, item, label, meta } = row;
  const viaSources = claimSources?.(row) ?? [];
  const s = item.strength;
  const trust = trustOf(item);
  const evidence = item.proximity_entries ?? [];
  // Public read-only mode: the evidence reads, nothing on the row edits.
  const isVisitor = useIsVisitor();
  const canModerate = !isVisitor && !!item.relationship_id && trust?.tier !== "corroborated";

  const hasEvidence = evidence.length > 0;
  const articleCount = s?.articles ?? item.relationship_evidence_count ?? 0;
  const evidenceParts = [
    articleCount ? `${articleCount} art` : null,
    s && s.sources > 1 ? `${s.sources} feeds` : null,
    s?.last_seen ? timeAgo(s.last_seen).replace(/ ago$/, "") : null,
  ].filter(Boolean);

  // Evidence structure: the shape phrase is the row's new information — the
  // counts shrink to confirmation. Stories group the evidence panel.
  const phrase = structurePhrase(item);
  const stories = item.evidence_structure?.stories ?? [];
  const storyIndexOf = new Map<string, number>();
  stories.forEach((st, i) => (st.entry_ids ?? []).forEach((id) => storyIndexOf.set(id, i)));

  const monthOf = (iso: string | null) =>
    iso ? new Date(iso).toLocaleDateString(undefined, { month: "short", year: "numeric" }) : "";
  const storyHeading = (st: (typeof stories)[number]) => {
    if (st.title) return st.title;
    const a = monthOf(st.first);
    const b = monthOf(st.last);
    return a && b && a !== b ? `Story · ${a} – ${b}` : `Story · ${a || b}`;
  };

  return (
    <div className={styles.relRow}>
      <div className={styles.relRowLine}>
        <button
          className={styles.relRowMain}
          onClick={() => onOpen(type, item.id, label)}
          title={
            item.relationship_id || item.country_relationship
              ? verbSentence(item, label, viewedLabel)
              : undefined
          }
        >
          <span className={styles.relDot} style={{ background: getEntityColor(type) }} />
          <span className={styles.relLabel}>{label}</span>
          <span className={styles.relType}>{getEntityLabel(type)}</span>
          {meta && <span className={styles.entityMeta}>{meta}</span>}
          {!trust && item.country_relationship && (
            // Geography rows carry a junction-derived verb but no typed
            // relationship — keep the verb visible ("targeted by", "origin of").
            <span className={`${styles.trustChip} ${styles.trustSignal}`}>{verbChipLabel(item)}</span>
          )}
          {/* Chip economy: reported is the unmarked default — a chip on 90% of
              rows carries no information and buries the corroborated ones. */}
          {trust && trust.tier !== "reported" && (
            <span
              className={`${styles.trustChip} ${TRUST_CLASS[trust.tier]}`}
              title={
                trust.tier === "corroborated"
                  ? `Corroborated by ${trust.provenance}`
                  : "Engine inference — corroboration pending"
              }
            >
              {trust.tier}
              {trust.provenance ? ` · ${trust.provenance}` : ""}
            </span>
          )}
          {viaSources.length > 0 && (
            <span className={styles.relSourceTag} title={`Claimed by ${viaSources.join(", ")}`}>
              {viaSources.join(" · ")}
            </span>
          )}
        </button>

        {/* One reading direction: name → shape phrase → counts hard right.
            The phrase is the row's information; the counts are confirmation. */}
        {phrase && hasEvidence && (
          <button
            className={styles.structPhraseBtn}
            onClick={() => setExpanded((e) => !e)}
            title="Show contributing articles"
          >
            <b>{phrase.lead}</b>
            {phrase.rest ? ` ${phrase.rest}` : ""}
          </button>
        )}

        {(hasEvidence || evidenceParts.length > 0) &&
          (hasEvidence ? (
            <button
              className={`${styles.evidenceToggle} ${expanded ? styles.evidenceToggleOpen : ""}`}
              onClick={() => setExpanded((e) => !e)}
              title="Show contributing articles"
              aria-expanded={expanded}
            >
              <span className={styles.evidenceMeta}>{evidenceParts.join(" · ")}</span>
            </button>
          ) : (
            <span className={styles.evidenceStatic}>{evidenceParts.join(" · ")}</span>
          ))}

        <span className={styles.rowActions}>
          {canModerate && onConfirm && (
            <button
              className={`${styles.rowActionBtn} ${styles.rowActionConfirm}`}
              title="Pin — mark corroborated by you"
              onClick={() => onConfirm(item.relationship_id!)}
            >
              ✓
            </button>
          )}
          {canModerate && onReject && (
            <button
              className={`${styles.rowActionBtn} ${styles.rowActionReject}`}
              title="Reject — hide and never re-infer"
              onClick={() => onReject(item.relationship_id!)}
            >
              ✕
            </button>
          )}
          {onUnlink && !isVisitor && (item.co_occurrence_count ?? 0) > 0 && (
            <button className={styles.rowActionBtn} title="Unlink from shared articles" onClick={() => onUnlink(row)}>
              unlink
            </button>
          )}
        </span>
      </div>

      {expanded && evidence.length > 0 && (
        <div className={styles.evidencePanel}>
          {s && s.trend?.some((v) => v > 0) && (
            <div className={styles.evidenceRow}>
              <Spark trend={s.trend} />
              <span className={styles.evidenceDate}>
                {s.first_seen
                  ? `since ${new Date(s.first_seen).toLocaleDateString(undefined, { month: "short", year: "numeric" })}`
                  : ""}
              </span>
            </div>
          )}
          {stories.length > 0
            ? (() => {
                // Group contributing articles under their story; the rest
                // (loose mentions + entries outside the sampled window) sit
                // in a dimmed tail so the panel reads as incidents, not a list.
                const grouped: Array<Array<(typeof evidence)[number]>> = stories.map(() => []);
                const rest: typeof evidence = [];
                for (const pe of evidence) {
                  const i = storyIndexOf.get(pe.entry_id);
                  if (i === undefined) rest.push(pe);
                  else grouped[i].push(pe);
                }
                const renderEntry = (pe: (typeof evidence)[number]) => (
                  <div
                    key={pe.entry_id}
                    className={styles.evidenceRow}
                    onClick={onOpenArticle ? () => onOpenArticle(pe.entry_id) : undefined}
                  >
                    <span className={`${styles.proxDropdownBadge} ${scoreClass(pe.score)}`}>{pe.score.toFixed(2)}</span>
                    <span className={styles.evidenceTitle}>{pe.title || pe.entry_id.slice(0, 8)}</span>
                    {pe.published_at && <span className={styles.evidenceDate}>{formatDate(pe.published_at)}</span>}
                  </div>
                );
                return (
                  <>
                    {stories.map((st, i) => {
                      const storyOpen = expandedStories.has(i);
                      const visible = storyOpen ? grouped[i] : grouped[i].slice(0, 2);
                      const hidden = grouped[i].length - visible.length;
                      return (
                        <div key={i} className={styles.evidenceStory}>
                          <div className={styles.evidenceStoryHead}>
                            {storyHeading(st)}
                            <span className={styles.evidenceDate}>
                              {st.entries} article{st.entries === 1 ? "" : "s"}
                            </span>
                          </div>
                          {visible.map(renderEntry)}
                          {hidden > 0 && (
                            <button
                              className={styles.storyMore}
                              onClick={() =>
                                setExpandedStories((prev) => new Set(prev).add(i))
                              }
                            >
                              + {hidden} more in this story
                            </button>
                          )}
                        </div>
                      );
                    })}
                    {rest.length > 0 && (
                      <div className={`${styles.evidenceStory} ${styles.evidenceStoryLoose}`}>
                        <div className={styles.evidenceStoryHead}>Outside these stories</div>
                        {rest.map(renderEntry)}
                      </div>
                    )}
                  </>
                );
              })()
            : evidence.map((pe) => (
                <div
                  key={pe.entry_id}
                  className={styles.evidenceRow}
                  onClick={onOpenArticle ? () => onOpenArticle(pe.entry_id) : undefined}
                >
                  <span className={`${styles.proxDropdownBadge} ${scoreClass(pe.score)}`}>{pe.score.toFixed(2)}</span>
                  <span className={styles.evidenceTitle}>{pe.title || pe.entry_id.slice(0, 8)}</span>
                  {pe.published_at && <span className={styles.evidenceDate}>{formatDate(pe.published_at)}</span>}
                </div>
              ))}
        </div>
      )}
    </div>
  );
}
