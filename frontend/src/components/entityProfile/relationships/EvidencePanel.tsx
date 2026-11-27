/** EvidencePanel — why one relationship is listed: who says so, its confidence status, the articles that state it (with their sentence), what the reviewers said, and, in a separate list, the articles that only mention both. */
import { useEffect, useState } from "react";
import type { EntityType } from "@/stores/intelStore";
import { useRelationshipEvidence, type RelationshipReview } from "@/hooks/useHygiene";
import { getEntityColor } from "@/utils/entityTheme";
import { formatDate } from "@/utils/formatDate";
import { verbKeyOf, verbSentence, verbsForStored, type RelRow } from "@/utils/relationshipBrowser";
import { reasonOf, sourceLabel, statusOf, type SourcePart } from "@/utils/relationshipSource";
import styles from "./relationships.module.css";

const PREVIEW = 4;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const REVIEWER: Record<string, string> = { adjudicator: "AI reviewer", sweep: "AI reviewer", analyst: "Analyst" };

function reviewLine(r: RelationshipReview): string | null {
  const who = REVIEWER[r.reviewer] ?? r.reviewer;
  switch (r.verdict) {
    case "keep":
      return `${who} kept it`;
    case "demote":
      return `${who} doubted it`;
    case "reverb":
      return `${who} said it should read "${(r.suggested_verb ?? "").replace(/_/g, " ")}"${r.flipped ? ", the other way round" : ""}`;
    case "unsure":
      return `${who} couldn't tell`;
    default:
      return null; // "unanswered": asked, no answer — nothing to show
  }
}

const monthYear = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { month: "short", year: "numeric" }) : "";

export function EvidencePanel({
  row,
  viewedType,
  viewedLabel,
  sources,
  isVisitor,
  onOpen,
  onOpenArticle,
  onOpenThread,
  onConfirm,
  onReject,
  onChangeVerb,
}: {
  row: RelRow;
  viewedType: EntityType;
  viewedLabel: string;
  sources: SourcePart[];
  isVisitor: boolean;
  onOpen: (type: EntityType, id: string, label: string) => void;
  onOpenArticle: (entryId: string) => void;
  onOpenThread: (slug: string) => void;
  onConfirm: (relationshipId: string) => void;
  onReject: (relationshipId: string) => void;
  onChangeVerb: (relationshipId: string, verb: string) => void;
}) {
  const { item, label, type } = row;
  const relId = item.relationship_id ?? null;
  // Catalog rows (ATT&CK technique ↔ mitigation) carry a synthetic id, not a stored relationship: there is no evidence to fetch and nothing to edit.
  const stored = !!relId && UUID.test(relId);
  const evidence = useRelationshipEvidence(stored && !isVisitor ? relId : null);
  const [showAllCited, setShowAllCited] = useState(false);
  const [showAllMentions, setShowAllMentions] = useState(false);
  const verb = verbKeyOf(item);
  const [newVerb, setNewVerb] = useState(verb);

  useEffect(() => {
    setShowAllCited(false);
    setShowAllMentions(false);
    setNewVerb(verb);
  }, [relId, item.id, verb]);

  const status = statusOf(item);
  const reason = reasonOf(row, sources);
  const s = item.strength;
  const stories = item.evidence_structure?.stories ?? [];

  const cited = (evidence.data?.articles ?? []).filter((a) => a.analysis_sentence || a.passages.length > 0);
  const citedIds = new Set(cited.map((a) => a.entry_id));
  const mentions = (item.proximity_entries ?? []).filter((pe) => !citedIds.has(pe.entry_id));
  const reviews = (evidence.data?.reviews ?? [])
    .map((r) => ({ r, line: reviewLine(r) }))
    .filter((x): x is { r: RelationshipReview; line: string } => x.line !== null)
    .slice(0, 4);

  // The stored direction decides which verbs the API accepts.
  const outbound = item.relationship_direction !== "inbound";
  const verbs = stored ? verbsForStored(outbound ? viewedType : type, outbound ? type : viewedType) : [];
  const isMitre = sources[0]?.key === "mitre";
  const canModerate = !isVisitor && stored && item.relationship_confidence !== "confirmed";

  return (
    <section className={styles.panel} aria-label="Why this relationship is listed">
      <div className={styles.panelKicker}>Relationship</div>
      <div className={styles.panelTitle}>{verbSentence(item, label, viewedLabel)}</div>
      <div className={styles.panelMeta}>
        <span className={styles[`tone_${sources[0]?.tone ?? "articles"}`]}>{sourceLabel(sources)}</span>
        {status && <span>{status}</span>}
      </div>

      <div className={styles.label}>Why it's listed</div>
      {reason.quote && <div className={styles.quote}>“{reason.quote}”</div>}
      <div className={styles.reasonText}>
        {reason.text}
        {isMitre && item.mitre_url && (
          <>
            {" "}
            <a href={item.mitre_url} target="_blank" rel="noreferrer">
              {item.technique_id ?? "Entry"} on attack.mitre.org
            </a>
          </>
        )}
      </div>

      {stored && !isVisitor && (evidence.isLoading || cited.length > 0) && (
        <>
          <div className={styles.label}>
            Articles that state it{evidence.data ? ` · ${evidence.data.article_count}` : ""}
          </div>
          {evidence.isLoading && <div className={styles.reasonText}>Loading…</div>}
          {(showAllCited ? cited : cited.slice(0, PREVIEW)).map((a) => (
            <div key={a.entry_id} className={styles.article}>
              <button className={styles.articleBtn} onClick={() => onOpenArticle(a.entry_id)}>
                {a.title || "Untitled"}
              </button>
              <span className={styles.articleMeta}>
                {[a.feed_title, a.published_at ? formatDate(a.published_at) : null].filter(Boolean).join(" · ")}
              </span>
              <span className={styles.sentence}>{a.analysis_sentence ?? a.passages[0]}</span>
            </div>
          ))}
          {cited.length > PREVIEW && (
            <button className={styles.linkBtn} style={{ paddingLeft: 0 }} onClick={() => setShowAllCited((v) => !v)}>
              {showAllCited ? "Show fewer" : `Show all ${cited.length}`}
            </button>
          )}
        </>
      )}

      {reviews.length > 0 && (
        <>
          <div className={styles.label}>Reviews</div>
          {reviews.map(({ r, line }, i) => (
            <div key={i} className={styles.review}>
              <b>{line}</b>
              {r.reason ? `: ${r.reason}` : ""}
              {r.entry_title && <div className={styles.articleMeta}>on “{r.entry_title}”</div>}
            </div>
          ))}
        </>
      )}

      {s && s.articles > 0 && (
        <>
          <div className={styles.label}>
            {s.articles} article{s.articles === 1 ? "" : "s"}
            {s.sources > 1 ? ` from ${s.sources} sources` : ""}
            {s.first_seen ? ` since ${monthYear(s.first_seen)}` : ""}
          </div>
          {s.trend?.some((v) => v > 0) && (
            <div className={styles.spark} title={`Articles per month, last ${s.trend.length} months`} aria-hidden="true">
              {(() => {
                const max = Math.max(...s.trend, 1);
                return s.trend.map((v, i) => <i key={i} style={{ height: `${Math.max(6, (v / max) * 100)}%`, opacity: v ? undefined : 0.15 }} />);
              })()}
            </div>
          )}
        </>
      )}

      {stories.length > 0 && (
        <>
          <div className={styles.label}>Part of these stories</div>
          <div>
            {stories.map((st, i) => {
              const a = monthYear(st.first);
              const b = monthYear(st.last);
              const text = `${st.title ?? (a && b && a !== b ? `${a} – ${b}` : a || b || "Story")} · ${st.entries}`;
              return st.slug ? (
                <button key={i} className={styles.story} onClick={() => onOpenThread(st.slug!)}>
                  {text}
                </button>
              ) : (
                <span key={i} className={styles.story}>
                  {text}
                </span>
              );
            })}
          </div>
        </>
      )}

      {mentions.length > 0 && (
        <>
          <div className={styles.label}>Articles that mention both (not checked for this claim)</div>
          {(showAllMentions ? mentions : mentions.slice(0, PREVIEW)).map((pe) => (
            <div key={pe.entry_id} className={styles.mentionRow}>
              <button className={styles.articleBtn} onClick={() => onOpenArticle(pe.entry_id)}>
                {pe.title || "Untitled"}
              </button>
              {pe.published_at && <span className={styles.articleMeta}>{formatDate(pe.published_at)}</span>}
            </div>
          ))}
          {mentions.length > PREVIEW && (
            <button className={styles.linkBtn} style={{ paddingLeft: 0 }} onClick={() => setShowAllMentions((v) => !v)}>
              {showAllMentions ? "Show fewer" : `Show all ${mentions.length}`}
            </button>
          )}
        </>
      )}

      <div className={styles.actions}>
        <button className={styles.btn} onClick={() => onOpen(type, item.id, label)}>
          <span className={styles.dot} style={{ background: getEntityColor(type), display: "inline-block", marginRight: 6 }} />
          Open {label}
        </button>
        {canModerate && (
          <>
            <button className={styles.btn} onClick={() => onConfirm(relId!)} title="Mark it as confirmed by you">
              Confirm
            </button>
            <button className={styles.btn} onClick={() => onReject(relId!)} title="Hide it, and never infer it again">
              Remove: it's wrong
            </button>
          </>
        )}
      </div>
      {!isVisitor && stored && verbs.length > 1 && (
        <div className={styles.actions} style={{ marginTop: 8 }}>
          <label className={styles.verbPick}>
            Change “{verb.replace(/_/g, " ")}” to
            <select className={styles.select} value={newVerb} onChange={(e) => setNewVerb(e.target.value)}>
              {verbs.map((v) => (
                <option key={v} value={v}>
                  {v.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>
          <button className={styles.btn} disabled={newVerb === verb} onClick={() => onChangeVerb(relId!, newVerb)}>
            Change
          </button>
        </div>
      )}
    </section>
  );
}
