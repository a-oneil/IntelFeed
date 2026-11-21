import { Fragment, type ReactNode } from "react";

import {
  type EvidenceArticle,
  type RelationshipEvidence,
  useRelationshipEvidence,
  useRowEvidence,
} from "@/hooks/useHygiene";
import { useEntityEvidence } from "@/hooks/useExtraction";
import { formatDateTime } from "@/utils/formatDate";

import styles from "./EvidencePanel.module.css";

/** Wrap every occurrence of a name in <mark>, longest names first. */
function highlight(text: string, names: string[]): ReactNode {
  const clean = [
    ...new Set(names.map((n) => n.trim()).filter((n) => n.length >= 2)),
  ].sort((a, b) => b.length - a.length);
  if (clean.length === 0) return text;
  const re = new RegExp(
    `(${clean.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`,
    "gi",
  );
  const lower = new Set(clean.map((n) => n.toLowerCase()));
  return text
    .split(re)
    .map((part, i) =>
      lower.has(part.toLowerCase()) ? (
        <mark key={i}>{part}</mark>
      ) : (
        <Fragment key={i}>{part}</Fragment>
      ),
    );
}

function ArticleHead({
  entryId,
  title,
  feed,
  published,
}: {
  entryId: string;
  title: string;
  feed: string;
  published: string | null;
}) {
  return (
    <div className={styles.articleHead}>
      <a className={styles.articleTitle} href={`/?entry=${entryId}`}>
        {title || "Untitled article"}
      </a>
      <span className={styles.muted}>
        {feed}
        {published ? ` · ${formatDateTime(published)}` : ""}
      </span>
    </div>
  );
}

function Article({
  article,
  names,
}: {
  article: EvidenceArticle;
  names: string[];
}) {
  const marks = [...article.highlight, ...names];
  return (
    <div className={styles.article}>
      <ArticleHead
        entryId={article.entry_id}
        title={article.title}
        feed={article.feed_title}
        published={article.published_at}
      />
      {article.paragraphs.length === 0 && (
        <p className={styles.muted}>
          The name isn't found in the article text.
        </p>
      )}
      {article.paragraphs.map((p, i) => (
        <p key={i} className={styles.para}>
          {highlight(p, marks)}
        </p>
      ))}
    </div>
  );
}

const VERDICT_LABEL: Record<string, string> = {
  keep: "Kept",
  demote: "Hid",
  reverb: "Corrected",
  unsure: "Unsure",
  unanswered: "No answer",
};
const REVIEWER_LABEL: Record<string, string> = {
  adjudicator: "Article review",
  sweep: "Edge sweep",
  analyst: "Analyst",
};

function RelationshipBody({
  data,
  names,
}: {
  data: RelationshipEvidence;
  names: string[];
}) {
  return (
    <>
      <div className={styles.section}>
        <div className={styles.label}>
          Articles ({data.article_count.toLocaleString()}
          {data.article_count > data.articles.length
            ? `, ${data.articles.length} shown`
            : ""}
          )
        </div>
        {data.articles.length === 0 && (
          <p className={styles.muted}>No evidence article is left.</p>
        )}
        {data.articles.map((a) => (
          <div key={a.entry_id} className={styles.article}>
            <ArticleHead
              entryId={a.entry_id}
              title={a.title}
              feed={a.feed_title}
              published={a.published_at}
            />
            {a.analysis_sentence && (
              <p className={styles.quote}>
                <span className={styles.muted}>
                  The analysis said ({a.analysis_verb?.replace(/_/g, " ")}
                  ):{" "}
                </span>
                {highlight(a.analysis_sentence, names)}
              </p>
            )}
            {a.passages.map((p, i) => (
              <p key={i} className={styles.para}>
                {highlight(p, names)}
              </p>
            ))}
            {a.passages.length === 0 && !a.analysis_sentence && (
              <>
                <p className={styles.muted}>No passage names both.</p>
                {a.source_only && (
                  <p className={styles.para}>
                    {highlight(a.source_only, names)}
                  </p>
                )}
                {a.target_only && (
                  <p className={styles.para}>
                    {highlight(a.target_only, names)}
                  </p>
                )}
              </>
            )}
          </div>
        ))}
      </div>
      <div className={styles.section}>
        <div className={styles.label}>Reviews</div>
        {data.reviews.length === 0 && (
          <p className={styles.muted}>Not reviewed yet.</p>
        )}
        <ul className={styles.reviews}>
          {data.reviews.map((r, i) => (
            <li key={i}>
              <span className={styles.reviewHead}>
                <b>{VERDICT_LABEL[r.verdict] ?? r.verdict}</b>
                {r.suggested_verb
                  ? ` → ${r.suggested_verb.replace(/_/g, " ")}`
                  : ""}
                {r.flipped ? " (reversed)" : ""}
                {" · "}
                {REVIEWER_LABEL[r.reviewer] ?? r.reviewer}
                {r.confidence ? ` · ${r.confidence}` : ""}
                {" · "}
                {formatDateTime(r.created_at)}
                {!r.counted && r.reviewer !== "analyst" ? " · not counted" : ""}
              </span>
              {r.entry_title && r.entry_id && (
                <a
                  className={styles.reviewArticle}
                  href={`/?entry=${r.entry_id}`}
                >
                  {r.entry_title}
                </a>
              )}
              {r.reason && <span className={styles.reason}>{r.reason}</span>}
              {r.quote && (
                <span className={styles.quote}>
                  “{highlight(r.quote, names)}”
                </span>
              )}
            </li>
          ))}
        </ul>
      </div>
    </>
  );
}

/** The evidence behind one Review row: its article paragraph, the AI's quote
 * and reason, the facts that decide it, an edge's articles and reviews, and
 * what was already decided about the same entity. */
export function RowEvidencePanel({
  id,
  names = [],
}: {
  id: string;
  names?: string[];
}) {
  const q = useRowEvidence(id);
  if (q.isLoading) return <div className={styles.panel}>Loading evidence…</div>;
  if (q.isError || !q.data)
    return <div className={styles.panel}>Couldn't load the evidence.</div>;
  const d = q.data;
  return (
    <div className={styles.panel}>
      {(d.reason || d.quote) && (
        <div className={styles.section}>
          <div className={styles.label}>
            Why it was proposed
            {d.confidence ? ` (${d.confidence} confidence)` : ""}
          </div>
          {d.reason && <p className={styles.reason}>{d.reason}</p>}
          {d.quote && (
            <p className={styles.quote}>
              <span className={styles.muted}>The AI quoted: </span>“
              {highlight(d.quote, [...(d.article?.highlight ?? []), ...names])}”
            </p>
          )}
        </div>
      )}
      {d.facts.length > 0 && (
        <dl className={styles.facts}>
          {d.facts.map((f) => (
            <Fragment key={`${f.label}:${f.value}`}>
              <dt>{f.label}</dt>
              <dd>{f.value}</dd>
            </Fragment>
          ))}
        </dl>
      )}
      {d.article && (
        <div className={styles.section}>
          <div className={styles.label}>Article</div>
          <Article article={d.article} names={names} />
        </div>
      )}
      {d.relationship && (
        <RelationshipBody data={d.relationship} names={names} />
      )}
      {d.history.length > 0 && (
        <div className={styles.section}>
          <div className={styles.label}>Already decided about this entity</div>
          <ul className={styles.reviews}>
            {d.history.map((h, i) => (
              <li key={i}>
                <span className={styles.reviewHead}>
                  {h.subject ?? h.action} · {formatDateTime(h.when)}
                </span>
                {h.reason && <span className={styles.reason}>{h.reason}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {!d.article && !d.relationship && !d.quote && d.facts.length === 0 && (
        <p className={styles.muted}>
          This proposal has no article or recorded evidence.
        </p>
      )}
    </div>
  );
}

/** One edge's articles and reviews, for the Relationships lens. */
export function RelationshipEvidencePanel({
  id,
  names,
}: {
  id: string;
  names: string[];
}) {
  const q = useRelationshipEvidence(id);
  if (q.isLoading) return <div className={styles.panel}>Loading evidence…</div>;
  if (q.isError || !q.data)
    return <div className={styles.panel}>Couldn't load the evidence.</div>;
  return (
    <div className={styles.panel}>
      <RelationshipBody data={q.data} names={names} />
    </div>
  );
}

/** An entity's articles, for the Review tab's entity lenses. */
export function EntityEvidencePanel({ entityType, entityId }: { entityType: string; entityId: string }) {
  const q = useEntityEvidence(entityType, entityId);
  if (q.isLoading) return <div className={styles.panel}>Loading evidence…</div>;
  if (q.isError || !q.data) return <div className={styles.panel}>Couldn't load the evidence.</div>;
  return (
    <div className={styles.panel}>
      {q.data.length === 0 && <p className={styles.muted}>No article is linked to it.</p>}
      {q.data.map((a, i) => (
        <div key={a.entry_id} className={styles.section}>
          <div className={styles.label}>{i === 0 ? "Articles (the first created it, when known)" : ""}</div>
          <Article article={a} names={[]} />
        </div>
      ))}
    </div>
  );
}
