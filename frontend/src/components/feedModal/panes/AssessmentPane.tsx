import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

/**
 * The analyst's judgement of the source, on all three Admiralty-style axes.
 *
 * `timeliness_rating` and `relevance_rating` have been in the schema, the PUT
 * body, the response and the TypeScript `Feed` type for a long time with no UI
 * anywhere that wrote them — so `last_reviewed_at` was being stamped off one
 * dimension out of three. These are those fields.
 */
const RELIABILITY = [
  { value: "", label: "Not rated" },
  { value: "A", label: "A — Reliable" },
  { value: "B", label: "B — Usually reliable" },
  { value: "C", label: "C — Fairly reliable" },
  { value: "D", label: "D — Not usually reliable" },
  { value: "E", label: "E — Unreliable" },
  { value: "F", label: "F — Cannot be judged" },
];

const TIMELINESS = [
  { value: "", label: "Not rated" },
  { value: "excellent", label: "Excellent — first to report" },
  { value: "good", label: "Good — same day" },
  { value: "fair", label: "Fair — a few days behind" },
  { value: "poor", label: "Poor — weeks behind" },
];

const RELEVANCE = [
  { value: "", label: "Not rated" },
  { value: "high", label: "High — on our threat model" },
  { value: "medium", label: "Medium — sometimes applies" },
  { value: "low", label: "Low — rarely applies" },
];

export function AssessmentPane({ form }: { form: FeedForm }) {
  const { values, set } = form;

  return (
    <div className={styles.stack}>
      <div className={styles.row3}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="feed-reliability">
            Reliability
          </label>
          <select
            id="feed-reliability"
            className={styles.select}
            value={values.reliability_rating}
            onChange={(e) => set("reliability_rating", e.target.value)}
          >
            {RELIABILITY.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="feed-timeliness">
            Timeliness
          </label>
          <select
            id="feed-timeliness"
            className={styles.select}
            value={values.timeliness_rating}
            onChange={(e) => set("timeliness_rating", e.target.value)}
          >
            {TIMELINESS.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="feed-relevance">
            Relevance
          </label>
          <select
            id="feed-relevance"
            className={styles.select}
            value={values.relevance_rating}
            onChange={(e) => set("relevance_rating", e.target.value)}
          >
            {RELEVANCE.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <p className={styles.note}>
        Reliability weights how much this source&rsquo;s entity matches count
        toward autolink confidence. Saving any of these stamps the review date.
      </p>

      <div className={styles.field}>
        <label className={styles.label} htmlFor="feed-notes">
          Analyst notes
        </label>
        <textarea
          id="feed-notes"
          rows={6}
          className={styles.textarea}
          value={values.analyst_notes}
          placeholder="What this source is good for, and what to corroborate elsewhere…"
          onChange={(e) => set("analyst_notes", e.target.value)}
        />
      </div>
    </div>
  );
}
