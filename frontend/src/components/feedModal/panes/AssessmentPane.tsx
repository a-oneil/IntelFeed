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
  { value: "excellent", label: "Excellent — often first to report" },
  { value: "good", label: "Good — reports the same day" },
  { value: "fair", label: "Fair — a few days behind" },
  { value: "poor", label: "Poor — weeks behind" },
];

const RELEVANCE = [
  { value: "", label: "Not rated" },
  { value: "high", label: "High — almost always worth reading" },
  { value: "medium", label: "Medium — sometimes worth reading" },
  { value: "low", label: "Low — rarely worth reading" },
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
          <span className={styles.hint}>
            How much you trust what it reports. Entity matches from a
            low-rated source carry less weight.
          </span>
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
          <span className={styles.hint}>
            How quickly it reports, not how accurate it is.
          </span>
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
          <span className={styles.hint}>
            How often its coverage matters to the threats you track.
          </span>
        </div>
      </div>

      <p className={styles.note}>
        Saving any of these three records today as the date this source was last
        assessed.
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
          placeholder="What this source is good for, and what to check elsewhere before trusting it…"
          onChange={(e) => set("analyst_notes", e.target.value)}
        />
      </div>
    </div>
  );
}
