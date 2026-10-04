import type { FeedForm } from "../useFeedForm";
import { AdapterFields, hasAdapterFields } from "./adapterFields";
import styles from "../fields.module.css";

/**
 * Where the articles come from and how often.
 *
 * Every type the adapter registry serves, and nothing else. The old dropdown
 * offered `github` — which has no adapter, so `get_adapter()` silently fell
 * back to RSS — and five types (github_repo, github_releases,
 * github_advisories, nvd, mastodon) that the PUT's allowlist rejected with a
 * 400. The server now derives its allowlist from the registry
 * (`known_feed_types()`), so this list and that one can only disagree by
 * someone editing this array.
 */
const FEED_TYPES: { value: string; label: string }[] = [
  { value: "rss", label: "RSS" },
  { value: "atom", label: "Atom" },
  { value: "youtube", label: "YouTube" },
  { value: "podcast", label: "Podcast" },
  { value: "reddit", label: "Reddit" },
  { value: "github_repo", label: "GitHub repo" },
  { value: "github_releases", label: "GitHub releases" },
  { value: "github_advisories", label: "GitHub advisories" },
  { value: "nvd", label: "NVD" },
  { value: "mastodon", label: "Mastodon" },
  { value: "bluesky", label: "Bluesky" },
  { value: "telegram", label: "Telegram" },
  { value: "web_scraper", label: "Web scraper" },
];

const INTERVALS = [
  { value: 15, label: "Every 15 min" },
  { value: 30, label: "Every 30 min" },
  { value: 60, label: "Every hour" },
  { value: 360, label: "Every 6 hours" },
  { value: 1440, label: "Once a day" },
];

const RETENTIONS = [
  { value: "", label: "Keep forever" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "180", label: "180 days" },
  { value: "365", label: "1 year" },
];

export function SourcePane({ feedId, form }: { feedId: string; form: FeedForm }) {
  const { values, set, setAdapter } = form;

  return (
    <div className={styles.stack}>
      <div className={styles.field}>
        <label className={styles.label} htmlFor="feed-url">
          Feed URL
        </label>
        <input
          id="feed-url"
          type="url"
          className={styles.input}
          value={values.url}
          placeholder="https://example.com/feed.xml"
          onChange={(e) => set("url", e.target.value)}
        />
        <span className={styles.hint}>
          Changing this clears the fetch state and error count.
        </span>
      </div>

      <div className={styles.row3}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="feed-type">
            Feed type
          </label>
          <select
            id="feed-type"
            className={styles.select}
            value={values.feed_type}
            onChange={(e) => set("feed_type", e.target.value)}
          >
            {FEED_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="feed-interval">
            Poll interval
          </label>
          <select
            id="feed-interval"
            className={styles.select}
            value={String(values.fetch_interval_minutes)}
            onChange={(e) => set("fetch_interval_minutes", Number(e.target.value))}
          >
            {INTERVALS.map((i) => (
              <option key={i.value} value={i.value}>
                {i.label}
              </option>
            ))}
          </select>
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="feed-retention">
            Article retention
          </label>
          <select
            id="feed-retention"
            className={styles.select}
            value={values.retention_days}
            onChange={(e) => set("retention_days", e.target.value)}
          >
            {RETENTIONS.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={values.is_active}
          onChange={(e) => set("is_active", e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Feed is active</span>
          <span className={styles.hint}>
            Pausing stops polling for everyone, not just you.
          </span>
        </span>
      </label>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={Boolean(values.adapter.auto_translate)}
          onChange={(e) => setAdapter("auto_translate", e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Auto-translate on ingest</span>
          <span className={styles.hint}>
            Detect the language and translate to English via the LibreTranslate
            sidecar. The original is kept and shown alongside.
          </span>
        </span>
      </label>

      {hasAdapterFields(values.feed_type) && (
        <>
          <span className={styles.sectionLabel}>
            {FEED_TYPES.find((t) => t.value === values.feed_type)?.label} options
          </span>
          <AdapterFields feedId={feedId} form={form} />
        </>
      )}
    </div>
  );
}
