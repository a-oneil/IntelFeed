import { useCategories } from "@/hooks/useFeeds";
import type { Feed } from "@/api/types";
import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

/**
 * The three things that are the reader's own, not the instance's: what this
 * feed is called in their sidebar, where it is filed, and whether it counts.
 *
 * Deliberately the one editable pane a non-admin shares with an admin, because
 * these are the API's curation fields — the only ones it accepts from them.
 */
export function IdentityPane({ feed, form }: { feed: Feed; form: FeedForm }) {
  const { data: categories } = useCategories();
  const { values, set } = form;

  return (
    <div className={styles.stack}>
      <div className={styles.row}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="feed-display-name">
            Display name
          </label>
          <input
            id="feed-display-name"
            type="text"
            className={styles.input}
            value={values.custom_title}
            placeholder={feed.title}
            onChange={(e) => set("custom_title", e.target.value)}
          />
          <span className={styles.hint}>
            Blank falls back to the feed&rsquo;s own title.
          </span>
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor="feed-category">
            Category
          </label>
          <select
            id="feed-category"
            className={styles.select}
            value={values.category_id}
            onChange={(e) => set("category_id", e.target.value)}
          >
            <option value="">Uncategorized</option>
            {categories?.map((cat) => (
              <option key={cat.id} value={cat.id}>
                {cat.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={!values.is_muted}
          onChange={(e) => set("is_muted", !e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Count toward unread</span>
          <span className={styles.hint}>
            {feed.per_user
              ? "Your own setting — a muted feed still syncs and other readers are unaffected."
              : "A muted feed still syncs, but stays out of unread counts."}
          </span>
        </span>
      </label>
    </div>
  );
}
