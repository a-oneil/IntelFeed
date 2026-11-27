import { useCategories } from "@/hooks/useFeeds";
import type { Feed } from "@/api/types";
import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

/**
 * The settings that belong to the reader, not the instance: what this feed is called in their sidebar, which category it is filed under, and whether it counts toward unread.
 * This is the one editable pane a non-admin shares with an admin, because these are the API's curation fields, the only ones it accepts from a non-admin.
 */
export function IdentityPane({
  feed,
  form,
  isAdmin,
}: {
  feed: Feed;
  form: FeedForm;
  isAdmin: boolean;
}) {
  const { data: categories } = useCategories();
  const { values, set } = form;
  // With per-user subscriptions on, pausing affects only the caller's copy; with the flag off it is one shared switch that only an admin may change.
  const canPause = Boolean(feed.per_user) || isAdmin;

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
            What this feed is called in your sidebar. Blank uses the name the
            feed publishes for itself.
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
          <span className={styles.hint}>
            Which group it sits under in your sidebar.
          </span>
        </div>
      </div>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={values.is_active}
          disabled={!canPause}
          onChange={(e) => set("is_active", e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Receive new articles</span>
          <span className={styles.hint}>
            {!canPause
              ? "Pausing a feed is an admin setting on this instance."
              : feed.per_user
                ? "When off, this feed stops delivering articles to you. It stays in your sidebar so you can start it again."
                : "When off, this feed is no longer fetched. It stays in your sidebar so you can start it again."}
          </span>
        </span>
      </label>

      <label className={styles.checkRow}>
        <input
          type="checkbox"
          checked={!values.is_muted}
          onChange={(e) => set("is_muted", !e.target.checked)}
        />
        <span className={styles.checkText}>
          <span className={styles.checkLabel}>Count toward unread</span>
          <span className={styles.hint}>
            {/* The checkbox is phrased positively ("counts"), so the hint explains the unchecked state and uses the name the rest of the app gives it: the sidebar groups these feeds under "Muted". Other readers are covered in the Readers pane, not here. */}
            When off, articles keep arriving and the feed still opens normally,
            but they stop adding to your unread count. The sidebar lists such feeds under Muted.
          </span>
        </span>
      </label>
    </div>
  );
}
