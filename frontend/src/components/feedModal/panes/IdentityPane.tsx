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
  // Pausing is the caller's own once subscriptions are on; with the flag off it
  // is the single shared switch, which only an admin may throw.
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
                ? "Off, this feed stops delivering. It stays in your sidebar so you can start it again."
                : "Off, this feed stops being fetched. It stays in your sidebar so you can start it again."}
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
            {/* The control is the positive ("counts"), so the hint explains the
                unchecked state and names what the rest of the app calls it —
                the sidebar folds these under "Muted". Nothing here mentions
                other readers: that is the Readers pane's subject. */}
            Off, articles keep arriving and the feed still opens normally — they
            just stop adding to your unread count. The sidebar calls this muted.
          </span>
        </span>
      </label>

      {/* Manual Uploads holds people's own documents and is never shown. */}
      {isAdmin && feed.feed_type !== "manual" && (
        <label className={styles.checkRow}>
          <input
            type="checkbox"
            checked={values.visible_to_visitors}
            onChange={(e) => set("visible_to_visitors", e.target.checked)}
          />
          <span className={styles.checkText}>
            <span className={styles.checkLabel}>Visible to visitors</span>
            <span className={styles.hint}>
              When public read-only mode is on, people who aren&apos;t signed in
              can see this feed and read its articles. Off, the feed and its
              articles are hidden from them everywhere.
            </span>
          </span>
        </label>
      )}
    </div>
  );
}
