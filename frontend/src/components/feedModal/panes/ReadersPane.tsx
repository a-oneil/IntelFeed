import { FeedSubscribersPanel } from "@/components/FeedSubscribersPanel";
import type { Feed } from "@/api/types";
import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

/**
 * Who reads this feed: whether signed-out visitors may, then which analysts do.
 * Admin-only, like the pane itself.
 */
export function ReadersPane({ feed, form }: { feed: Feed; form: FeedForm }) {
  const { values, set } = form;

  return (
    <div className={styles.stack}>
      {/* Manual Uploads holds people's own documents and is never shown. */}
      {feed.feed_type !== "manual" && (
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

      <FeedSubscribersPanel feedId={feed.id} feedTitle={feed.title} />
    </div>
  );
}
