import { useState } from "react";
import { toast } from "sonner";
import {
  useFeedSubscribers,
  usePushFeedToUsers,
  useRemoveFeedSubscriber,
} from "@/hooks/useFeeds";
import styles from "./FeedSubscribersPanel.module.css";

/**
 * Admin control over who reads one feed: the roster, a push-to-everyone
 * shortcut, and per-analyst add/remove.
 *
 * Used in two places and deliberately identical in both — as the body of the
 * reach popover on the Engine's feed-health rows (triage: "this feed is broken,
 * who does it cost?") and as an inline block in the admin half of
 * EditFeedModal (curation: "this one should be on everyone's list").
 */
export function FeedSubscribersPanel({
  feedId,
  feedTitle,
}: {
  feedId: string;
  feedTitle?: string;
}) {
  const { data, isLoading } = useFeedSubscribers(feedId);
  const push = usePushFeedToUsers();
  const remove = useRemoveFeedSubscriber();
  const [showAdd, setShowAdd] = useState(false);

  if (isLoading || !data) {
    return <p className={styles.muted}>Loading readers…</p>;
  }

  const { subscribers, non_subscribers, muted_count, per_user_active } = data;
  const total = subscribers.length + non_subscribers.length;
  const busy = push.isPending || remove.isPending;

  const pushAll = async () => {
    try {
      const res = await push.mutateAsync({ feedId });
      toast.success(
        res.added === 0
          ? "Everyone was already subscribed"
          : `Added ${res.added} ${res.added === 1 ? "reader" : "readers"}${
              res.is_active ? "" : " — feed is paused"
            }`
      );
    } catch {
      toast.error("Could not push this feed");
    }
  };

  const addOne = async (userId: string, username: string) => {
    try {
      await push.mutateAsync({ feedId, userIds: [userId] });
      toast.success(`Subscribed ${username}`);
    } catch {
      toast.error(`Could not subscribe ${username}`);
    }
  };

  const removeOne = async (userId: string, username: string) => {
    try {
      await remove.mutateAsync({ feedId, userId });
      toast.success(`Unsubscribed ${username}`);
    } catch {
      toast.error(`Could not unsubscribe ${username}`);
    }
  };

  return (
    <div className={styles.panel}>
      <div className={styles.head}>
        <span className={styles.count}>
          <strong>{subscribers.length}</strong> of {total}{" "}
          {total === 1 ? "analyst" : "analysts"}
          {muted_count > 0 && (
            <span className={styles.mutedNote}> · {muted_count} muted</span>
          )}
        </span>
        {non_subscribers.length > 0 && (
          <button className={styles.pushBtn} onClick={pushAll} disabled={busy}>
            Push to everyone
          </button>
        )}
      </div>

      {!per_user_active && (
        // Without the flag the sidebar ignores this table entirely, so an admin
        // staring at a roster that doesn't match what people see needs telling.
        <p className={styles.flagNote}>
          Per-user subscriptions are off, so everyone currently sees every feed.
          These rows are kept up to date and become each analyst's real list the
          moment the setting is turned on.
        </p>
      )}

      {subscribers.length === 0 ? (
        <p className={styles.muted}>
          Nobody reads {feedTitle ? `“${feedTitle}”` : "this feed"} yet.
        </p>
      ) : (
        <ul className={styles.list}>
          {subscribers.map((s) => (
            <li key={s.user_id} className={styles.item}>
              <span className={styles.name}>{s.username}</span>
              {s.is_muted && <span className={styles.mutedChip}>muted</span>}
              <button
                className={styles.removeBtn}
                onClick={() => removeOne(s.user_id, s.username)}
                disabled={busy}
                title={`Unsubscribe ${s.username}`}
                aria-label={`Unsubscribe ${s.username}`}
              >
                &times;
              </button>
            </li>
          ))}
        </ul>
      )}

      {non_subscribers.length > 0 && (
        <div className={styles.addBlock}>
          <button
            className={styles.addToggle}
            onClick={() => setShowAdd((v) => !v)}
          >
            {showAdd ? "Hide" : `Not subscribed (${non_subscribers.length})`}
          </button>
          {showAdd && (
            <ul className={styles.list}>
              {non_subscribers.map((u) => (
                <li key={u.user_id} className={styles.item}>
                  <span className={styles.name}>{u.username}</span>
                  <button
                    className={styles.addBtn}
                    onClick={() => addOne(u.user_id, u.username)}
                    disabled={busy}
                  >
                    Add
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
