/** ActiveStoryCard — the open story threads this entity is part of, leading the Overview's activity section: title, coverage span, and the latest update, followed by a list of previous stories. Opening a story puts ThreadReader in the workbench's docked reader, the way an article opens there. */
import { useEntityStoryThreads } from "@/hooks/useEntityProfile";
import { useOpenThread } from "@/utils/openEntry";
import { formatDate } from "@/utils/formatDate";
import styles from "./entityProfile.module.css";

function spanLabel(d: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function ActiveStoryCard({ entityType, entityId }: { entityType: string; entityId: string }) {
  // Two queries, one per status: a single "any"-status fetch is ordered by last-seen desc, so open stories would fill its limit and past stories, which are older, would be left out.
  const { data: open } = useEntityStoryThreads(entityType, entityId, { limit: 2, status: "open" });
  const { data: past = [] } = useEntityStoryThreads(entityType, entityId, { limit: 5, status: "past" });
  const openThread = useOpenThread();
  const threads = open ?? [];
  if (threads.length === 0 && past.length === 0) return null;

  return (
    <>
      {threads.map((t) => {
        // Freshness bar: how far into the story's run the last coverage sits — a story still getting coverage fills the bar; one that has gone quiet leaves a gap.
        const start = t.first_seen ? new Date(t.first_seen).getTime() : null;
        const last = t.last_seen ? new Date(t.last_seen).getTime() : null;
        const now = Date.now();
        const fill =
          start != null && last != null && now > start
            ? Math.max(0.05, Math.min(1, (last - start) / (now - start)))
            : null;
        return (
          <div key={t.slug} className={styles.storyCard}>
            <div className={styles.storyCardHead}>
              <span className={styles.storyCardTag}>Active story</span>
              {t.last_seen && <span className={styles.storyCardWhen}>updated {formatDate(t.last_seen)}</span>}
              <button className={styles.storyCardOpen} onClick={() => openThread(t.slug)}>
                Open thread →
              </button>
            </div>
            <button className={styles.storyCardTitle} onClick={() => openThread(t.slug)}>
              {t.title}
            </button>
            <div className={styles.storyCardMeta}>
              <span>
                {t.entry_count} article{t.entry_count === 1 ? "" : "s"} · {t.source_count} feed
                {t.source_count === 1 ? "" : "s"}
              </span>
              {fill != null && (
                <span className={styles.storyCardBar}>
                  <span className={styles.storyCardBarFill} style={{ width: `${Math.round(fill * 100)}%` }} />
                </span>
              )}
              <span>
                {spanLabel(t.first_seen)} → {spanLabel(t.last_seen)}
              </span>
            </div>
            {t.latest_beat && (
              <div className={styles.storyCardBeat}>
                Latest update: {t.latest_beat.headline}
              </div>
            )}
          </div>
        );
      })}
      {past.length > 0 && (
        <div className={styles.storyHistory}>
          <div className={styles.storyHistoryLabel}>Previous stories</div>
          {past.map((t) => (
            <button key={t.slug} className={styles.storyHistoryRow} onClick={() => openThread(t.slug)}>
              <span className={styles.storyHistoryTitle}>{t.title}</span>
              <span className={styles.storyHistoryMeta}>
                {t.entry_count} article{t.entry_count === 1 ? "" : "s"} · {spanLabel(t.first_seen)} →{" "}
                {spanLabel(t.last_seen)}
              </span>
            </button>
          ))}
        </div>
      )}
    </>
  );
}
