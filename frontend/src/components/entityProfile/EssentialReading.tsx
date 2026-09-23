/**
 * EssentialReading — the three highest-signal articles mentioning this entity
 * in the last 30 days, ranked by the signal engine. The activity chart says how
 * much is being written; this says which pieces are worth reading.
 */
import { useEntityTopEntries } from "@/hooks/useEntityProfile";
import { formatDate } from "@/utils/formatDate";
import type { EntityType } from "@/stores/intelStore";
import styles from "./entityProfile.module.css";

export function EssentialReading({
  entityType,
  entityId,
  onOpenArticle,
}: {
  entityType: EntityType;
  entityId: string;
  onOpenArticle: (entryId: string) => void;
}) {
  const { data: items } = useEntityTopEntries(entityType, entityId, 30);
  if (!items || items.length === 0) return null;
  const hasSignals = items.some((i) => i.signal != null);

  return (
    <div className={styles.reading}>
      <div className={styles.readingTitle}>
        Essential reading
        <span className={styles.readingSub}>
          {hasSignals ? "top signal · last 30 days" : "most recent · last 30 days"}
        </span>
      </div>
      {items.map((item) => (
        <div key={item.entry_id} className={styles.readingItem}>
          {item.signal != null && (
            <span className={styles.readingScore} title="Signal-engine score">
              {Math.round(item.signal * 100)}
            </span>
          )}
          <button className={styles.readingLink} onClick={() => onOpenArticle(item.entry_id)}>
            {item.title}
          </button>
          <span className={styles.readingSource}>
            {item.feed_title}
            {item.published_at ? ` · ${formatDate(item.published_at)}` : ""}
          </span>
        </div>
      ))}
    </div>
  );
}
