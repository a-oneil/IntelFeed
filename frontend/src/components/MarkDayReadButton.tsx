import { useMarkAllRead } from "@/hooks/useEntries";
import styles from "./MarkDayReadButton.module.css";

interface Props {
  dayKey: string;
  dayCount: number;
  feedId?: string;
  categoryId?: string;
}

function dayWindowIso(dayKey: string): { since: string; before: string } | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dayKey);
  if (!m) return null;
  const [, y, mo, d] = m;
  const start = new Date(Number(y), Number(mo) - 1, Number(d), 0, 0, 0, 0);
  const end = new Date(Number(y), Number(mo) - 1, Number(d), 23, 59, 59, 999);
  return { since: start.toISOString(), before: end.toISOString() };
}

export function MarkDayReadButton({ dayKey, dayCount, feedId, categoryId }: Props) {
  const markAllRead = useMarkAllRead();
  if (dayCount < 1) return null;

  return (
    <button
      type="button"
      className={styles.btn}
      disabled={markAllRead.isPending}
      onClick={(e) => {
        e.stopPropagation();
        const win = dayWindowIso(dayKey);
        if (!win) return;
        markAllRead.mutate({
          feed_id: feedId,
          category_id: categoryId,
          since: win.since,
          before: win.before,
        });
      }}
      title={markAllRead.isPending ? "Marking…" : "Mark all entries for this day as read"}
      aria-label={markAllRead.isPending ? "Marking…" : "Mark all entries for this day as read"}
    >
      {markAllRead.isPending ? (
        <span className={styles.spinner} aria-hidden />
      ) : (
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M3 8.5l3 3 7-7" />
        </svg>
      )}
    </button>
  );
}
