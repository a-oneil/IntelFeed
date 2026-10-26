import { useThread } from "@/hooks/useThreads";
import { signalBand } from "@/utils/signalBand";
import { threadSummaryLine } from "@/utils/threads";
import { Hint } from "@/components/primitives";
import type { StoryThread } from "@/api/types";
import styles from "./ThreadRow.module.css";

interface ThreadRowProps {
  thread: StoryThread;
  score: number;
  expanded: boolean;
  onToggle: () => void;
  onOpenThread: () => void;
  onEntryClick: (entryId: string) => void;
  /** Absent for a visitor, who has no read state to change. */
  onMarkRead?: () => void;
  isMarking?: boolean;
  selectedEntryId: string | null;
}

const KIND_LABEL: Record<string, string> = {
  first_disclosure: "First",
  new_tradecraft: "New tradecraft",
  peak: "Peak",
  update: "Update",
};

function beatDate(iso: string | null): string {
  if (!iso) return "";
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

/**
 * One unfolding story as a single row in the entry list.
 *
 * Collapsed it replaces the pile: the story's name, how many outlets carried
 * it, and how much of it is new since you last looked. Expanded it shows the
 * spine — one line per wave of coverage — rather than the articles, because the
 * articles are the thing the thread exists to stop you from scrolling through.
 */
export function ThreadRow({
  thread,
  score,
  expanded,
  onToggle,
  onOpenThread,
  onEntryClick,
  onMarkRead,
  isMarking = false,
  selectedEntryId,
}: ThreadRowProps) {
  const band = signalBand(score);
  // Beats only matter once the row is open, so the detail fetch waits for it.
  const { data: detail, isLoading } = useThread(expanded ? thread.slug : null);

  return (
    <div className={`${styles.thread} ${expanded ? styles.expanded : ""}`}>
      <div className={styles.headerRow}>
        <button
          className={styles.caretBtn}
          onClick={onToggle}
          aria-expanded={expanded}
          aria-label={expanded ? "Collapse thread" : "Expand thread"}
        >
          <span className={`${styles.caret} ${expanded ? styles.caretOpen : ""}`}>▸</span>
        </button>
        <Hint
          title="Story thread"
          body="A run of coverage of the same event, clustered into one timeline instead of nine separate rows."
          aside="Open it to read the spine — what actually changed, in order."
        >
        <button className={styles.header} onClick={onOpenThread}>
          <span className={`${styles.score} ${styles[band]}`}>◆ {score.toFixed(1)}</span>
          <span className={styles.thread_} aria-hidden>
            ⟲
          </span>
          <span className={styles.title}>{thread.title}</span>
          <span className={styles.chips}>
            {thread.key_entities.slice(0, 3).map((e) => (
              <span key={`${e.entity_type}-${e.entity_id}`} className={styles.entityChip}>
                {e.label}
              </span>
            ))}
          </span>
          <span className={styles.count}>{threadSummaryLine(thread)}</span>
        </button>
        </Hint>
        {onMarkRead && (
          <button
            type="button"
            className={styles.clearBtn}
            disabled={isMarking}
            onClick={(e) => {
              e.stopPropagation();
              onMarkRead?.();
            }}
            title={isMarking ? "Marking…" : "Mark every article in this thread read"}
            aria-label={isMarking ? "Marking…" : "Mark every article in this thread read"}
          >
            {isMarking ? (
              <span className={styles.spinner} aria-hidden />
            ) : (
              <svg
                viewBox="0 0 16 16"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden
              >
                <path d="M3 8.5l3 3 7-7" />
              </svg>
            )}
          </button>
        )}
      </div>

      {expanded && (
        <div className={styles.spine}>
          {isLoading && <div className={styles.loading}>Loading the spine…</div>}
          {detail?.beats.map((beat) => (
            <button
              key={beat.id}
              className={`${styles.beat} ${
                beat.lead_entry_id && selectedEntryId === beat.lead_entry_id ? styles.beatActive : ""
              }`}
              onClick={() => beat.lead_entry_id && onEntryClick(beat.lead_entry_id)}
            >
              <span className={styles.beatMeta}>
                <span className={styles.beatDate}>{beatDate(beat.occurred_at)}</span>
                <span className={`${styles.beatKind} ${styles[beat.kind] ?? ""}`}>
                  {KIND_LABEL[beat.kind] ?? beat.kind}
                </span>
                {beat.collapsed_count > 0 && (
                  <span className={styles.folded}>{beat.collapsed_count} re-reports folded</span>
                )}
              </span>
              <span className={styles.beatHeadline}>{beat.headline}</span>
              {beat.body && <span className={styles.beatBody}>{beat.body}</span>}
            </button>
          ))}
          {detail && (
            <button className={styles.openThread} onClick={onOpenThread}>
              Open thread →
            </button>
          )}
        </div>
      )}
    </div>
  );
}
