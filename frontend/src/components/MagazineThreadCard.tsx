import { signalBand } from "@/utils/signalBand";
import { threadSummaryLine } from "@/utils/threads";
import { formatDate } from "@/utils/formatDate";
import { Hint } from "@/components/primitives";
import type { StoryThread } from "@/api/types";
import styles from "./MagazineThreadCard.module.css";

interface MagazineThreadCardProps {
  thread: StoryThread;
  /** The queue's score for this row — the same number ThreadRow shows. */
  score: number;
  onOpen: () => void;
}

/**
 * One story thread as a card in the magazine grid.
 *
 * It is a separate card next to the article cards, not a decoration on one: in the Priority Queue the articles a story absorbed are not shown in the grid, so this card is the only place that coverage appears. It leads with the count line ("11 outlets · 23 articles · 6 new"), which shows how many article cards it stands in for.
 *
 * It has no image on purpose. The lead article's image would cost a request per card and would make a story look like an article; the grid is easier to scan when the difference is visible at a glance. The ⟲ glyph, the accent border and the count line mark that difference, the same markers ThreadRow uses in the list views.
 *
 * Opening it shows the story in the reader. There is no expand-in-place: the thread's spine (its timeline) is a vertical list, which fits a row, not a card.
 */
export function MagazineThreadCard({ thread, score, onOpen }: MagazineThreadCardProps) {
  const band = signalBand(score);
  const updated = formatDate(thread.last_seen, "");

  return (
    <div
      className={styles.card}
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      }}
    >
      <div className={styles.head}>
        <Hint
          title="Story thread"
          body="Articles about the same event, grouped into one card."
          aside="Open it to see the timeline of what changed."
        >
          <span className={styles.kicker}>
            <span className={styles.glyph} aria-hidden>
              ⟲
            </span>
            Story
          </span>
        </Hint>
        <span className={`${styles.score} ${styles[band]}`}>◆ {score.toFixed(1)}</span>
      </div>

      <h3 className={styles.title}>{thread.title}</h3>
      <p className={styles.count}>{threadSummaryLine(thread)}</p>
      {thread.summary && <p className={styles.summary}>{thread.summary}</p>}

      {thread.key_entities.length > 0 && (
        <div className={styles.chips}>
          {thread.key_entities.slice(0, 3).map((e) => (
            <span key={`${e.entity_type}-${e.entity_id}`} className={styles.chip}>
              {e.label}
            </span>
          ))}
        </div>
      )}

      <div className={styles.foot}>
        {updated && <span>updated {updated}</span>}
        <span className={styles.open}>Open thread →</span>
      </div>
    </div>
  );
}
