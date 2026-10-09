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
 * One unfolding story as a card in the magazine grid.
 *
 * A sibling of the article cards, not an ornament on one: in the Priority Queue
 * the articles a story absorbed never reach the grid, so this card is the only
 * place that coverage exists. It leads with the count line — "11 outlets · 23
 * articles · 6 new" is the card's whole argument for standing where twenty-odd
 * article cards would have.
 *
 * Deliberately image-less. The lead article's art would cost a request per
 * card, and the fetch would buy a disguise: a story is not an article and the
 * grid reads better when the difference is visible at a glance. The ⟲ glyph,
 * the accent rule and the count line carry that difference — the same vocabulary
 * ThreadRow uses in the list views.
 *
 * Opening it puts the story in the reader. There is no expand-in-place: the
 * spine is a vertical list of beats, which is a row's shape, not a card's.
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
          body="A run of coverage of the same event, clustered into one card instead of nine."
          aside="Its articles are folded in — open it to read the spine."
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
