import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useSetInfoRating } from "@/hooks/useEntries";
import styles from "./InfoGradeChip.module.css";

/** Admiralty Table B-2: how credible one report is. */
export const INFO_RATINGS: Record<number, { label: string; meaning: string }> = {
  1: { label: "Confirmed", meaning: "Reported by another independent outlet; logical; consistent" },
  2: { label: "Probably true", meaning: "Not confirmed; logical; backed by evidence it shows" },
  3: { label: "Possibly true", meaning: "Not confirmed; reasonably logical; thin or secondhand" },
  4: { label: "Doubtfully true", meaning: "Not confirmed; possible but unsupported" },
  5: { label: "Improbable", meaning: "Not logical, or contradicted" },
  6: { label: "Cannot be judged", meaning: "No basis to judge (marketing, opinion, a bare link)" },
};

const RELIABILITY: Record<string, string> = {
  A: "Reliable",
  B: "Usually reliable",
  C: "Fairly reliable",
  D: "Not usually reliable",
  E: "Unreliable",
  F: "Cannot be judged",
};

const ACCESS: Record<string, string> = {
  firsthand: "Author saw it firsthand",
  secondhand: "Author relays someone else's report",
  unclear: "Author's access unclear",
};

function tone(rating: number | null | undefined): string {
  if (rating == null || rating === 6) return styles.unjudged;
  if (rating <= 2) return styles.high;
  if (rating === 3) return styles.mid;
  return styles.low;
}

interface Props {
  entryId: string;
  /** The feed's A–F letter, judged over time. */
  reliability: string | null | undefined;
  rating: number | null | undefined;
  ratingBy?: "ai" | "analyst" | null;
  aiRating?: number | null;
  access?: string | null;
  note?: string | null;
  /** Visitors see the grade but can't change it. */
  readOnly?: boolean;
}

/**
 * The article's Admiralty grade: the feed's letter (source reliability, judged
 * over time) beside this article's number (information credibility, judged
 * per report). The two are rated independently — a B feed can publish a 4.
 */
export function InfoGradeChip({ entryId, reliability, rating, ratingBy, aiRating, access, note, readOnly }: Props) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);
  const setRating = useSetInfoRating();

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // A grade with no letter isn't a grade: rate the feed first.
  if (!reliability) return null;

  const letter = reliability;
  const number = rating != null ? String(rating) : "–";

  const choose = (value: number | null) => {
    setRating.mutate(
      { entryId, rating: value },
      { onError: () => toast.error("Couldn't save the rating") },
    );
  };

  return (
    <span className={styles.wrap} ref={wrapRef}>
      <button
        type="button"
        className={`${styles.chip} ${tone(rating)}`}
        aria-expanded={open}
        aria-label={`Grade ${letter}${number}`}
        title="Admiralty grade: source reliability + information credibility"
        onClick={() => setOpen((o) => !o)}
      >
        {letter}
        {number}
      </button>
      {open && (
        <div className={styles.popover} role="dialog" aria-label="Admiralty grade">
          <div className={styles.row}>
            <span className={styles.key}>{letter}</span>
            <span>
              <strong>Source:</strong> {RELIABILITY[reliability] ?? reliability}
              <span className={styles.sub}>The feed's track record. Set under Edit Feed → Assessment.</span>
            </span>
          </div>
          <div className={styles.row}>
            <span className={styles.key}>{number}</span>
            <span>
              <strong>This article:</strong> {rating != null ? INFO_RATINGS[rating].label : "Not rated yet"}
              <span className={styles.sub}>
                {rating != null && INFO_RATINGS[rating].meaning}
                {ratingBy === "analyst" && " · set by an analyst"}
                {ratingBy === "ai" && rating === 1 && aiRating != null && aiRating !== 1 && (
                  <> · AI rated it {aiRating}; another outlet confirmed it</>
                )}
              </span>
              {access && <span className={styles.sub}>{ACCESS[access] ?? access}</span>}
              {note && <span className={styles.note}>{note}</span>}
            </span>
          </div>
          {!readOnly && (
            <>
              <div className={styles.pickLabel}>Rate this article</div>
              <div className={styles.pick}>
                {[1, 2, 3, 4, 5, 6].map((n) => (
                  <button
                    key={n}
                    type="button"
                    className={`${styles.pickBtn} ${rating === n && ratingBy === "analyst" ? styles.picked : ""}`}
                    title={`${n} — ${INFO_RATINGS[n].label}: ${INFO_RATINGS[n].meaning}`}
                    disabled={setRating.isPending}
                    onClick={() => choose(n)}
                  >
                    {n}
                  </button>
                ))}
              </div>
              {ratingBy === "analyst" && (
                <button
                  type="button"
                  className={styles.reset}
                  disabled={setRating.isPending}
                  onClick={() => choose(null)}
                >
                  Go back to the AI's rating
                </button>
              )}
            </>
          )}
        </div>
      )}
    </span>
  );
}
