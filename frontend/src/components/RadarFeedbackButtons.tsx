import { useState } from "react";

import api from "@/api/client";

import styles from "./RadarFeedbackButtons.module.css";

/**
 * Thumbs on a ranked entry — the input the signal engine learns from, twice:
 * everyone's verdicts pool into the global nightly weight nudge, and your own
 * feed the per-analyst weights behind "Tuned for you". Deleted as an orphan
 * when the old Priority page was retired; restored onto the "Why it's ranked"
 * card, which is where the ranking explains itself.
 *
 * Verdict state is session-local: the API stores one verdict per user+entry
 * (voting again overwrites; a second click clears), but there is no read-back
 * endpoint yet, so a reload shows the buttons unlit even where a verdict is
 * on record.
 */
export function RadarFeedbackButtons({ entryId }: { entryId: string }) {
  const [verdict, setVerdict] = useState<number>(0);

  const send = async (v: number, e: React.MouseEvent) => {
    e.stopPropagation();
    const next = verdict === v ? 0 : v;
    setVerdict(next);
    try {
      await api.put("/engine/radar-feedback", { entry_id: entryId, verdict: next });
    } catch {
      setVerdict(verdict);
    }
  };

  return (
    <span className={styles.wrap}>
      <button
        className={`${styles.btn} ${verdict === 1 ? styles.active : ""}`}
        onClick={(e) => send(1, e)}
        title="Useful signal — teach the ranking to boost entries like this"
        aria-pressed={verdict === 1}
      >
        ▲
      </button>
      <button
        className={`${styles.btn} ${verdict === -1 ? styles.activeDown : ""}`}
        onClick={(e) => send(-1, e)}
        title="Noise — teach the ranking to quiet entries like this"
        aria-pressed={verdict === -1}
      >
        ▼
      </button>
    </span>
  );
}
