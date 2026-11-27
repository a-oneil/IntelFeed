import { useState } from "react";

import api from "@/api/client";

import styles from "./RadarFeedbackButtons.module.css";

/**
 * Up/down vote buttons on a ranked entry, shown on the "Why it's ranked" card. The signal engine uses the votes in two ways: everyone's verdicts pool into the global nightly weight nudge, and your own feed the per-analyst weights behind "Tuned for you".
 *
 * Verdict state is session-local: the API stores one verdict per user+entry (voting again overwrites; clicking the same button again clears it), but there is no read-back endpoint yet, so after a reload the buttons show unlit even where a verdict is on record.
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
        title="Useful. Rank entries like this higher."
        aria-pressed={verdict === 1}
      >
        ▲
      </button>
      <button
        className={`${styles.btn} ${verdict === -1 ? styles.activeDown : ""}`}
        onClick={(e) => send(-1, e)}
        title="Noise. Rank entries like this lower."
        aria-pressed={verdict === -1}
      >
        ▼
      </button>
    </span>
  );
}
