/**
 * "Your Radar" — the per-analyst view of the learned signal weights fitted
 * from their own Priority Queue thumbs.
 *
 * The engine's priority score is global: one number per entry, shared by
 * everyone. These weights are applied on top of it at read time, so the card
 * only ever describes a re-ordering of this analyst's queue — never a change
 * to what the queue contains, and never a write to a stored score. Both exits
 * are one click: the toggle restores the house ranking immediately, and the
 * reset discards the fitted weights so the nightly job starts over.
 */
import { useMemo } from "react";
import { toast } from "sonner";

import {
  useMyRadar,
  useResetMyRadarWeights,
  useSetMyRadarPersonalized,
  type MyRadarFamily,
} from "@/hooks/useEngine";

import styles from "./MyRadarCard.module.css";

const FAMILY_LABEL: Record<string, string> = {
  novelty: "Novelty",
  coverage: "Coverage",
  severity: "Severity",
  interest: "Declared interest",
  content: "Content value",
};

const FAMILY_HINT: Record<string, string> = {
  novelty: "New entities, first pairings, scoops",
  coverage: "Cross-source convergence, under-reported, echo",
  severity: "KEV, EPSS, public exploits, CVSS",
  interest: "Your PIRs and correlation events",
  content: "Extractable detection rules, deep research",
};

/** Percent change from the house weight, as a signed display string. */
function pct(weight: number): string {
  const delta = Math.round((weight - 1) * 100);
  return `${delta > 0 ? "+" : ""}${delta}%`;
}

/** Why a family's vote count is what it is — each thumb counts toward one
 *  family only, the one that contributed most to that entry's score. */
function votesHint(row: MyRadarFamily, minSamples: number): string {
  if (row.learned) return `${row.sample_count} votes decided by this family`;
  if (row.sample_count > 0) {
    return `${row.sample_count} of ${minSamples} votes needed — each thumb counts toward one family only`;
  }
  if (row.votes_seen > 0) {
    return `Fired on ${row.votes_seen} voted entries, but another signal always contributed more to the score`;
  }
  return "No votes on entries carrying this family yet";
}

function FamilyRow({ row, minSamples }: { row: MyRadarFamily; minSamples: number }) {
  const delta = row.weight - 1;
  // One bar, centred on the house weight: left of centre is suppressed, right
  // is boosted. The full-scale end is the ±35% bound the fit is clamped to.
  const magnitude = Math.min(100, Math.round((Math.abs(delta) / 0.35) * 100));
  const direction = delta > 0.001 ? "up" : delta < -0.001 ? "down" : "flat";

  return (
    <div className={styles.row}>
      <div className={styles.rowHead}>
        <span className={styles.famName}>{FAMILY_LABEL[row.family] ?? row.family}</span>
        <span className={`${styles.famDelta} ${styles[direction]}`}>
          {direction === "flat" ? "house weight" : pct(row.weight)}
        </span>
      </div>
      <div className={styles.track}>
        <span className={styles.centre} aria-hidden="true" />
        <span
          className={`${styles.fill} ${styles[direction]}`}
          style={{ width: `${magnitude / 2}%`, [direction === "down" ? "right" : "left"]: "50%" }}
        />
      </div>
      <div className={styles.rowFoot}>
        <span className={styles.famHint}>{FAMILY_HINT[row.family] ?? ""}</span>
        <span className={styles.famVotes}>
          {row.learned ? (
            <>
              {row.up_votes > 0 && <span className={styles.up}>▲{row.up_votes}</span>}
              {row.down_votes > 0 && <span className={styles.down}>▼{row.down_votes}</span>}
              <span className={styles.dim}>{row.sample_count} votes</span>
            </>
          ) : (
            <span className={styles.dim} title={votesHint(row, minSamples)}>
              {row.sample_count > 0
                ? `${row.sample_count}/${minSamples} votes`
                : row.votes_seen > 0
                  ? "never the deciding signal"
                  : "no votes yet"}
            </span>
          )}
        </span>
      </div>
    </div>
  );
}

export function MyRadarCard() {
  const { data, isLoading } = useMyRadar();
  const setPersonalized = useSetMyRadarPersonalized();
  const reset = useResetMyRadarWeights();

  const learnedCount = useMemo(() => data?.families.filter((f) => f.learned).length ?? 0, [data]);

  if (isLoading || !data) return null;
  // Nothing to configure until an admin turns personalisation on instance-wide.
  if (!data.enabled) return null;

  return (
    <div className={styles.card}>
      <div className={styles.head}>
        <h3 className={styles.title}>Your Radar</h3>
        <label className={styles.toggle}>
          <input
            type="checkbox"
            checked={data.personalized}
            onChange={(e) =>
              setPersonalized.mutate(e.target.checked, {
                onError: () => toast.error("Couldn't change your Radar ranking"),
              })
            }
          />
          <span className={styles.toggleSlider} />
        </label>
      </div>

      <p className={styles.lede}>
        Your ▲/▼ votes on Priority Queue items are fitted into a weight per signal family and
        applied to your ordering only. The score itself stays shared &mdash; personalising changes
        the order you see, never which entries reach the queue.
      </p>

      {learnedCount === 0 ? (
        <div className={styles.empty}>
          <b>Nothing learned yet.</b> Vote on Priority Queue items with ▲ and ▼. A family starts
          steering your order once it has {data.min_samples} votes in the last {data.window_days}{" "}
          days &mdash; {data.total_votes === 0 ? "you have none so far" : `you have ${data.total_votes} so far`}.
        </div>
      ) : (
        <>
          <div className={`${styles.rows} ${data.personalized ? "" : styles.inactive}`}>
            {data.families.map((f) => (
              <FamilyRow key={f.family} row={f} minSamples={data.min_samples} />
            ))}
          </div>
          <div className={styles.foot}>
            <span className={styles.dim}>
              {data.personalized
                ? `Fitted from ${data.total_votes} votes in the last ${data.window_days} days · refits nightly`
                : "Paused — you're seeing the shared ranking"}
            </span>
            <button
              className={styles.reset}
              disabled={reset.isPending}
              onClick={() =>
                reset.mutate(undefined, {
                  onSuccess: (r) => toast.success(`Cleared ${r.cleared} learned weights`),
                  onError: () => toast.error("Couldn't clear your learned weights"),
                })
              }
            >
              Forget what it learned
            </button>
          </div>
        </>
      )}
    </div>
  );
}
