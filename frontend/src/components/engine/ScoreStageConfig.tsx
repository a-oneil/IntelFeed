import { useEffect, useState } from "react";
import { toast } from "sonner";

import SystemSettings from "@/components/SystemSettings";
import { useSignalStats, useUpdateSignalSettings } from "@/hooks/useEngine";
import { useDeleteWatch, useWatchlist } from "@/hooks/useWatchlist";
import { Hint } from "@/components/primitives";

import styles from "./ScoreStageConfig.module.css";

const FAMILY_LABELS: Record<string, string> = {
  novelty: "Novelty (new entities, first pairings, scoops)",
  coverage: "Coverage (convergence, under-reported, echo)",
  severity: "Severity (KEV, EPSS, exploits, CVSS)",
  interest: "Declared interest (PIRs, correlation events)",
  content: "Content value (detection rules, deep research)",
};

const SIGNAL_DESCRIPTIONS: Record<string, string> = {
  novel_entity: "Links an actor/malware/CVE first seen in the last 14 days or with ≤3 prior articles",
  entity_resurgence: "A known entity resurfaces after 90+ days of silence",
  new_pairing: "First article ever pairing two entities (actor+malware, actor+country, malware+CVE)",
  scoop: "A reliable (A/B) feed reports a novel entity before anyone else echoes it",
  source_convergence: "3+ independent outlets on the same story thread (or, unthreaded, sharing 2+ entities within 24h)",
  under_reported: "Severe CVE (KEV, CVSS ≥9, or EPSS ≥0.5) that ≤2 sources have ever covered",
  feed_echo: "A re-report its story thread folded, or a near-duplicate of a recent entry (negative — sinks repeats)",
  kev_added: "Links a CVE added to CISA KEV within a week of publication",
  epss_jump: "A linked CVE's EPSS exploitation-probability jumped significantly this week",
  epss_high: "A linked CVE sits at the 95th+ percentile of EPSS exploitation probability",
  weaponized_poc: "A linked CVE has public PoC/weaponized exploit code on GitHub",
  critical_cvss: "Links a CVE with CVSS ≥9",
  pir_match: "Matches one of your priority intelligence requirements",
  correlation_event: "Triggered correlation events (new TTP for actor, coverage gap, trends…)",
  detection_content: "Article contains extractable detection rules",
  research_depth: "Long-form research (1500+ words with TTPs, rules, or code)",
};

/** Signal engine tuning: family multipliers, radar threshold, self-tuning readout.
 *  Interim home: Settings → System. Re-hosted under Engine → score stage in phase 6. */
export function ScoreStageConfig() {
  const { data: stats, isLoading } = useSignalStats();
  const update = useUpdateSignalSettings();
  const { data: watches } = useWatchlist();
  const deleteWatch = useDeleteWatch();
  const [multipliers, setMultipliers] = useState<Record<string, number>>({});
  const [thresholdInput, setThresholdInput] = useState<string>("");

  useEffect(() => {
    if (stats) setMultipliers(stats.family_multipliers);
  }, [stats]);

  if (isLoading || !stats) return <div className={styles.loading}>Loading signal stats…</div>;

  const save = () => {
    const body: Parameters<typeof update.mutate>[0] = { family_multipliers: multipliers };
    if (thresholdInput === "auto") {
      body.clear_threshold_override = true;
    } else if (thresholdInput !== "") {
      const v = parseFloat(thresholdInput);
      if (!Number.isNaN(v)) body.threshold_override = v;
    }
    update.mutate(body, {
      onSuccess: () => toast.success("Signal settings saved — recent entries rescoring"),
      onError: () => toast.error("Failed to save signal settings"),
    });
  };

  const health = stats.health;
  const fmtRun = (run: { status: string; finished_at: string | null } | null) =>
    run ? `${run.status}${run.finished_at ? ` · ${new Date(run.finished_at).toLocaleString()}` : ""}` : "never";

  return (
    <div className={styles.wrap}>
      <h4 className={styles.heading}>Engine settings</h4>
      <SystemSettings filterGroups={["scoring"]} flat />

      {/* Threads live under Score because they are read in the queue this stage
          ranks: a thread takes the score of its best unread beat. Its own block
          so fifteen clustering knobs don't swamp the scoring ones. */}
      <h4 className={styles.heading}>Story threads</h4>
      <SystemSettings filterGroups={["threads"]} flat hideGroupTitle />

      {health && (
        <>
          <h4 className={styles.heading}>Engine health</h4>
          <table className={styles.statsTable}>
            <tbody>
              <tr>
                <Hint
                  title="Shadow mode"
                  body="The stage runs and records what it would have done, without changing anything you see."
                  aside="Use it to grade a config before you trust it; surfacing is the separate switch."
                  place="right"
                  align="center"
                >
                  <td>Mode</td>
                </Hint>
                <td>
                  {health.surface_enabled
                    ? "surfaced (scores drive Radar & chips)"
                    : health.shadow_enabled
                      ? "shadow (scoring silently)"
                      : "off"}
                </td>
              </tr>
              <tr>
                <td title="Entries published in the last 72h with no score. A handful just ingested is normal; a growing number means scoring is failing — the 6-hourly rescore sweep picks these up.">
                  Unscored recent entries (72h)
                </td>
                <td>{health.unscored_recent}</td>
              </tr>
              <tr>
                <td>Last rate recompute (nightly)</td>
                <td>{fmtRun(health.last_rate_recompute)}</td>
              </tr>
              <tr>
                <td>Last rescore sweep (6-hourly)</td>
                <td>{fmtRun(health.last_rescore)}</td>
              </tr>
              <tr>
                <td title="Radar ▲▼ feedback per signal family over 30 days. A family needs the minimum sample count before its nudge applies.">
                  Feedback collected (30d)
                </td>
                <td>
                  {Object.keys(health.feedback_counts).length === 0
                    ? "none yet"
                    : Object.entries(health.feedback_counts)
                        .map(([family, n]) => {
                          const nudge = health.feedback_nudges[family];
                          const state =
                            n < health.feedback_min_samples
                              ? `collecting ${n}/${health.feedback_min_samples}`
                              : `${n} · nudge ${nudge != null ? `${nudge.toFixed(2)}×` : "1.00×"}`;
                          return `${family}: ${state}`;
                        })
                        .join(" · ")}
                </td>
              </tr>
            </tbody>
          </table>
        </>
      )}

      <p className={styles.hint}>
        How scoring works: every new entry is checked against 15 signals (hover a signal below for
        what it detects). An entry's priority score is the sum of its firing signals, each weighted
        by rarity — a signal that fires on 5% of entries gets weight 1.0; rarer fires count for
        more, common ones for less — times its family multiplier. Entries scoring at or above the
        radar threshold get a signal chip and rank first in Triage.
      </p>

      <h4 className={styles.heading}>Signal families</h4>
      <p className={styles.hint}>
        Steer whole families without touching individual weights: 1.0× is neutral, 0× silences the
        family, 2× doubles its influence. Saving rescores the last 7 days immediately.
      </p>
      {Object.keys(FAMILY_LABELS).map((family) => (
        <label key={family} className={styles.sliderRow}>
          <span className={styles.sliderLabel}>{FAMILY_LABELS[family]}</span>
          <input
            type="range"
            min={0}
            max={2}
            step={0.1}
            value={multipliers[family] ?? 1}
            onChange={(e) => setMultipliers((m) => ({ ...m, [family]: parseFloat(e.target.value) }))}
          />
          <span className={styles.sliderValue}>{(multipliers[family] ?? 1).toFixed(1)}×</span>
        </label>
      ))}

      <h4 className={styles.heading}>Radar threshold</h4>
      <p className={styles.hint}>
        The cut line for "on radar": entries scoring at or above it show signal chips and lead the
        Priority Queue. Currently {stats.threshold.toFixed(2)}{" "}
        ({stats.threshold_is_auto
          ? "auto: tracks the 95th percentile of the last 7 days' scores, so roughly the top 5% of entries make the cut"
          : "manual override"}).
        Enter a value to override (lower = more entries on radar), or "auto" to restore
        self-tuning.
      </p>
      <div className={styles.thresholdRow}>
        <input
          type="text"
          placeholder={stats.threshold.toFixed(2)}
          value={thresholdInput}
          onChange={(e) => setThresholdInput(e.target.value)}
          className={styles.thresholdInput}
        />
        <button className={styles.saveBtn} onClick={save} disabled={update.isPending}>
          {update.isPending ? "Saving…" : "Save"}
        </button>
      </div>

      <h4 className={styles.heading}>Watched &amp; muted entities</h4>
      <p className={styles.hint}>
        Watches boost matching entries at read time; mutes suppress them. Add or remove from any entity profile's ⋯
        menu.
      </p>
      {!watches?.length ? (
        <p className={styles.hint}>No watched or muted entities yet.</p>
      ) : (
        <table className={styles.statsTable}>
          <thead>
            <tr>
              <th>Entity</th>
              <th>Type</th>
              <th>Mode</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {watches.map((w) => (
              <tr key={w.id}>
                <td>{w.entity_name ?? w.entity_id}</td>
                <td>{w.entity_type.replace(/_/g, " ")}</td>
                <td>{w.mode === "watch" ? `watch (+${w.boost.toFixed(1)})` : "mute"}</td>
                <td>
                  <button
                    className={styles.removeBtn}
                    onClick={() => deleteWatch.mutate({ entity_type: w.entity_type, entity_id: w.entity_id })}
                    disabled={deleteWatch.isPending}
                    title="Remove"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h4 className={styles.heading}>Self-tuning readout</h4>
      <p className={styles.hint}>
        Firing rate = share of scored entries where the signal fired over the last 30 days
        (recomputed nightly). Effective weight = rarity weight × family multiplier — what one
        firing adds to an entry's score. ▲▼ feedback on Priority Queue items nudges family weights up to
        ±10%. Hover a signal name for what it detects.
      </p>
      <table className={styles.statsTable}>
        <thead>
          <tr>
            <th>Signal</th>
            <th>Family</th>
            <th>30d firing rate</th>
            <th>Effective weight</th>
          </tr>
        </thead>
        <tbody>
          {stats.signals
            .slice()
            .sort((a, b) => b.effective_weight - a.effective_weight)
            .map((s) => (
              <tr key={s.signal_type}>
                <td title={SIGNAL_DESCRIPTIONS[s.signal_type]}>{s.signal_type.replace(/_/g, " ")}</td>
                <td>{s.family}</td>
                <td>{s.firing_rate != null ? `${(s.firing_rate * 100).toFixed(2)}%` : "—"}</td>
                <td>{s.effective_weight.toFixed(2)}</td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}
