import { useEffect, useState } from "react";

import api from "@/api/client";
import SystemSettings from "@/components/SystemSettings";

import styles from "@/pages/SettingsPage.module.css";

/** Correlation engine tuning (proximity scoring + intelligence settings) —
 *  formerly Settings → Workbench, re-hosted on the correlation stage. */
export function CorrelationTuningPanel() {
  // Proximity tuning
  const [proxSettings, setProxSettings] = useState<{
    proximity_default_score: number;
    proximity_decay_rate: number;
    proximity_strong_threshold: number;
    proximity_moderate_threshold: number;
  } | null>(null);
  const [proxDraft, setProxDraft] = useState<typeof proxSettings>(null);
  const [proxSaving, setProxSaving] = useState(false);
  const [proxStatus, setProxStatus] = useState<string | null>(null);

  useEffect(() => {
    api.get<{
      proximity_default_score: number;
      proximity_decay_rate: number;
      proximity_strong_threshold: number;
      proximity_moderate_threshold: number;
    }>("/proximity-settings").then((res) => {
      setProxSettings(res.data);
      setProxDraft(res.data);
    });
  }, []);

  const proxDirty =
    proxSettings && proxDraft
      ? JSON.stringify(proxSettings) !== JSON.stringify(proxDraft)
      : false;

  const handleProxSave = async () => {
    if (!proxDraft) return;
    setProxSaving(true);
    setProxStatus(null);
    try {
      await api.patch("/system-settings", proxDraft);
      setProxSettings({ ...proxDraft });
      setProxStatus("Proximity settings saved. Changes apply to new queries immediately.");
    } catch {
      setProxStatus("Failed to save proximity settings.");
    } finally {
      setProxSaving(false);
    }
  };

  const handleProxReset = () => {
    if (proxSettings) setProxDraft({ ...proxSettings });
    setProxStatus(null);
  };

  // Live preview: compute example scores for the draft values
  const previewScores = proxDraft
    ? [0, 1, 2, 4, 8, 15].map((d) => ({
        distance: d,
        score: +(1.0 / (1 + proxDraft.proximity_decay_rate * d)).toFixed(3),
      }))
    : [];

  return (
    <div className={styles.sectionContent}>
      <p className={styles.sectionDesc}>
        Tune how the correlation engine scores and stores entity relationships.
      </p>

      <SystemSettings
        filterGroups={["intelligence"]}
        flat
        excludeKeys={[
          "proximity_default_score",
          "proximity_decay_rate",
          "proximity_strong_threshold",
          "proximity_moderate_threshold",
        ]}
      />

      {proxDraft && (
        <div>
          <h3 className={styles.cardTitle}>Proximity Scoring</h3>
          <p className={styles.hint}>
            Controls how the correlation engine scores entity relationships based on
            paragraph distance. When two entities appear in the same article, their
            proximity score is calculated as:
          </p>
          <pre className={styles.formula}>
            score = 1 / (1 + decay_rate × paragraph_distance)
          </pre>
          <p className={styles.hint}>
            Entities in the same paragraph (distance 0) always score 1.0.
            Higher decay rates penalize distance more aggressively — entities further
            apart in an article get lower scores. The thresholds control how scores
            map to the "strong," "moderate," and "weak" badges on entity profiles.
          </p>

          <div className={styles.proxGrid}>
            <div className={styles.proxField}>
              <label className={styles.proxLabel}>
                Decay Rate
                <span className={styles.proxHint}>
                  How fast scores drop with paragraph distance.
                  At 1.0 (default), adjacent paragraphs score 0.5.
                  At 2.0, adjacent paragraphs score 0.33 — much stricter.
                  At 0.5, adjacent paragraphs score 0.67 — more lenient.
                </span>
              </label>
              <input
                type="number"
                className={styles.proxInput}
                min={0.1}
                max={10}
                step={0.1}
                value={proxDraft.proximity_decay_rate}
                onChange={(e) =>
                  setProxDraft({ ...proxDraft, proximity_decay_rate: +e.target.value })
                }
              />
            </div>

            <div className={styles.proxField}>
              <label className={styles.proxLabel}>
                Default Score (legacy data)
                <span className={styles.proxHint}>
                  Score assigned when paragraph positions are unknown (pre-backfill data).
                  Set lower to de-emphasize unverified relationships, higher to trust them more.
                </span>
              </label>
              <input
                type="number"
                className={styles.proxInput}
                min={0}
                max={1}
                step={0.05}
                value={proxDraft.proximity_default_score}
                onChange={(e) =>
                  setProxDraft({ ...proxDraft, proximity_default_score: +e.target.value })
                }
              />
            </div>

            <div className={styles.proxField}>
              <label className={styles.proxLabel}>
                Strong Threshold
                <span className={styles.proxHint}>
                  Minimum score for a "strong" badge. Default 0.7 = same paragraph or
                  adjacent with low decay.
                </span>
              </label>
              <input
                type="number"
                className={styles.proxInput}
                min={0}
                max={1}
                step={0.05}
                value={proxDraft.proximity_strong_threshold}
                onChange={(e) =>
                  setProxDraft({ ...proxDraft, proximity_strong_threshold: +e.target.value })
                }
              />
            </div>

            <div className={styles.proxField}>
              <label className={styles.proxLabel}>
                Moderate Threshold
                <span className={styles.proxHint}>
                  Minimum score for a "moderate" badge. Below this is "weak."
                  Default 0.3 = roughly 2–3 paragraphs apart at decay 1.0.
                </span>
              </label>
              <input
                type="number"
                className={styles.proxInput}
                min={0}
                max={1}
                step={0.05}
                value={proxDraft.proximity_moderate_threshold}
                onChange={(e) =>
                  setProxDraft({ ...proxDraft, proximity_moderate_threshold: +e.target.value })
                }
              />
            </div>
          </div>

          <div className={styles.proxPreview}>
            <h4 className={styles.proxPreviewTitle}>Live Preview — Score by Paragraph Distance</h4>
            <table className={styles.proxTable}>
              <thead>
                <tr>
                  <th>Distance</th>
                  <th>Score</th>
                  <th>Badge</th>
                  <th>Example</th>
                </tr>
              </thead>
              <tbody>
                {previewScores.map((row) => {
                  const badge =
                    row.score >= proxDraft.proximity_strong_threshold
                      ? "strong"
                      : row.score >= proxDraft.proximity_moderate_threshold
                        ? "moderate"
                        : "weak";
                  const examples: Record<number, string> = {
                    0: "Same paragraph — \"APT29 deployed Cobalt Strike\"",
                    1: "Adjacent paragraphs — likely same topic",
                    2: "Two paragraphs apart — probable context",
                    4: "Nearby section — possible relationship",
                    8: "Different section — weak signal",
                    15: "Distant mention — likely unrelated topics",
                  };
                  return (
                    <tr key={row.distance}>
                      <td>{row.distance === 0 ? "0 (same ¶)" : `${row.distance} ¶`}</td>
                      <td>{row.score}</td>
                      <td>
                        <span className={`${styles.proxBadge} ${styles[`prox_${badge}`]}`}>
                          {badge}
                        </span>
                      </td>
                      <td className={styles.proxExample}>{examples[row.distance]}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className={styles.cardActions}>
            <button
              className={styles.btnPrimary}
              onClick={handleProxSave}
              disabled={proxSaving || !proxDirty}
            >
              {proxSaving ? "Saving..." : "Save Proximity Settings"}
            </button>
            {proxDirty && (
              <button className={styles.btnSecondary} onClick={handleProxReset}>
                Discard Changes
              </button>
            )}
            {proxStatus && <span className={styles.successMsg}>{proxStatus}</span>}
          </div>
        </div>
      )}
    </div>
  );
}
