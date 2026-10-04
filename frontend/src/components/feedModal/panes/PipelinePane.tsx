import { useSystemSettings } from "@/hooks/useSystemSettings";
import { describeStages, summarizeStages, toggleStage } from "../pipelineStages";
import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

/**
 * What the ingest pipeline does with this feed's articles.
 *
 * Replaces the five-way "Intelligence Extraction" preset, three of whose
 * labels no longer described anything real — see pipelineStages.ts for which
 * ones and why. Each row here names a stage that actually runs and the field
 * that drives it; the two with no per-feed field are marked `global` and shown
 * read-only rather than implied.
 */
export function PipelinePane({ form }: { form: FeedForm }) {
  const { data: settings } = useSystemSettings();
  // Absent (not yet loaded, or a non-admin who can't read settings): assume the
  // AI runs, which is the shipped default — better to over-warn than to tell
  // someone nothing will be created when it will.
  const aiEnabled = settings ? Boolean(settings.settings.ai_one_pass_enabled?.value) : true;

  const stages = describeStages(form.values, aiEnabled);
  const summary = summarizeStages(form.values, aiEnabled);

  return (
    <div className={styles.stack}>
      <span className={styles.sectionLabel}>What happens to a new article</span>

      <div className={styles.stageList}>
        {stages.map((stage) => {
          const rowClass = [
            styles.stageRow,
            stage.nested ? styles.stageRowNested : "",
            stage.disabled ? styles.stageRowDisabled : "",
          ]
            .filter(Boolean)
            .join(" ");

          return (
            <label key={stage.id} className={rowClass}>
              <input
                type="checkbox"
                checked={stage.on}
                disabled={stage.disabled}
                onChange={(e) =>
                  form.setMany(toggleStage(form.values, stage.id, e.target.checked))
                }
              />
              <span className={styles.stageText}>
                <span className={styles.stageHead}>
                  <span
                    className={`${styles.stageLabel} ${
                      stage.on ? "" : styles.stageLabelOff
                    }`}
                  >
                    {stage.label}
                  </span>
                  {stage.writes && stage.on && (
                    <span className={styles.writesChip}>writes entities</span>
                  )}
                </span>
                <span className={styles.stageDetail}>{stage.detail}</span>
              </span>
              {stage.scope === "global" && (
                <span className={styles.scopeChip}>global</span>
              )}
            </label>
          );
        })}
      </div>

      <div className={styles.summaryBox}>
        <span className={styles.summaryLabel}>In plain words</span>
        <span className={styles.summaryText}>{summary}</span>
      </div>
    </div>
  );
}
