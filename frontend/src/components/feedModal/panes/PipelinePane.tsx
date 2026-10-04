import { Link } from "react-router-dom";
import { useFeedPipeline } from "@/hooks/useFeeds";
import { useSystemSettings } from "@/hooks/useSystemSettings";
import { describeStages, summarizeStages, toggleStage } from "../pipelineStages";
import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

const PLAN_SCOPE_LABEL: Record<string, string> = {
  global: "global plan",
  category: "category plan",
  feed: "feed plan",
};

/**
 * What the ingest pipeline does with this feed's articles.
 *
 * Replaces the five-way "Intelligence Extraction" preset, three of whose
 * labels no longer described anything real — see pipelineStages.ts for which
 * ones and why. Each row names a stage that actually runs and the field that
 * drives it; rows this pane cannot change say who holds them instead.
 */
export function PipelinePane({ feedId, form }: { feedId: string; form: FeedForm }) {
  const { data: settings } = useSystemSettings();
  const { data: pipeline } = useFeedPipeline(feedId);

  // Absent (not yet loaded, or a non-admin who can't read settings): assume the
  // AI runs, which is the shipped default — better to over-warn than to tell
  // someone nothing will be created when it will.
  const aiEnabled = settings ? Boolean(settings.settings.ai_one_pass_enabled?.value) : true;
  const ctx = { aiEnabled, pipeline };

  const stages = describeStages(form.values, ctx);
  const summary = summarizeStages(form.values, ctx);
  const planned = stages.filter((s) => s.scope === "plan");

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
                    className={`${styles.stageLabel} ${stage.on ? "" : styles.stageLabelOff}`}
                  >
                    {stage.label}
                  </span>
                  {stage.writes && stage.on && (
                    <span className={styles.writesChip}>writes entities</span>
                  )}
                </span>
                <span className={styles.stageDetail}>{stage.detail}</span>
              </span>
              {stage.scope === "global" && <span className={styles.scopeChip}>global</span>}
              {stage.scope === "plan" && (
                <span className={`${styles.scopeChip} ${styles.scopeChipPlan}`}>
                  {PLAN_SCOPE_LABEL[stage.planScope ?? "global"]}
                </span>
              )}
            </label>
          );
        })}
      </div>

      <div className={styles.summaryBox}>
        <span className={styles.summaryLabel}>In plain words</span>
        <span className={styles.summaryText}>{summary}</span>
      </div>

      {planned.length > 0 && (
        // Plans layer over the Feed booleans, so for these stages a checkbox
        // here would write a value nothing reads. Say where they live instead.
        <p className={styles.note}>
          {planned.length === 1 ? "One stage is" : `${planned.length} stages are`} set by a
          pipeline plan, which overrides this feed&rsquo;s own settings. Change{" "}
          {planned.length === 1 ? "it" : "them"} under{" "}
          <Link to="/settings?section=engine&tab=plans">Engine &rsaquo; Pipeline plans</Link>.
        </p>
      )}
    </div>
  );
}
