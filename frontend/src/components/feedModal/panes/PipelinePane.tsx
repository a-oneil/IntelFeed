import { Link } from "react-router-dom";
import { toast } from "sonner";
import { useBulkExtract, useBulkTranslate } from "@/hooks/useIntelligence";
import { useFeedPipeline } from "@/hooks/useFeeds";
import { useSystemSettings } from "@/hooks/useSystemSettings";
import { describeStages, summarizeStages, toggleStage } from "../pipelineStages";
import { reliabilityNote } from "../reliability";
import type { FeedForm } from "../useFeedForm";
import styles from "../fields.module.css";

const PLAN_SCOPE_LABEL: Record<string, string> = {
  global: "global plan",
  category: "category plan",
  feed: "feed plan",
};

/**
 * Shows what the ingest pipeline does with this feed's articles.
 * Replaces the five-way "Intelligence Extraction" preset, three of whose labels did not match any real behavior (see pipelineStages.ts for which ones and why). Each row names a stage that actually runs and the field that drives it; rows this pane cannot change say what controls them instead.
 */
export function PipelinePane({ feedId, form }: { feedId: string; form: FeedForm }) {
  const { data: settings } = useSystemSettings();
  const bulkExtract = useBulkExtract();
  const bulkTranslate = useBulkTranslate();
  const { data: pipeline } = useFeedPipeline(feedId);

  // When settings are absent (not loaded yet, or a non-admin who can't read them), assume the AI runs, which is the default; it is better to over-warn than to tell someone nothing will be created when it will.
  const aiEnabled = settings ? Boolean(settings.settings.ai_one_pass_enabled?.value) : true;
  const ctx = { aiEnabled, pipeline };

  const stages = describeStages(form.values, ctx);
  const summary = summarizeStages(form.values, ctx);
  const planned = stages.filter((s) => s.scope === "plan");

  return (
    <div className={styles.stack}>
      {/* The summary sentence comes first: it is the only part of this pane you can read without already knowing the pipeline, and it states the overall result the checkboxes below produce. */}
      <div className={styles.summaryBox}>
        <span className={styles.summaryLabel}>In short</span>
        <span className={styles.summaryText}>{summary}</span>
      </div>

      <span className={styles.sectionLabel}>What runs on each new article</span>

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

      {/* The reliability rating is set under Assessment but affects the confidence of every catalog match made here, so this pane says so. */}
      <p className={styles.note}>{reliabilityNote(form.values.reliability_rating)}</p>

      {/* Changing a switch only affects articles that arrive next. These two actions reprocess the articles already stored, which is what you need right after turning on one of the stages above. They are also in the sidebar's context menu, which cannot be reached from inside this dialog. */}
      <div className={styles.field}>
        <span className={styles.sectionLabel}>Catch up on articles already here</span>
        <div className={styles.actionRow}>
          <button
            type="button"
            className={styles.actionBtn}
            disabled={bulkExtract.isPending}
            onClick={() =>
              bulkExtract.mutate(
                {
                  feed_id: feedId,
                  extract_types: [
                    "ttps",
                    "cves",
                    "threat_actors",
                    "malware",
                    "sectors",
                    "article_metadata",
                    "detection_rules",
                  ],
                  use_ai: true,
                },
                {
                  onSuccess: (r) =>
                    toast.success(`Queued extraction for ${r.entry_count} articles`),
                }
              )
            }
          >
            {bulkExtract.isPending ? "Starting…" : "Re-analyze past articles"}
          </button>
          <button
            type="button"
            className={styles.actionBtn}
            disabled={bulkTranslate.isPending}
            onClick={() =>
              bulkTranslate.mutate(
                { feed_id: feedId },
                {
                  onSuccess: (r) =>
                    toast.success(`Queued translation for ${r.entry_count} articles`),
                }
              )
            }
          >
            {bulkTranslate.isPending ? "Starting…" : "Translate past articles"}
          </button>
        </div>
        <span className={styles.hint}>
          The settings above only change what arrives next. These two go back over
          the articles you already have, in the background.
        </span>
      </div>

      {planned.length > 0 && (
        // Pipeline plans take priority over the Feed booleans, so for these stages a checkbox here would write a value nothing reads. Point to where they are set instead.
        <p className={styles.note}>
          {planned.length === 1 ? "One setting above is" : `${planned.length} settings above are`}{" "}
          controlled by a pipeline plan, which takes priority over this feed&rsquo;s
          own. Change {planned.length === 1 ? "it" : "them"} under{" "}
          <Link to="/settings?section=engine&tab=plans">Engine &rsaquo; Pipeline plans</Link>.
        </p>
      )}
    </div>
  );
}
