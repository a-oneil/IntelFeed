import { useState } from "react";
import { useBulkUpdateCategoryFeeds } from "@/hooks/useFeeds";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import type { Category, Feed } from "@/api/types";
import styles from "./EditCategoryModal.module.css";

interface Props {
  category: Category;
  feeds: Feed[];
  onClose: () => void;
}

export function EditCategoryModal({ category, feeds, onClose }: Props) {
  const [interval, setInterval] = useState("");
  const [retentionDays, setRetentionDays] = useState("");
  const [reliability, setReliability] = useState("");
  const [analystNotes, setAnalystNotes] = useState("");
  // Bulk edits keep the "leave unchanged" idiom rather than tri-state
  // checkboxes: across N feeds a checkbox has no honest unchecked state.
  const [processing, setProcessing] = useState("");
  const [aiAnalysis, setAiAnalysis] = useState("");
  const [regexEnrich, setRegexEnrich] = useState("");
  const [detectionRules, setDetectionRules] = useState("");
  const [toolEntities, setToolEntities] = useState("");

  const bulkUpdate = useBulkUpdateCategoryFeeds();
  const trapRef = useFocusTrap<HTMLDivElement>();

  const hasChanges =
    interval !== "" ||
    retentionDays !== "" ||
    reliability !== "" ||
    analystNotes !== "" ||
    processing !== "" ||
    aiAnalysis !== "" ||
    regexEnrich !== "" ||
    detectionRules !== "" ||
    toolEntities !== "";

  const handleSave = async () => {
    const data: Record<string, unknown> = {};

    if (interval !== "") {
      data.fetch_interval_minutes = parseInt(interval, 10);
    }
    if (retentionDays === "clear") {
      data.clear_retention = true;
    } else if (retentionDays !== "") {
      data.retention_days = parseInt(retentionDays, 10);
    }
    if (reliability !== "") {
      data.reliability_rating = reliability;
    }
    if (analystNotes !== "") {
      data.analyst_notes = analystNotes;
    }
    // One field per stage, not a preset: the old five-way control mapped onto
    // two columns and three of its labels described a pipeline that no longer
    // exists. See frontend/src/components/feedModal/pipelineStages.ts.
    if (processing !== "") {
      data.intel_extraction_mode = processing;
    }
    if (aiAnalysis !== "") {
      data.ai_analysis_enabled = aiAnalysis === "on";
    }
    if (regexEnrich !== "") {
      data.auto_extract_on_ingest = regexEnrich === "on";
    }
    if (detectionRules !== "") {
      data.extract_detection_rules = detectionRules === "on";
    }
    if (toolEntities !== "") {
      data.extract_tools = toolEntities === "on";
    }

    try {
      await bulkUpdate.mutateAsync({ categoryId: category.id, data });
      onClose();
    } catch {
      // error handled by mutation
    }
  };

  // Summarize current state across feeds
  const intervals = [...new Set(feeds.map((s) => s.fetch_interval_minutes))];
  const retentions = [...new Set(feeds.map((s) => s.retention_days))];
  const reliabilities = [...new Set(feeds.map((s) => s.reliability_rating))];
  const modes = [...new Set(feeds.map((s) => s.intel_extraction_mode || "selective"))];
  const aiStates = [...new Set(feeds.map((s) => s.ai_analysis_enabled ?? true))];
  const regexStates = [...new Set(feeds.map((s) => s.auto_extract_on_ingest ?? false))];
  const ruleStates = [...new Set(feeds.map((s) => s.extract_detection_rules ?? false))];
  const toolStates = [...new Set(feeds.map((s) => s.extract_tools ?? true))];
  const onOff = (v: boolean) => (v ? "on" : "off");

  const mixedLabel = (values: unknown[]) =>
    values.length > 1 ? " (mixed)" : "";

  const intervalLabel = (v: number) => {
    if (v === 15) return "15 min";
    if (v === 30) return "30 min";
    if (v === 60) return "1 hour";
    if (v === 360) return "6 hours";
    if (v === 1440) return "1 day";
    return `${v} min`;
  };

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div
        className={styles.modal}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => e.key === "Escape" && onClose()}
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-label="Edit category feeds"
      >
        <div className={styles.header}>
          <h2>Edit Category: {category.name}</h2>
          <button onClick={onClose} className={styles.closeBtn} aria-label="Close">
            &times;
          </button>
        </div>

        <div className={styles.body}>
          <div className={styles.fieldHint} style={{ marginBottom: "1rem" }}>
            Bulk update {feeds.length} feed{feeds.length !== 1 ? "s" : ""} in this
            category. Only fields you change will be applied.
          </div>

          <div className={styles.field}>
            <label>Poll Interval{mixedLabel(intervals)}</label>
            <select
              value={interval}
              onChange={(e) => setInterval(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {intervals.length === 1
                  ? ` (all ${intervalLabel(intervals[0])})`
                  : ""}
              </option>
              <option value="15">Every 15 min</option>
              <option value="30">Every 30 min</option>
              <option value="60">Every hour</option>
              <option value="360">Every 6 hours</option>
              <option value="1440">Once a day</option>
            </select>
          </div>

          <div className={styles.field}>
            <label>Article Retention{mixedLabel(retentions)}</label>
            <select
              value={retentionDays}
              onChange={(e) => setRetentionDays(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {retentions.length === 1
                  ? ` (all ${retentions[0] == null ? "keep forever" : `${retentions[0]} days`})`
                  : ""}
              </option>
              <option value="clear">Keep forever</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="180">180 days</option>
              <option value="365">1 year</option>
            </select>
          </div>

          <div className={styles.sectionDivider}>
            <span>Intelligence</span>
          </div>

          <div className={styles.field}>
            <label>Processing{mixedLabel(modes)}</label>
            <select
              value={processing}
              onChange={(e) => setProcessing(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {modes.length === 1 ? ` (all ${modes[0]})` : ""}
              </option>
              <option value="selective">Autolink security-relevant articles</option>
              <option value="full">Autolink every article</option>
              <option value="manual">No autolinking</option>
              <option value="none">Process nothing</option>
            </select>
            {processing && (
              <span className={styles.fieldHint}>
                {processing === "selective" &&
                  "A keyword filter runs first; articles below the threshold skip autolinking."}
                {processing === "full" &&
                  "Every article is matched against your catalog, no relevance gate."}
                {processing === "manual" &&
                  "Nothing is matched automatically. The AI still reads these feeds unless you turn it off below."}
                {processing === "none" &&
                  "Articles are ingested and searchable, but nothing is extracted, linked or scored."}
              </span>
            )}
          </div>

          <div className={styles.field}>
            <label>AI analysis{mixedLabel(aiStates)}</label>
            <select
              value={aiAnalysis}
              onChange={(e) => setAiAnalysis(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {aiStates.length === 1 ? ` (all ${onOff(aiStates[0])})` : ""}
              </option>
              <option value="on">On — the AI reads every article</option>
              <option value="off">Off — no AI pass on these feeds</option>
            </select>
            <span className={styles.fieldHint}>
              The one-pass analysis that extracts TTPs, actors, malware, sectors and
              indicators. It can create entities you do not have yet.
            </span>
          </div>

          <div className={styles.field}>
            <label>Regex enrichment{mixedLabel(regexStates)}</label>
            <select
              value={regexEnrich}
              onChange={(e) => setRegexEnrich(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {regexStates.length === 1 ? ` (all ${onOff(regexStates[0])})` : ""}
              </option>
              <option value="on">On</option>
              <option value="off">Off</option>
            </select>
            <span className={styles.fieldHint}>
              Standalone CVE pass with NVD hydration, plus TTP and mitigation IDs.
            </span>
          </div>

          <div className={styles.field}>
            <label>Detection rule extraction{mixedLabel(ruleStates)}</label>
            <select
              value={detectionRules}
              onChange={(e) => setDetectionRules(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {ruleStates.length === 1 ? ` (all ${onOff(ruleStates[0])})` : ""}
              </option>
              <option value="on">On</option>
              <option value="off">Off</option>
            </select>
          </div>

          <div className={styles.field}>
            <label>Create tool entities{mixedLabel(toolStates)}</label>
            <select
              value={toolEntities}
              onChange={(e) => setToolEntities(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {toolStates.length === 1 ? ` (all ${onOff(toolStates[0])})` : ""}
              </option>
              <option value="on">On</option>
              <option value="off">Off</option>
            </select>
            <span className={styles.fieldHint}>
              Off for advisory and rule-repository feeds — they name affected software,
              not tooling an adversary wielded.
            </span>
          </div>

          <div className={styles.field}>
            <label>Source Reliability{mixedLabel(reliabilities)}</label>
            <select
              value={reliability}
              onChange={(e) => setReliability(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {reliabilities.length === 1
                  ? ` (all ${reliabilities[0] || "not rated"})`
                  : ""}
              </option>
              <option value="A">A — Reliable</option>
              <option value="B">B — Usually reliable</option>
              <option value="C">C — Fairly reliable</option>
              <option value="D">D — Not usually reliable</option>
              <option value="E">E — Unreliable</option>
              <option value="F">F — Cannot be judged</option>
            </select>
          </div>

          <div className={styles.field}>
            <label>Analyst Notes</label>
            <textarea
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              placeholder="Set notes for all feeds in this category..."
              className={styles.textarea}
              rows={2}
            />
            <span className={styles.fieldHint}>
              Will overwrite existing notes on all feeds in this category
            </span>
          </div>

          <div className={styles.actions}>
            <div className={styles.actionsSpacer} />
            <button onClick={onClose} className={styles.cancelBtn}>
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={bulkUpdate.isPending || !hasChanges}
              className={styles.saveBtn}
            >
              {bulkUpdate.isPending
                ? "Applying..."
                : `Apply to ${feeds.length} Feed${feeds.length !== 1 ? "s" : ""}`}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
