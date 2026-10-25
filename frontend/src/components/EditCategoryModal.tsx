import { useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useBulkUpdateCategoryFeeds, useUpdateCategory } from "@/hooks/useFeeds";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { confirmDialog } from "@/utils/dialog";
import { STAGE_COPY } from "./feedModal/pipelineStages";
import type { Category, CategoryFeedDefaults, Feed } from "@/api/types";
import shell from "./feedModal/modalShell.module.css";
import styles from "./feedModal/fields.module.css";

interface Props {
  category: Category;
  feeds: Feed[];
  onClose: () => void;
}

/** Every bulk control is a three-way: leave alone, or set it one way or the other. */
const KEEP = "";

const INTERVALS = [
  { value: "15", label: "Every 15 min" },
  { value: "30", label: "Every 30 min" },
  { value: "60", label: "Every hour" },
  { value: "360", label: "Every 6 hours" },
  { value: "1440", label: "Once a day" },
];

const RETENTIONS = [
  { value: "clear", label: "Keep forever" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "180", label: "180 days" },
  { value: "365", label: "1 year" },
];

const PROCESSING = [
  { value: "selective", label: "Tag articles, skipping off-topic ones" },
  { value: "full", label: "Tag every article" },
  { value: "manual", label: "Do not tag articles" },
  { value: "none", label: "Do not analyse these feeds at all" },
];

const RELIABILITY = [
  { value: "A", label: "A — Reliable" },
  { value: "B", label: "B — Usually reliable" },
  { value: "C", label: "C — Fairly reliable" },
  { value: "D", label: "D — Not usually reliable" },
  { value: "E", label: "E — Unreliable" },
  { value: "F", label: "F — Cannot be judged" },
];

const TIMELINESS = [
  { value: "excellent", label: "Excellent — often first to report" },
  { value: "good", label: "Good — reports the same day" },
  { value: "fair", label: "Fair — a few days behind" },
  { value: "poor", label: "Poor — weeks behind" },
];

const RELEVANCE = [
  { value: "high", label: "High — almost always worth reading" },
  { value: "medium", label: "Medium — sometimes worth reading" },
  { value: "low", label: "Low — rarely worth reading" },
];

const ON_OFF = [
  { value: "on", label: "On" },
  { value: "off", label: "Off" },
];

/**
 * The category's saved defaults as one sentence, in the same words the
 * controls use. Exported for the test.
 */
export function describeDefaults(defaults: CategoryFeedDefaults | undefined): string | null {
  const d = defaults ?? {};
  const parts: string[] = [];
  if (d.intel_extraction_mode) {
    const mode = PROCESSING.find((p) => p.value === d.intel_extraction_mode)?.label;
    if (mode) parts.push(mode.toLowerCase());
  }
  const flag = (label: string, v: boolean | undefined) => {
    if (v !== undefined) parts.push(`${label.toLowerCase()} ${v ? "on" : "off"}`);
  };
  flag(STAGE_COPY.ai.label, d.ai_analysis_enabled);
  flag(STAGE_COPY.tools.label, d.extract_tools);
  flag(STAGE_COPY.regex.label, d.auto_extract_on_ingest);
  flag(STAGE_COPY.rules.label, d.extract_detection_rules);
  return parts.length ? parts.join("; ") : null;
}

/**
 * Apply one setting to every feed in a category at once, and optionally keep
 * the pipeline settings as the category's defaults for feeds added later.
 *
 * No analyst-notes field, deliberately: a single textarea here would replace
 * whatever every feed in the category already had, with nothing to undo it.
 * Notes are per-source judgement and belong in the feed modal.
 *
 * Deliberately not the feed modal's six-pane rail: there are nine controls, no
 * per-feed facts to show, and seeing everything you are about to apply in one
 * column is the point. What it does share is the shell, the field styles and —
 * importantly — `STAGE_COPY`, so the two modals cannot describe the same
 * setting differently again. That drift is what issue #60 was about.
 *
 * Every control is a select rather than a checkbox because across N feeds a
 * checkbox has no honest unchecked state: "off" and "leave as they are" look
 * identical and mean opposite things.
 */
export function EditCategoryModal({ category, feeds, onClose }: Props) {
  const [interval, setInterval] = useState(KEEP);
  const [retentionDays, setRetentionDays] = useState(KEEP);
  const [reliability, setReliability] = useState(KEEP);
  const [timeliness, setTimeliness] = useState(KEEP);
  const [relevance, setRelevance] = useState(KEEP);
  const [processing, setProcessing] = useState(KEEP);
  const [aiAnalysis, setAiAnalysis] = useState(KEEP);
  const [cveLookup, setCveLookup] = useState(KEEP);
  const [detectionRules, setDetectionRules] = useState(KEEP);
  const [toolEntities, setToolEntities] = useState(KEEP);

  // Where the changes go: the feeds here now, and/or the category's defaults
  // for feeds added later. Only the five pipeline settings can be defaults.
  const [applyNow, setApplyNow] = useState(true);
  const [saveDefault, setSaveDefault] = useState(false);

  const bulkUpdate = useBulkUpdateCategoryFeeds();
  const updateCategory = useUpdateCategory();
  const trapRef = useFocusTrap<HTMLDivElement>();

  const pipelineCount = [processing, aiAnalysis, cveLookup, detectionRules, toolEntities].filter(
    (v) => v !== ""
  ).length;
  const feedOnlyCount = [interval, retentionDays, reliability, timeliness, relevance].filter(
    (v) => v !== ""
  ).length;
  const pending = pipelineCount + feedOnlyCount;
  const actionable = (applyNow ? pending : 0) + (saveDefault && !applyNow ? pipelineCount : 0);
  const savedDefaults = describeDefaults(category.feed_defaults);

  const handleSave = async () => {
    const data: Record<string, unknown> = {
      apply_to_feeds: applyNow,
      save_as_category_default: saveDefault,
    };

    if (applyNow) {
      if (interval !== KEEP) data.fetch_interval_minutes = parseInt(interval, 10);
      if (retentionDays === "clear") data.clear_retention = true;
      else if (retentionDays !== KEEP) data.retention_days = parseInt(retentionDays, 10);
      if (reliability !== KEEP) data.reliability_rating = reliability;
      if (timeliness !== KEEP) data.timeliness_rating = timeliness;
      if (relevance !== KEEP) data.relevance_rating = relevance;
    }
    // One field per stage, not a preset: the old five-way control mapped onto
    // two columns and three of its labels described a pipeline that no longer
    // exists. See frontend/src/components/feedModal/pipelineStages.ts.
    if (processing !== KEEP) data.intel_extraction_mode = processing;
    if (aiAnalysis !== KEEP) data.ai_analysis_enabled = aiAnalysis === "on";
    if (cveLookup !== KEEP) data.auto_extract_on_ingest = cveLookup === "on";
    if (detectionRules !== KEEP) data.extract_detection_rules = detectionRules === "on";
    if (toolEntities !== KEEP) data.extract_tools = toolEntities === "on";

    // A bulk write over N feeds is not something to do on a stray click.
    const feedsWord = `${feeds.length} ${feeds.length === 1 ? "feed" : "feeds"}`;
    const asDefault = saveDefault && pipelineCount > 0;
    const message = applyNow
      ? `Apply ${pending} ${pending === 1 ? "change" : "changes"} to all ${feedsWord} in ${
          category.name
        }${asDefault ? ", and save the pipeline settings as its default for feeds added later" : ""}?`
      : `Save these pipeline settings as the default for feeds added to ${category.name} later? The ${feedsWord} already there stay as they are.`;
    const ok = await confirmDialog({ message, confirmLabel: applyNow ? "Apply" : "Save default" });
    if (!ok) return;

    try {
      await bulkUpdate.mutateAsync({ categoryId: category.id, data });
      onClose();
    } catch {
      // The mutation cache raises a toast; stay open so nothing is lost.
    }
  };

  const clearDefaults = async () => {
    const ok = await confirmDialog({
      message: `Clear ${category.name}'s defaults? Feeds added later start with the global defaults. Feeds already there stay as they are.`,
      confirmLabel: "Clear",
    });
    if (!ok) return;
    try {
      await updateCategory.mutateAsync({ categoryId: category.id, data: { feed_defaults: {} } });
    } catch {
      // The mutation cache raises a toast.
    }
  };

  const requestClose = async () => {
    if (pending === 0) {
      onClose();
      return;
    }
    const ok = await confirmDialog({
      message: "Discard these changes?",
      confirmLabel: "Discard",
      destructive: true,
    });
    if (ok) onClose();
  };

  /**
   * What the feeds hold today, appended to the "leave as they are" option.
   *
   * Without it a bulk editor is blind: you cannot tell whether you are about to
   * change everything or nothing, and "mixed" is the case that matters most.
   */
  const current = useMemo(() => {
    const summarize = <T,>(pick: (f: Feed) => T, render: (v: T) => string): string => {
      const values = [...new Set(feeds.map(pick))];
      if (values.length === 0) return "";
      if (values.length > 1) return " — mixed today";
      return ` — all ${render(values[0])}`;
    };
    const onOff = (v: boolean) => (v ? "on" : "off");

    return {
      interval: summarize(
        (f) => f.fetch_interval_minutes,
        (v) => (v === 1440 ? "once a day" : v >= 60 ? `every ${v / 60}h` : `every ${v}m`)
      ),
      retention: summarize(
        (f) => f.retention_days,
        (v) => (v == null ? "kept forever" : `${v} days`)
      ),
      reliability: summarize(
        (f) => f.reliability_rating,
        (v) => (v ? `rated ${v}` : "unrated")
      ),
      timeliness: summarize(
        (f) => f.timeliness_rating,
        (v) => v ?? "unrated"
      ),
      relevance: summarize(
        (f) => f.relevance_rating,
        (v) => v ?? "unrated"
      ),
      processing: summarize(
        (f) => f.intel_extraction_mode || "selective",
        (v) => v
      ),
      ai: summarize((f) => f.ai_analysis_enabled ?? true, onOff),
      cve: summarize((f) => f.auto_extract_on_ingest ?? false, onOff),
      rules: summarize((f) => f.extract_detection_rules ?? false, onOff),
      tools: summarize((f) => f.extract_tools ?? true, onOff),
    };
  }, [feeds]);

  const field = (
    id: string,
    label: string,
    value: string,
    onChange: (v: string) => void,
    options: { value: string; label: string }[],
    keepSuffix: string,
    hint?: string
  ) => (
    <div className={styles.field}>
      <label className={styles.label} htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        className={styles.select}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value={KEEP}>Leave as they are{keepSuffix}</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {hint && <span className={styles.hint}>{hint}</span>}
    </div>
  );

  return createPortal(
    <div className={shell.overlay} onClick={requestClose}>
      <div
        className={shell.modal}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.stopPropagation();
            void requestClose();
          }
        }}
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Change every feed in ${category.name}`}
      >
        <div className={shell.header}>
          <div className={shell.headerText}>
            <div className={shell.titleRow}>
              <h2 className={shell.title}>{category.name}</h2>
            </div>
            <span className={shell.headerUrl}>
              Changes apply to the {feeds.length} {feeds.length === 1 ? "feed" : "feeds"} in
              this category now. Pipeline settings can also be saved as the default for
              feeds added later.
            </span>
          </div>
          <button
            type="button"
            onClick={requestClose}
            className={shell.closeBtn}
            aria-label="Close"
          >
            <svg
              width="15"
              height="15"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className={shell.body}>
          <div className={shell.pane}>
            <div className={styles.stack}>
              <span className={styles.sectionLabel}>Fetching</span>
              <div className={styles.row}>
                {field(
                  "cat-interval",
                  "Check for new articles",
                  interval,
                  setInterval,
                  INTERVALS,
                  current.interval
                )}
                {field(
                  "cat-retention",
                  "Keep articles for",
                  retentionDays,
                  setRetentionDays,
                  RETENTIONS,
                  current.retention,
                  "Older articles are deleted. Anything extracted from them stays."
                )}
              </div>

              <span className={styles.sectionLabel}>What runs on each new article</span>
              <p className={styles.note}>
                {savedDefaults ? (
                  <>
                    Feeds added here later start with: {savedDefaults}.{" "}
                    <button
                      type="button"
                      className={styles.linkBtn}
                      onClick={clearDefaults}
                      disabled={updateCategory.isPending}
                    >
                      Clear
                    </button>
                  </>
                ) : (
                  "Feeds added here later start with the global defaults."
                )}
              </p>
              {field(
                "cat-processing",
                STAGE_COPY.master.label,
                processing,
                setProcessing,
                PROCESSING,
                current.processing,
                "Not analysing a feed leaves its articles searchable but pulls nothing out of them."
              )}
              {field(
                "cat-ai",
                STAGE_COPY.ai.label,
                aiAnalysis,
                setAiAnalysis,
                ON_OFF,
                current.ai,
                STAGE_COPY.ai.detail
              )}
              {field(
                "cat-tools",
                STAGE_COPY.tools.label,
                toolEntities,
                setToolEntities,
                ON_OFF,
                current.tools,
                STAGE_COPY.tools.detail
              )}
              {field(
                "cat-cve",
                STAGE_COPY.regex.label,
                cveLookup,
                setCveLookup,
                ON_OFF,
                current.cve,
                STAGE_COPY.regex.detail
              )}
              {field(
                "cat-rules",
                STAGE_COPY.rules.label,
                detectionRules,
                setDetectionRules,
                ON_OFF,
                current.rules,
                STAGE_COPY.rules.detail
              )}

              <span className={styles.sectionLabel}>Assessment</span>
              <div className={styles.row3}>
                {field(
                  "cat-reliability",
                  "Reliability",
                  reliability,
                  setReliability,
                  RELIABILITY,
                  current.reliability
                )}
                {field(
                  "cat-timeliness",
                  "Timeliness",
                  timeliness,
                  setTimeliness,
                  TIMELINESS,
                  current.timeliness
                )}
                {field(
                  "cat-relevance",
                  "Relevance",
                  relevance,
                  setRelevance,
                  RELEVANCE,
                  current.relevance
                )}
              </div>
              <p className={styles.note}>
                Setting any of these three records today as the date each source was
                last assessed.
              </p>

              <span className={styles.sectionLabel}>Where the changes go</span>
              <label className={styles.checkRow}>
                <input
                  type="checkbox"
                  checked={applyNow}
                  onChange={(e) => setApplyNow(e.target.checked)}
                />
                <span className={styles.checkText}>
                  <span className={styles.checkLabel}>
                    Apply to the {feeds.length} {feeds.length === 1 ? "feed" : "feeds"} here now
                  </span>
                  <span className={styles.hint}>Every setting above, on every feed in this category.</span>
                </span>
              </label>
              <label className={styles.checkRow}>
                <input
                  type="checkbox"
                  checked={saveDefault}
                  onChange={(e) => setSaveDefault(e.target.checked)}
                />
                <span className={styles.checkText}>
                  <span className={styles.checkLabel}>
                    Save the pipeline settings as this category&rsquo;s default
                  </span>
                  <span className={styles.hint}>
                    A feed added here later, by hand, OPML or a starter pack, starts with the
                    five settings under &ldquo;What runs on each new article&rdquo;. Interval,
                    retention and ratings are never defaults.
                  </span>
                </span>
              </label>

            </div>
          </div>
        </div>

        <div className={shell.footer}>
          <span className={shell.footerSpacer} />
          <span className={actionable ? shell.dirtyNote : shell.cleanNote}>
            {actionable ? `${actionable} to apply` : "No changes"}
          </span>
          <button type="button" onClick={requestClose} className={shell.cancelBtn}>
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={bulkUpdate.isPending || actionable === 0}
            className={shell.saveBtn}
          >
            {bulkUpdate.isPending
              ? "Applying…"
              : applyNow
                ? `Apply to ${feeds.length}`
                : "Save default"}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
