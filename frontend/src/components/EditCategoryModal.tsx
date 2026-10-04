import { useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useBulkUpdateCategoryFeeds } from "@/hooks/useFeeds";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { confirmDialog } from "@/utils/dialog";
import { STAGE_COPY } from "./feedModal/pipelineStages";
import type { Category, Feed } from "@/api/types";
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
 * Apply one setting to every feed in a category at once.
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

  const bulkUpdate = useBulkUpdateCategoryFeeds();
  const trapRef = useFocusTrap<HTMLDivElement>();

  const pending = [
    interval,
    retentionDays,
    reliability,
    timeliness,
    relevance,
    processing,
    aiAnalysis,
    cveLookup,
    detectionRules,
    toolEntities,
  ].filter((v) => v !== "").length;

  const handleSave = async () => {
    const data: Record<string, unknown> = {};

    if (interval !== KEEP) data.fetch_interval_minutes = parseInt(interval, 10);
    if (retentionDays === "clear") data.clear_retention = true;
    else if (retentionDays !== KEEP) data.retention_days = parseInt(retentionDays, 10);
    if (reliability !== KEEP) data.reliability_rating = reliability;
    if (timeliness !== KEEP) data.timeliness_rating = timeliness;
    if (relevance !== KEEP) data.relevance_rating = relevance;
    // One field per stage, not a preset: the old five-way control mapped onto
    // two columns and three of its labels described a pipeline that no longer
    // exists. See frontend/src/components/feedModal/pipelineStages.ts.
    if (processing !== KEEP) data.intel_extraction_mode = processing;
    if (aiAnalysis !== KEEP) data.ai_analysis_enabled = aiAnalysis === "on";
    if (cveLookup !== KEEP) data.auto_extract_on_ingest = cveLookup === "on";
    if (detectionRules !== KEEP) data.extract_detection_rules = detectionRules === "on";
    if (toolEntities !== KEEP) data.extract_tools = toolEntities === "on";

    // A bulk write over N feeds is not something to do on a stray click.
    const ok = await confirmDialog({
      message: `Apply ${pending} ${pending === 1 ? "change" : "changes"} to all ${feeds.length} ${
        feeds.length === 1 ? "feed" : "feeds"
      } in ${category.name}?`,
      confirmLabel: "Apply",
    });
    if (!ok) return;

    try {
      await bulkUpdate.mutateAsync({ categoryId: category.id, data });
      onClose();
    } catch {
      // The mutation cache raises a toast; stay open so nothing is lost.
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
              Changes apply to all {feeds.length} {feeds.length === 1 ? "feed" : "feeds"} in
              this category
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

            </div>
          </div>
        </div>

        <div className={shell.footer}>
          <span className={shell.footerSpacer} />
          <span className={pending ? shell.dirtyNote : shell.cleanNote}>
            {pending ? `${pending} to apply` : "No changes"}
          </span>
          <button type="button" onClick={requestClose} className={shell.cancelBtn}>
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={bulkUpdate.isPending || pending === 0}
            className={shell.saveBtn}
          >
            {bulkUpdate.isPending ? "Applying…" : `Apply to ${feeds.length}`}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
