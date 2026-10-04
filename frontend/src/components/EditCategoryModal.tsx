import { useState } from "react";
import { useBulkUpdateCategoryFeeds } from "@/hooks/useFeeds";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { deriveIntelLevel } from "./IntelLevelBadge";
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
  const [intelLevel, setIntelLevel] = useState("");

  const bulkUpdate = useBulkUpdateCategoryFeeds();
  const trapRef = useFocusTrap<HTMLDivElement>();

  const hasChanges =
    interval !== "" ||
    retentionDays !== "" ||
    reliability !== "" ||
    analystNotes !== "" ||
    intelLevel !== "";

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
    if (intelLevel !== "") {
      const map: Record<string, { mode: string; extract: boolean }> = {
        full: { mode: "full", extract: true },
        selective: { mode: "selective", extract: true },
        known_only: { mode: "full", extract: false },
        manual: { mode: "manual", extract: false },
        none: { mode: "none", extract: false },
      };
      const { mode, extract } = map[intelLevel];
      data.intel_extraction_mode = mode;
      data.auto_extract_on_ingest = extract;
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
  // IntelLevelBadge owns this mapping; there were three hand-rolled copies.
  const intelLevels = [
    ...new Set(
      feeds.map((s) =>
        deriveIntelLevel(s.intel_extraction_mode || "selective", s.auto_extract_on_ingest ?? false)
      )
    ),
  ];

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
            <label>Intelligence Extraction{mixedLabel(intelLevels)}</label>
            <select
              value={intelLevel}
              onChange={(e) => setIntelLevel(e.target.value)}
              className={styles.select}
            >
              <option value="">
                — No change
                {intelLevels.length === 1 ? ` (all ${intelLevels[0]})` : ""}
              </option>
              <option value="full">Full — Extract all intelligence automatically</option>
              <option value="selective">Selective — Security-relevant articles only</option>
              <option value="known_only">Known entities only — Match against existing database</option>
              <option value="manual">Manual — Only when triggered</option>
              <option value="none">None — Disabled</option>
            </select>
            {intelLevel && (
              <span className={styles.fieldHint}>
                {intelLevel === "full" &&
                  "Best for dedicated threat intel feeds (CISA, Mandiant, CrowdStrike)"}
                {intelLevel === "selective" &&
                  "Runs a relevance check, then extracts TTPs, CVEs, and matches known entities"}
                {intelLevel === "known_only" &&
                  "Matches articles against threat actors, malware, and TTPs already in your database"}
                {intelLevel === "manual" &&
                  "No automatic processing — extract per-article from the context menu"}
                {intelLevel === "none" &&
                  "For non-security feeds (YouTube entertainment, general news)"}
              </span>
            )}
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
