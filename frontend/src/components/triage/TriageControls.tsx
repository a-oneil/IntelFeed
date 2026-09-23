import type { ReactNode } from "react";
import { TimeRangeSelector, type TimeRange } from "@/components/TimeRangeSelector";
import type { TriageView } from "@/types/triageView";
import styles from "./TriageControls.module.css";

interface TriageControlsProps {
  view: TriageView;
  onGlobalRangeChange: (range: TimeRange, customStart?: string, customEnd?: string) => void;
  /** Dashboard tabs, rendered inline to the right of the range picker. */
  tabs?: ReactNode;
}

/**
 * The dashboard's header controls — global range + board tabs. Lives in
 * PageHeader's `controls` slot; the widget actions are `TriageActions`, in the
 * `actions` slot. Split so the dashboard header has the same two-slot shape as
 * every other workbench route.
 */
export function TriageControls({ view, onGlobalRangeChange, tabs }: TriageControlsProps) {
  return (
    <div className={styles.bar}>
      <div className={styles.zoneCenter}>
        <span className={styles.label}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
          Range
        </span>
        <TimeRangeSelector
          value={view.global_range}
          customStart={view.global_custom_start ?? undefined}
          customEnd={view.global_custom_end ?? undefined}
          onChange={onGlobalRangeChange}
          align="left"
        />
      </div>

      {tabs && <div className={styles.zone}>{tabs}</div>}
    </div>
  );
}

interface TriageActionsProps {
  onAddWidget: () => void;
  onShowTemplates: () => void;
  /** Layout lock — when on, widgets can't be dragged or resized. */
  locked: boolean;
  onToggleLocked: () => void;
}

/** Widget actions for the dashboard header. Only meaningful with a live board. */
export function TriageActions({
  onAddWidget,
  onShowTemplates,
  locked,
  onToggleLocked,
}: TriageActionsProps) {
  return (
    <>
      <button
        className={`${styles.secondaryAction} ${locked ? styles.actionOn : ""}`}
        onClick={onToggleLocked}
        title={locked ? "Unlock layout (allow drag + resize)" : "Lock layout (prevent drag + resize)"}
        aria-pressed={locked}
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" />
          {locked ? (
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          ) : (
            <path d="M7 11V7a5 5 0 0 1 9.9-1" />
          )}
        </svg>
        {locked ? "Locked" : "Lock"}
      </button>
      <button className={styles.secondaryAction} onClick={onShowTemplates}>
        Templates
      </button>
      <button className={styles.primaryAction} onClick={onAddWidget}>
        + Widget
      </button>
    </>
  );
}
