import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  useGroupedCorrelationEvents,
  useMarkEventRead,
  useMarkAllEventsRead,
} from "@/hooks/useCorrelation";
import { useTriageView } from "@/hooks/useTriageView";
import type { CorrelationEvent } from "@/api/types";
import { CorrelationSkeleton } from "@/components/Skeleton";
import { type CorrelationFilter, type CorrelationSeverity } from "@/types/triageView";
import {
  CORR_EVENT_ICONS,
  CORR_EVENT_LABELS,
  CORR_SEVERITY_MAP,
  CORR_EVENT_TYPE_GROUPS,
  CorrArticleGroup,
  getCorrEntityNav,
  getCorrArticleNav,
} from "@/components/triage/corrEventCards";
import styles from "@/components/triage/corrEvents.module.css";
import { useIsVisitor } from "@/stores/authStore";

interface Props {
  config: Record<string, unknown>;
}

/**
 * Full correlation event browser as a dashboard widget. Filters live on the
 * shared triage view (same store the priority queue reads), so they persist
 * per user rather than per widget instance.
 */
export default function CorrelationBrowserWidget({ config }: Props) {
  const navigate = useNavigate();
  const limit = (config.limit as number) || 50;

  const { view, setWidget } = useTriageView();
  // Event read state is shared and a visitor can't change it, so they see
  // every event: no "smart" or "unread" filter, nothing to mark read.
  const isVisitor = useIsVisitor();
  const savedFilter = view.widgets.correlations.filter;
  const corrFilter = isVisitor ? "all" : savedFilter;
  const corrEventTypes = view.widgets.correlations.event_types;
  const corrSeverity = view.widgets.correlations.severity;
  const corrEntityType = view.widgets.correlations.entity_type;

  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [showEventTypePicker, setShowEventTypePicker] = useState(false);
  const eventTypePickerRef = useRef<HTMLDivElement>(null);

  const setCorrFilter = useCallback(
    (filter: CorrelationFilter) => setWidget("correlations", { filter }),
    [setWidget],
  );
  const setCorrSeverity = useCallback(
    (severity: CorrelationSeverity) => setWidget("correlations", { severity }),
    [setWidget],
  );
  const setCorrEventTypes = useCallback(
    (event_types: string[]) => setWidget("correlations", { event_types }),
    [setWidget],
  );
  const toggleCorrEventType = useCallback(
    (type: string) => {
      const next = corrEventTypes.includes(type)
        ? corrEventTypes.filter((t) => t !== type)
        : [...corrEventTypes, type];
      setCorrEventTypes(next);
    },
    [corrEventTypes, setCorrEventTypes],
  );
  const setCorrEntityType = useCallback(
    (entity_type: string) => setWidget("correlations", { entity_type }),
    [setWidget],
  );

  // Close event-type picker on outside click
  useEffect(() => {
    if (!showEventTypePicker) return;
    const handler = (e: MouseEvent) => {
      if (eventTypePickerRef.current && !eventTypePickerRef.current.contains(e.target as Node)) {
        setShowEventTypePicker(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showEventTypePicker]);

  // Honor the dashboard's global range bar. Presets map straight onto the
  // API's rolling-window shorthand; a custom range sends explicit bounds with
  // the end date included in full.
  const timeBounds = useMemo<{ since?: string; until?: string }>(() => {
    const range = config.timeRange as string | undefined;
    if (!range || range === "all") return {};
    if (range === "custom") {
      const start = config.timeRangeStart as string | undefined;
      const end = config.timeRangeEnd as string | undefined;
      if (!start || !end) return {};
      return {
        since: new Date(`${start}T00:00:00`).toISOString(),
        until: new Date(`${end}T23:59:59.999`).toISOString(),
      };
    }
    return { since: range === "1y" ? "365d" : range };
  }, [config.timeRange, config.timeRangeStart, config.timeRangeEnd]);

  const corrQueryParams = useMemo(() => {
    const base: Record<string, unknown> = {
      event_types: corrEventTypes.length > 0 ? corrEventTypes.join(",") : undefined,
      exclude_types: ["feed_stale", "feed_error"],
      source_entity_type: corrEntityType || undefined,
      since: timeBounds.since,
      until: timeBounds.until,
      limit,
    };
    if (corrFilter === "smart") {
      base.is_read = false;
      base.severity = "high";
    } else if (corrFilter === "unread") {
      base.is_read = false;
      base.severity = corrSeverity || undefined;
    } else {
      base.severity = corrSeverity || undefined;
    }
    return base;
  }, [corrFilter, corrEventTypes, corrSeverity, corrEntityType, timeBounds, limit]);

  const { data: corrGroupedData, isLoading: corrLoading } = useGroupedCorrelationEvents(
    corrQueryParams as Parameters<typeof useGroupedCorrelationEvents>[0],
  );
  const corrMarkRead = useMarkEventRead();
  const corrMarkAllRead = useMarkAllEventsRead();
  const corrGroups = corrGroupedData?.groups ?? [];
  const corrUnread = corrGroupedData?.unread_count ?? 0;
  const corrHasFilters = corrEventTypes.length > 0 || !!corrSeverity || !!corrEntityType;

  // Severity counts (computed from visible groups)
  const severityCounts = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0 };
    for (const g of corrGroups) {
      for (const ev of g.events) {
        const sev = CORR_SEVERITY_MAP[ev.event_type] ?? "low";
        counts[sev]++;
      }
    }
    return counts;
  }, [corrGroups]);

  const handleCorrEventClick = (event: CorrelationEvent) => {
    if (!event.is_read && !isVisitor) corrMarkRead.mutate(event.id);
    navigate(getCorrEntityNav(event));
  };

  const handleCorrArticleClick = (event: CorrelationEvent) => {
    const nav = getCorrArticleNav(event);
    if (nav) navigate(nav);
  };

  const handleCorrClearFilters = () => {
    setCorrEventTypes([]);
    setCorrSeverity("");
    setCorrEntityType("");
  };

  const handleSeverityPillClick = (sev: CorrelationSeverity) => {
    // Switch out of smart mode when manually selecting severity
    if (corrFilter === "smart") setCorrFilter("unread");
    setCorrSeverity(corrSeverity === sev ? "" : sev);
  };

  return (
    <div className={styles.browser}>
      <div className={styles.browserToolbar}>
        {corrGroupedData ? <span className={styles.browserCount}>{corrGroupedData.total}</span> : null}

        {/* Filter mode */}
        <div className={styles.corrFilterRow}>
          {!isVisitor && (
          <>
          <button
            className={`${styles.corrFilterBtn} ${corrFilter === "smart" ? styles.corrFilterActive : ""}`}
            onClick={() => { setCorrFilter("smart"); setCorrSeverity(""); }}
            title="High severity + unread"
          >
            Smart
          </button>
          <button
            className={`${styles.corrFilterBtn} ${corrFilter === "unread" ? styles.corrFilterActive : ""}`}
            onClick={() => { setCorrFilter("unread"); setCorrSeverity(""); }}
          >
            Unread{corrUnread > 0 ? ` (${corrUnread})` : ""}
          </button>
          </>
          )}
          <button
            className={`${styles.corrFilterBtn} ${corrFilter === "all" ? styles.corrFilterActive : ""}`}
            onClick={() => { setCorrFilter("all"); setCorrSeverity(""); }}
          >
            All
          </button>
        </div>

        {/* Severity pills */}
        <div className={styles.severityPills}>
          <button
            className={`${styles.severityPill} ${styles.severityPillHigh} ${corrSeverity === "high" ? styles.severityPillActive : ""}`}
            onClick={() => handleSeverityPillClick("high")}
          >
            H <span className={styles.severityPillCount}>{severityCounts.high}</span>
          </button>
          <button
            className={`${styles.severityPill} ${styles.severityPillMedium} ${corrSeverity === "medium" ? styles.severityPillActive : ""}`}
            onClick={() => handleSeverityPillClick("medium")}
          >
            M <span className={styles.severityPillCount}>{severityCounts.medium}</span>
          </button>
          <button
            className={`${styles.severityPill} ${styles.severityPillLow} ${corrSeverity === "low" ? styles.severityPillActive : ""}`}
            onClick={() => handleSeverityPillClick("low")}
          >
            L <span className={styles.severityPillCount}>{severityCounts.low}</span>
          </button>
        </div>

        {/* Advanced filters toggle */}
        <button
          className={`${styles.advancedToggle} ${showAdvancedFilters ? styles.advancedToggleActive : ""}`}
          onClick={() => setShowAdvancedFilters((v) => !v)}
          title="More filters"
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
          </svg>
        </button>

        {corrHasFilters && (
          <button className={styles.corrClearBtn} onClick={handleCorrClearFilters} title="Clear filters">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        )}

        {corrUnread > 0 && !isVisitor && (
          <button className={styles.corrMarkAllBtn} onClick={() => corrMarkAllRead.mutate()}>
            Mark all read
          </button>
        )}
      </div>

      {/* Advanced filters row */}
      {showAdvancedFilters && (
        <div className={styles.browserAdvanced}>
          <span className={styles.advancedLabel}>Filters</span>

          <div className={styles.eventTypePicker} ref={eventTypePickerRef}>
            <button
              className={`${styles.corrSelect} ${styles.eventTypeTrigger}`}
              onClick={() => setShowEventTypePicker((v) => !v)}
              type="button"
            >
              <span>
                {corrEventTypes.length === 0
                  ? "All types"
                  : corrEventTypes.length === 1
                    ? CORR_EVENT_LABELS[corrEventTypes[0]] || corrEventTypes[0]
                    : `${corrEventTypes.length} types selected`}
              </span>
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M2 4l3 3 3-3" />
              </svg>
            </button>
            {showEventTypePicker && (
              <div className={styles.eventTypeMenu}>
                <button
                  className={styles.eventTypeAllRow}
                  onClick={() => setCorrEventTypes([])}
                  type="button"
                >
                  <span className={`${styles.checkbox} ${corrEventTypes.length === 0 ? styles.checkboxOn : ""}`} />
                  All types
                </button>
                {CORR_EVENT_TYPE_GROUPS.map((group) => (
                  <div key={group.label} className={styles.eventTypeGroup}>
                    <div className={styles.eventTypeGroupLabel}>{group.label}</div>
                    {group.types.map((type) => {
                      const checked = corrEventTypes.includes(type);
                      return (
                        <button
                          key={type}
                          className={styles.eventTypeRow}
                          onClick={() => toggleCorrEventType(type)}
                          type="button"
                        >
                          <span className={`${styles.checkbox} ${checked ? styles.checkboxOn : ""}`} />
                          <span className={styles.eventTypeIcon}>{CORR_EVENT_ICONS[type] || "\u{26A0}"}</span>
                          <span className={styles.eventTypeLabel}>{CORR_EVENT_LABELS[type] || type}</span>
                        </button>
                      );
                    })}
                  </div>
                ))}
              </div>
            )}
          </div>

          <select className={styles.corrSelect} value={corrEntityType} onChange={(e) => setCorrEntityType(e.target.value)}>
            <option value="">All entities</option>
            <option value="threat_actor">Threat Actor</option>
            <option value="malware">Malware</option>
            <option value="ttp">TTP</option>
            <option value="cve">CVE</option>
          </select>
        </div>
      )}

      <div className={styles.browserBody}>
        {corrLoading && <CorrelationSkeleton />}

        {!corrLoading && corrGroups.length === 0 && (
          <div className={styles.panelEmpty}>
            <p>{corrFilter === "smart" ? "No high-severity unread correlations" : corrFilter === "unread" ? "No unread correlations" : "No correlation events yet"}</p>
            <span>
              {timeBounds.since
                ? "Nothing in the selected range \u2014 widen it from the range bar above"
                : "Correlations appear when intelligence extraction finds entity relationships across articles"}
            </span>
          </div>
        )}

        <div className={styles.browserList}>
          {corrGroups.map((group, idx) => (
            <CorrArticleGroup
              key={group.entry_id ?? `system-${idx}`}
              group={group}
              onDismiss={isVisitor ? undefined : (id) => corrMarkRead.mutate(id)}
              onEventClick={handleCorrEventClick}
              onArticleClick={handleCorrArticleClick}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
