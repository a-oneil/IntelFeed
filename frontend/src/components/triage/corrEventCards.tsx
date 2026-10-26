import { useState } from "react";
import { Chip } from "@/components/primitives/Chip";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";
import type { CorrelationEvent, GroupedCorrelationEventsEntry } from "@/api/types";
// Shared stylesheet with the correlation browser widget — the correlation
// cards render identically in the queue's inline expansions and the browser.
import styles from "./corrEvents.module.css";

/**
 * Correlation-event severity is its own three-step scale, deliberately kept on
 * literal values rather than aliased onto --severity-* or --entity-*: "low"
 * here means "informational", and the app's severity ramp paints low green,
 * which would read as "resolved" in a feed of open findings.
 */
const CORR_SEVERITY_COLORS: Record<string, string> = {
  high: "#ef4444",
  medium: "#f59e0b",
  low: "var(--text-muted)",
};

export const CORR_EVENT_ICONS: Record<string, string> = {
  new_ttp_for_known_actor: "\u{1F3AF}",
  new_ttp_for_known_malware: "\u{1F41B}",
  new_malware_for_known_actor: "\u{1F41B}",
  actor_malware_cooccurrence: "\u{1F517}",
  coverage_gap: "\u{26A0}",
  exploit_status_change: "\u{1F4A5}",
  cve_score_change: "\u{1F4CA}",
  new_exploit_discovered: "\u{1F6A8}",
  kev_addition: "\u{1F6E1}",
  trending_entity: "\u{1F4C8}",
  requirement_match: "\u{1F4CB}",
  campaign_match: "\u{1F3F4}",
  new_intel_for_rule: "\u{1F50D}",
  feed_stale: "\u{23F0}",
  feed_error: "\u{274C}",
};

export const CORR_EVENT_LABELS: Record<string, string> = {
  new_ttp_for_known_actor: "New TTP for known actor",
  new_ttp_for_known_malware: "New TTP for known malware",
  new_malware_for_known_actor: "New malware for known actor",
  actor_malware_cooccurrence: "Actor-malware co-occurrence",
  coverage_gap: "Detection coverage gap",
  exploit_status_change: "Exploit status change",
  cve_score_change: "CVE score change",
  new_exploit_discovered: "New exploit discovered",
  kev_addition: "CISA KEV addition",
  trending_entity: "Trending entity",
  requirement_match: "Requirement match",
  campaign_match: "Campaign match",
  new_intel_for_rule: "New intel for detection rule",
  feed_stale: "Feed stale",
  feed_error: "Feed error",
};

export const CORR_SEVERITY_MAP: Record<string, "high" | "medium" | "low"> = {
  coverage_gap: "high",
  exploit_status_change: "high",
  cve_score_change: "high",
  new_exploit_discovered: "high",
  kev_addition: "high",
  new_ttp_for_known_actor: "medium",
  new_ttp_for_known_malware: "medium",
  new_malware_for_known_actor: "medium",
  actor_malware_cooccurrence: "medium",
  trending_entity: "medium",
  requirement_match: "medium",
  campaign_match: "medium",
  new_intel_for_rule: "low",
  feed_stale: "low",
  feed_error: "low",
};

export const CORR_EVENT_TYPE_GROUPS: { label: string; types: string[] }[] = [
  {
    label: "Correlations",
    types: [
      "new_ttp_for_known_actor",
      "new_ttp_for_known_malware",
      "new_malware_for_known_actor",
      "actor_malware_cooccurrence",
    ],
  },
  {
    label: "Coverage",
    types: [
      "coverage_gap",
      "exploit_status_change",
      "cve_score_change",
      "new_exploit_discovered",
      "kev_addition",
      "trending_entity",
    ],
  },
  {
    label: "Requirements",
    types: ["requirement_match", "campaign_match", "new_intel_for_rule"],
  },
];

export function corrTimeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function getCorrEntityNav(event: CorrelationEvent): string {
  if (event.source_entity_type === "entry") {
    return `/?entry=${event.source_entity_id}`;
  }

  const slug = event.source_entity_type;
  return `/workbench/${slug}/${event.source_entity_id}`;
}

export function getCorrArticleNav(event: CorrelationEvent): string | null {
  if (!event.entry_id) return null;
  if (event.source_entity_type === "entry") return null;
  return `/?entry=${event.entry_id}`;
}

export function summarizeCorrGroup(group: GroupedCorrelationEventsEntry): string {
  const typeCounts: Record<string, number> = {};
  for (const ev of group.events) {
    const label = CORR_EVENT_LABELS[ev.event_type] || ev.event_type;
    typeCounts[label] = (typeCounts[label] || 0) + 1;
  }
  return Object.entries(typeCounts)
    .map(([label, count]) => (count > 1 ? `${count} ${label}` : label))
    .join(", ");
}

export function CorrEventCard({
  event,
  nested = false,
  showTime = false,
  onDismiss,
  onEventClick,
  onArticleClick,
}: {
  event: CorrelationEvent;
  nested?: boolean;
  showTime?: boolean;
  /** Absent for a visitor, who can't change an event's read state. */
  onDismiss?: (eventId: string) => void;
  onEventClick: (event: CorrelationEvent) => void;
  onArticleClick: (event: CorrelationEvent) => void;
}) {
  const entityCssVar = getEntityCssVar(event.source_entity_type);
  const sev = CORR_SEVERITY_MAP[event.event_type] ?? "low";
  return (
    <div className={`${styles.corrCard} ${nested ? styles.corrNestedCard : ""} ${!event.is_read ? styles.corrCardUnread : ""}`}>
      <div className={styles.corrCardHeader}>
        <span className={styles.corrIcon}>{CORR_EVENT_ICONS[event.event_type] || "\u{26A0}"}</span>
        <span className={styles.corrType}>{CORR_EVENT_LABELS[event.event_type] || event.event_type}</span>
        <Chip
          tone="toned"
          tint={CORR_SEVERITY_COLORS[sev]}
          className={styles.corrSeverity}
        >
          {sev}
        </Chip>
        {showTime && <span className={styles.corrTime}>{corrTimeAgo(event.created_at)}</span>}
      </div>
      <p className={styles.corrContext}>{event.context}</p>
      <div className={styles.corrFooter}>
        <Chip tone="outline" truncate tint={entityCssVar} className={styles.corrEntity}>
          {getEntityLabel(event.source_entity_type)}
        </Chip>
        <div className={styles.corrActions}>
          {!event.is_read && onDismiss && (
            <button className={styles.corrDismissBtn} onClick={() => onDismiss(event.id)}>Dismiss</button>
          )}
          {getCorrArticleNav(event) && (
            <button className={styles.corrViewArticleBtn} onClick={() => onArticleClick(event)}>View Article</button>
          )}
          <button className={styles.corrViewBtn} onClick={() => onEventClick(event)}>View Entity</button>
        </div>
      </div>
    </div>
  );
}

export function CorrArticleGroup({
  group,
  onDismiss,
  onEventClick,
  onArticleClick,
}: {
  group: GroupedCorrelationEventsEntry;
  /** Absent for a visitor, who can't change an event's read state. */
  onDismiss?: (eventId: string) => void;
  onEventClick: (event: CorrelationEvent) => void;
  onArticleClick: (event: CorrelationEvent) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const events = group.events;
  if (events.length === 0) return null;

  const unreadCount = group.unread_count;
  const severity = group.highest_severity as "high" | "medium" | "low";

  // Single event: render inline
  if (events.length === 1) {
    return (
      <CorrEventCard
        event={events[0]}
        showTime
        onDismiss={onDismiss}
        onEventClick={onEventClick}
        onArticleClick={onArticleClick}
      />
    );
  }

  // Multiple events: grouped card
  return (
    <div className={`${styles.corrGroupCard} ${unreadCount > 0 ? styles.corrCardUnread : ""}`}>
      <button className={styles.corrGroupHeader} onClick={() => setExpanded(!expanded)} aria-expanded={expanded}>
        <div className={styles.corrGroupLeft}>
          <span className={`${styles.corrExpandIcon} ${expanded ? styles.corrExpandOpen : ""}`}>
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
              <path d="M9 18l6-6-6-6" />
            </svg>
          </span>
          <Chip
            tone="toned"
            tint={CORR_SEVERITY_COLORS[severity]}
            className={styles.corrSeverity}
          >
            {severity}
          </Chip>
          <span className={styles.corrGroupTitle}>{group.entry_title || (group.entry_id === null ? "System alert" : "Untitled article")}</span>
        </div>
        <div className={styles.corrGroupRight}>
          <span className={styles.corrGroupCount}>
            {events.length} event{events.length !== 1 ? "s" : ""}
            {unreadCount > 0 && <span className={styles.corrGroupNew}> ({unreadCount} new)</span>}
          </span>
          <span className={styles.corrTime}>{corrTimeAgo(group.latest_at)}</span>
        </div>
      </button>

      {!expanded && <p className={styles.corrGroupSummary}>{summarizeCorrGroup(group)}</p>}

      {expanded && (
        <div className={styles.corrGroupEvents}>
          {events.map((event) => (
            <CorrEventCard
              key={event.id}
              event={event}
              nested
              onDismiss={onDismiss}
              onEventClick={onEventClick}
              onArticleClick={onArticleClick}
            />
          ))}
        </div>
      )}
    </div>
  );
}
