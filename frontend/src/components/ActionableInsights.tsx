// ActionableInsights.tsx
import { useNavigate } from "react-router-dom";
import { useEntryInsights } from "@/hooks/useAnalytics";
import type { EntryInsight } from "@/api/types";
import styles from "./ActionableInsights.module.css";

interface ActionableInsightsProps {
  entryId: string;
  /** Only render insights of these types (e.g. ["requirement_match"]). */
  includeTypes?: string[];
  /** Render everything except these types. */
  excludeTypes?: string[];
}

const SEVERITY_ICONS: Record<string, string> = {
  high: "!",
  medium: "~",
  low: "i",
};

const TYPE_LABELS: Record<string, string> = {
  entity_overlap_actor: "Actor Overlap",
  detection_gap: "Detection Opportunity",
  campaign_match: "Campaign Match",
  requirement_match: "PIR Match",
  critical_cve: "Critical CVE",
};

function getInsightLink(insight: EntryInsight): string {
  switch (insight.action) {
    case "view_actor_profile":
      if (insight.related_ids?.length) return `/workbench/threat_actor/${insight.related_ids[0]}`;
      break;
    case "view_cve_profile":
      if (insight.entity_id) return `/workbench/cve/${insight.entity_id}`;
      break;
    case "generate_rule":
      if (insight.entity_id && insight.entity_type === "ttp") return `/workbench/ttp/${insight.entity_id}`;
      if (insight.entity_id && insight.entity_type === "cve") return `/workbench/cve/${insight.entity_id}`;
      break;
    case "add_to_campaign":
      if (insight.campaign_id) return `/workbench/campaign/${insight.campaign_id}`;
      break;
  }
  return "/workbench/explore";
}

const ACTION_LABELS: Record<string, string> = {
  view_actor_profile: "View Actor",
  view_cve_profile: "View CVE",
  generate_rule: "Create Rule",
  add_to_campaign: "View Campaign",
  view_requirement: "View PIR",
};

export function ActionableInsights({ entryId, includeTypes, excludeTypes }: ActionableInsightsProps) {
  const navigate = useNavigate();
  const { data: insights, isLoading } = useEntryInsights(entryId);

  const filtered = (insights ?? []).filter(
    (insight) =>
      (!includeTypes || includeTypes.includes(insight.type)) &&
      (!excludeTypes || !excludeTypes.includes(insight.type))
  );
  if (isLoading || filtered.length === 0) return null;

  return (
    <div className={styles.container}>
      <div className={styles.list}>
        {filtered.map((insight, i) => (
          <div key={i} className={`${styles.card} ${styles[`severity_${insight.severity}`] || ""}`}>
            <span className={styles.icon}>{SEVERITY_ICONS[insight.severity] || "i"}</span>
            <div className={styles.content}>
              <span className={styles.typeBadge}>{TYPE_LABELS[insight.type] || insight.type.replace(/_/g, " ")}</span>
              <span className={styles.title}>{insight.message}</span>
            </div>
            {(insight.entity_id || insight.related_ids?.length || insight.campaign_id) && (
              <button
                className={styles.actionBtn}
                onClick={() => navigate(getInsightLink(insight))}
              >
                {ACTION_LABELS[insight.action || ""] || "View"}
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
