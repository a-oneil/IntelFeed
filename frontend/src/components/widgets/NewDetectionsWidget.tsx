import { useNavigate } from "react-router-dom";
import { useNewDetections } from "@/hooks/useWidgetData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";
import { severityChipColors } from "@/utils/severity";

interface Props {
  config: Record<string, unknown>;
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "now";
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

export default function NewDetectionsWidget({ config }: Props) {
  const limit = (config.limit as number) || 100;
  const days = (config.days as number) || 7;
  const includeDrafts = config.include_drafts !== false;
  const { data, isLoading } = useNewDetections({ limit, days, include_drafts: includeDrafts });
  const navigate = useNavigate();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.rules.length === 0) {
    return <div className={styles.noData}>No new detection rules in the last {days} days</div>;
  }

  return (
    <div className={styles.automationLogsWidget}>
      <div className={styles.automationSummary}>
        <div className={styles.automationSummaryItem}>
          <div className={styles.automationSummaryValue}>{data.summary.total}</div>
          <div className={styles.automationSummaryLabel}>Past {days}d</div>
        </div>
        <div className={styles.automationSummaryItem}>
          <div className={styles.automationSummaryValue}>{data.summary.published}</div>
          <div className={styles.automationSummaryLabel}>Published</div>
        </div>
        <div className={styles.automationSummaryItem}>
          <div className={styles.automationSummaryValue}>{data.summary.draft}</div>
          <div className={styles.automationSummaryLabel}>Draft</div>
        </div>
      </div>
      <div className={styles.list}>
        {data.rules.map((rule) => (
          <button
            key={rule.id}
            className={styles.listItemClickable}
            onClick={() => navigate(`/workbench/rule/${rule.id}`)}
          >
            <div className={styles.listItemMain}>
              <span className={styles.actorName}>{rule.title}</span>
              <Chip className={styles.tagSmall}>{rule.rule_type}</Chip>
              {rule.severity && (
                <Chip tone="solid" {...severityChipColors(rule.severity)}>
                  {rule.severity}
                </Chip>
              )}
              {rule.is_draft && <Chip className={styles.tagSmall}>draft</Chip>}
            </div>
            <div className={styles.listItemMeta}>
              {rule.entry_title ? (
                <span title={rule.entry_title}>
                  {rule.entry_title.length > 40 ? `${rule.entry_title.slice(0, 40)}…` : rule.entry_title}
                </span>
              ) : (
                <span>manual</span>
              )}
              <span> · {timeAgo(rule.created_at)}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
