import { useNavigate } from "react-router-dom";
import { useAutomationLogsWidget } from "@/hooks/useWidgetData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const STATUS_COLORS: Record<string, string> = {
  success: "var(--success)",
  error: "var(--danger)",
  skipped: "var(--text-muted)",
};

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

function formatTrigger(trigger: string): string {
  return trigger.replace(/^on_/, "").replace(/_/g, " ");
}

function actionSummary(actions: Array<{ type?: string; status?: string }>): string {
  if (!actions.length) return "";
  const counts: Record<string, number> = {};
  for (const a of actions) {
    const s = a.status || "unknown";
    counts[s] = (counts[s] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([s, c]) => `${c} ${s}`)
    .join(", ");
}

export default function AutomationLogsWidget({ config }: Props) {
  const limit = (config.limit as number) || 15;
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const days = (config.days as number) || 1;
  const queryParams: { limit: number; date_from?: string; date_to?: string } = { limit };
  if (date_from) queryParams.date_from = date_from;
  if (date_to) queryParams.date_to = date_to;
  const { data, isLoading } = useAutomationLogsWidget(queryParams);
  const navigate = useNavigate();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data) return <div className={styles.noData}>No automation logs</div>;

  const { summary, logs } = data;

  return (
    <div className={styles.automationLogsWidget}>
      <div className={styles.automationSummary}>
        <div className={styles.automationSummaryItem}>
          <span className={styles.automationSummaryValue} style={{ color: "var(--success)" }}>
            {summary.success}
          </span>
          <span className={styles.automationSummaryLabel}>success</span>
        </div>
        <div className={styles.automationSummaryItem}>
          <span className={styles.automationSummaryValue} style={{ color: "var(--danger)" }}>
            {summary.error}
          </span>
          <span className={styles.automationSummaryLabel}>errors</span>
        </div>
        <div className={styles.automationSummaryItem}>
          <span className={styles.automationSummaryValue} style={{ color: "var(--text-muted)" }}>
            {summary.skipped}
          </span>
          <span className={styles.automationSummaryLabel}>skipped</span>
        </div>
        <div className={styles.automationSummaryItem}>
          <span className={styles.automationSummaryValue}>{summary.total}</span>
          <span className={styles.automationSummaryLabel}>
            {date_from ? `${days}d total` : "24h total"}
          </span>
        </div>
      </div>

      {logs.length === 0 ? (
        <div className={styles.noData}>No recent executions</div>
      ) : (
        <div className={styles.list}>
          {logs.map((log) => (
            <button
              key={log.id}
              className={styles.listItemClickable}
              onClick={() => navigate("/automation")}
            >
              <div className={styles.listItemMain}>
                <span
                  className={styles.statusDot}
                  style={{ background: STATUS_COLORS[log.status] || "var(--text-muted)" }}
                />
                <span className={styles.automationRuleName}>{log.rule_name}</span>
                <Chip className={styles.automationTrigger}>
                  {formatTrigger(log.trigger_type)}
                </Chip>
              </div>
              <div className={styles.listItemMeta}>
                {timeAgo(log.executed_at)}
                {log.actions_executed.length > 0 && (
                  <> &middot; {actionSummary(log.actions_executed)}</>
                )}
                {log.error_message && (
                  <span className={styles.errorText}> &middot; {log.error_message}</span>
                )}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
