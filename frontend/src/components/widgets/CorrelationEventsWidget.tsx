import { useNavigate } from "react-router-dom";
import { useRecentCorrelationEvents } from "@/hooks/useWidgetData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { CorrEventIcon } from "@/components/triage/corrEventCards";
import styles from "./widgets.module.css";

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

export default function CorrelationEventsWidget({ config }: Props) {
  const limit = (config.limit as number) || 10;
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const range = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useRecentCorrelationEvents(limit, range);
  const navigate = useNavigate();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No correlation events</div>;

  return (
    <div className={styles.list}>
      {data.map((evt) => (
        <div
          key={evt.id}
          className={`${styles.corrEventRow} ${!evt.is_read ? styles.unreadEvent : ""}`}
        >
          <button
            className={styles.corrEventMain}
            onClick={() => evt.entry_id ? navigate(`/?entry=${evt.entry_id}`) : navigate("/workbench")}
          >
            <div className={styles.listItemMain}>
              <CorrEventIcon type={evt.event_type} className={styles.eventIcon} />
              <span className={styles.eventContext}>{evt.context}</span>
            </div>
            <div className={styles.listItemMeta}>{timeAgo(evt.created_at)}</div>
          </button>
          {evt.entry_id && (
            <button
              className={styles.corrArticleBtn}
              onClick={() => navigate(`/?entry=${evt.entry_id}`)}
              title={evt.entry_title || "View article"}
            >
              View Article
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
