import { useFeedActivity } from "@/hooks/useWidgetData";
import { formatDate } from "@/utils/formatDate";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function FeedActivityChart({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useFeedActivity(params);

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No feed activity data</div>;

  const max = Math.max(...data.map((d) => d.count), 1);

  return (
    <div className={styles.barChart}>
      {data.map((item) => (
        <div key={item.date} className={styles.barGroup}>
          <div className={styles.barContainer}>
            <div
              className={styles.bar}
              style={{
                height: `${(item.count / max) * 100}%`,
                backgroundColor: "var(--accent)",
              }}
              title={`${item.date}: ${item.count} articles`}
            />
          </div>
          <span className={styles.barLabel}>
            {formatDate(item.date)}
          </span>
        </div>
      ))}
    </div>
  );
}
