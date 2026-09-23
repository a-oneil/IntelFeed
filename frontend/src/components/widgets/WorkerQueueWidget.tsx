import { useWorkerQueue } from "@/hooks/useWidgetOpsData";
import { WidgetStatSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const numberFmt = new Intl.NumberFormat();

export default function WorkerQueueWidget(_props: Props) {
  const { data, isLoading } = useWorkerQueue();

  if (isLoading) return <WidgetStatSkeleton />;
  if (!data) return <div className={styles.noData}>No queue data</div>;
  if (data.redis_ok === false) return <div className={styles.noData}>Redis unreachable</div>;

  return (
    <div className={styles.statCard}>
      <div className={styles.statValue}>{numberFmt.format(data.total_pending)}</div>
      <div className={styles.statLabel}>pending tasks</div>
      <div className={styles.queueList}>
        {data.queues.map((q) => (
          <div key={q.name} className={styles.queueRow}>
            <span className={styles.queueName}>{q.name}</span>
            <span className={styles.queueCount}>{numberFmt.format(q.pending)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
