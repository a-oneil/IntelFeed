import { useNavigate } from "react-router-dom";
import { useFeedHealth } from "@/hooks/useWidgetOpsData";
import { useUIStore } from "@/stores/uiStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

function formatStale(hours: number | null): string {
  if (hours == null) return "never";
  if (hours < 1) return `${Math.round(hours * 60)}m ago`;
  if (hours < 48) return `${Math.round(hours)}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export default function FeedHealthWidget({ config }: Props) {
  const navigate = useNavigate();
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const limit = (config.limit as number) || 20;
  const { data, isLoading } = useFeedHealth({ limit });

  const handleClick = (feedId: string) => {
    setSelectedFeed(feedId);
    navigate("/");
  };

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>All feeds healthy</div>;

  return (
    <div className={styles.list}>
      {data.map((feed) => {
        const isStale = feed.hours_since_fetch != null && feed.hours_since_fetch > 24;
        return (
          <button
            key={feed.id}
            className={styles.listItemClickable}
            onClick={() => handleClick(feed.id)}
          >
            <div className={styles.feedHealthRow}>
              <span className={styles.feedHealthName}>{feed.name}</span>
              {feed.error_count > 0 && (
                <Chip
                  tone="solid"
                  tint="var(--severity-critical)"
                  fg="var(--severity-critical-fg)"
                  className={styles.countChip}
                  title={`${feed.error_count} errors`}
                >
                  {feed.error_count}
                </Chip>
              )}
              <span
                className={`${styles.feedHealthStale} ${isStale ? styles.feedHealthStaleBad : ""}`}
              >
                {formatStale(feed.hours_since_fetch)}
              </span>
            </div>
            {feed.last_error && (
              <div className={styles.lastErrorText} title={feed.last_error}>
                {feed.last_error}
              </div>
            )}
          </button>
        );
      })}
    </div>
  );
}
