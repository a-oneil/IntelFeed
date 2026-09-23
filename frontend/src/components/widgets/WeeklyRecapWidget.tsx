import { useWeeklyRecap, type WeeklyRecapMetric } from "@/hooks/useWidgetStrategicData";
import { WidgetStatSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const TILES: Array<{ key: "entries" | "actors" | "cves" | "detections"; label: string }> = [
  { key: "entries", label: "Articles" },
  { key: "actors", label: "Actors" },
  { key: "cves", label: "CVEs" },
  { key: "detections", label: "Detections" },
];

export default function WeeklyRecapWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useWeeklyRecap(params);

  if (isLoading) return <WidgetStatSkeleton />;
  if (!data) return <div className={styles.noData}>No data</div>;

  return (
    <div className={styles.recapGrid}>
      {TILES.map((tile) => {
        const metric: WeeklyRecapMetric = data[tile.key];
        const trend = metric.trend_pct;
        const isNew = metric.previous === 0 && metric.count > 0;
        const trendCls = trend >= 0 ? styles.trendUp : styles.trendDown;
        return (
          <div key={tile.key} className={styles.recapTile}>
            <div className={styles.recapValue}>{metric.count.toLocaleString()}</div>
            <div className={styles.recapLabel}>{tile.label}</div>
            {isNew ? (
              <div className={styles.recapNew}>new</div>
            ) : metric.previous === 0 && metric.count === 0 ? (
              <div className={styles.recapTrend} style={{ color: "var(--text-muted)" }}>—</div>
            ) : (
              <div className={`${styles.recapTrend} ${trendCls}`}>
                {trend >= 0 ? "▲" : "▼"} {Math.abs(trend)}%
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
