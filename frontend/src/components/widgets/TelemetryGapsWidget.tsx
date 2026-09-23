import { useNavigate } from "react-router-dom";
import { useTelemetryGaps } from "@/hooks/useWidgetBoardData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function TelemetryGapsWidget({ config }: Props) {
  const limit = (config.limit as number) || 6;
  const { data, isLoading } = useTelemetryGaps();
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const openTelemetry = () => {
    setActiveSection("telemetry");
    navigate("/workbench/explore");
  };

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.most_needed_sources.length === 0) {
    return <div className={styles.noData}>No telemetry gaps — every rule&apos;s log sources are covered</div>;
  }

  const sources = data.most_needed_sources.slice(0, limit);
  const maxCount = Math.max(...sources.map(([, count]) => count), 1);

  return (
    <div className={styles.list}>
      {sources.map(([source, count]) => (
        <button
          key={source}
          className={styles.boardRow}
          onClick={openTelemetry}
          title={`${count} rule${count === 1 ? "" : "s"} need ${source}`}
        >
          <span className={styles.boardGrow}>
            <span className={styles.boardPrimary}>{source}</span>
            <span className={styles.meterRow}>
              <span className={styles.meterTrack}>
                <span className={styles.meterFill} style={{ width: `${(count / maxCount) * 100}%` }} />
              </span>
              <span className={styles.boardNum} style={{ color: "var(--text-secondary)" }}>
                blocks {count}
              </span>
            </span>
          </span>
        </button>
      ))}
      <div className={styles.boardFootNote}>
        {data.rules_with_gaps_count} of {data.total_rules_checked} rules need log sources you don&apos;t have
      </div>
    </div>
  );
}
