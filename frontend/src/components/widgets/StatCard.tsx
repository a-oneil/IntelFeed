import { useNavigate } from "react-router-dom";
import { useWidgetStats } from "@/hooks/useWidgetData";
import { useIntelStore } from "@/stores/intelStore";
import { useUIStore } from "@/stores/uiStore";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function StatCard({ config }: Props) {
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const setShowUnreadOnly = useUIStore((s) => s.setShowUnreadOnly);
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const setSelectedCategory = useUIStore((s) => s.setSelectedCategory);
  const setVirtualFolder = useUIStore((s) => s.setVirtualFolder);
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useWidgetStats(params);
  const statType = (config.stat_type as string) || "entries";

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data) return <div className={styles.noData}>No data</div>;

  const stat = statType === "unread" ? data.unread : data[statType as keyof typeof data];
  if (!stat) return <div className={styles.noData}>No data</div>;

  const count = (stat as { count: number }).count;
  const trend = "trend" in stat ? (stat as { trend: number }).trend : undefined;

  const labels: Record<string, string> = {
    entries: "Articles",
    cves: "CVEs",
    unread: "Unread",
  };

  const handleClick = () => {
    if (statType === "cves") {
      setActiveSection("cves");
      navigate("/workbench/explore");
      return;
    }
    if (statType === "unread") {
      setSelectedFeed(null);
      setSelectedCategory(null);
      setVirtualFolder(null);
      setShowUnreadOnly(true);
      navigate("/");
      return;
    }
    setSelectedFeed(null);
    setSelectedCategory(null);
    setVirtualFolder(null);
    navigate("/");
  };

  return (
    <div
      className={styles.statCard}
      style={{ cursor: "pointer" }}
      onClick={handleClick}
    >
      <div className={styles.statValue}>{count.toLocaleString()}</div>
      <div className={styles.statLabel}>{labels[statType] || statType}</div>
      {trend !== undefined && (
        <div className={`${styles.statTrend} ${trend >= 0 ? styles.trendUp : styles.trendDown}`}>
          {trend >= 0 ? "+" : ""}{trend}%
        </div>
      )}
    </div>
  );
}
