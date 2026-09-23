import { useNavigate } from "react-router-dom";
import { useAnalyticsOverview } from "@/hooks/useAnalytics";
import { getEntityColor } from "@/utils/entityTheme";
import { useIntelStore, type WorkspaceSection } from "@/stores/intelStore";
import { WidgetStatSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function OverviewWidget({ config }: Props) {
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useAnalyticsOverview(params);

  if (isLoading) return <WidgetStatSkeleton />;
  if (!data) return <div className={styles.noData}>No data</div>;

  const days = (config.days as number) || 7;
  const eventsLabel = params ? `Events (${days}d)` : "Events (7d)";
  const items: Array<{ label: string; value: number; color: string; section: WorkspaceSection | null }> = [
    { label: "CVEs", value: data.entity_counts.cves, color: getEntityColor("cve"), section: "cves" },
    { label: "Actors", value: data.entity_counts.threat_actors, color: getEntityColor("threat_actor"), section: "threat_actors" },
    { label: "TTPs", value: data.entity_counts.ttps, color: getEntityColor("ttp"), section: "ttps" },
    { label: "Rules", value: data.detection.total_rules, color: getEntityColor("detection_rule"), section: "rules" },
    { label: eventsLabel, value: data.events.recent_7d, color: "#06b6d4", section: null },
  ];

  const handleClick = (item: (typeof items)[number]) => {
    if (item.section) setActiveSection(item.section);
    navigate("/workbench/explore");
  };

  return (
    <div className={styles.overviewGrid}>
      {items.map((item) => (
        <div
          key={item.label}
          className={styles.overviewItem}
          style={{ cursor: "pointer" }}
          onClick={() => handleClick(item)}
        >
          <span className={styles.overviewValue} style={{ color: item.color }}>
            {item.value.toLocaleString()}
          </span>
          <span className={styles.overviewLabel}>{item.label}</span>
        </div>
      ))}
    </div>
  );
}
