import { useNavigate } from "react-router-dom";
import { useIntelVelocity } from "@/hooks/useAnalytics";
import { useIntelStore, type WorkspaceSection } from "@/stores/intelStore";
import { getEntityColor } from "@/utils/entityTheme";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const TYPE_TO_SECTION: Record<string, WorkspaceSection> = {
  cve: "cves",
  threat_actor: "threat_actors",
  malware: "malware",
  ttp: "ttps",
};

export default function IntelVelocityWidget({ config }: Props) {
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const days = (config.days as number) || 30;
  const { data, isLoading } = useIntelVelocity(days);

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data) return <div className={styles.noData}>No data</div>;

  // Aggregate totals per entity type
  const totals: Record<string, number> = {};
  for (const [type, entries] of Object.entries(data.velocity)) {
    totals[type] = entries.reduce((sum, d) => sum + d.count, 0);
  }

  const maxTotal = Math.max(...Object.values(totals), 1);

  return (
    <div className={styles.horizontalBars}>
      {Object.entries(totals).map(([type, count]) => (
        <div
          key={type}
          className={styles.hBarRow}
          style={{ cursor: "pointer" }}
          onClick={() => { const section = TYPE_TO_SECTION[type]; if (section) { setActiveSection(section); navigate("/workbench/explore"); } }}
          title={`View ${type.replace("_", " ")} entities`}
        >
          <span className={styles.hBarLabel}>{type.replace("_", " ")}</span>
          <div className={styles.hBarTrack}>
            <div
              className={styles.hBarFill}
              style={{
                width: `${(count / maxTotal) * 100}%`,
                background: getEntityColor(type),
              }}
            />
          </div>
          <span className={styles.hBarValue}>{count}</span>
        </div>
      ))}
    </div>
  );
}
