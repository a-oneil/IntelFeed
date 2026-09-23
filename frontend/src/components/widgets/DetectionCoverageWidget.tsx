import { useNavigate } from "react-router-dom";
import { useDetectionCoverage } from "@/hooks/useWidgetData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

function coverageColor(pct: number): string {
  if (pct >= 70) return "#22c55e";
  if (pct >= 30) return "#f59e0b";
  return "#ef4444";
}

export default function DetectionCoverageWidget({ config }: Props) {
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useDetectionCoverage(params);

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data) return <div className={styles.noData}>No data</div>;

  const color = coverageColor(data.coverage_pct);

  return (
    <div className={styles.coverageWidget} style={{ cursor: "pointer" }} onClick={() => { setActiveSection("rules"); navigate("/workbench/explore"); }} title="View detection rules">
      <div className={styles.coveragePct} style={{ color }}>
        {data.coverage_pct}%
      </div>
      <div className={styles.coverageLabel}>Detection Coverage</div>
      <div className={styles.coverageBar}>
        <div
          className={styles.coverageFill}
          style={{ width: `${Math.min(data.coverage_pct, 100)}%`, background: color }}
        />
      </div>
      <div className={styles.coverageMeta}>
        {data.covered_ttps} of {data.total_ttps} TTPs covered
      </div>
    </div>
  );
}
