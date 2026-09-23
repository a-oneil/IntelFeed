import { useNavigate } from "react-router-dom";
import { useDetectionFormatBreakdown } from "@/hooks/useWidgetDetectionData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const RULE_COLORS: Record<string, string> = {
  sigma: "#3b82f6",
  splunk_spl: "#f97316",
  kql: "#06b6d4",
  elastic_ql: "#14b8a6",
  crowdstrike_ql: "#ef4444",
  yara: "#a855f7",
};

const FALLBACK = "#6b7280";

function colorFor(ruleType: string): string {
  return RULE_COLORS[ruleType] || FALLBACK;
}

export default function DetectionFormatBreakdownWidget({ config }: Props) {
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useDetectionFormatBreakdown(params);

  const handleLegendClick = () => {
    setActiveSection("rules");
    navigate("/workbench/explore");
  };

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No detection rules</div>;

  const total = data.reduce((sum, d) => sum + d.count, 0);
  const cx = 50;
  const cy = 50;
  const r = 48;
  let cursor = -Math.PI / 2;
  const slices = data
    .filter((s) => s.count > 0)
    .map((item) => {
      const pct = item.count / total;
      const angle = pct * Math.PI * 2;
      const startX = cx + r * Math.cos(cursor);
      const startY = cy + r * Math.sin(cursor);
      const endAngle = cursor + angle;
      const endX = cx + r * Math.cos(endAngle);
      const endY = cy + r * Math.sin(endAngle);
      const largeArc = angle > Math.PI ? 1 : 0;
      cursor = endAngle;
      const path =
        pct >= 0.999
          ? `M ${cx} ${cy - r} A ${r} ${r} 0 1 1 ${cx - 0.001} ${cy - r} Z`
          : `M ${cx} ${cy} L ${startX} ${startY} A ${r} ${r} 0 ${largeArc} 1 ${endX} ${endY} Z`;
      return {
        rule_type: item.rule_type,
        count: item.count,
        pct,
        path,
        color: colorFor(item.rule_type),
      };
    });

  return (
    <div className={styles.pieWidget}>
      <svg
        className={styles.pieChart}
        viewBox="0 0 100 100"
        role="img"
        aria-label="Detection rule format breakdown"
      >
        {slices.map((s) => (
          <path
            key={s.rule_type}
            d={s.path}
            fill={s.color}
            stroke="var(--bg-secondary)"
            strokeWidth="1"
          >
            <title>{`${s.rule_type}: ${s.count} (${(s.pct * 100).toFixed(1)}%)`}</title>
          </path>
        ))}
      </svg>
      <div className={styles.pieLegend}>
        {data.map((item) => (
          <Chip
            key={item.rule_type}
            tone="quiet"
            marker
            markerShape="dot"
            tint={colorFor(item.rule_type)}
            className={styles.legendItem}
            onClick={handleLegendClick}
            title={`View ${item.rule_type} rules`}
          >
            <span className={styles.legendLabel}>{item.rule_type}</span>
            <span className={styles.legendValue}>{item.count}</span>
          </Chip>
        ))}
      </div>
    </div>
  );
}
