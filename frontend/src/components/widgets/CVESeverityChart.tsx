import { useNavigate } from "react-router-dom";
import { useCVESeverity } from "@/hooks/useWidgetData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import { SEVERITY_COLORS } from "@/utils/colorSchemes";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

export default function CVESeverityChart({ config }: Props) {
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useCVESeverity(params);

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No CVE data</div>;

  const ordered = [...data].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity as typeof SEVERITY_ORDER[number])
            - SEVERITY_ORDER.indexOf(b.severity as typeof SEVERITY_ORDER[number]),
  );
  const total = ordered.reduce((sum, d) => sum + d.count, 0);

  // Build pie slice paths. cx,cy = center; r = radius. Angles in radians,
  // starting from 12 o'clock and sweeping clockwise.
  const cx = 50;
  const cy = 50;
  const r = 48;
  let cursor = -Math.PI / 2;
  const slices = ordered
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
      // A single 100% slice would degenerate to startX==endX; render as a full circle path.
      const path =
        pct >= 0.999
          ? `M ${cx} ${cy - r} A ${r} ${r} 0 1 1 ${cx - 0.001} ${cy - r} Z`
          : `M ${cx} ${cy} L ${startX} ${startY} A ${r} ${r} 0 ${largeArc} 1 ${endX} ${endY} Z`;
      return {
        severity: item.severity,
        count: item.count,
        pct,
        path,
        color: SEVERITY_COLORS[item.severity] || "var(--text-muted)",
      };
    });

  return (
    <div className={styles.pieWidget}>
      <svg className={styles.pieChart} viewBox="0 0 100 100" role="img" aria-label="CVE severity distribution">
        {slices.map((s) => (
          <path
            key={s.severity}
            d={s.path}
            fill={s.color}
            stroke="var(--bg-secondary)"
            strokeWidth="1"
          >
            <title>{`${s.severity}: ${s.count} (${(s.pct * 100).toFixed(1)}%)`}</title>
          </path>
        ))}
      </svg>
      <div className={styles.pieLegend}>
        {ordered.map((item) => (
          <Chip
            key={item.severity}
            tone="quiet"
            marker
            markerShape="dot"
            tint={SEVERITY_COLORS[item.severity] || "var(--text-muted)"}
            className={styles.legendItem}
            onClick={() => { setActiveSection("cves"); navigate("/workbench/explore"); }}
            title={`Filter CVEs by ${item.severity} severity`}
          >
            <span className={styles.legendLabel}>{item.severity}</span>
            <span className={styles.legendValue}>{item.count}</span>
          </Chip>
        ))}
      </div>
    </div>
  );
}
