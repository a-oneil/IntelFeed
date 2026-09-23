import { useNavigate } from "react-router-dom";
import { useTargetingGrid } from "@/hooks/useWidgetBoardData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

/** Sequential blue ramp — one hue, more-is-darker. */
function cellStyle(value: number, max: number): { background: string; color?: string } {
  if (value <= 0 || max <= 0) return { background: "rgba(255,255,255,0.03)", color: "var(--text-muted)" };
  const ratio = value / max;
  if (ratio > 0.75) return { background: "#3987e5", color: "#fff" };
  if (ratio > 0.5) return { background: "rgba(57,135,229,0.78)", color: "#fff" };
  if (ratio > 0.25) return { background: "rgba(57,135,229,0.52)" };
  if (ratio > 0.1) return { background: "rgba(57,135,229,0.30)" };
  return { background: "rgba(57,135,229,0.14)", color: "var(--text-secondary)" };
}

export default function TargetingGridWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const { data, isLoading } = useTargetingGrid({ date_from, date_to });
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const openTracker = () => {
    setActiveSection("ransomware");
    navigate("/workbench/explore");
  };

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data || data.rows.length === 0) {
    return <div className={styles.noData}>No victim disclosures with sector data in this window</div>;
  }

  return (
    <div>
      <div
        className={styles.heatGrid}
        style={{ gridTemplateColumns: `minmax(70px, 110px) repeat(${data.regions.length}, 1fr)` }}
      >
        <div className={styles.heatCorner} />
        {data.regions.map((region) => (
          <div key={region} className={styles.heatColHead} title={region}>
            {region}
          </div>
        ))}
        {data.rows.map((row) => (
          <div key={row.sector} style={{ display: "contents" }}>
            <div className={styles.heatRowLabel} title={`${row.label} — ${row.total} victims`}>
              {row.label}
            </div>
            {row.cells.map((value, i) => (
              <button
                key={`${row.sector}-${data.regions[i]}`}
                className={styles.heatCellBtn}
                style={cellStyle(value, data.max_cell)}
                title={`${row.label} · ${data.regions[i]} — ${value} victim${value === 1 ? "" : "s"}`}
                onClick={openTracker}
              >
                {value > 0 ? value : "·"}
              </button>
            ))}
          </div>
        ))}
      </div>
      <div className={styles.chartLegend}>
        <span className={styles.chartLegendItem}>
          <span className={styles.chartLegendSwatch} style={{ background: "rgba(57,135,229,0.14)" }} />
          few
        </span>
        <span className={styles.chartLegendItem}>
          <span className={styles.chartLegendSwatch} style={{ background: "#3987e5" }} />
          most victims
        </span>
      </div>
    </div>
  );
}
