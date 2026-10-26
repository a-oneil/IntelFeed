import { useNavigate } from "react-router-dom";
import { useRansomwarePulse } from "@/hooks/useWidgetBoardData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import { DeltaText, SERIES_OTHER, seriesColor, useChartWidth } from "./boardShared";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const FALLBACK_W = 640;
const VIEW_H = 190;
const PAD = { left: 34, right: 6, top: 14, bottom: 22 };

function groupColor(group: string, index: number, total: number): string {
  if (group === "Other" || index === total - 1) return SERIES_OTHER;
  return seriesColor(index);
}

export default function RansomwarePulseWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const { data, isLoading } = useRansomwarePulse({ date_from, date_to });
  const [chartRef, VIEW_W] = useChartWidth<HTMLDivElement>(FALLBACK_W);
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const openTracker = () => {
    setActiveSection("ransomware");
    navigate("/workbench/explore");
  };

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data || data.weeks.length === 0) {
    return <div className={styles.noData}>No ransomware disclosures in this window</div>;
  }

  const plotW = VIEW_W - PAD.left - PAD.right;
  const plotH = VIEW_H - PAD.top - PAD.bottom;
  const maxTotal = Math.max(...data.weeks.map((w) => w.total), 1);
  const step = plotW / data.weeks.length;
  const barW = Math.min(24, Math.max(4, step - 6));
  const gap = 2;

  // Stack bottom-up in the validated slot order so adjacent segments separate.
  const stackOrder = data.groups;

  return (
    <div ref={chartRef}>
      <svg
        className={styles.stackChart}
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        role="img"
        aria-label="Weekly ransomware victim disclosures stacked by group"
      >
        {[0, 0.5, 1].map((f) => {
          const y = PAD.top + plotH * (1 - f);
          return (
            <g key={f}>
              <line
                x1={PAD.left}
                x2={PAD.left + plotW}
                y1={y}
                y2={y}
                stroke={f === 0 ? "var(--border)" : "var(--bg-tertiary)"}
                strokeWidth="1"
              />
              <text x={PAD.left - 5} y={y + 3.5} textAnchor="end" fontSize="10" fill="var(--text-muted)">
                {Math.round(maxTotal * f)}
              </text>
            </g>
          );
        })}

        {data.weeks.map((week, wi) => {
          const x = PAD.left + step * wi + (step - barW) / 2;
          let cursorY = PAD.top + plotH;
          return (
            <g key={week.week_start}>
              <title>
                {`Wk of ${week.label} — ${week.total} victims`}
                {stackOrder
                  .filter((g) => (week.groups[g] ?? 0) > 0)
                  .map((g) => `\n${g}: ${week.groups[g]}`)
                  .join("")}
              </title>
              {stackOrder.map((group, gi) => {
                const value = week.groups[group] ?? 0;
                if (value <= 0) return null;
                const h = (plotH * value) / maxTotal;
                cursorY -= h;
                return (
                  <rect
                    key={group}
                    x={x}
                    y={cursorY + gap / 2}
                    width={barW}
                    height={Math.max(1, h - gap)}
                    rx="1.5"
                    fill={groupColor(group, gi, stackOrder.length)}
                  />
                );
              })}
              <rect
                x={PAD.left + step * wi}
                y={PAD.top}
                width={step}
                height={plotH}
                fill="transparent"
                style={{ cursor: "pointer" }}
                onClick={openTracker}
              />
            </g>
          );
        })}

        <text x={PAD.left} y={VIEW_H - 5} fontSize="10" fill="var(--text-muted)">
          {data.weeks[0].label}
        </text>
        <text x={PAD.left + plotW} y={VIEW_H - 5} textAnchor="end" fontSize="10" fill="var(--text-muted)">
          {data.weeks[data.weeks.length - 1].label}
        </text>
      </svg>

      <div className={styles.chartLegend}>
        {stackOrder.map((group, gi) => (
          <span key={group} className={styles.chartLegendItem}>
            <span
              className={styles.chartLegendSwatch}
              style={{ background: groupColor(group, gi, stackOrder.length) }}
            />
            {group}
          </span>
        ))}
        <span className={styles.chartLegendItem} style={{ marginLeft: "auto" }}>
          {data.totals.victims.toLocaleString()} victims · <DeltaText value={data.totals.trend} suffix="%" />
        </span>
      </div>
    </div>
  );
}
