import { useTriageFlow } from "@/hooks/useWidgetBoardData";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import { clampDays, useChartWidth } from "./boardShared";
import { useIsVisitor } from "@/stores/authStore";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const FALLBACK_W = 560;
const VIEW_H = 180;
const PAD = { left: 38, right: 10, top: 12, bottom: 20 };
const ARRIVED_COLOR = "#3987e5";
const READ_COLOR = "#199e70";

/** Round an axis maximum up to a clean 1/2/5 × 10ⁿ tick value. */
function niceMax(value: number): number {
  if (value <= 5) return 5;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const scaled = value / magnitude;
  const step = scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10;
  return step * magnitude;
}

/**
 * Tallest value in one arm that isn't a bulk action. A single "mark all as read"
 * runs to tens of thousands against a normal day of a few hundred; scaling to it
 * flattens every real day into a hairline. Peel order-of-magnitude outliers (≥15×
 * the median of what remains, never more than a quarter of the points) so they can
 * be clipped instead.
 *
 * Per arm, deliberately: intake and reads sit on different orders of magnitude, so
 * pooling them puts the median down among the quiet read days and makes every
 * ordinary arrival look like an outlier.
 */
function robustPeak(values: number[]): number {
  const sorted = values.filter((v) => v > 0).sort((a, b) => a - b);
  if (sorted.length === 0) return 0;
  const peelable = sorted.length >= 4 ? Math.floor(sorted.length / 4) : 0;
  let end = sorted.length;
  for (let peeled = 0; peeled < peelable; peeled++) {
    const median = sorted[Math.floor((end - 1) / 2)];
    if (sorted[end - 1] < median * 15) break;
    end--;
  }
  return sorted[end - 1];
}

/** Short, absolute axis label — never relative, so both ends read the same way. */
function axisDate(iso: string): string {
  const d = new Date(`${iso}T00:00:00`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function compact(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k` : String(n);
}

export default function TriageFlowWidget({ config }: Props) {
  const { data, isLoading } = useTriageFlow(clampDays(config.days, 1, 365));
  const isVisitor = useIsVisitor();
  const [chartRef, VIEW_W] = useChartWidth<HTMLDivElement>(FALLBACK_W);

  if (isLoading) return <WidgetChartSkeleton />;
  // All-zero days (a visitor with no visible feeds, a paused instance) would
  // draw an empty axis scaled to 5.
  if (!data || !data.days.some((d) => d.arrived > 0 || d.read > 0)) {
    return <div className={styles.noData}>No triage activity</div>;
  }

  const plotW = VIEW_W - PAD.left - PAD.right;
  const plotH = VIEW_H - PAD.top - PAD.bottom;
  const mid = PAD.top + plotH / 2;
  const half = plotH / 2;
  // One shared scale for both arms. A per-arm scale would be a dual axis —
  // it would invent a visual parity between intake and reads that isn't real.
  const max = niceMax(
    Math.max(robustPeak(data.days.map((d) => d.arrived)), robustPeak(data.days.map((d) => d.read)), 1)
  );
  const step = plotW / data.days.length;
  const barW = Math.min(22, Math.max(3, step - 4));
  const gap = 2;

  const ticks = [max / 2, max];

  // Bulk actions the axis can't hold. The bar gets a break mark and the legend
  // carries the count — per-bar numerals collide as soon as two clipped days land
  // near each other, and the exact figure is a hover away in the tooltip.
  const clipped = data.days.flatMap((d) => [d.arrived, d.read]).filter((v) => v > max);

  /** Axis-break mark across the outer end of a bar that runs off-scale. */
  const clipMark = (x: number, up: boolean) => {
    const yBreak = (up ? mid - half : mid + half) + (up ? 9 : -9);
    return [0, 4].map((o) => (
      <line
        key={o}
        x1={x - 1}
        x2={x + barW + 1}
        y1={yBreak + o + 2.5}
        y2={yBreak + o - 2.5}
        stroke="var(--bg-secondary)"
        strokeWidth="2"
      />
    ));
  };

  return (
    <div ref={chartRef}>
      <svg
        className={styles.stackChart}
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        role="img"
        aria-label={
          isVisitor
            ? "Entries arriving per day"
            : "Entries arriving above the line versus entries you read below it, per day"
        }
      >
        {ticks.map((t) => {
          const dy = (half * t) / max;
          return (
            <g key={t}>
              <line
                x1={PAD.left}
                x2={PAD.left + plotW}
                y1={mid - dy}
                y2={mid - dy}
                stroke="var(--bg-tertiary)"
                strokeWidth="1"
              />
              <line
                x1={PAD.left}
                x2={PAD.left + plotW}
                y1={mid + dy}
                y2={mid + dy}
                stroke="var(--bg-tertiary)"
                strokeWidth="1"
              />
              <text x={PAD.left - 5} y={mid - dy + 3.5} textAnchor="end" fontSize="10" fill="var(--text-muted)">
                {compact(t)}
              </text>
              <text x={PAD.left - 5} y={mid + dy + 3.5} textAnchor="end" fontSize="10" fill="var(--text-muted)">
                {compact(t)}
              </text>
            </g>
          );
        })}
        <line x1={PAD.left} x2={PAD.left + plotW} y1={mid} y2={mid} stroke="var(--border)" strokeWidth="1" />

        {data.days.map((day, i) => {
          const x = PAD.left + step * i + (step - barW) / 2;
          const hUp = Math.min(half, (half * day.arrived) / max);
          const hDown = Math.min(half, (half * day.read) / max);
          return (
            <g key={day.date}>
              <title>
                {isVisitor
                  ? `${axisDate(day.date)} — ${day.arrived} arrived`
                  : `${axisDate(day.date)} — ${day.arrived} arrived, ${day.read} read`}
              </title>
              {day.arrived > 0 && (
                <rect
                  x={x}
                  y={mid - hUp}
                  width={barW}
                  height={Math.max(1, hUp - gap / 2)}
                  rx="1.5"
                  fill={ARRIVED_COLOR}
                />
              )}
              {day.arrived > max && clipMark(x, true)}
              {day.read > 0 && (
                <rect
                  x={x}
                  y={mid + gap / 2}
                  width={barW}
                  height={Math.max(1, hDown - gap / 2)}
                  rx="1.5"
                  fill={READ_COLOR}
                />
              )}
              {day.read > max && clipMark(x, false)}
            </g>
          );
        })}

        <text x={PAD.left} y={VIEW_H - 4} fontSize="10" fill="var(--text-muted)">
          {axisDate(data.days[0].date)}
        </text>
        <text x={PAD.left + plotW} y={VIEW_H - 4} textAnchor="end" fontSize="10" fill="var(--text-muted)">
          {axisDate(data.days[data.days.length - 1].date)}
        </text>
      </svg>

      <div className={styles.chartLegend}>
        <span className={styles.chartLegendItem}>
          <span className={styles.chartLegendSwatch} style={{ background: ARRIVED_COLOR }} />
          arrived
        </span>
        {/* A visitor has no reads, so the lower arm is empty and the backlog
            would count every article. */}
        {!isVisitor && (
          <span className={styles.chartLegendItem}>
            <span className={styles.chartLegendSwatch} style={{ background: READ_COLOR }} />
            read by you
          </span>
        )}
        {clipped.length > 0 && (
          <span className={styles.chartLegendItem}>
            {clipped.length === 1 ? "1 day" : `${clipped.length} days`} off-scale · peak{" "}
            {compact(Math.max(...clipped))}
          </span>
        )}
        {!isVisitor && (
          <span className={styles.chartLegendItem} style={{ marginLeft: "auto" }}>
            backlog {data.backlog.toLocaleString()}
          </span>
        )}
      </div>
    </div>
  );
}
