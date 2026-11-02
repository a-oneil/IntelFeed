import s from "../EnrichmentConsole.module.css";

/** A line of hourly counts, oldest first. */
export function Sparkline({ points, label }: { points: number[]; label: string }) {
  const max = Math.max(1, ...points);
  const step = points.length > 1 ? 96 / (points.length - 1) : 0;
  const coords = points.map((v, i) => `${(i * step).toFixed(1)},${(20 - (v / max) * 17).toFixed(1)}`).join(" ");
  return (
    <svg className={s.spark} viewBox="0 0 96 22" role="img" aria-label={label}>
      <polyline fill="none" stroke="currentColor" strokeWidth="1.4" points={coords} />
    </svg>
  );
}
