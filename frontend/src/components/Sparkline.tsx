/** Dependency-free inline SVG sparkline — weekly mention counts, no axes/labels. */
export function Sparkline({
  values,
  width = 72,
  height = 20,
  color = "var(--accent)",
}: {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
}) {
  if (values.length < 2) return null;

  const max = Math.max(...values, 1);
  const step = width / (values.length - 1);
  const points = values.map((v, i) => `${(i * step).toFixed(1)},${(height - (v / max) * height).toFixed(1)}`).join(" ");

  // Spiking this week vs. the trailing average — a simple, cheap "is this hot" signal.
  const last = values[values.length - 1];
  const priorAvg = values.slice(0, -1).reduce((a, b) => a + b, 0) / Math.max(values.length - 1, 1);
  const isSpiking = last > 0 && last >= priorAvg * 2 && last >= 3;

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      <title>{`Last ${values.length} weeks: ${values.join(", ")}`}</title>
      <polyline points={points} fill="none" stroke={isSpiking ? "#ef4444" : color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
