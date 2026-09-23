import { useMemo, useState } from "react";

import type { TimeseriesPoint } from "@/hooks/useRansomware";

import styles from "./VictimsTimeChart.module.css";

const W = 900;
const H = 230;
const PAD = { l: 34, r: 14, t: 14, b: 24 };

/** Weekly victim-disclosure line/area chart. Self-contained SVG (no chart lib),
 * following the MentionsTimeline geometry but decoupled from entity data. */
export function VictimsTimeChart({ points }: { points: TimeseriesPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);

  const geom = useMemo(() => {
    if (points.length === 0) return null;
    const iw = W - PAD.l - PAD.r;
    const ih = H - PAD.t - PAD.b;
    const max = Math.max(1, ...points.map((p) => p.count)) * 1.12;
    const avg = points.reduce((a, p) => a + p.count, 0) / points.length;
    const n = points.length;
    const X = (i: number) => PAD.l + (n === 1 ? iw / 2 : iw * (i / (n - 1)));
    const Y = (v: number) => PAD.t + ih * (1 - v / max);
    const line = points.map((p, i) => `${i ? "L" : "M"}${X(i)},${Y(p.count)}`).join("");
    const area = `M${X(0)},${Y(0)}` + points.map((p, i) => `L${X(i)},${Y(p.count)}`).join("") + `L${X(n - 1)},${Y(0)}Z`;
    const ticks = [0, Math.round(max * 0.33), Math.round(max * 0.66), Math.round(max)];
    return { iw, ih, max, avg, X, Y, line, area, ticks, n };
  }, [points]);

  if (!geom) return <div className={styles.empty}>No disclosures in this window.</div>;

  return (
    <div className={styles.wrap}>
      <svg className={styles.svg} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label="Weekly victim disclosures">
        <defs>
          <linearGradient id="rwTsGrad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor="var(--accent)" stopOpacity="0.24" />
            <stop offset="1" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {geom.ticks.map((t, i) => (
          <g key={i}>
            <line x1={PAD.l} x2={W - PAD.r} y1={geom.Y(t)} y2={geom.Y(t)} className={styles.grid} />
            <text x={PAD.l - 7} y={geom.Y(t) + 3} textAnchor="end" className={styles.axis}>{t}</text>
          </g>
        ))}
        <path d={geom.area} fill="url(#rwTsGrad)" />
        <line x1={PAD.l} x2={W - PAD.r} y1={geom.Y(geom.avg)} y2={geom.Y(geom.avg)} className={styles.avg} />
        <path d={geom.line} className={styles.line} fill="none" />
        {points.map((p, i) =>
          i % 2 === 0 || i === points.length - 1 ? (
            <text key={i} x={geom.X(i)} y={H - 7} textAnchor="middle" className={styles.axis}>{p.label}</text>
          ) : null,
        )}
        <circle cx={geom.X(geom.n - 1)} cy={geom.Y(points[geom.n - 1].count)} r={4.2} className={styles.endpoint} />
        {hover != null && (
          <g>
            <line x1={geom.X(hover)} x2={geom.X(hover)} y1={PAD.t} y2={PAD.t + geom.ih} className={styles.hoverLine} />
            <circle cx={geom.X(hover)} cy={geom.Y(points[hover].count)} r={4.5} className={styles.endpoint} />
          </g>
        )}
        <rect
          x={PAD.l}
          y={PAD.t}
          width={geom.iw}
          height={geom.ih}
          fill="transparent"
          onMouseMove={(e) => {
            const rect = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
            const px = ((e.clientX - rect.left) * (W / rect.width) - PAD.l) / geom.iw;
            const i = Math.max(0, Math.min(geom.n - 1, Math.round(px * (geom.n - 1))));
            setHover(i);
          }}
          onMouseLeave={() => setHover(null)}
        />
      </svg>
      {hover != null && (
        <div
          className={styles.tip}
          style={{ left: `${(geom.X(hover) / W) * 100}%`, top: `${(geom.Y(points[hover].count) / H) * 100}%` }}
        >
          <b>{points[hover].count} victims</b> · {points[hover].label}
        </div>
      )}
    </div>
  );
}
