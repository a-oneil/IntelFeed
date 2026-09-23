import { useEffect, useRef } from "react";
import { useMediaQuery } from "@/hooks/useMediaQuery";
import styles from "./AuthGraphBackground.module.css";

interface GraphNode {
  fx: number;
  fy: number;
  vx: number;
  vy: number;
  r: number;
  color: string;
}

const NODE_COUNT = 46;
const LINK_DISTANCE = 150;
const FALLBACK_COLORS = ["#f78166", "#58a6ff", "#3fb950", "#bc8cff"];
const COLOR_VARS = ["--accent-feeds", "--accent-intel", "--accent-detect", "--accent-dash"];

function readNodeColors(): string[] {
  const style = getComputedStyle(document.documentElement);
  return COLOR_VARS.map((name, i) => style.getPropertyValue(name).trim() || FALLBACK_COLORS[i]);
}

/**
 * Ambient, decorative entity-graph animation for auth screens.
 * Node positions are stored as fractions (0-1) of the canvas size rather
 * than absolute pixels, so they redistribute correctly regardless of the
 * canvas size at first measurement or after a later resize.
 */
export function AuthGraphBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const reduceMotion = useMediaQuery("(prefers-reduced-motion: reduce)");

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const colors = readNodeColors();
    const nodes: GraphNode[] = Array.from({ length: NODE_COUNT }, (_, i) => ({
      fx: Math.random(),
      fy: Math.random(),
      vx: (Math.random() - 0.5) * 0.00028,
      vy: (Math.random() - 0.5) * 0.00028,
      r: 1.6 + Math.random() * 2,
      color: colors[i % colors.length],
    }));

    const dpr = window.devicePixelRatio || 1;
    let raf = 0;

    function size() {
      const parent = canvas!.parentElement;
      if (!parent) return;
      canvas!.width = parent.clientWidth * dpr;
      canvas!.height = parent.clientHeight * dpr;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function step() {
      const w = canvas!.clientWidth;
      const h = canvas!.clientHeight;
      ctx!.clearRect(0, 0, w, h);

      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        if (!reduceMotion) {
          a.fx += a.vx;
          a.fy += a.vy;
        }
        if (a.fx < 0 || a.fx > 1) {
          a.vx *= -1;
          a.fx = Math.min(1, Math.max(0, a.fx));
        }
        if (a.fy < 0 || a.fy > 1) {
          a.vy *= -1;
          a.fy = Math.min(1, Math.max(0, a.fy));
        }
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const d = Math.hypot((a.fx - b.fx) * w, (a.fy - b.fy) * h);
          if (d < LINK_DISTANCE) {
            ctx!.strokeStyle = `rgba(139,148,158,${0.16 * (1 - d / LINK_DISTANCE)})`;
            ctx!.lineWidth = 1;
            ctx!.beginPath();
            ctx!.moveTo(a.fx * w, a.fy * h);
            ctx!.lineTo(b.fx * w, b.fy * h);
            ctx!.stroke();
          }
        }
      }

      for (const n of nodes) {
        ctx!.beginPath();
        ctx!.fillStyle = n.color;
        ctx!.globalAlpha = 0.55;
        ctx!.arc(n.fx * w, n.fy * h, n.r, 0, Math.PI * 2);
        ctx!.fill();
        ctx!.globalAlpha = 1;
      }

      if (!reduceMotion) raf = requestAnimationFrame(step);
    }

    size();
    step();
    window.addEventListener("resize", size);
    return () => {
      window.removeEventListener("resize", size);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [reduceMotion]);

  return <canvas ref={canvasRef} className={styles.canvas} aria-hidden="true" />;
}
