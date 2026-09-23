import { useCallback, useEffect, useRef, useState } from "react";
import styles from "./MermaidDiagram.module.css";

let mermaidPromise: Promise<typeof import("mermaid").default> | null = null;

/**
 * Mermaid is ~500KB, so it is imported on first diagram render rather than at
 * module load — the documentation route is the only place that pulls it in, and a
 * page with no diagrams never pays for it.
 */
function loadMermaid() {
  if (!mermaidPromise) {
    mermaidPromise = import("mermaid").then((mod) => mod.default);
  }
  return mermaidPromise;
}

/** Read the active theme's palette so diagrams follow the app's theme switcher. */
function themeVariables() {
  const css = getComputedStyle(document.documentElement);
  const read = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  const line = read("--border", "#30363d");
  const text = read("--text-primary", "#e6edf3");
  return {
    background: read("--bg-primary", "#0d1117"),
    primaryColor: read("--bg-tertiary", "#21262d"),
    primaryTextColor: text,
    primaryBorderColor: line,
    secondaryColor: read("--bg-secondary", "#161b22"),
    tertiaryColor: read("--bg-secondary", "#161b22"),
    lineColor: read("--text-secondary", "#8b949e"),
    textColor: text,
    mainBkg: read("--bg-tertiary", "#21262d"),
    nodeBorder: line,
    clusterBkg: read("--bg-secondary", "#161b22"),
    clusterBorder: line,
    edgeLabelBackground: read("--bg-primary", "#0d1117"),
  };
}

// Zoom-out limit: low enough to survey even the ~14000px ER diagram.
const MIN_SCALE = 0.05;
// A diagram never *opens* smaller than this, however wide it is.
const MIN_LEGIBLE_SCALE = 0.4;
const MAX_SCALE = 6;
const ZOOM_STEP = 1.25;
// Matches .canvas padding in the stylesheet.
const PADDING = 16;

let seq = 0;

interface Props {
  chart: string;
}

export function MermaidDiagram({ chart }: Props) {
  const [svg, setSvg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // scale and pan live in ONE state object: zooming has to move the pan in the
  // same commit, and splitting them meant the zoom updater mutated the other
  // piece of state — an impure updater React is free to run more than once,
  // which multiplied the pan and flung the diagram off-screen.
  const [view, setView] = useState({ scale: 1, x: 0, y: 0 });
  const [isFullscreen, setIsFullscreen] = useState(false);
  const idRef = useRef(`mermaid-${(seq += 1)}`);
  const shellRef = useRef<HTMLDivElement>(null);
  const viewportRef = useRef<HTMLDivElement>(null);
  const fitScaleRef = useRef(1);
  const dragRef = useRef<{ x: number; y: number; ox: number; oy: number } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const renderId = idRef.current;
    setError(null);
    loadMermaid()
      .then((mermaid) => {
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "strict",
          theme: "base",
          themeVariables: themeVariables(),
        });
        return mermaid.render(renderId, chart);
      })
      .then(({ svg: rendered }) => {
        if (!cancelled) setSvg(rendered);
      })
      .catch((err: unknown) => {
        // A malformed diagram should show its source, not blank the page.
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
      // mermaid.render appends a detached measuring node keyed by id; drop it.
      document.getElementById(`d${renderId}`)?.remove();
    };
  }, [chart]);

  /**
   * Give the SVG a real pixel size. mermaid emits width="100%" and keeps the true
   * dimensions only in the viewBox; inside a max-content container that is
   * circular, so the browser fell back to the 300x150 default for replaced
   * elements and every diagram rendered as a ~300px thumbnail. Returns the
   * natural size so fit() does not have to re-measure the layout.
   */
  const normalize = useCallback(() => {
    const svgEl = viewportRef.current?.querySelector("svg");
    if (!svgEl) return null;
    const box = svgEl.getAttribute("viewBox")?.split(/[\s,]+/).map(Number);
    if (!box || box.length < 4 || !box[2] || !box[3]) return null;
    svgEl.style.width = `${box[2]}px`;
    svgEl.style.height = `${box[3]}px`;
    svgEl.style.maxWidth = "none";
    return { width: box[2], height: box[3] };
  }, []);

  /**
   * Fit the diagram's *width*, never magnifying past 1:1.
   *
   * `legible: true` (how a diagram opens) additionally refuses to go below
   * MIN_LEGIBLE_SCALE. Sizes here span three orders of magnitude — the ER diagram
   * is ~14000px wide, which a true fit renders as an unreadable 45px-tall smear —
   * so opening favours readable text over completeness, and panning covers the
   * rest. The toolbar button calls this with `legible: false` for a genuine
   * whole-diagram fit.
   */
  const fit = useCallback(
    (legible = false) => {
      const viewport = viewportRef.current;
      const dims = normalize();
      if (!viewport || !dims) return;
      const vw = viewport.clientWidth - PADDING * 2;
      const vh = viewport.clientHeight - PADDING * 2;
      const raw = Math.min(1, vw / dims.width);
      const scale = legible ? Math.max(raw, MIN_LEGIBLE_SCALE) : raw;
      // Remember the true fit so zooming out can always reach a full overview.
      fitScaleRef.current = raw;
      const width = dims.width * scale;
      const height = dims.height * scale;
      setView({
        scale,
        // Centre whichever axis fits; anchor the other at the start.
        x: width < vw ? PADDING + (vw - width) / 2 : PADDING,
        y: height < vh ? PADDING + (vh - height) / 2 : PADDING,
      });
    },
    [normalize],
  );

  // Fit once the SVG is in the DOM, and again when the box resizes (fullscreen).
  useEffect(() => {
    if (!svg) return;
    const raf = requestAnimationFrame(() => fit(true));
    const viewport = viewportRef.current;
    const ro = viewport ? new ResizeObserver(() => fit(true)) : null;
    if (viewport && ro) ro.observe(viewport);
    return () => {
      cancelAnimationFrame(raf);
      ro?.disconnect();
    };
  }, [svg, fit]);

  useEffect(() => {
    const onChange = () => setIsFullscreen(document.fullscreenElement === shellRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  /** Zoom about a fixed point so the content under it stays put. */
  const zoomAt = useCallback((factor: number, clientX?: number, clientY?: number) => {
    const viewport = viewportRef.current;
    setView((prev) => {
      // A huge diagram fits below MIN_SCALE; never clamp above its own fit.
      const floor = Math.min(MIN_SCALE, fitScaleRef.current);
      const scale = Math.min(MAX_SCALE, Math.max(floor, prev.scale * factor));
      if (!viewport || scale === prev.scale) return { ...prev, scale };
      const rect = viewport.getBoundingClientRect();
      const px = (clientX ?? rect.left + rect.width / 2) - rect.left;
      const py = (clientY ?? rect.top + rect.height / 2) - rect.top;
      const ratio = scale / prev.scale;
      return { scale, x: px - (px - prev.x) * ratio, y: py - (py - prev.y) * ratio };
    });
  }, []);

  // Non-passive listener: React's onWheel is passive, so it cannot preventDefault
  // and the page would scroll away underneath the zoom.
  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport || !svg) return;
    const onWheel = (e: WheelEvent) => {
      // Plain scroll keeps scrolling the page; ctrl/⌘ + wheel zooms, matching
      // the pinch gesture browsers already map to ctrl+wheel.
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      zoomAt(e.deltaY < 0 ? ZOOM_STEP : 1 / ZOOM_STEP, e.clientX, e.clientY);
    };
    viewport.addEventListener("wheel", onWheel, { passive: false });
    return () => viewport.removeEventListener("wheel", onWheel);
  }, [svg, zoomAt]);

  const onPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0) return;
    dragRef.current = { x: e.clientX, y: e.clientY, ox: view.x, oy: view.y };
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    const drag = dragRef.current;
    if (!drag) return;
    setView((prev) => ({ ...prev, x: drag.ox + (e.clientX - drag.x), y: drag.oy + (e.clientY - drag.y) }));
  };

  const endDrag = (e: React.PointerEvent) => {
    dragRef.current = null;
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
  };

  const toggleFullscreen = () => {
    if (document.fullscreenElement === shellRef.current) void document.exitFullscreen();
    else void shellRef.current?.requestFullscreen();
  };

  if (error) {
    return (
      <div className={styles.fallback}>
        <p className={styles.error}>Diagram failed to render: {error}</p>
        <pre>
          <code>{chart}</code>
        </pre>
      </div>
    );
  }

  if (!svg) return <div className={styles.loading}>Rendering diagram…</div>;

  return (
    <div ref={shellRef} className={styles.shell}>
      <div className={styles.toolbar}>
        <button type="button" onClick={() => zoomAt(1 / ZOOM_STEP)} title="Zoom out" aria-label="Zoom out">
          −
        </button>
        <button type="button" className={styles.zoomLabel} onClick={() => fit(false)} title="Fit whole diagram">
          {Math.round(view.scale * 100)}%
        </button>
        <button type="button" onClick={() => zoomAt(ZOOM_STEP)} title="Zoom in" aria-label="Zoom in">
          +
        </button>
        <button
          type="button"
          onClick={toggleFullscreen}
          title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
          aria-label={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
        >
          {isFullscreen ? "⤡" : "⤢"}
        </button>
      </div>
      <div
        ref={viewportRef}
        className={styles.viewport}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        onDoubleClick={() => zoomAt(ZOOM_STEP)}
      >
        {/* mermaid sanitizes its own output under securityLevel: "strict". */}
        <div
          className={styles.canvas}
          style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.scale})` }}
          dangerouslySetInnerHTML={{ __html: svg }}
        />
      </div>
      <p className={styles.hint}>Drag to pan · ⌘/Ctrl + scroll to zoom · double-click to zoom in</p>
    </div>
  );
}
