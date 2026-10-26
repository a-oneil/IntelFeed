import { useState, useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import type { GlossaryMatch } from "@/api/types";
import { Chip } from "@/components/primitives";
import styles from "./GlossaryTooltip.module.css";

const NIST_CSF_COLORS: Record<string, string> = {
  govern: "#6366f1",
  identify: "#3b82f6",
  protect: "#22c55e",
  detect: "#f59e0b",
  respond: "#ef4444",
  recover: "#8b5cf6",
};

interface Props {
  containerRef: React.RefObject<HTMLDivElement | null>;
  matches: GlossaryMatch[];
  onOpenPanel?: () => void;
  onSearchArticles?: (term: GlossaryMatch["term"]) => void;
}

interface TooltipState {
  match: GlossaryMatch;
  x: number;
  y: number;
}

export function GlossaryTooltip({ containerRef, matches, onOpenPanel, onSearchArticles }: Props) {
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const hideTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);

  const termMap = useRef(new Map<string, GlossaryMatch>());
  useEffect(() => {
    termMap.current.clear();
    for (const m of matches) {
      termMap.current.set(m.term.id, m);
    }
  }, [matches]);

  const show = useCallback((target: HTMLElement) => {
    if (hideTimeoutRef.current) {
      clearTimeout(hideTimeoutRef.current);
      hideTimeoutRef.current = null;
    }
    const id = target.dataset.glossaryId;
    if (!id) return;
    const match = termMap.current.get(id);
    if (!match) return;

    const rect = target.getBoundingClientRect();
    const viewportHeight = window.innerHeight;
    const spaceBelow = viewportHeight - rect.bottom;
    const showAbove = spaceBelow < 200;

    setTooltip({
      match,
      x: rect.left + rect.width / 2,
      y: showAbove ? rect.top - 8 : rect.bottom + 8,
    });
  }, []);

  const hide = useCallback(() => {
    hideTimeoutRef.current = setTimeout(() => setTooltip(null), 200);
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const handleMouseOver = (e: MouseEvent) => {
      const target = (e.target as HTMLElement).closest(".glossary-term") as HTMLElement | null;
      if (target) show(target);
    };
    const handleMouseOut = (e: MouseEvent) => {
      const target = (e.target as HTMLElement).closest(".glossary-term");
      if (target) hide();
    };

    container.addEventListener("mouseover", handleMouseOver);
    container.addEventListener("mouseout", handleMouseOut);
    return () => {
      container.removeEventListener("mouseover", handleMouseOver);
      container.removeEventListener("mouseout", handleMouseOut);
    };
  }, [containerRef, show, hide]);

  if (!tooltip) return null;

  const categoryColor = NIST_CSF_COLORS[tooltip.match.term.category] || "#6b7280";
  const spaceBelow = window.innerHeight - tooltip.y;
  const showAbove = spaceBelow < 200;

  return createPortal(
    <div
      ref={tooltipRef}
      className={`${styles.tooltip} ${showAbove ? styles.above : ""}`}
      style={{ left: tooltip.x, top: tooltip.y }}
      onMouseEnter={() => {
        if (hideTimeoutRef.current) clearTimeout(hideTimeoutRef.current);
      }}
      onMouseLeave={hide}
    >
      <div className={styles.header}>
        <span className={styles.name}>{tooltip.match.term.name}</span>
        <Chip tone="solid" tint={categoryColor} className={styles.categoryBadge}>
          {tooltip.match.term.category.toUpperCase()}
        </Chip>
        {tooltip.match.term.maturity && (
          <Chip className={styles.maturityBadge}>{tooltip.match.term.maturity}</Chip>
        )}
      </div>
      <p className={styles.description}>{tooltip.match.term.description}</p>
      {tooltip.match.term.technologies.length > 0 && (
        <div className={styles.techList}>
          {tooltip.match.term.technologies.slice(0, 5).map((tech) => (
            <Chip key={tech.name} className={styles.techBadge}>
              {tech.url ? (
                <a href={tech.url} target="_blank" rel="noopener noreferrer">
                  {tech.name}
                </a>
              ) : (
                tech.name
              )}
            </Chip>
          ))}
        </div>
      )}
      <div className={styles.actions}>
        <button
          className={styles.actionBtn}
          onClick={() => {
            setTooltip(null);
            onOpenPanel?.();
          }}
        >
          View in panel
        </button>
        {onSearchArticles && (
          <button
            className={styles.actionBtn}
            onClick={() => {
              setTooltip(null);
              onSearchArticles(tooltip.match.term);
            }}
          >
            Search articles
          </button>
        )}
      </div>
    </div>,
    document.body,
  );
}
