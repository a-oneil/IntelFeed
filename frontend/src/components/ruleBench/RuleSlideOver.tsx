import { useEffect, type CSSProperties, type ReactNode } from "react";
import { RailToggle } from "@/components/primitives";
import { ResizeHandle } from "@/components/ResizeHandle";
import { useIsMobile } from "@/hooks/useMediaQuery";
import styles from "./RuleSlideOver.module.css";

interface RuleSlideOverProps {
  title: string;
  /** Tabs for the secondary surfaces that no longer sit on the primary axis. */
  tabs?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  /** Docked-rail furniture — the same collapse/resize the entry reader uses. */
  collapsed: boolean;
  onToggleCollapse: () => void;
  railStyle: CSSProperties;
  onResize: (delta: number) => void;
  onResizeStart?: () => void;
  onResizeEnd?: () => void;
  onResizeReset?: () => void;
}

/** The rule shelf: everything the bench pushed off the three columns, docked on
    the right exactly like the workbench entry reader — a resizable, collapsible
    rail that pushes the editor rather than overlaying it. */
export function RuleSlideOver({
  title,
  tabs,
  onClose,
  children,
  collapsed,
  onToggleCollapse,
  railStyle,
  onResize,
  onResizeStart,
  onResizeEnd,
  onResizeReset,
}: RuleSlideOverProps) {
  // Below 767px the panel stops being a rail and becomes a full-width overlay
  // (see the media query in the stylesheet). The persisted rail width is a
  // desktop measurement — applied inline it beats `width: min(560px, 100vw)`
  // and hangs the left half of the panel off the screen — so drop it, along
  // with the resize/collapse furniture that only makes sense for a docked rail.
  const isMobile = useIsMobile();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      {!isMobile && (
        <RailToggle side="right" collapsed={collapsed} onToggle={onToggleCollapse} label={title.toLowerCase()} />
      )}
      {!collapsed && !isMobile && (
        <ResizeHandle
          label={title}
          onResize={(delta) => onResize(-delta)}
          onResizeStart={onResizeStart}
          onResizeEnd={onResizeEnd}
          onReset={onResizeReset}
        />
      )}
      {!collapsed && (
        <aside
          className={styles.panel}
          style={isMobile ? undefined : railStyle}
          role="region"
          aria-label={title}
        >
          {/* One toolbar, like the entry reader: Close and the tabs share a row. */}
          <div className={styles.head}>
            <button type="button" className={styles.close} onClick={onClose} aria-label="Close">
              Close
            </button>
            {tabs ? <div className={styles.headTabs}>{tabs}</div> : <span className={styles.title}>{title}</span>}
          </div>
          <div className={styles.body}>{children}</div>
        </aside>
      )}
    </>
  );
}
