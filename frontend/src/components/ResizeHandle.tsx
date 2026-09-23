import { useCallback, useRef } from "react";
import styles from "./ResizeHandle.module.css";

interface ResizeHandleProps {
  onResize: (delta: number) => void;
  /** Fires once when the drag starts — hosts use it to suspend width transitions. */
  onResizeStart?: () => void;
  onResizeEnd?: () => void;
  /** Double-click restores the pane's default width, when the host supports it. */
  onReset?: () => void;
  /** Names the pane being resized, e.g. "settings menu". */
  label?: string;
  className?: string;
}

export function ResizeHandle({ onResize, onResizeStart, onResizeEnd, onReset, label, className }: ResizeHandleProps) {
  const isDragging = useRef(false);
  const lastX = useRef(0);

  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    isDragging.current = true;
    lastX.current = e.clientX;
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    onResizeStart?.();
  }, [onResizeStart]);

  const handlePointerMove = useCallback(
    (e: React.PointerEvent) => {
      if (!isDragging.current) return;
      const delta = e.clientX - lastX.current;
      lastX.current = e.clientX;
      onResize(delta);
    },
    [onResize],
  );

  const handlePointerUp = useCallback(
    (e: React.PointerEvent) => {
      if (!isDragging.current) return;
      isDragging.current = false;
      (e.target as HTMLElement).releasePointerCapture(e.pointerId);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      onResizeEnd?.();
    },
    [onResizeEnd],
  );

  return (
    <div
      className={`${styles.handle} ${className || ""}`}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onDoubleClick={onReset}
      role="separator"
      aria-orientation="vertical"
      aria-label={label ? `Resize ${label}` : undefined}
      title={onReset ? "Drag to resize · double-click to reset" : "Drag to resize"}
    />
  );
}
