import { useCallback, useMemo, useState } from "react";
import type { CSSProperties } from "react";

import { useUIStore } from "@/stores/uiStore";

interface RailWidthOptions {
  /** Width the rail ships with, used until the user drags it. */
  default: number;
  min?: number;
  max?: number;
}

export interface RailWidth {
  width: number;
  /** Inline sizing for the rail element; pass undefined when it is collapsed or a mobile sheet. */
  style: CSSProperties;
  /** Spread onto <ResizeHandle>. */
  handleProps: {
    onResize: (delta: number) => void;
    onResizeStart: () => void;
    onResizeEnd: () => void;
    onReset: () => void;
  };
}

/**
 * Drag-to-resize for a secondary or tertiary rail — the workbench and settings
 * navs, the search / rule library / ransomware facet rails, the docs and prompt
 * lists. The app sidebar has had this since the three-panel layout landed; this
 * gives every rail nested inside it the same handle off one persisted map.
 *
 * The bounds are enforced on both sides — clamped as the persisted width is
 * read, and again in the store on every drag — so a stale localStorage width
 * from a rail whose design minimum later grew renders inside the current bounds
 * instead of restoring a broken column.
 */
export function useRailWidth(
  railId: string,
  { default: dflt, min = 160, max = 560 }: RailWidthOptions,
): RailWidth {
  // Clamp on read, not just on write: `setRailWidth` bounds a live drag, but a
  // width persisted under an older min/max (or by a rail that has since been
  // redesigned) came straight back out of localStorage unbounded. For the
  // docked reader that meant it could open as an invisible sliver — the click
  // worked, the pane just had no width.
  const stored = useUIStore((s) => s.railWidths[railId]);
  const width = stored == null ? dflt : Math.max(min, Math.min(max, stored));
  const [dragging, setDragging] = useState(false);

  // Read the current width off the store rather than closing over `width`: the
  // handle fires a delta per pointermove, and a stale closure would drop every
  // move that lands before React re-renders. The base is clamped the same way
  // the rendered width is, so the first drag off an out-of-bounds stored value
  // continues from the column the user can see instead of jumping.
  const resize = useCallback(
    (delta: number) => {
      const store = useUIStore.getState();
      const current = store.railWidths[railId];
      const base = current == null ? dflt : Math.max(min, Math.min(max, current));
      store.setRailWidth(railId, base + delta, min, max);
    },
    [railId, dflt, min, max],
  );

  const handleProps = useMemo(
    () => ({
      onResize: resize,
      onResizeStart: () => setDragging(true),
      onResizeEnd: () => setDragging(false),
      onReset: () => useUIStore.getState().resetRailWidth(railId),
    }),
    [resize, railId],
  );

  const style = useMemo<CSSProperties>(
    // Several rails ease their width so collapsing animates. That same easing
    // makes a drag lag a few frames behind the pointer, so it is suspended for
    // the duration of the drag only.
    () => ({ width, minWidth: width, ...(dragging ? { transition: "none" } : null) }),
    [width, dragging],
  );

  return { width, style, handleProps };
}
