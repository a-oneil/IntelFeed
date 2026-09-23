import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useRailWidth } from "@/hooks/useRailWidth";
import { useUIStore } from "@/stores/uiStore";

const READER = { default: 560, min: 400, max: 960 };

describe("useRailWidth", () => {
  beforeEach(() => {
    useUIStore.setState({ railWidths: {} });
  });

  it("uses the default when nothing is persisted", () => {
    const { result } = renderHook(() => useRailWidth("workbench-reader", READER));
    expect(result.current.width).toBe(560);
  });

  it("returns a persisted width that is already in bounds", () => {
    useUIStore.setState({ railWidths: { "workbench-reader": 700 } });
    const { result } = renderHook(() => useRailWidth("workbench-reader", READER));
    expect(result.current.width).toBe(700);
  });

  // Bounds used to be enforced only inside setRailWidth, so a width persisted
  // under an older min came straight back out of localStorage. For the docked
  // reader that rendered the pane as an invisible sliver: the article link
  // worked, the reader just had no width to show it in.
  it("clamps a stale persisted width below the current minimum", () => {
    useUIStore.setState({ railWidths: { "workbench-reader": 12 } });
    const { result } = renderHook(() => useRailWidth("workbench-reader", READER));
    expect(result.current.width).toBe(400);
    expect(result.current.style).toMatchObject({ width: 400, minWidth: 400 });
  });

  it("clamps a stale persisted width above the current maximum", () => {
    useUIStore.setState({ railWidths: { "workbench-reader": 5000 } });
    const { result } = renderHook(() => useRailWidth("workbench-reader", READER));
    expect(result.current.width).toBe(960);
  });

  it("drags from the clamped width, not the out-of-bounds stored one", () => {
    useUIStore.setState({ railWidths: { "workbench-reader": 12 } });
    const { result } = renderHook(() => useRailWidth("workbench-reader", READER));
    act(() => result.current.handleProps.onResize(50));
    // 400 (clamped base) + 50, rather than 12 + 50 clamped back up to 400.
    expect(useUIStore.getState().railWidths["workbench-reader"]).toBe(450);
  });

  it("resets back to the default", () => {
    useUIStore.setState({ railWidths: { "workbench-reader": 700 } });
    const { result } = renderHook(() => useRailWidth("workbench-reader", READER));
    act(() => result.current.handleProps.onReset());
    expect(useUIStore.getState().railWidths["workbench-reader"]).toBeUndefined();
  });
});
