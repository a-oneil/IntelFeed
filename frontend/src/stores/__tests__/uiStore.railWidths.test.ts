import { beforeEach, describe, expect, it } from "vitest";

import { useUIStore } from "@/stores/uiStore";

/**
 * Every secondary/tertiary rail (workbench nav, settings nav, the search / rule
 * / ransomware facet rails, the docs and prompt lists) sizes itself off this one
 * map, so the clamping and the reset are what keep a dragged rail from being
 * left unusable.
 */
describe("uiStore rail widths", () => {
  beforeEach(() => {
    useUIStore.setState({ railWidths: {} });
  });

  it("stores a width per rail id", () => {
    useUIStore.getState().setRailWidth("settings-nav", 300, 170, 420);
    useUIStore.getState().setRailWidth("docs-nav", 400, 190, 480);

    expect(useUIStore.getState().railWidths).toEqual({ "settings-nav": 300, "docs-nav": 400 });
  });

  it("clamps to the rail's own bounds rather than a shared one", () => {
    useUIStore.getState().setRailWidth("settings-nav", 20, 170, 420);
    expect(useUIStore.getState().railWidths["settings-nav"]).toBe(170);

    useUIStore.getState().setRailWidth("settings-nav", 9000, 170, 420);
    expect(useUIStore.getState().railWidths["settings-nav"]).toBe(420);
  });

  it("rounds sub-pixel drag deltas", () => {
    useUIStore.getState().setRailWidth("rule-facets", 233.6, 170, 420);
    expect(useUIStore.getState().railWidths["rule-facets"]).toBe(234);
  });

  it("drops the key on reset so the rail falls back to its default", () => {
    useUIStore.getState().setRailWidth("rule-facets", 300, 170, 420);
    useUIStore.getState().resetRailWidth("rule-facets");

    expect("rule-facets" in useUIStore.getState().railWidths).toBe(false);
  });

  it("leaves the map alone when resetting a rail that was never dragged", () => {
    const before = useUIStore.getState().railWidths;
    useUIStore.getState().resetRailWidth("never-dragged");

    expect(useUIStore.getState().railWidths).toBe(before);
  });
});
