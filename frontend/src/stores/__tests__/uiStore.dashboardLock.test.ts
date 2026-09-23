import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * The dashboard grid starts locked on every viewport: rearranging a board is a
 * deliberate act, and an accidental drag on a phone is destructive — the grid
 * collapses to one column there, and saving that clamped layout flattens every
 * widget to a 1/12-width sliver on desktop.
 */
async function freshStore(isNarrow: boolean) {
  localStorage.clear();
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: isNarrow,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
    onchange: null,
  }));
  vi.resetModules();
  const { useUIStore } = await import("@/stores/uiStore");
  return useUIStore;
}

describe("dashboard layout lock", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("starts locked on a phone-sized viewport", async () => {
    const store = await freshStore(true);
    expect(store.getState().dashboardLocked).toBe(true);
  });

  it("starts locked on a desktop viewport too", async () => {
    const store = await freshStore(false);
    expect(store.getState().dashboardLocked).toBe(true);
  });

  it("remembers an unlock across sessions on this device", async () => {
    const store = await freshStore(false);
    store.getState().toggleDashboardLocked();
    expect(store.getState().dashboardLocked).toBe(false);

    const persisted = JSON.parse(localStorage.getItem("intelfeed-ui") ?? "{}");
    expect(persisted.state.dashboardLocked).toBe(false);

    // Rehydrating from that storage keeps the user unlocked rather than
    // re-applying the locked default.
    vi.resetModules();
    const { useUIStore } = await import("@/stores/uiStore");
    expect(useUIStore.getState().dashboardLocked).toBe(false);
  });
});
