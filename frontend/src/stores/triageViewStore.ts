import { create } from "zustand";
import { persist } from "zustand/middleware";
import { normalizeTriageView } from "@/types/triageView";
import type { TriageView } from "@/types/triageView";

/**
 * Local-only mirror of the triage view. The authoritative copy lives in user
 * settings (`triage_view`); this store gives the page a synchronous handle and
 * survives reloads while a pending auto-save is in flight.
 *
 * `viewOwnerId` records whose view the mirror holds (same pattern as
 * uiStore.tablesOwnerId): when a different account signs in on this browser,
 * the leftover view must be replaced with that account's server copy, never
 * merged — and never auto-saved onto the new account's profile.
 */
interface TriageViewStoreState {
  view: TriageView | null;
  viewOwnerId: string | null;
  setView: (view: TriageView) => void;
  patchView: (patch: (current: TriageView) => TriageView) => void;
  takeOverView: (ownerId: string, view: TriageView) => void;
}

export const useTriageViewStore = create<TriageViewStoreState>()(
  persist(
    (set, get) => ({
      view: null,
      viewOwnerId: null,
      setView: (view) => set({ view }),
      patchView: (patch) => {
        const current = get().view;
        if (!current) return;
        set({ view: patch(current) });
      },
      takeOverView: (ownerId, view) => set({ viewOwnerId: ownerId, view }),
    }),
    {
      name: "intelfeed-triage-view",
      // Bump when the persisted TriageView shape changes. The migrate step
      // normalizes an old-shape stored view (e.g. one still carrying the
      // removed `atlas`/`priority` widget keys) to the canonical shape, so it
      // matches the server-saved view on mount and doesn't trigger a spurious
      // (and race-prone) auto-save.
      // v2 adds viewOwnerId; a pre-v2 store can't know whose view it holds, so
      // the owner starts null and the first authenticated mount claims it.
      version: 2,
      migrate: (persisted) => {
        const raw = (persisted as { view?: unknown; viewOwnerId?: unknown } | null)?.view;
        const owner = (persisted as { viewOwnerId?: unknown } | null)?.viewOwnerId;
        return {
          view: raw ? normalizeTriageView(raw) : null,
          viewOwnerId: typeof owner === "string" ? owner : null,
        };
      },
      partialize: (state) => ({ view: state.view, viewOwnerId: state.viewOwnerId }),
    },
  ),
);
