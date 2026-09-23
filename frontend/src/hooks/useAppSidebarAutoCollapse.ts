import { useEffect } from "react";
import { useUIStore } from "@/stores/uiStore";

/**
 * Fold the app (feeds) sidebar away for pages that carry a sidebar of their own,
 * and put it back on the way out.
 *
 * The workbench, settings and search all render a second nav rail inside the
 * content area. Stacking that beside the app sidebar spends ~500px on two navs
 * before any content, so these pages collapse the outer one — and restore it
 * when you leave, but only if *this* collapsed it. A manual toggle clears
 * `sidebarAutoCollapsed`, so an explicit choice is never overridden on exit.
 *
 * Restoring on unmount rather than on a route effect matters: the page can be
 * left by any means (nav click, back button, a deep link from the copilot), and
 * unmount is the only signal common to all of them.
 */
export function useAppSidebarAutoCollapse() {
  useEffect(() => {
    if (!useUIStore.getState().sidebarCollapsed) {
      useUIStore.setState({ sidebarCollapsed: true, sidebarAutoCollapsed: true });
    }
    return () => {
      if (useUIStore.getState().sidebarAutoCollapsed) {
        useUIStore.setState({ sidebarCollapsed: false, sidebarAutoCollapsed: false });
      }
    };
  }, []);
}
