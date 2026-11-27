import { useEffect } from "react";
import { useUIStore } from "@/stores/uiStore";

/**
 * Collapse the app (feeds) sidebar on pages that have a sidebar of their own, and expand it again when the page unmounts.
 *
 * The workbench, settings and search all render a second nav rail inside the content area. Showing that beside the app sidebar spends ~500px on two navs before any content, so these pages collapse the outer one, and restore it on exit only if this hook collapsed it. A manual toggle clears `sidebarAutoCollapsed`, so an explicit choice is never overridden on exit.
 *
 * The restore runs on unmount rather than in a route effect because the page can be left by any means (nav click, back button, a deep link from the copilot), and unmount is the only signal common to all of them.
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
