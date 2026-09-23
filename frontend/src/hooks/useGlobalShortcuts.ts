import { useEffect } from "react";
import { useUIStore } from "@/stores/uiStore";

/**
 * Registers app-wide keyboard shortcuts that must work under every layout.
 * Currently: ⌘⇧K / Ctrl+Shift+K toggles the global copilot dock. The Shift
 * modifier keeps this from colliding with ⌘K (command palette), which the
 * layouts guard with `!e.shiftKey`.
 *
 * Mounted once in App.tsx so it's live under both MainLayout and SidebarLayout.
 */
export function useGlobalShortcuts() {
  const toggleCopilotPanel = useUIStore((s) => s.toggleCopilotPanel);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        toggleCopilotPanel();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [toggleCopilotPanel]);
}
