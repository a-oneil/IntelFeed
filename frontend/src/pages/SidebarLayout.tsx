import { Suspense, useEffect } from "react";
import { Outlet } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import { usePlayerStore } from "@/stores/playerStore";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useSwipe } from "@/hooks/useSwipe";
import { Sidebar } from "@/components/Sidebar";
import { AppHeader } from "@/components/AppHeader";
import { CommandPalette } from "@/components/CommandPalette";
import { ResizeHandle } from "@/components/ResizeHandle";
import { RailToggle } from "@/components/primitives";
import { RouteFallback } from "@/components/RouteFallback";
import styles from "./SidebarLayout.module.css";
import { useIsVisitor } from "@/stores/authStore";

export function SidebarLayout() {
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const sidebarWidth = useUIStore((s) => s.sidebarWidth);
  const setSidebarWidth = useUIStore((s) => s.setSidebarWidth);
  const hasActiveTrack = usePlayerStore((s) => !!s.currentTrack || (s.mode === "speech" && !!s.speechTrack && s.isPlaying));
  const isMobile = useIsMobile();
  const commandPaletteOpen = useUIStore((s) => s.commandPaletteOpen);
  // No command palette in public read-only mode: most of what it does writes.
  const isVisitor = useIsVisitor();

  const sidebarSwipeRef = useSwipe<HTMLDivElement>({
    onSwipeLeft: () => useUIStore.getState().setSidebarCollapsed(true),
    threshold: 50,
    enabled: isMobile && !sidebarCollapsed,
  });

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        useUIStore.getState().toggleCommandPalette();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <div className={`${styles.outerLayout} ${hasActiveTrack ? styles.withPlayer : ""}`}>
      <AppHeader onShowShortcuts={useUIStore.getState().openShortcutsHelp} />
      <div className={styles.layout}>
        <div
          ref={sidebarSwipeRef}
          className={`${styles.sidebar} ${sidebarCollapsed ? styles.collapsed : ""}`}
          style={!sidebarCollapsed && !isMobile ? { width: sidebarWidth, minWidth: sidebarWidth } : undefined}
        >
          <Sidebar />
        </div>
        {isMobile && !sidebarCollapsed && (
          <div className={styles.backdrop} onClick={toggleSidebar} />
        )}
        {!sidebarCollapsed && !isMobile && (
          <ResizeHandle
            onResize={(delta) => setSidebarWidth(sidebarWidth + delta)}
          />
        )}
        {!isMobile && (
          <RailToggle
            side="left"
            collapsed={sidebarCollapsed}
            onToggle={toggleSidebar}
            label="menu"
          />
        )}
        <div className={styles.content}>
          {/* Boundary lives HERE, not at the app root: a lazy page suspending
              must swap only this pane, leaving the header, sidebar and copilot
              dock mounted. */}
          <Suspense fallback={<RouteFallback />}>
            <Outlet />
          </Suspense>
        </div>
      </div>
      <CommandPalette
        open={commandPaletteOpen && !isVisitor}
        onClose={useUIStore.getState().closeCommandPalette}
      />
    </div>
  );
}
