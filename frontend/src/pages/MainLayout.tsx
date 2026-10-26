import { useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { useMarkRead } from "@/hooks/useEntries";
import { useUIStore } from "@/stores/uiStore";
import { usePlayerStore } from "@/stores/playerStore";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useSwipe } from "@/hooks/useSwipe";
import { exportEntry } from "@/hooks/useExport";
import { Sidebar } from "@/components/Sidebar";
import { EntryList } from "@/components/EntryList";
import { ThreadReader } from "@/components/ThreadReader";
import { EntryReader } from "@/components/EntryReader";
import { NoteBrowser } from "@/components/NoteBrowser";
import { CommandPalette } from "@/components/CommandPalette";
import { AppHeader } from "@/components/AppHeader";
import { ResizeHandle } from "@/components/ResizeHandle";
import { RailToggle } from "@/components/primitives";
import styles from "./MainLayout.module.css";
import { useIsVisitor } from "@/stores/authStore";

interface MainLayoutProps {
  // Priority Queue mode: renders the same list + reader shell, but pins the
  // entry list to the signal-engine "radar" sort and always shows entries
  // (never the search/notes panels).
  priorityMode?: boolean;
}

export function MainLayout({ priorityMode = false }: MainLayoutProps = {}) {
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const sidebarWidth = useUIStore((s) => s.sidebarWidth);
  const setSidebarWidth = useUIStore((s) => s.setSidebarWidth);
  const readerOpen = useUIStore((s) => s.readerOpen);
  const selectedEntryId = useUIStore((s) => s.selectedEntryId);
  const selectedThreadSlug = useUIStore((s) => s.selectedThreadSlug);
  const setSelectedThread = useUIStore((s) => s.setSelectedThread);
  const hasActiveTrack = usePlayerStore((s) => !!s.currentTrack || (s.mode === "speech" && !!s.speechTrack && s.isPlaying));
  const activePanel = useUIStore((s) => s.activePanel);
  const setActivePanel = useUIStore((s) => s.setActivePanel);
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const entryListWidth = useUIStore((s) => s.entryListWidth);
  const setEntryListWidth = useUIStore((s) => s.setEntryListWidth);
  const entryListCollapsed = useUIStore((s) => s.entryListCollapsed);
  const setEntryListCollapsed = useUIStore((s) => s.setEntryListCollapsed);
  const markReadOnScroll = useUIStore((s) => s.markReadOnScroll);
  const markRead = useMarkRead();

  // Auto-read: mark the previous entry read when the selection moves on. This
  // lives in MainLayout (always mounted while reading) rather than in EntryList,
  // because collapsing the entry list unmounts EntryList — and reader-internal
  // navigation (Next/Prev, j/k) would then change the selection with no mounted
  // effect to catch it, leaving articles unread. Covers every navigation path:
  // list clicks, reader nav, and closing the reader / switching scope (→ null).
  const prevEntryIdRef = useRef<string | null>(null);
  useEffect(() => {
    if (markReadOnScroll && prevEntryIdRef.current && prevEntryIdRef.current !== selectedEntryId) {
      markRead.mutate(prevEntryIdRef.current);
    }
    prevEntryIdRef.current = selectedEntryId;
  }, [selectedEntryId, markReadOnScroll, markRead]);

  const isMobile = useIsMobile();
  const [searchParams, setSearchParams] = useSearchParams();
  const commandPaletteOpen = useUIStore((s) => s.commandPaletteOpen);
  // No command palette in public read-only mode: most of what it does writes.
  const isVisitor = useIsVisitor();

  // On mobile, ensure sidebar starts collapsed and stays collapsed on navigation
  useEffect(() => {
    if (isMobile) {
      useUIStore.getState().setSidebarCollapsed(true);
    }
  }, [isMobile, readerOpen, selectedEntryId]);

  // Open entry from ?entry= query parameter (used by triage, dashboards, etc.)
  useEffect(() => {
    const entryParam = searchParams.get("entry");
    if (entryParam) {
      setActivePanel("entries");
      setSelectedEntry(entryParam);
      setSearchParams({}, { replace: true });
    }
  }, [searchParams, setActivePanel, setSelectedEntry, setSearchParams]);

  // Open a story thread from ?thread=<slug>. Threads have no page of their own —
  // they are read in this reader — so this is how one is linked to or bookmarked.
  useEffect(() => {
    const threadParam = searchParams.get("thread");
    if (threadParam) {
      setActivePanel("entries");
      setSelectedThread(threadParam);
      setSearchParams({}, { replace: true });
    }
  }, [searchParams, setActivePanel, setSelectedThread, setSearchParams]);

  // Global keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Cmd+K / Ctrl+K — command palette (Shift is reserved for the copilot)
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        useUIStore.getState().toggleCommandPalette();
        return;
      }

      const target = e.target as HTMLElement;
      const isInput =
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable;

      if (e.key === "Escape") {
        if (useUIStore.getState().shortcutsHelpOpen) {
          useUIStore.getState().closeShortcutsHelp();
          return;
        }
        if (readerOpen) useUIStore.getState().setSelectedEntry(null);
      }

      // Shortcuts that only work when an entry reader is open and not in an input
      if (!isInput && readerOpen && selectedEntryId) {
        const currentPanel = useUIStore.getState().activeReaderPanel;
        if (e.key === "w") {
          e.preventDefault();
          useUIStore.getState().setActiveReaderPanel(currentPanel === "intel" ? null : "intel");
        } else if (e.key === "a") {
          e.preventDefault();
          useUIStore.getState().setActiveReaderPanel(currentPanel === "ai" ? null : "ai");
        } else if (e.key === "n") {
          e.preventDefault();
          useUIStore.getState().setActiveReaderPanel(currentPanel === "notes" ? null : "notes");
        } else if (e.key === "t") {
          e.preventDefault();
          useUIStore.getState().setActiveReaderPanel(currentPanel === "tag" ? null : "tag");
        } else if (e.key === "e") {
          e.preventDefault();
          exportEntry(selectedEntryId);
        }
      }

      if (e.key === "?" && !isInput) {
        e.preventDefault();
        useUIStore.getState().toggleShortcutsHelp();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [readerOpen, selectedEntryId]);

  const renderEntryListAndReader = (listContent: React.ReactNode) => (
    <>
      {!entryListCollapsed && (
        <div
          className={`${styles.entryList} ${readerOpen ? styles.withReader : ""}`}
          style={readerOpen && !isMobile ? { width: entryListWidth, flex: "none" } : undefined}
        >
          {listContent}
        </div>
      )}
      {readerOpen && !entryListCollapsed && !isMobile && (
        <ResizeHandle
          onResize={(delta) => setEntryListWidth(entryListWidth + delta)}
        />
      )}
      {readerOpen && !isMobile && (
        <RailToggle
          side="both"
          collapsed={entryListCollapsed}
          onToggle={() => setEntryListCollapsed(!entryListCollapsed)}
          label="entry list"
          verbs={["Show", "Hide"]}
        />
      )}
      {readerOpen && selectedThreadSlug && (
        <div className={styles.reader}>
          <ThreadReader slug={selectedThreadSlug} />
        </div>
      )}
      {readerOpen && !selectedThreadSlug && selectedEntryId && (
        <div className={styles.reader}>
          <EntryReader entryId={selectedEntryId} />
        </div>
      )}
    </>
  );

  const mainSwipeRef = useSwipe<HTMLElement>({
    onSwipeRight: () => {
      if (sidebarCollapsed && isMobile) toggleSidebar();
    },
    edgeOnly: true,
    edgeWidth: 25,
    threshold: 50,
    enabled: isMobile,
  });

  const sidebarSwipeRef = useSwipe<HTMLDivElement>({
    onSwipeLeft: () => useUIStore.getState().setSidebarCollapsed(true),
    threshold: 50,
    enabled: isMobile && !sidebarCollapsed,
  });

  return (
    <div className={`${styles.outerLayout} ${hasActiveTrack ? styles.withPlayer : ""}`}>
      <a href="#main-content" className={styles.skipLink}>Skip to content</a>
      <AppHeader onShowShortcuts={useUIStore.getState().openShortcutsHelp} />
      {/* Body: sidebar + main */}
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
        <main id="main-content" className={styles.main} role="main" ref={mainSwipeRef}>
          {priorityMode ? (
            renderEntryListAndReader(<EntryList sortOverride="radar" withThreads priorityMode />)
          ) : activePanel === "notes" ? (
            <div className={styles.fullPanel}>
              <NoteBrowser />
            </div>
          ) : (
            renderEntryListAndReader(<EntryList />)
          )}
        </main>
      </div>
      <div aria-live="polite" aria-atomic="true" className={styles.srOnly} />
      <CommandPalette
        open={commandPaletteOpen && !isVisitor}
        onClose={useUIStore.getState().closeCommandPalette}
      />
    </div>
  );
}
