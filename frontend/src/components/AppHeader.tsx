import { useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import { logoutDestination, useAuthStore, useIsVisitor } from "@/stores/authStore";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { HeaderSearch } from "./HeaderSearch";
import { BrandButton } from "./BrandButton";
import { EngineStatusButton } from "./EngineStatusButton";
import { Hint } from "./primitives";
import styles from "./AppHeader.module.css";
import { confirmDialog } from "@/utils/dialog";

interface AppHeaderProps {
  onShowShortcuts: () => void;
}

export function AppHeader({ onShowShortcuts }: AppHeaderProps) {
  const isMobile = useIsMobile();
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const copilotOpen = useUIStore((s) => s.copilotOpen);
  const copilotCollapsed = useUIStore((s) => s.copilotCollapsed);
  const toggleCopilot = useUIStore((s) => s.toggleCopilot);
  const toggleCopilotPanel = useUIStore((s) => s.toggleCopilotPanel);
  const toggleCommandPalette = useUIStore((s) => s.toggleCommandPalette);
  const setSettingsNavCollapsed = useUIStore((s) => s.setSettingsNavCollapsed);
  const isMac = typeof navigator !== "undefined" && /Mac|iP(hone|ad|od)/.test(navigator.platform);
  const logout = useAuthStore((s) => s.logout);
  const navigate = useNavigate();
  const location = useLocation();
  const isVisitor = useIsVisitor();
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Desktop: once open, this button only expands/collapses the panel — it
  // never re-closes it (the panel's own "×" is the only full close). Mobile
  // has no collapsed rail, so it stays a plain open/close toggle there.
  const handleCopilotClick = isMobile ? toggleCopilot : toggleCopilotPanel;
  const copilotLabel = isMobile
    ? copilotOpen
      ? "Close copilot"
      : "Open copilot"
    : !copilotOpen
      ? "Open copilot"
      : copilotCollapsed
        ? "Expand copilot"
        : "Collapse copilot";

  return (
    <header className={styles.header}>
      {isMobile && (
        <button
          className={styles.mobileMenuBtn}
          onClick={toggleSidebar}
          aria-label={sidebarCollapsed ? "Open menu" : "Close menu"}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
      )}
      {!isMobile && <BrandButton />}
      {/* The app's only search input, on every route and every breakpoint. The
          mobile workbench used to suppress it in favour of its own full-screen
          overlay, which ran a second, weaker search engine — that overlay is
          gone. */}
      {isVisitor ? <div className={styles.visitorSpacer} /> : <HeaderSearch inputRef={searchInputRef} />}
      <div className={styles.actions}>
        {!isMobile && !isVisitor && (
          <Hint
            title="Jump to anything"
            body="Find any article, entity, feed or rule by name — and run actions like Add feed or New report."
            aside={<>Press <kbd>{isMac ? "⌘K" : "Ctrl K"}</kbd> from anywhere.</>}
            align="end"
          >
            <button
              className={styles.paletteBtn}
              onClick={toggleCommandPalette}
              aria-label="Open command palette"
            >
              <kbd className={styles.paletteKbd}>{isMac ? "⌘K" : "Ctrl K"}</kbd>
              <span>Jump or act…</span>
            </button>
          </Hint>
        )}
        {!isVisitor && (
        <Hint
          title="Copilot"
          body="Ask about whatever is on screen. It can search your feeds, pivot between entities and draft detection rules."
          aside={<><kbd>{isMac ? "⌘⇧K" : "Ctrl ⇧ K"}</kbd></>}
          align="end"
        >
          <button
            className={styles.copilotBtn}
            onClick={handleCopilotClick}
            aria-label={copilotLabel}
          >
            <span className={styles.copilotStar} aria-hidden="true">✦</span>
            {!isMobile && <span className={styles.copilotLabel}>Copilot</span>}
          </button>
        </Hint>
        )}
        {!isMobile && (
          <>
            {!isVisitor && <EngineStatusButton />}
            {!isVisitor && (
              <Hint
                title="Settings"
                body="Your account, appearance, AI settings, and reading preferences."
                align="end"
              >
                <button
                  className={styles.iconBtn}
                  onClick={() => {
                    // The engine light folds the settings nav away; the gear
                    // always brings it back.
                    setSettingsNavCollapsed(false);
                    navigate("/settings");
                  }}
                  aria-label="Settings"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="3" />
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                  </svg>
                </button>
              </Hint>
            )}
            <Hint
              title="Documentation"
              body="Guides for every part of IntelFeed, with a copilot that answers out of them."
              align="end"
            >
              <button
                className={styles.iconBtn}
                onClick={() => navigate("/documentation")}
                aria-label="Documentation"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 7v14" />
                  <path d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z" />
                </svg>
              </button>
            </Hint>
          </>
        )}
        {/* No keyboard, no shortcuts: the button is desktop-only. */}
        {!isMobile && (
          <Hint
            title="Keyboard shortcuts"
            body="Every shortcut for reading, triage and navigation."
            aside={<>Press <kbd>?</kbd> from anywhere.</>}
            align="end"
          >
            <button
              className={styles.shortcutsBtn}
              onClick={onShowShortcuts}
              aria-label="Keyboard shortcuts"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="2" y="4" width="20" height="16" rx="2" />
                <line x1="6" y1="8" x2="6" y2="8" />
                <line x1="10" y1="8" x2="10" y2="8" />
                <line x1="14" y1="8" x2="14" y2="8" />
                <line x1="18" y1="8" x2="18" y2="8" />
                <line x1="6" y1="12" x2="6" y2="12" />
                <line x1="10" y1="12" x2="10" y2="12" />
                <line x1="14" y1="12" x2="14" y2="12" />
                <line x1="18" y1="12" x2="18" y2="12" />
                <line x1="8" y1="16" x2="16" y2="16" />
              </svg>
            </button>
          </Hint>
        )}
        {/* Last icon in the bar, on purpose: logout is destructive and sits
            furthest from the controls people click all day. */}
        {isVisitor && (
          <button
            className={styles.signInBtn}
            onClick={() => navigate("/login", { state: { from: location.pathname + location.search } })}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
              <polyline points="10 17 15 12 10 7" />
              <line x1="15" y1="12" x2="3" y2="12" />
            </svg>
            Sign in
          </button>
        )}
        {!isMobile && !isVisitor && (
          <Hint title="Log out" body="Sign out of IntelFeed on this browser." align="end">
            <button
              className={styles.iconBtn}
              onClick={async () => {
                // Confirmed, not because logging out loses data, but because it
                // is one stray click from the shortcuts button and costs a
                // re-auth to undo.
                if (
                  !(await confirmDialog({
                    title: "Log out?",
                    message: "You'll need to sign in again to get back to your feeds.",
                    confirmLabel: "Log out",
                  }))
                )
                  return;
                const destination = logoutDestination();
                logout();
                window.location.assign(destination);
              }}
              aria-label="Logout"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                <polyline points="16 17 21 12 16 7" />
                <line x1="21" y1="12" x2="9" y2="12" />
              </svg>
            </button>
          </Hint>
        )}
      </div>
    </header>
  );
}
