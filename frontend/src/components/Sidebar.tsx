import { useState, useRef, useEffect, useLayoutEffect, useCallback, type ReactNode } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useCategories, useFeeds, useDeleteFeed, useRefreshFeed, useUpdateFeed, useCreateCategory, useUpdateCategory, useDeleteCategory, useReorderCategories } from "@/hooks/useFeeds";
import { useMarkAllRead, usePriorityQueueCount, useVirtualFolderCounts } from "@/hooks/useEntries";
import { useBulkExtract, useBulkTranslate } from "@/hooks/useIntelligence";
import { useSavedSearches, useDeleteSavedSearch, useUpdateSavedSearch } from "@/hooks/useSearch";
import { useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";
import { useOpenSavedSearch } from "@/hooks/useOpenSavedSearch";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useLongPress } from "@/hooks/useLongPress";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useSidebarCustomization } from "@/hooks/useSidebarCustomization";
import { useStaleBundle } from "@/hooks/useBuildVersion";
import { WorkbenchNav } from "./WorkbenchNav";
import { IngestModal } from "./IngestModal";
import { EditFeedModal } from "./feedModal/EditFeedModal";
import { EditCategoryModal } from "./EditCategoryModal";
import { Tooltip } from "./Tooltip";
import { Hint } from "./primitives";
import { FeedTypeIcon } from "./FeedTypeIcon";
import { deriveIntelLevel } from "./IntelLevelBadge";
import type { Category, Feed, SidebarSectionId } from "@/api/types";
import { BrandButton } from "./BrandButton";
import styles from "./Sidebar.module.css";
import { promptDialog } from "@/utils/dialog";
import { describeHealthWarning, describePauseReason } from "@/utils/feedHealth";

/** Where the footer link points. Hard-coded upstream — a fork edits one line. */
const REPO_URL = "https://github.com/a-oneil/IntelFeed";

/** Hover text for the footer's version: the commit and when it was built. */
function buildStampTitle(): string {
  const parts = [`Version ${__APP_VERSION__}`];
  if (__GIT_SHA__) parts.push(`commit ${__GIT_SHA__}`);
  if (__BUILD_TIME__) {
    const built = new Date(__BUILD_TIME__);
    if (!Number.isNaN(built.getTime())) parts.push(`built ${built.toLocaleString()}`);
  }
  if (__GIT_SHA__) parts.push("open on GitHub");
  return parts.join(" · ");
}

/** Format large counts to fit in a fixed-width badge (e.g. 13272 → "13.3k") */
function useClampedContextMenu() {
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number } | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!contextMenu) return;
    const handler = () => setContextMenu(null);
    window.addEventListener("click", handler);
    return () => window.removeEventListener("click", handler);
  }, [contextMenu]);

  useLayoutEffect(() => {
    if (!contextMenu || !menuRef.current) return;
    const rect = menuRef.current.getBoundingClientRect();
    const PAD = 8;
    let x = contextMenu.x;
    let y = contextMenu.y;
    if (rect.right > window.innerWidth - PAD) {
      x = Math.max(PAD, window.innerWidth - rect.width - PAD);
    }
    if (rect.bottom > window.innerHeight - PAD) {
      y = Math.max(PAD, window.innerHeight - rect.height - PAD);
    }
    if (x !== contextMenu.x || y !== contextMenu.y) {
      setContextMenu({ x, y });
    }
  }, [contextMenu]);

  return { contextMenu, setContextMenu, menuRef };
}

function formatCount(n: number): string {
  if (n < 10000) return String(n);
  if (n < 1000000) return (n / 1000).toFixed(n < 100000 ? 1 : 0) + "k";
  return (n / 1000000).toFixed(1) + "M";
}

/** Compact wall-clock for the "since" delta, e.g. 9:14a / 12:03p (no leading zero on hour). */
function formatClock(ts: number): string {
  const d = new Date(ts);
  const m = d.getMinutes().toString().padStart(2, "0");
  const ap = d.getHours() < 12 ? "a" : "p";
  const h12 = d.getHours() % 12 || 12;
  return `${h12}:${m}${ap}`;
}

/** Articles quick-view chips — the virtual folders, rendered in the uniform filter grid under the hero. */
const QUICK_VIEWS: { folder: "last_24h" | "this_week" | "watched" | "bookmarked" | "starred"; label: string }[] = [
  { folder: "last_24h", label: "Last 24h" },
  { folder: "this_week", label: "This Week" },
  { folder: "watched", label: "Watched" },
  { folder: "bookmarked", label: "Bookmarked" },
  { folder: "starred", label: "Starred" },
];

export function Sidebar() {
  const { data: feedsData } = useFeeds();
  const { data: categories } = useCategories();
  const navigate = useNavigate();
  const location = useLocation();
  const logout = useAuthStore((s) => s.logout);

  // Navigate to main feed view if not already there
  const goHome = useCallback(() => {
    if (location.pathname !== "/") navigate("/");
  }, [location.pathname, navigate]);
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const setSelectedCategory = useUIStore((s) => s.setSelectedCategory);
  const selectedFeedId = useUIStore((s) => s.selectedFeedId);
  const selectedCategoryId = useUIStore((s) => s.selectedCategoryId);
  const virtualFolder = useUIStore((s) => s.virtualFolder);
  const setVirtualFolder = useUIStore((s) => s.setVirtualFolder);
  const articlesSeenCount = useUIStore((s) => s.articlesSeenCount);
  const articlesSeenAt = useUIStore((s) => s.articlesSeenAt);
  const markArticlesSeen = useUIStore((s) => s.markArticlesSeen);
  const folderCounts = useVirtualFolderCounts();
  const priorityUnread = usePriorityQueueCount();

  const activePanel = useUIStore((s) => s.activePanel);
  const setActivePanel = useUIStore((s) => s.setActivePanel);
  const openSavedSearch = useOpenSavedSearch();
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed);
  // Add-feed dialog is app-level (rendered by GlobalModals) so the command
  // palette can open it and a collapsed sidebar can't hide it.
  const openAddFeed = useUIStore((s) => s.openAddFeed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const { data: savedSearches } = useSavedSearches();
  const deleteSavedSearch = useDeleteSavedSearch();
  const undoableDeleteSearch = useUndoableDelete();
  const updateSavedSearch = useUpdateSavedSearch();
  const isMobile = useIsMobile();

  const closeSidebarIfMobile = useCallback(() => {
    if (isMobile && !sidebarCollapsed) {
      toggleSidebar();
    }
  }, [isMobile, sidebarCollapsed, toggleSidebar]);

  // The sidebar shows one half of the app at a time — the feed tree, or the
  // workbench's sections. The switch at the top is the only always-visible
  // statement that this app is more than a reader.
  const sidebarMode = useUIStore((s) => s.sidebarMode);
  const setSidebarMode = useUIStore((s) => s.setSidebarMode);

  // Routes drive the mode, not just the switch: a deep link, a back button, or
  // a copilot hand-off into an entity profile must land with the workbench nav
  // already showing. setState rather than setSidebarMode — the action also
  // expands the sidebar, which would fight the detail-route auto-collapse.
  // Settings and search belong to neither half, so they leave the mode alone.
  useEffect(() => {
    const path = location.pathname;
    if (path.startsWith("/workbench")) {
      useUIStore.setState({ sidebarMode: "workbench" });
    } else if (path === "/" || path === "/priority-queue" || path === "/automation") {
      useUIStore.setState({ sidebarMode: "reading" });
    }
  }, [location.pathname]);

  // One-time nudge on the Workbench half of the switch: a small pulsing dot
  // until the user has visited Workbench once (on this browser).
  const [workbenchSeen, setWorkbenchSeen] = useState(
    () => localStorage.getItem("intelfeed-workbench-seen") === "1",
  );
  useEffect(() => {
    if (sidebarMode === "workbench" && !workbenchSeen) {
      localStorage.setItem("intelfeed-workbench-seen", "1");
      setWorkbenchSeen(true);
    }
  }, [sidebarMode, workbenchSeen]);

  const switchMode = useCallback(
    (mode: "reading" | "workbench") => {
      setSidebarMode(mode);
      const inWorkbench = location.pathname.startsWith("/workbench");
      if (mode === "workbench" && !inWorkbench) navigate("/workbench");
      if (mode === "reading" && inWorkbench) navigate("/");
    },
    [setSidebarMode, location.pathname, navigate],
  );

  const renderQuickChip = (qv: (typeof QUICK_VIEWS)[number]) => {
    const count = folderCounts[qv.folder] ?? 0;
    return (
      <button
        key={qv.folder}
        className={`${styles.quickChip} ${location.pathname === "/" && virtualFolder === qv.folder ? styles.active : ""}`}
        onClick={() => { setVirtualFolder(qv.folder); goHome(); closeSidebarIfMobile(); }}
        title={qv.label}
      >
        <span className={`${styles.quickChipCount} ${count ? "" : styles.quickChipCountZero}`}>{formatCount(count)}</span>
        <span className={styles.quickChipLabel}>{qv.label}</span>
      </button>
    );
  };

  const [showIngestModal, setShowIngestModal] = useState(false);
  const [showNewCategory, setShowNewCategory] = useState(false);
  const [newCategoryName, setNewCategoryName] = useState("");
  const [feedSearchActive, setFeedSearchActive] = useState(false);
  const [feedSearchQuery, setFeedSearchQuery] = useState("");
  const feedSearchInputRef = useRef<HTMLInputElement>(null);
  const feedsSectionCollapsed = useUIStore((s) => s.feedsSectionCollapsed);
  const setFeedsSectionCollapsed = useUIStore((s) => s.setFeedsSectionCollapsed);
  const savedSearchesSectionCollapsed = useUIStore((s) => s.savedSearchesSectionCollapsed);
  const setSavedSearchesSectionCollapsed = useUIStore((s) => s.setSavedSearchesSectionCollapsed);
  const [draggedCatId, setDraggedCatId] = useState<string | null>(null);
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string> | null>(null);
  const reorderCategories = useReorderCategories();
  const createCategory = useCreateCategory();

  // Sidebar customization
  const { sectionOrder, reorderSections } = useSidebarCustomization();
  // Only ever true for a stamped image build; see useStaleBundle.
  const { stale: bundleStale, serverVersion } = useStaleBundle();
  const [draggedSectionId, setDraggedSectionId] = useState<SidebarSectionId | null>(null);

  // Default all categories to collapsed on first load
  useEffect(() => {
    if (collapsedCategories === null && categories && categories.length > 0) {
      setCollapsedCategories(new Set(categories.map((c) => c.id)));
    }
  }, [categories, collapsedCategories]);

  const feeds = feedsData?.items || [];
  const totalUnread = feeds.reduce((sum, sub) => sub.is_muted ? sum : sum + sub.unread_count, 0);

  // Group feeds by category
  const sortByTitle = (a: Feed, b: Feed) =>
    (a.custom_title || a.title).localeCompare(b.custom_title || b.title, undefined, { sensitivity: "base" });
  // Manual Uploads is a system feed, not a subscription: it has no category by
  // design and sits above the tree as its own row rather than under an
  // "Uncategorized" label. Filing it in a category moves it into that node.
  const manualFeed = feeds.find((s) => s.feed_type === "manual" && !s.is_muted && !s.category_id) ?? null;
  const uncategorized = feeds
    .filter((s) => !s.category_id && !s.is_muted && s.id !== manualFeed?.id)
    .sort(sortByTitle);
  const categorizedFeeds = (catId: string) => feeds.filter((s) => s.category_id === catId && !s.is_muted).sort(sortByTitle);
  // Feeds "by unread": categories rank by active (non-muted) unread total, muted
  // feeds are pulled out of the tree into the bottom fold, and each header gets a
  // volume bar scaled to the busiest category.
  const categoryUnread = (catId: string) =>
    feeds.reduce((sum, s) => (s.category_id === catId && !s.is_muted ? sum + s.unread_count : sum), 0);
  const mutedFeeds = feeds.filter((s) => s.is_muted).sort(sortByTitle);

  const toggleCategory = useCallback((catId: string) => {
    setCollapsedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(catId)) {
        next.delete(catId);
      } else {
        next.add(catId);
      }
      return next;
    });
  }, []);

  const collapseAll = useCallback(() => {
    if (categories) {
      setCollapsedCategories(new Set(categories.map((c) => c.id)));
    }
  }, [categories]);

  const expandAll = useCallback(() => {
    setCollapsedCategories(new Set());
  }, []);

  const collapsed = collapsedCategories ?? new Set<string>();
  const allCollapsed = categories ? categories.length > 0 && collapsed.size >= categories.length : false;

  const handleCategoryDrop = (targetCatId: string) => {
    if (!draggedCatId || draggedCatId === targetCatId || !categories) return;
    const oldIndex = categories.findIndex((c) => c.id === draggedCatId);
    const newIndex = categories.findIndex((c) => c.id === targetCatId);
    if (oldIndex === -1 || newIndex === -1) return;

    // Build new order
    const reordered = [...categories];
    const [moved] = reordered.splice(oldIndex, 1);
    reordered.splice(newIndex, 0, moved);

    reorderCategories.mutate(
      reordered.map((cat, i) => ({ id: cat.id, position: i, parent_id: cat.parent_id }))
    );
    setDraggedCatId(null);
  };

  // Section drag-and-drop
  const handleSectionDrop = (targetId: SidebarSectionId) => {
    if (!draggedSectionId || draggedSectionId === targetId) return;
    const oldIndex = sectionOrder.indexOf(draggedSectionId);
    const newIndex = sectionOrder.indexOf(targetId);
    if (oldIndex === -1 || newIndex === -1) return;
    const reordered = [...sectionOrder];
    const [moved] = reordered.splice(oldIndex, 1);
    reordered.splice(newIndex, 0, moved);
    reorderSections(reordered);
    setDraggedSectionId(null);
  };

  // Section registry: maps section IDs to render functions
  const sectionRenderers: Record<SidebarSectionId, () => ReactNode> = {
    nav: () => (
      <div className={styles.section}>
        <>
            {(() => {
            const allItemsActive = location.pathname === "/" && !selectedFeedId && !selectedCategoryId && !virtualFolder && activePanel === "entries";
            const delta = articlesSeenAt != null && articlesSeenCount != null ? totalUnread - articlesSeenCount : 0;
            return (<>
            <button
              className={`${styles.articlesHero} ${allItemsActive ? styles.active : ""}`}
              onClick={() => { setSelectedFeed(null); setSelectedCategory(null); setVirtualFolder(null); markArticlesSeen(totalUnread); goHome(); closeSidebarIfMobile(); }}
            >
              <span className={styles.heroTop}>
                <span className={styles.heroCount}>{formatCount(totalUnread)}</span>
                {delta > 0 && articlesSeenAt != null && (
                  <span className={styles.heroDelta}>
                    <span className={styles.heroDeltaPlus}>+{formatCount(delta)}</span> since {formatClock(articlesSeenAt)}
                  </span>
                )}
              </span>
              <span className={styles.heroLabel}>Unread articles</span>
            </button>
            <div className={styles.quickGrid} role="group" aria-label="Article filters">
              {QUICK_VIEWS.map(renderQuickChip)}
              <Hint
                title="Priority Queue"
                body="The unread pile re-ordered by signal score instead of by time."
                aside="Scored on source reliability, entity heat and what you've read before."
              >
                <button
                  className={`${styles.quickChip} ${location.pathname === "/priority-queue" ? styles.active : ""}`}
                  onClick={() => { navigate("/priority-queue"); closeSidebarIfMobile(); }}
                >
                  <span className={`${styles.quickChipCount} ${priorityUnread ? "" : styles.quickChipCountZero}`}>{formatCount(priorityUnread ?? 0)}</span>
                  <span className={styles.quickChipLabel}>Priority Queue</span>
                </button>
              </Hint>
            </div>
            </>);
            })()}
            <div className={`${styles.toolStrip} ${styles.toolStripPair}`} role="group" aria-label="Tools">
              <Hint
                title="Automation"
                body="Rules that act on articles the moment they land — tag, star, summarise, add to a campaign."
                aside="A trigger, then conditions, then actions."
              >
                <button
                  className={`${styles.toolBtn} ${location.pathname === "/automation" ? styles.active : ""}`}
                  onClick={() => { navigate("/automation"); closeSidebarIfMobile(); }}
                >
                  <svg className={styles.toolIcon} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                  </svg>
                  <span className={styles.toolLabel}>Automation</span>
                </button>
              </Hint>
              <button
                className={`${styles.toolBtn} ${location.pathname === "/" && activePanel === "notes" ? styles.active : ""}`}
                onClick={() => { setActivePanel("notes"); goHome(); closeSidebarIfMobile(); }}
                title="Notes"
              >
                <svg className={styles.toolIcon} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                </svg>
                <span className={styles.toolLabel}>Notes</span>
              </button>
            </div>
        </>
      </div>
    ),

    saved_searches: () => {
      if (!savedSearches || savedSearches.length === 0) return null;
      return (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            <Hint
              title="Saved Searches"
              body="Searches you've pinned, so a filter you built once is one click away."
              aside="Run a search, then hit Save on the search bar."
            >
              <span className={styles.sectionLabel} onClick={() => setSavedSearchesSectionCollapsed(!savedSearchesSectionCollapsed)} role="button" tabIndex={0}>
                <svg
                  viewBox="0 0 10 10"
                  fill="currentColor"
                  className={savedSearchesSectionCollapsed ? styles.chevronCollapsed : styles.chevronExpanded}
                >
                  <path d="M2.5 1L7.5 5L2.5 9" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Saved Searches
              </span>
            </Hint>
          </div>
          {!savedSearchesSectionCollapsed && [...savedSearches].sort((a, b) => (a.display_name || a.name).localeCompare(b.display_name || b.name)).map((s) => (
            <div key={s.id} className={styles.savedSearchRow}>
              <button
                className={styles.navItem}
                onClick={() => { openSavedSearch(s); closeSidebarIfMobile(); }}
                onDoubleClick={async (e) => {
                  e.stopPropagation();
                  // An empty answer is meaningful here — it clears the display
                  // name back to the raw query — so it must stay submittable.
                  const newName = await promptDialog({
                    title: "Set display name",
                    message: "Set display name:",
                    defaultValue: s.display_name || s.name,
                    required: false,
                    confirmLabel: "Save",
                  });
                  if (newName !== null) {
                    updateSavedSearch.mutate({ id: s.id, data: { display_name: newName || null } });
                  }
                }}
                title={s.name}
              >
                <span className={styles.navLabel}>{s.display_name || s.name}</span>
                {(s.total_count > 0 || s.unread_count > 0) && (
                  <span className={styles.savedSearchRatio}>
                    <b>{s.unread_count}</b>/{s.total_count}
                  </span>
                )}
              </button>
              <button
                className={styles.savedSearchReportBtn}
                onClick={() => {
                  useUIStore.getState().openReportWizard({
                    sourceType: "saved_search",
                    savedSearchId: s.id,
                    savedSearchName: s.display_name || s.name,
                  });
                }}
                title="Create AI report from this saved search"
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                </svg>
              </button>
              <button
                className={styles.savedSearchDeleteBtn}
                onClick={() => undoableDeleteSearch({
                  label: `Saved search "${s.name}"`,
                  key: `saved-search-${s.id}`,
                  onDelete: () => deleteSavedSearch.mutate(s.id),
                })}
                title="Delete saved search"
              >
                &times;
              </button>
            </div>
          ))}
        </div>
      );
    },

    feeds: () => (
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <span className={styles.sectionLabel} onClick={() => setFeedsSectionCollapsed(!feedsSectionCollapsed)} role="button" tabIndex={0}>
            <svg
              viewBox="0 0 10 10"
              fill="currentColor"
              className={feedsSectionCollapsed ? styles.chevronCollapsed : styles.chevronExpanded}
            >
              <path d="M2.5 1L7.5 5L2.5 9" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Feeds
          </span>
          <div className={styles.sectionActions}>
            <button
              className={`${styles.collapseToggleBtn} ${feedSearchActive ? styles.searchActiveBtn : ""}`}
              onClick={() => {
                const next = !feedSearchActive;
                setFeedSearchActive(next);
                if (!next) setFeedSearchQuery("");
                if (next) setTimeout(() => feedSearchInputRef.current?.focus(), 0);
              }}
              title="Search feeds"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
            </button>
            <button
              className={styles.collapseToggleBtn}
              onClick={allCollapsed ? expandAll : collapseAll}
              title={allCollapsed ? "Expand all categories" : "Collapse all categories"}
            >
              {allCollapsed ? (
                <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M1 4l7 7 7-7H1z" />
                </svg>
              ) : (
                <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M1 12l7-7 7 7H1z" />
                </svg>
              )}
            </button>
            <button
              className={styles.collapseToggleBtn}
              onClick={() => setShowNewCategory((v) => !v)}
              title="New category"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                <line x1="12" y1="11" x2="12" y2="17" />
                <line x1="9" y1="14" x2="15" y2="14" />
              </svg>
            </button>
            <Hint
              title="Ingest"
              body="Drop a pile of files, paste links or text, or point at a GitHub repo. Each item becomes an entry under Manual Uploads and runs through the pipeline like any feed article."
              aside="Originals are kept and downloadable from the entry."
              align="end"
            >
              <button
                className={styles.addBtn}
                onClick={() => setShowIngestModal(true)}
                aria-label="Ingest files, URLs or text"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="17 8 12 3 7 8" />
                  <line x1="12" y1="3" x2="12" y2="15" />
                </svg>
              </button>
            </Hint>
            {/* Accent-tinted on purpose: the row's one "bring content in" primary
                action shouldn't disappear into the grey icon strip. */}
            <button className={styles.newFeedBtn} onClick={openAddFeed} title="Add feed">+</button>
          </div>
        </div>

        {feedSearchActive && !feedsSectionCollapsed && (
          <div className={styles.feedSearchRow}>
            <input
              ref={feedSearchInputRef}
              type="text"
              value={feedSearchQuery}
              onChange={(e) => setFeedSearchQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  setFeedSearchQuery("");
                  setFeedSearchActive(false);
                }
              }}
              placeholder="Filter feeds..."
              className={styles.feedSearchInput}
              autoFocus
            />
            {feedSearchQuery && (
              <button
                className={styles.feedSearchClear}
                onClick={() => { setFeedSearchQuery(""); feedSearchInputRef.current?.focus(); }}
                title="Clear search"
              >
                &times;
              </button>
            )}
          </div>
        )}

        {!feedsSectionCollapsed && feedSearchQuery.trim() && feedSearchActive ? (
          <div className={styles.feedSearchResults}>
            {(() => {
              const filtered = feeds
                .filter((sub) => {
                  const q = feedSearchQuery.toLowerCase();
                  const title = (sub.custom_title || sub.title).toLowerCase();
                  const url = (sub.url || "").toLowerCase();
                  return title.includes(q) || url.includes(q);
                })
                .sort(sortByTitle);
              return filtered.length > 0 ? (
                filtered.map((sub) => (
                  <FeedItem
                    key={sub.id}
                    subscription={sub}
                    categories={categories || []}
                    isSelected={location.pathname === "/" && selectedFeedId === sub.id}
                    onSelect={() => { setSelectedFeed(sub.id); goHome(); closeSidebarIfMobile(); }}
                    categoryLabel={categories?.find((c) => c.id === sub.category_id)?.name}
                  />
                ))
              ) : (
                <div className={styles.feedSearchEmpty}>No feeds found</div>
              );
            })()}
          </div>
        ) : !feedsSectionCollapsed ? (
          <>
            {showNewCategory && (
              <div className={styles.newCategoryRow}>
                <input
                  type="text"
                  value={newCategoryName}
                  onChange={(e) => setNewCategoryName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && newCategoryName.trim()) {
                      createCategory.mutate({ name: newCategoryName.trim() });
                      setNewCategoryName("");
                      setShowNewCategory(false);
                    }
                    if (e.key === "Escape") {
                      setNewCategoryName("");
                      setShowNewCategory(false);
                    }
                  }}
                  placeholder="Category name..."
                  className={styles.newCategoryInput}
                  autoFocus
                />
                <button
                  className={styles.newCategoryCancelBtn}
                  onClick={() => { setNewCategoryName(""); setShowNewCategory(false); }}
                >
                  Cancel
                </button>
              </div>
            )}

            {manualFeed && (
              <div className={styles.pinnedFeed} data-testid="manual-uploads-row">
                <FeedItem
                  subscription={manualFeed}
                  categories={categories || []}
                  isSelected={location.pathname === "/" && selectedFeedId === manualFeed.id}
                  onSelect={() => { setSelectedFeed(manualFeed.id); goHome(); closeSidebarIfMobile(); }}
                />
              </div>
            )}

            {categories?.slice().sort((a, b) =>
              categoryUnread(b.id) - categoryUnread(a.id) ||
              a.name.localeCompare(b.name, undefined, { sensitivity: "base" })
            ).map((cat) => (
              <CategoryNode
                key={cat.id}
                category={cat}
                feeds={categorizedFeeds(cat.id)}
                categories={categories}
                selectedFeedId={selectedFeedId}
                selectedCategoryId={selectedCategoryId}
                isOnHomePage={location.pathname === "/"}
                onSelectCategory={(id) => { setSelectedCategory(id); goHome(); closeSidebarIfMobile(); }}
                onSelectFeed={(id) => { setSelectedFeed(id); goHome(); closeSidebarIfMobile(); }}
                onDragStart={() => setDraggedCatId(cat.id)}
                onDrop={() => handleCategoryDrop(cat.id)}
                isDragging={draggedCatId === cat.id}
                isCollapsed={collapsedCategories === null || collapsed.has(cat.id)}
                onToggleCollapse={() => toggleCategory(cat.id)}
              />
            ))}

            {uncategorized.length > 0 && (
              <div className={styles.uncategorizedSection}>
                {categories && categories.length > 0 && (
                  <div className={styles.uncategorizedLabel}>Uncategorized</div>
                )}
                {uncategorized.map((sub) => (
                  <FeedItem
                    key={sub.id}
                    subscription={sub}
                    categories={categories || []}
                    isSelected={location.pathname === "/" && selectedFeedId === sub.id}
                    onSelect={() => { setSelectedFeed(sub.id); goHome(); closeSidebarIfMobile(); }}
                  />
                ))}
              </div>
            )}

            {mutedFeeds.length > 0 && (
              <MutedFeedsFold
                feeds={mutedFeeds}
                categories={categories || []}
                selectedFeedId={selectedFeedId}
                isOnHomePage={location.pathname === "/"}
                onSelectFeed={(id) => { setSelectedFeed(id); goHome(); closeSidebarIfMobile(); }}
              />
            )}
          </>
        ) : null}
      </div>
    ),
  };

  return (
    <nav className={styles.sidebar} aria-label="Feed navigation">
      {/* Brand + user actions */}
      <div className={styles.brandSection}>
        <BrandButton className={styles.brandName} />
        <div className={styles.userActions}>
          {/* The header's Settings and Documentation buttons are desktop-only —
              on a phone the header is a hamburger and a search box, so this row
              is the only way to either. Docs was missing from it entirely. */}
          <button onClick={() => { navigate("/documentation"); closeSidebarIfMobile(); }} className={styles.iconBtn} title="Documentation">
            Docs
          </button>
          <button onClick={() => { navigate("/settings"); closeSidebarIfMobile(); }} className={styles.iconBtn} title="Settings">
            Settings
          </button>
          <button onClick={() => { logout(); window.location.assign("/login"); }} className={styles.iconBtn} title="Logout">
            Logout
          </button>
        </div>
      </div>

      {/* The app has two halves. Say so, before anything else in the column. */}
      <div className={styles.modeSwitch} role="group" aria-label="Workspace mode">
        <div className={styles.modeCell}>
          <button
            className={`${styles.modeBtn} ${sidebarMode === "reading" ? styles.modeBtnActive : ""}`}
            aria-pressed={sidebarMode === "reading"}
            aria-describedby="mode-hint-reading"
            onClick={() => switchMode("reading")}
          >
            <svg className={styles.modeIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="22 12 16 12 14 15 10 15 8 12 2 12" />
              <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
            </svg>
            Reading
          </button>
          <div className={styles.modeHint} role="tooltip" id="mode-hint-reading">
            <strong>Reading</strong>
            <span>Triage the news: your feeds, filters, saved searches and the priority queue.</span>
          </div>
        </div>
        <div className={styles.modeCell}>
          <button
            className={`${styles.modeBtn} ${sidebarMode === "workbench" ? styles.modeBtnActive : ""} ${workbenchSeen ? "" : styles.modeBtnNudge}`}
            aria-pressed={sidebarMode === "workbench"}
            aria-describedby="mode-hint-workbench"
            onClick={() => switchMode("workbench")}
          >
            <svg className={styles.modeIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            Workbench
          </button>
          <div className={styles.modeHint} role="tooltip" id="mode-hint-workbench">
            <strong>Workbench</strong>
            <span>Investigate what you&rsquo;ve read: threat dossiers, CVEs, ATT&amp;CK coverage and your detection rule library.</span>
            <em>Intelligence extracted while reading lands here.</em>
          </div>
        </div>
      </div>

      {sidebarMode === "workbench" && <WorkbenchNav onNavigate={closeSidebarIfMobile} />}

      {/* Dynamic sections rendered in user-defined order */}
      {sidebarMode === "reading" && sectionOrder.map((sectionId) => {
        const render = sectionRenderers[sectionId];
        if (!render) return null;
        const content = render();
        if (!content) return null;
        return (
          <SectionDragWrapper
            key={sectionId}
            sectionId={sectionId}
            isDragging={draggedSectionId === sectionId}
            onDragStart={() => setDraggedSectionId(sectionId)}
            onDrop={() => handleSectionDrop(sectionId)}
            onDragEnd={() => setDraggedSectionId(null)}
          >
            {content}
          </SectionDragWrapper>
        );
      })}

      {/* The one path back to the source. Chrome rather than navigation, so it
          stays muted until hovered and sits under both modes' sections. */}
      <div className={styles.sidebarFooter}>
        <a
          className={styles.repoLink}
          href={REPO_URL}
          target="_blank"
          rel="noopener noreferrer"
          aria-label="IntelFeed on GitHub"
          title="IntelFeed on GitHub"
        >
          <svg className={styles.repoIcon} width="15" height="15" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 4 0c1.53-1.03 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.74.54 1.49 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
          </svg>
          <span className={styles.repoLabel}>GitHub</span>
        </a>
        {bundleStale && (
          <button
            type="button"
            className={styles.stale}
            onClick={() => window.location.reload()}
            title={`This tab is running ${__APP_VERSION__}; the server is on ${serverVersion}. Reload to catch up.`}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M21 12a9 9 0 1 1-2.64-6.36" />
              <polyline points="21 3 21 9 15 9" />
            </svg>
            Reload
          </button>
        )}

        {/* What is actually running. A bare short SHA until the repo carries
            tags, a tag after — see scripts/ops/version.sh. Links to the commit
            itself, which beats searching main's history for a SHA that is
            sitting on a branch. Falls back to plain text in an unstamped build,
            where there is no commit to point at. */}
        {__GIT_SHA__ ? (
          <a
            className={styles.version}
            href={`${REPO_URL}/commit/${__GIT_SHA__}`}
            target="_blank"
            rel="noopener noreferrer"
            title={buildStampTitle()}
          >
            {__APP_VERSION__}
          </a>
        ) : (
          <span className={styles.version} title={buildStampTitle()}>
            {__APP_VERSION__}
          </span>
        )}
      </div>

      {showIngestModal && <IngestModal onClose={() => setShowIngestModal(false)} />}
    </nav>
  );
}

/* ===== Section drag wrapper ===== */

function SectionDragWrapper({
  sectionId,
  isDragging,
  onDragStart,
  onDrop,
  onDragEnd,
  children,
}: {
  sectionId: SidebarSectionId;
  isDragging: boolean;
  onDragStart: () => void;
  onDrop: () => void;
  onDragEnd: () => void;
  children: ReactNode;
}) {
  const [dragOver, setDragOver] = useState(false);

  return (
    <div
      className={`${styles.draggableSection} ${isDragging ? styles.dragging : ""} ${dragOver ? styles.dragOver : ""}`}
      draggable
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = "move";
        e.dataTransfer.setData("text/x-sidebar-section", sectionId);
        onDragStart();
      }}
      onDragOver={(e) => {
        if (e.dataTransfer.types.includes("text/x-sidebar-section")) {
          e.preventDefault();
          setDragOver(true);
        }
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        if (e.dataTransfer.types.includes("text/x-sidebar-section")) {
          e.preventDefault();
          setDragOver(false);
          onDrop();
        }
      }}
      onDragEnd={onDragEnd}
    >
      {children}
    </div>
  );
}

/* ===== Category node ===== */

function CategoryNode({
  category,
  feeds,
  categories,
  selectedFeedId,
  selectedCategoryId,
  isOnHomePage,
  onSelectCategory,
  onSelectFeed,
  onDragStart,
  onDrop,
  isDragging,
  isCollapsed,
  onToggleCollapse,
}: {
  category: Category;
  feeds: Feed[];
  categories: Category[];
  selectedFeedId: string | null;
  selectedCategoryId: string | null;
  isOnHomePage: boolean;
  onSelectCategory: (id: string) => void;
  onSelectFeed: (id: string) => void;
  onDragStart: () => void;
  onDrop: () => void;
  isDragging: boolean;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}) {
  const [dragOver, setDragOver] = useState(false);
  const { contextMenu, setContextMenu, menuRef } = useClampedContextMenu();
  const [isRenaming, setIsRenaming] = useState(false);
  const [renameValue, setRenameValue] = useState(category.name);
  const markAllRead = useMarkAllRead();
  const updateCategory = useUpdateCategory();
  const deleteCategory = useDeleteCategory();
  const undoableDelete = useUndoableDelete();
  const bulkExtract = useBulkExtract();
  const [editModal, setEditModal] = useState(false);
  // Category bulk-edit and delete are admin-only endpoints; rename stays open.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const totalUnread = feeds.reduce((sum, s) => s.is_muted ? sum : sum + s.unread_count, 0);

  const longPressHandlers = useLongPress({
    onLongPress: (pos) => setContextMenu(pos),
    onContextMenu: (e) => {
      e.preventDefault();
      setContextMenu({ x: e.clientX, y: e.clientY });
    },
  });

  const tooltipContent = (() => {
    const lines: string[] = [];
    lines.push(`${feeds.length} feed${feeds.length !== 1 ? "s" : ""}`);
    if (totalUnread > 0) lines.push(`${totalUnread} unread`);
    const mutedCount = feeds.filter((s) => s.is_muted).length;
    if (mutedCount > 0) lines.push(`${mutedCount} muted`);
    const errorCount = feeds.filter((s) => s.error_count > 0).length;
    if (errorCount > 0) lines.push(`${errorCount} feed${errorCount !== 1 ? "s" : ""} erroring`);
    // Feed type breakdown
    const types: Record<string, number> = {};
    feeds.forEach((s) => {
      const t = s.feed_type || "rss";
      types[t] = (types[t] || 0) + 1;
    });
    if (Object.keys(types).length > 1) {
      lines.push(Object.entries(types).map(([t, n]) => `${n} ${t.toUpperCase()}`).join(", "));
    }
    // Last fetched
    const fetchTimes = feeds
      .map((s) => s.last_fetched_at)
      .filter(Boolean) as string[];
    if (fetchTimes.length > 0) {
      const latest = new Date(fetchTimes.sort().reverse()[0]);
      const ago = Math.round((Date.now() - latest.getTime()) / 60000);
      if (ago < 1) lines.push("Fetched just now");
      else if (ago < 60) lines.push(`Fetched ${ago}m ago`);
      else if (ago < 1440) lines.push(`Fetched ${Math.round(ago / 60)}h ago`);
      else lines.push(`Fetched ${Math.round(ago / 1440)}d ago`);
    }
    return lines;
  })();

  return (
    <div
      className={`${styles.category} ${isDragging ? styles.dragging : ""} ${dragOver ? styles.dragOver : ""}`}
      draggable
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = "move";
        onDragStart();
      }}
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragOver(false);
        onDrop();
      }}
    >
      <button
        className={`${styles.categoryHeader} ${isOnHomePage && selectedCategoryId === category.id ? styles.active : ""}`}
        onClick={() => onSelectCategory(category.id)}
        {...longPressHandlers}
      >
        <span
          className={styles.expandIcon}
          onClick={(e) => { e.stopPropagation(); onToggleCollapse(); }}
          role="button"
          tabIndex={-1}
        >
          <svg
            width="10"
            height="10"
            viewBox="0 0 10 10"
            fill="currentColor"
            className={isCollapsed ? styles.chevronCollapsed : styles.chevronExpanded}
          >
            <path d="M2.5 1L7.5 5L2.5 9" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </span>
        {isRenaming ? (
          <input
            type="text"
            value={renameValue}
            onChange={(e) => setRenameValue(e.target.value)}
            onKeyDown={(e) => {
              e.stopPropagation();
              if (e.key === "Enter" && renameValue.trim()) {
                updateCategory.mutate({ categoryId: category.id, data: { name: renameValue.trim() } });
                setIsRenaming(false);
              }
              if (e.key === "Escape") {
                setRenameValue(category.name);
                setIsRenaming(false);
              }
            }}
            onBlur={() => {
              if (renameValue.trim() && renameValue.trim() !== category.name) {
                updateCategory.mutate({ categoryId: category.id, data: { name: renameValue.trim() } });
              }
              setIsRenaming(false);
            }}
            onClick={(e) => e.stopPropagation()}
            className={styles.renameInput}
            autoFocus
          />
        ) : (
          <Tooltip
            content={
              <div className={styles.categoryTooltipContent}>
                {tooltipContent.map((line, i) => (
                  <div key={i}>{line}</div>
                ))}
              </div>
            }
            position="bottom"
            className={styles.categoryTooltip}
          >
            <span className={styles.categoryName}>{category.name}</span>
          </Tooltip>
        )}
        {totalUnread > 0 && (
          <span className={styles.categoryCount}>{formatCount(totalUnread)}</span>
        )}

      </button>

      {contextMenu && (
        <div
          ref={menuRef}
          className={styles.contextMenu}
          style={{ top: contextMenu.y, left: contextMenu.x }}
        >
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              markAllRead.mutate({ category_id: category.id });
              setContextMenu(null);
            }}
          >
            Mark All Read
          </button>
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              onToggleCollapse();
              setContextMenu(null);
            }}
          >
            {isCollapsed ? "Expand" : "Collapse"}
          </button>
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              bulkExtract.mutate({
                category_id: category.id,
                extract_types: ["ttps", "cves", "threat_actors", "malware", "sectors", "article_metadata", "detection_rules"],
                use_ai: true,
              });
              setContextMenu(null);
            }}
            disabled={bulkExtract.isPending || feeds.length === 0}
          >
            {bulkExtract.isPending ? "Extracting..." : `Extract Intelligence (${feeds.length} feeds)`}
          </button>
          <div className={styles.contextMenuDivider} />
          {isAdmin && (
            <button
              className={styles.contextMenuItem}
              onClick={() => {
                setEditModal(true);
                setContextMenu(null);
              }}
            >
              Edit Category...
            </button>
          )}
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              setIsRenaming(true);
              setRenameValue(category.name);
              setContextMenu(null);
            }}
          >
            Rename...
          </button>
          {isAdmin && (
            <button
              className={`${styles.contextMenuItem} ${styles.contextMenuDanger}`}
              onClick={() => {
                setContextMenu(null);
                undoableDelete({
                  label: `Category "${category.name}"`,
                  key: `category-${category.id}`,
                  onDelete: () => deleteCategory.mutate(category.id),
                });
              }}
            >
              Delete Category
            </button>
          )}
        </div>
      )}

      {!isCollapsed && (
        <div className={styles.categoryFeeds}>
          {feeds.map((sub) => (
            <FeedItem
              key={sub.id}
              subscription={sub}
              categories={categories}
              isSelected={isOnHomePage && selectedFeedId === sub.id}
              onSelect={() => onSelectFeed(sub.id)}
            />
          ))}
        </div>
      )}

      {editModal && (
        <EditCategoryModal
          category={category}
          feeds={feeds}
          onClose={() => setEditModal(false)}
        />
      )}
    </div>
  );
}

/* ===== Feed item ===== */

function FeedItem({
  subscription,
  categories,
  isSelected,
  onSelect,
  categoryLabel,
}: {
  subscription: Feed;
  categories: Category[];
  isSelected: boolean;
  onSelect: () => void;
  categoryLabel?: string;
}) {
  const { contextMenu, setContextMenu, menuRef } = useClampedContextMenu();
  const [editModal, setEditModal] = useState(false);
  // With per-user subscriptions on (feed.per_user), unsubscribing only affects
  // the caller. Otherwise removal deletes the feed for everyone — admin-only.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const canUnsubscribe = isAdmin || Boolean(subscription.per_user);
  const deleteFeed = useDeleteFeed();
  const refreshFeed = useRefreshFeed();
  const updateFeed = useUpdateFeed();
  const markAllRead = useMarkAllRead();
  const bulkExtract = useBulkExtract();
  const bulkTranslate = useBulkTranslate();

  const feedLongPressHandlers = useLongPress({
    onLongPress: (pos) => setContextMenu(pos),
    onContextMenu: (e) => {
      e.preventDefault();
      setContextMenu({ x: e.clientX, y: e.clientY });
    },
  });

  const title = subscription.custom_title || subscription.title;
  const feedType = subscription.feed_type?.toLowerCase() || "rss";
  // The Manual Uploads pseudo-feed is created inactive so the poller skips it;
  // that is its nature, not a pause, so it gets neither the dimming nor the badge.
  const isManual = feedType === "manual";
  const isPaused = !subscription.is_active && !isManual;

  const tooltipContent = (() => {
    const lines: string[] = [];
    lines.push(title);
    if (subscription.unread_count > 0) {
      lines.push(`${subscription.unread_count} unread`);
    }
    lines.push(`${feedType.toUpperCase()} feed`);
    if (isManual) {
      lines.push("Files, links and pasted text you ingest by hand");
    } else if (subscription.last_fetched_at) {
      const ago = Math.round((Date.now() - new Date(subscription.last_fetched_at).getTime()) / 60000);
      if (ago < 1) lines.push("Fetched just now");
      else if (ago < 60) lines.push(`Fetched ${ago}m ago`);
      else if (ago < 1440) lines.push(`Fetched ${Math.round(ago / 60)}h ago`);
      else lines.push(`Fetched ${Math.round(ago / 1440)}d ago`);
    } else {
      lines.push("Never fetched");
    }
    if (subscription.fetch_interval_minutes && !isManual) {
      const m = subscription.fetch_interval_minutes;
      lines.push(`Every ${m < 60 ? `${m}m` : m % 60 === 0 ? `${m / 60}h` : `${Math.round((m / 60) * 10) / 10}h`}`);
    }
    if (subscription.language) lines.push(`Language: ${subscription.language}`);
    if (isPaused) {
      lines.push(subscription.pause_reason ? describePauseReason(subscription.pause_reason) : "Paused");
    } else if (subscription.health_warning && !isManual) {
      lines.push(describeHealthWarning(subscription.health_warning));
    }
    if (subscription.is_muted) lines.push("Muted");
    if (subscription.error_count > 0) {
      lines.push(`${subscription.error_count} recent error${subscription.error_count !== 1 ? "s" : ""}`);
      if (subscription.last_error) lines.push(subscription.last_error);
    }
    return lines;
  })();

  return (
    <>
      <button
        className={`${styles.feedItem} ${isSelected ? styles.active : ""} ${subscription.is_muted ? styles.muted : ""} ${isPaused ? styles.paused : ""}`}
        onClick={onSelect}
        {...feedLongPressHandlers}
      >
        {(() => {
          const { fill, label } = deriveIntelLevel({
            mode: subscription.intel_extraction_mode || "selective",
            aiAnalysis: subscription.ai_analysis_enabled ?? true,
            autoExtract: subscription.auto_extract_on_ingest ?? false,
          });
          if (fill < 0) return null;
          return (
            <span
              className={`${styles.levelRail} ${fill === 1 ? styles.levelRailFull : ""} ${fill === 0 ? styles.levelRailEmpty : ""}`}
              title={label}
              aria-label={label}
            >
              {fill > 0 && <span className={styles.levelRailFill} style={{ height: `${fill * 100}%` }} />}
            </span>
          );
        })()}
        <FeedTypeIcon type={feedType} />
        <Tooltip
          content={
            <div className={styles.categoryTooltipContent}>
              {tooltipContent.map((line, i) => (
                <div key={i}>{line}</div>
              ))}
            </div>
          }
          position="bottom"
          className={styles.feedTitleTooltip}
        >
          <span className={styles.feedTitle}>{title}</span>
        </Tooltip>
        {categoryLabel && <span className={styles.feedSearchCategory}>{categoryLabel}</span>}
        {isPaused && <span className={styles.pausedBadge}>||</span>}
        {subscription.error_count > 0 && <span className={styles.errorBadge}>!</span>}
        {subscription.unread_count > 0 && (
          <span className={styles.feedCount}>{formatCount(subscription.unread_count)}</span>
        )}
      </button>
      {contextMenu && (
        <div
          ref={menuRef}
          className={styles.contextMenu}
          style={{ top: contextMenu.y, left: contextMenu.x }}
        >
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              setEditModal(true);
              setContextMenu(null);
            }}
          >
            Edit Feed...
          </button>
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              markAllRead.mutate({ feed_id: subscription.id });
              setContextMenu(null);
            }}
          >
            Mark All Read
          </button>
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              refreshFeed.mutate(subscription.id);
              setContextMenu(null);
            }}
          >
            Refresh
          </button>
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              updateFeed.mutate({
                feedId: subscription.id,
                data: { is_muted: !subscription.is_muted },
              });
              setContextMenu(null);
            }}
          >
            {subscription.is_muted ? "Unmute" : "Mute"}
          </button>
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              bulkExtract.mutate({ feed_id: subscription.id, extract_types: ["ttps", "cves", "threat_actors", "malware", "sectors", "article_metadata", "detection_rules"], use_ai: true });
              setContextMenu(null);
            }}
            disabled={bulkExtract.isPending}
          >
            {bulkExtract.isPending ? "Extracting..." : "Extract Intelligence"}
          </button>
          <button
            className={styles.contextMenuItem}
            onClick={() => {
              bulkTranslate.mutate({ feed_id: subscription.id });
              setContextMenu(null);
            }}
            disabled={bulkTranslate.isPending}
          >
            {bulkTranslate.isPending ? "Translating..." : "Translate Articles"}
          </button>

          {/* Move to category submenu */}
          {categories.length > 0 && (
            <>
              <div className={styles.contextMenuDivider} />
              <div className={styles.contextMenuLabel}>Move to...</div>
              {subscription.category_id && (
                <button
                  className={styles.contextMenuItem}
                  onClick={() => {
                    updateFeed.mutate({ feedId: subscription.id, data: { category_id: null } });
                    setContextMenu(null);
                  }}
                >
                  Uncategorized
                </button>
              )}
              {categories
                .filter((c) => c.id !== subscription.category_id)
                .map((cat) => (
                  <button
                    key={cat.id}
                    className={styles.contextMenuItem}
                    onClick={() => {
                      updateFeed.mutate({ feedId: subscription.id, data: { category_id: cat.id } });
                      setContextMenu(null);
                    }}
                  >
                    {cat.name}
                  </button>
                ))}
            </>
          )}

          {canUnsubscribe && (
            <>
              <div className={styles.contextMenuDivider} />
              <button
                className={`${styles.contextMenuItem} ${styles.contextMenuDanger}`}
                onClick={() => {
                  setContextMenu(null);
                  deleteFeed.mutate(subscription.id);
                }}
              >
                Unsubscribe
              </button>
            </>
          )}
        </div>
      )}
      {editModal && (
        <EditFeedModal subscription={subscription} onClose={() => setEditModal(false)} />
      )}
    </>
  );
}

/* ===== Muted feeds fold ===== */

function MutedFeedsFold({
  feeds,
  categories,
  selectedFeedId,
  isOnHomePage,
  onSelectFeed,
}: {
  feeds: Feed[];
  categories: Category[];
  selectedFeedId: string | null;
  isOnHomePage: boolean;
  onSelectFeed: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={styles.uncategorizedSection}>
      <button className={styles.mutedFoldHeader} onClick={() => setExpanded((v) => !v)}>
        <svg
          viewBox="0 0 10 10"
          fill="currentColor"
          className={expanded ? styles.chevronExpanded : styles.chevronCollapsed}
        >
          <path d="M2.5 1L7.5 5L2.5 9" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        Muted <span className={styles.mutedFoldCount}>· {feeds.length} feeds</span>
      </button>
      {expanded && (
        <div className={styles.mutedFoldFeeds}>
          {feeds.map((sub) => (
            <FeedItem
              key={sub.id}
              subscription={sub}
              categories={categories}
              isSelected={isOnHomePage && selectedFeedId === sub.id}
              onSelect={() => onSelectFeed(sub.id)}
              categoryLabel={categories.find((c) => c.id === sub.category_id)?.name}
            />
          ))}
        </div>
      )}
    </div>
  );
}
