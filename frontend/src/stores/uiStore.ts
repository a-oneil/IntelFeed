import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { SavedSearch } from "@/api/types";
import type { TableLayoutMap } from "@/types/tableLayout";
import { adjacentEntryId } from "@/utils/entryNavigation";

/**
 * One turn of the documentation-page copilot thread. Kept in the store rather
 * than in the component so leaving `/documentation` and coming back resumes the
 * conversation instead of restarting it.
 */
export interface DocsChatMessage {
  role: "user" | "assistant";
  content: string;
  traces?: {
    id: string;
    name: string;
    args: Record<string, unknown>;
    status: "pending" | "success" | "error";
    summary?: string;
  }[];
}

export interface DocsChatState {
  conversationId: string | null;
  messages: DocsChatMessage[];
  /**
   * Slug of the last documentation page read this session. The chat lives on
   * the landing page, so by the time you come back to ask about a page you have
   * already navigated off it — this is what keeps "how do I do that?" answerable.
   */
  lastDocSlug?: string | null;
  /**
   * A turn is mid-flight. Deliberately NOT persisted: on reload the stream is
   * gone, and a `true` restored from localStorage would lock the composer
   * forever. Rehydration drops it, which reads as false.
   */
  streaming?: boolean;
}

/** Transient payload to open the global copilot pre-scoped from anywhere. */
export interface CopilotSeed {
  /** Optional starter question to auto-send when the copilot opens. */
  prompt?: string;
  /** Ambient context to pin for the seeded thread (entity/campaign/entry). */
  context?: {
    entry_id?: string;
    /** Multi-article pinning (bulk selection). entry_id wins if both set. */
    entry_ids?: string[];
    entity_type?: string;
    entity_id?: string;
    campaign_id?: string;
    search_query?: string;
    route?: string;
    /** Human-readable name for the pinned entity/entry/campaign, for display. */
    label?: string;
  } | null;
  /** When true, the copilot pins this context and ignores route-derived context. */
  lockContext?: boolean;
}

// Mobile viewport keeps the sidebar as an overlay drawer — auto-restoring it
// after a reader closes (desktop behavior) clobbers manual/swipe dismissals.
const isMobileViewport = () =>
  typeof window !== "undefined" && window.matchMedia("(max-width: 767px)").matches;

export interface ReportWizardState {
  isOpen: boolean;
  sourceType: "entry" | "entries" | "search" | "saved_search";
  entryId?: string;
  entryIds?: string[];
  searchQuery?: string;
  savedSearchId?: string;
  entryTitle?: string;
  savedSearchName?: string;
  searchResultCount?: number;
  /** Preselect this template in the wizard (recipe cards pass it). */
  templateType?: string;
}

/** Context carried by the send-to-report gesture: evidence to attach to a
 *  draft, plus an optional wizard seed for the "start new" path. */
export interface SendToReportPayload {
  entryIds?: string[];
  entityIds?: Record<string, string[]>;
  wizardState?: Omit<ReportWizardState, "isOpen">;
  label?: string;
  /** Sender's commentary, seeding the detections section body — a coverage
      set's skipped rules read as known gaps. Never overwrites analyst prose. */
  note?: string;
}

export interface SendToReportState {
  isOpen: boolean;
  payload: SendToReportPayload;
}

/**
 * Per-table layout + filter state for the shared DataTable. Keyed by a stable
 * table id ("entries", "entity:threat_actor", …) so every table remembers its
 * own columns, widths, order, filters and sort independently.
 */
export interface TableLayout {
  /** Explicit visibility overrides; columns the user never touched follow the
   *  column definition's default, so newly shipped columns get sane defaults. */
  columnVisibility: Record<string, boolean>;
  columnWidths: Record<string, number>;
  /** User-arranged order (select column excluded — it stays pinned first).
   *  Empty = default order; unlisted columns keep their default position. */
  columnOrder: string[];
  textFilters: Record<string, string>;
  hasFilters: Record<string, boolean>;
  /** Per-column dropdown filters (entry State, malware type, CVE severity, …). */
  choiceFilters: Record<string, string>;
  clientSort: { key: string; dir: "asc" | "desc" } | null;
  /** Epoch ms of the last column visibility/width/order edit. Only the layout
   *  fields sync to the user profile, and this is the tiebreaker deciding which
   *  device's arrangement wins — see useTableLayoutSync. */
  layoutUpdatedAt: number;
}

export const EMPTY_TABLE_LAYOUT: TableLayout = {
  columnVisibility: {},
  columnWidths: {},
  columnOrder: [],
  textFilters: {},
  hasFilters: {},
  choiceFilters: {},
  clientSort: null,
  layoutUpdatedAt: 0,
};

/** Immutably merge a partial layout into one table's slot. */
const patchTable = (
  tables: Record<string, TableLayout>,
  tableId: string,
  patch: Partial<TableLayout>
) => ({
  tables: { ...tables, [tableId]: { ...EMPTY_TABLE_LAYOUT, ...tables[tableId], ...patch } },
});

export type ViewMode = "compact" | "expanded" | "magazine" | "table";
export type SortOrder = "newest" | "oldest" | "title_asc" | "title_desc" | "shortest" | "longest" | "radar";
type VirtualFolder = "starred" | "bookmarked" | "watched" | "today" | "last_24h" | "this_week" | null;
type ActivePanel = "entries" | "notes";

/**
 * How wide the search page is looking.
 *
 * This is the `in:` chip in the header field, lifted into the store because two
 * components read it: the chip itself, and the /search page that decides which
 * halves of the result set to render. The entity half is named after the
 * surface that owns entities — the workbench — so the chip matches the nav.
 */
export type SearchScope = "feeds" | "workbench" | "everything";
type ReaderPanel = "intel" | "ai" | "notes" | "tag" | "create_entity" | "add_alias" | "link_entity" | null;

/** "piper" = server-generated natural voice (consistent across devices);
 *  "browser" = the OS Web Speech voice (instant, offline, word-highlighting). */
export type ReadAloudEngine = "piper" | "browser";

export type ReaderFontSize = 13 | 14 | 15 | 16 | 18 | 20;
export type ReaderLineHeight = 1.4 | 1.6 | 1.7 | 1.8 | 2.0;
export type ReaderMaxWidth = 600 | 720 | 860 | 1000 | 0; // 0 = unlimited

/**
 * Which half of the app the sidebar is showing.
 *
 * IntelFeed is a reader *and* an intelligence workbench, but the sidebar only
 * ever described the reader — the workbench hid behind a 14px icon in the tool
 * strip, and users reported the app as "just an RSS reader". The sidebar now
 * declares both halves up top and swaps its body between them.
 */
export type SidebarMode = "reading" | "workbench";

interface UIState {
  sidebarCollapsed: boolean;
  sidebarWidth: number;
  sidebarMode: SidebarMode;
  setSidebarMode: (mode: SidebarMode) => void;
  viewMode: ViewMode;
  sortOrder: SortOrder;
  // DataTable layout + filter state, namespaced per table id. Persisted so the
  // columns, widths, order, filters and sort a user set up survive route
  // navigation and reloads: click around and you return to the view you left.
  tables: Record<string, TableLayout>;
  setTableColumnVisible: (tableId: string, key: string, visible: boolean) => void;
  setTableColumnWidth: (tableId: string, key: string, width: number) => void;
  setTableColumnOrder: (tableId: string, order: string[]) => void;
  resetTableLayout: (tableId: string) => void;
  /** Adopt server-side layouts for tables whose stored arrangement is newer
   *  (or that this device has never touched). Filters/sort are left alone. */
  applyRemoteTableLayouts: (remote: TableLayoutMap) => void;
  /** Whose layouts the `tables` map currently holds. Null on a browser that
   *  hasn't synced yet; a mismatch means someone else logged in here. */
  tablesOwnerId: string | null;
  /** Hand the tables over to a different user: their server layouts replace
   *  what the previous account left behind, filters and all. */
  takeOverTableLayouts: (userId: string, remote: TableLayoutMap) => void;
  setTableTextFilter: (tableId: string, key: string, value: string) => void;
  setTableHasFilter: (tableId: string, key: string, value: boolean) => void;
  setTableChoiceFilter: (tableId: string, key: string, value: string) => void;
  setTableClientSort: (tableId: string, sort: { key: string; dir: "asc" | "desc" } | null) => void;
  clearTableFilters: (tableId: string) => void;
  readerOpen: boolean;
  selectedEntryId: string | null;
  /** Slug of the story thread open in the reader pane, if any. */
  selectedThreadSlug: string | null;
  /**
   * Threads cleared this session, by id. Session-only (never persisted) so a
   * dismissed thread stays gone across refetches but comes back tomorrow if
   * the story is still running. Shared state because a thread can be cleared
   * from its row in the queue or from the reader's top bar.
   */
  dismissedThreadIds: string[];
  selectedFeedId: string | null;
  selectedCategoryId: string | null;
  virtualFolder: VirtualFolder;
  showUnreadOnly: boolean;
  // Priority Queue's own Hide Read preference, kept separate from the main feed's
  // showUnreadOnly so the queue can default to hiding read entries without
  // clobbering (or being clobbered by) the reader's setting. Defaults on.
  priorityShowUnreadOnly: boolean;
  // Ephemeral: set true when a feed/category has no unread entries so the UI
  // shows all entries without clobbering the user's persisted preference.
  unreadFallbackActive: boolean;
  markReadOnScroll: boolean;
  // Day dividers the user has collapsed in the entry list (persisted as an
  // array — Sets don't survive JSON serialization). collapseAllMode keeps any
  // day that loads in later collapsed too, until expand-all / a manual toggle.
  collapsedDays: string[];
  collapseAllMode: boolean;
  activePanel: ActivePanel;
  entryListWidth: number;
  entryListCollapsed: boolean;
  entryListAutoCollapsed: boolean;
  sidebarAutoCollapsed: boolean;
  activeReaderPanel: ReaderPanel;
  sidePanelWidth: number;
  settingsNavCollapsed: boolean;
  docsNavCollapsed: boolean;
  // Automations page: disabled rules are folded away by default so the list
  // shows only what's actually running.
  automationShowDisabled: boolean;
  // Dashboard grid: when locked, widgets can't be dragged or resized. Starts
  // locked everywhere — rearranging a board is a deliberate act, while an
  // accidental drag is costly, and on a phone it is destructive: the grid
  // collapses to one column, and saving that clamped layout flattens every
  // widget to a 1/12-width sliver on desktop. Persisted per device.
  dashboardLocked: boolean;
  pendingSavedSearch: SavedSearch | null;
  /** Filter text handed to the note browser when search sends a note there. */
  pendingNoteSearch: string | null;
  headerSearchQuery: string;
  setHeaderSearchQuery: (query: string) => void;
  searchScope: SearchScope;
  setSearchScope: (scope: SearchScope) => void;
  searchFacetsCollapsed: boolean;
  setSearchFacetsCollapsed: (collapsed: boolean) => void;
  ruleFacetsCollapsed: boolean;
  setRuleFacetsCollapsed: (collapsed: boolean) => void;
  ransomwareFacetsCollapsed: boolean;
  setRansomwareFacetsCollapsed: (collapsed: boolean) => void;
  // Widths of the secondary/tertiary rails (workbench nav, settings nav, the
  // search / rule / ransomware facet rails, the docs and prompt lists). Keyed
  // by rail id rather than a field per rail: every one of them wants the same
  // drag-to-resize behaviour the app sidebar has, and a map keeps adding the
  // next rail to a single `useRailWidth` call. Absent key = the rail's default.
  railWidths: Record<string, number>;
  setRailWidth: (railId: string, width: number, min: number, max: number) => void;
  resetRailWidth: (railId: string) => void;
  selectedEntryIds: Set<string>;
  lastSelectedIndex: number | null;
  navSectionCollapsed: boolean;
  feedsSectionCollapsed: boolean;
  toolsSectionCollapsed: boolean;
  keywordsSectionCollapsed: boolean;
  savedSearchesSectionCollapsed: boolean;
  allItemsCollapsed: boolean;
  // Articles "since last visit" tracker: unread total + timestamp stamped
  // whenever the user opens the Articles hero, so we can show a "+N since Ht"
  // delta of articles that arrived since. Frontend-only (no last-read endpoint).
  articlesSeenCount: number | null;
  articlesSeenAt: number | null;
  markArticlesSeen: (count: number) => void;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setSidebarWidth: (width: number) => void;
  setViewMode: (mode: ViewMode) => void;
  setSortOrder: (order: SortOrder) => void;
  setSelectedEntry: (id: string | null) => void;
  setSelectedThread: (slug: string | null) => void;
  dismissThread: (id: string) => void;
  setSelectedFeed: (id: string | null) => void;
  setSelectedCategory: (id: string | null) => void;
  setVirtualFolder: (folder: VirtualFolder) => void;
  setReaderOpen: (open: boolean) => void;
  toggleUnreadOnly: () => void;
  setShowUnreadOnly: (value: boolean) => void;
  togglePriorityUnreadOnly: () => void;
  setPriorityShowUnreadOnly: (value: boolean) => void;
  setUnreadFallbackActive: (value: boolean) => void;
  toggleMarkReadOnScroll: () => void;
  setMarkReadOnScroll: (value: boolean) => void;
  toggleDayCollapsed: (dayKey: string) => void;
  collapseAllDays: (dayKeys: string[]) => void;
  expandAllDays: () => void;
  mergeCollapsedDays: (dayKeys: string[]) => void;
  setActivePanel: (panel: ActivePanel) => void;
  setEntryListWidth: (width: number) => void;
  setEntryListCollapsed: (collapsed: boolean) => void;
  setActiveReaderPanel: (panel: ReaderPanel) => void;
  setSidePanelWidth: (width: number) => void;
  toggleSettingsNav: () => void;
  toggleDocsNav: () => void;
  toggleAutomationShowDisabled: () => void;
  toggleDashboardLocked: () => void;
  loadSavedSearch: (saved: SavedSearch) => void;
  clearPendingSavedSearch: () => void;
  setPendingNoteSearch: (query: string) => void;
  clearPendingNoteSearch: () => void;
  toggleEntrySelection: (id: string) => void;
  setEntrySelection: (ids: string[]) => void;
  clearEntrySelection: () => void;
  setLastSelectedIndex: (index: number | null) => void;
  setNavSectionCollapsed: (collapsed: boolean) => void;
  setFeedsSectionCollapsed: (collapsed: boolean) => void;
  setToolsSectionCollapsed: (collapsed: boolean) => void;
  setKeywordsSectionCollapsed: (collapsed: boolean) => void;
  setSavedSearchesSectionCollapsed: (collapsed: boolean) => void;
  setAllItemsCollapsed: (collapsed: boolean) => void;
  entryNavigationIds: string[];
  entryNavTrail: string[];
  entryNavTrailIndex: number;
  setEntryNavigationIds: (ids: string[]) => void;
  navigateEntry: (direction: "prev" | "next") => void;
  readerFontSize: ReaderFontSize;
  readerLineHeight: ReaderLineHeight;
  readerMaxWidth: ReaderMaxWidth;
  readerHighlightEntities: boolean;
  articleSummaryCollapsed: boolean;
  readAloudEngine: ReadAloudEngine;
  setReaderFontSize: (size: ReaderFontSize) => void;
  setReaderLineHeight: (height: ReaderLineHeight) => void;
  setReaderMaxWidth: (width: ReaderMaxWidth) => void;
  setReaderHighlightEntities: (enabled: boolean) => void;
  setArticleSummaryCollapsed: (collapsed: boolean) => void;
  setReadAloudEngine: (engine: ReadAloudEngine) => void;
  reportWizardState: ReportWizardState | null;
  openReportWizard: (state: Omit<ReportWizardState, "isOpen">) => void;
  sendToReportState: SendToReportState | null;
  openSendToReport: (payload: SendToReportPayload) => void;
  closeSendToReport: () => void;
  closeReportWizard: () => void;
  /** App-level modals. Both used to be layout-local state, but the command
   *  palette has to open them from anywhere, and the add-feed dialog rendered
   *  inside the sidebar was invisible whenever the sidebar was collapsed. */
  addFeedOpen: boolean;
  openAddFeed: () => void;
  closeAddFeed: () => void;
  ingestOpen: boolean;
  openIngest: () => void;
  closeIngest: () => void;
  shortcutsHelpOpen: boolean;
  openShortcutsHelp: () => void;
  closeShortcutsHelp: () => void;
  toggleShortcutsHelp: () => void;
  commandPaletteOpen: boolean;
  closeCommandPalette: () => void;
  toggleCommandPalette: () => void;
  // Global copilot dock
  copilotOpen: boolean;
  copilotWidth: number;
  copilotCollapsed: boolean;
  copilotActiveConversationId: string | null;
  openCopilot: () => void;
  closeCopilot: () => void;
  toggleCopilot: () => void;
  setCopilotWidth: (width: number) => void;
  setCopilotCollapsed: (collapsed: boolean) => void;
  /** Header button behavior: open+expand if closed, otherwise just toggle expand/collapse — never re-closes. */
  toggleCopilotPanel: () => void;
  setCopilotActiveConversationId: (id: string | null) => void;
  /** Transient seed for opening the copilot pre-scoped (external "Ask Copilot" buttons). */
  copilotSeed: CopilotSeed | null;
  copilotSeedNonce: number;
  /** Open the copilot in a fresh thread, pinned to context and/or with a starter prompt. */
  openCopilotWith: (seed: CopilotSeed) => void;
  clearCopilotSeed: () => void;
  /** The documentation landing page's chat thread — survives navigation. */
  docsChat: DocsChatState;
  setDocsChat: (update: (prev: DocsChatState) => DocsChatState) => void;
  resetDocsChat: () => void;
}

/** How far back j/k can walk after auto-read empties the list behind you. */
const NAV_TRAIL_LIMIT = 200;

/**
 * Record an opened entry on the visit trail. Stepping onto the neighbour the
 * trail already holds just moves the cursor (so walking back and forth doesn't
 * grow a trail of duplicates); anything else truncates the forward half and
 * appends, like browser history.
 */
function recordNavTrail(s: UIState, id: string): Pick<UIState, "entryNavTrail" | "entryNavTrailIndex"> {
  const trail = s.entryNavTrail;
  const idx = s.entryNavTrailIndex;
  if (trail[idx] === id) return { entryNavTrail: trail, entryNavTrailIndex: idx };
  if (idx > 0 && trail[idx - 1] === id) return { entryNavTrail: trail, entryNavTrailIndex: idx - 1 };
  if (trail[idx + 1] === id) return { entryNavTrail: trail, entryNavTrailIndex: idx + 1 };
  const next = [...trail.slice(0, idx + 1), id].slice(-NAV_TRAIL_LIMIT);
  return { entryNavTrail: next, entryNavTrailIndex: next.length - 1 };
}

/** A scope change (feed, category, folder, thread) retires the old trail. */
const CLEARED_NAV_TRAIL = { entryNavTrail: [] as string[], entryNavTrailIndex: -1 };

/** How many docs-chat turns survive a page reload. Navigation keeps them all. */
const DOCS_CHAT_PERSIST_LIMIT = 30;

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      sidebarWidth: 280,
      sidebarMode: "reading",
      viewMode: "magazine",
      sortOrder: "newest",
      readerOpen: false,
      selectedEntryId: null,
      selectedThreadSlug: null,
      dismissedThreadIds: [],
      selectedFeedId: null,
      selectedCategoryId: null,
      virtualFolder: null,
      showUnreadOnly: true,
      priorityShowUnreadOnly: true,
      unreadFallbackActive: false,
      markReadOnScroll: true,
      collapsedDays: [],
      collapseAllMode: false,
      activePanel: "entries",
      entryListWidth: 300,
      entryListCollapsed: false,
      entryListAutoCollapsed: false,
      sidebarAutoCollapsed: false,
      activeReaderPanel: null,
      sidePanelWidth: 380,
      settingsNavCollapsed: false,
      docsNavCollapsed: false,
      automationShowDisabled: false,
      dashboardLocked: true,
      pendingSavedSearch: null,
      pendingNoteSearch: null,
      headerSearchQuery: "",
      setHeaderSearchQuery: (query) => set({ headerSearchQuery: query }),
      searchScope: "everything",
      setSearchScope: (scope) => set({ searchScope: scope }),
      searchFacetsCollapsed: false,
      setSearchFacetsCollapsed: (collapsed) => set({ searchFacetsCollapsed: collapsed }),
      ruleFacetsCollapsed: false,
      setRuleFacetsCollapsed: (collapsed) => set({ ruleFacetsCollapsed: collapsed }),
      ransomwareFacetsCollapsed: false,
      setRansomwareFacetsCollapsed: (collapsed) => set({ ransomwareFacetsCollapsed: collapsed }),
      railWidths: {},
      setRailWidth: (railId, width, min, max) =>
        set((s) => ({
          railWidths: { ...s.railWidths, [railId]: Math.max(min, Math.min(max, Math.round(width))) },
        })),
      resetRailWidth: (railId) =>
        set((s) => {
          if (!(railId in s.railWidths)) return s;
          const next = { ...s.railWidths };
          delete next[railId];
          return { railWidths: next };
        }),
      selectedEntryIds: new Set<string>(),
      lastSelectedIndex: null,
      navSectionCollapsed: false,
      feedsSectionCollapsed: false,
      toolsSectionCollapsed: true,
      keywordsSectionCollapsed: true,
      savedSearchesSectionCollapsed: true,
      allItemsCollapsed: false,
      articlesSeenCount: null,
      articlesSeenAt: null,
      // Manual toggles take ownership: auto-collapse restores (reader panel,
      // workbench detail routes) must not override an explicit user choice.
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed, sidebarAutoCollapsed: false })),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed, sidebarAutoCollapsed: false }),
      setSidebarWidth: (width) => set({ sidebarWidth: Math.max(275, Math.min(480, width)) }),
      // Switching mode always shows the sidebar: the switch is inside it, so a
      // collapsed sidebar means the click came from the rail toggle's flyout or
      // a keyboard shortcut, and leaving it collapsed would look like a no-op.
      setSidebarMode: (mode) => set({ sidebarMode: mode, sidebarCollapsed: false, sidebarAutoCollapsed: false }),
      setViewMode: (mode) => set({ viewMode: mode }),
      setSortOrder: (order) => set({ sortOrder: order }),
      tables: {},
      // Every layout mutation stamps layoutUpdatedAt so the profile sync can
      // tell which device arranged the table most recently.
      setTableColumnOrder: (tableId, order) =>
        set((s) => patchTable(s.tables, tableId, { columnOrder: order, layoutUpdatedAt: Date.now() })),
      setTableColumnVisible: (tableId, key, visible) =>
        set((s) => {
          const t = s.tables[tableId] ?? EMPTY_TABLE_LAYOUT;
          return patchTable(s.tables, tableId, {
            columnVisibility: { ...t.columnVisibility, [key]: visible },
            layoutUpdatedAt: Date.now(),
          });
        }),
      setTableColumnWidth: (tableId, key, width) =>
        set((s) => {
          const t = s.tables[tableId] ?? EMPTY_TABLE_LAYOUT;
          return patchTable(s.tables, tableId, {
            columnWidths: {
              ...t.columnWidths,
              [key]: Math.max(40, Math.min(1200, Math.round(width))),
            },
            layoutUpdatedAt: Date.now(),
          });
        }),
      // Layout reset only — the user's active filters and sort are a separate
      // concern with their own "Clear filters" action.
      resetTableLayout: (tableId) =>
        set((s) =>
          patchTable(s.tables, tableId, {
            columnVisibility: {},
            columnWidths: {},
            columnOrder: [],
            layoutUpdatedAt: Date.now(),
          })
        ),
      tablesOwnerId: null,
      takeOverTableLayouts: (userId, remote) =>
        set(() => ({
          tablesOwnerId: userId,
          tables: Object.fromEntries(
            Object.entries(remote).map(([tableId, r]) => [
              tableId,
              {
                ...EMPTY_TABLE_LAYOUT,
                columnVisibility: r.columnVisibility,
                columnWidths: r.columnWidths,
                columnOrder: r.columnOrder,
                layoutUpdatedAt: r.updatedAt,
              },
            ])
          ),
        })),
      applyRemoteTableLayouts: (remote) =>
        set((s) => {
          const next = { ...s.tables };
          let changed = false;
          for (const [tableId, r] of Object.entries(remote)) {
            const local = s.tables[tableId];
            // A table this device has never touched adopts the server layout
            // outright; otherwise only a strictly newer edit wins, so the
            // arrangement you just made locally is never yanked out from under you.
            if (local && r.updatedAt <= local.layoutUpdatedAt) continue;
            next[tableId] = {
              ...(local ?? EMPTY_TABLE_LAYOUT),
              columnVisibility: r.columnVisibility,
              columnWidths: r.columnWidths,
              columnOrder: r.columnOrder,
              layoutUpdatedAt: r.updatedAt,
            };
            changed = true;
          }
          return changed ? { tables: next } : {};
        }),
      setTableTextFilter: (tableId, key, value) =>
        set((s) => {
          const t = s.tables[tableId] ?? EMPTY_TABLE_LAYOUT;
          return patchTable(s.tables, tableId, { textFilters: { ...t.textFilters, [key]: value } });
        }),
      setTableHasFilter: (tableId, key, value) =>
        set((s) => {
          const t = s.tables[tableId] ?? EMPTY_TABLE_LAYOUT;
          return patchTable(s.tables, tableId, { hasFilters: { ...t.hasFilters, [key]: value } });
        }),
      setTableChoiceFilter: (tableId, key, value) =>
        set((s) => {
          const t = s.tables[tableId] ?? EMPTY_TABLE_LAYOUT;
          return patchTable(s.tables, tableId, { choiceFilters: { ...t.choiceFilters, [key]: value } });
        }),
      setTableClientSort: (tableId, sort) =>
        set((s) => patchTable(s.tables, tableId, { clientSort: sort })),
      // Matches the header "Clear filters" action: resets the column filters and
      // dropdowns but leaves the active sort intact.
      clearTableFilters: (tableId) =>
        set((s) => patchTable(s.tables, tableId, { textFilters: {}, hasFilters: {}, choiceFilters: {} })),
      // A thread and an article are both "what the reader pane is showing", so
      // selecting either clears the other.
      setSelectedThread: (slug) => set(() => {
        if (slug) {
          return {
            ...CLEARED_NAV_TRAIL,
            selectedThreadSlug: slug,
            selectedEntryId: null,
            readerOpen: true,
            activeReaderPanel: null,
            entryListCollapsed: false,
            entryListAutoCollapsed: false,
            sidebarCollapsed: true,
            sidebarAutoCollapsed: true,
          };
        }
        return { selectedThreadSlug: null, readerOpen: false, activeReaderPanel: null };
      }),
      dismissThread: (id) =>
        set((s) =>
          s.dismissedThreadIds.includes(id)
            ? s
            : { dismissedThreadIds: [...s.dismissedThreadIds, id] },
        ),
      setSelectedEntry: (id) => set((s) => {
        if (id) {
          return {
            ...recordNavTrail(s, id),
            selectedThreadSlug: null,
            selectedEntryId: id,
            readerOpen: true,
            activeReaderPanel: null,
            entryListCollapsed: false,
            entryListAutoCollapsed: false,
            sidebarCollapsed: true,
            sidebarAutoCollapsed: true,
          };
        }
        return {
          selectedEntryId: null,
          selectedThreadSlug: null,
          readerOpen: false,
          activeReaderPanel: null,
          entryListCollapsed: false,
          entryListAutoCollapsed: false,
          sidebarCollapsed: isMobileViewport(),
          sidebarAutoCollapsed: false,
        };
      }),
      setSelectedFeed: (id) => set(() => ({
        ...CLEARED_NAV_TRAIL,
        selectedFeedId: id, selectedCategoryId: null, virtualFolder: null, activePanel: "entries", headerSearchQuery: "",
        selectedEntryId: null, readerOpen: false, activeReaderPanel: null,
        entryListCollapsed: false, entryListAutoCollapsed: false,
        sidebarCollapsed: isMobileViewport(), sidebarAutoCollapsed: false,
      })),
      setSelectedCategory: (id) => set(() => ({
        ...CLEARED_NAV_TRAIL,
        selectedCategoryId: id, selectedFeedId: null, virtualFolder: null, activePanel: "entries", headerSearchQuery: "",
        selectedEntryId: null, readerOpen: false, activeReaderPanel: null,
        entryListCollapsed: false, entryListAutoCollapsed: false,
        sidebarCollapsed: isMobileViewport(), sidebarAutoCollapsed: false,
      })),
      setVirtualFolder: (folder) => set(() => ({
        ...CLEARED_NAV_TRAIL,
        virtualFolder: folder, selectedFeedId: null, selectedCategoryId: null, activePanel: "entries", headerSearchQuery: "",
        selectedEntryId: null, readerOpen: false, activeReaderPanel: null,
        entryListCollapsed: false, entryListAutoCollapsed: false,
        sidebarCollapsed: isMobileViewport(), sidebarAutoCollapsed: false,
      })),
      setReaderOpen: (open) => set({ readerOpen: open }),
      toggleUnreadOnly: () => set((s) => {
        // Toggle based on effective state so clicking always flips what the user sees.
        const effective = s.showUnreadOnly && !s.unreadFallbackActive;
        return { showUnreadOnly: !effective, unreadFallbackActive: false };
      }),
      setShowUnreadOnly: (value: boolean) => set({ showUnreadOnly: value, unreadFallbackActive: false }),
      togglePriorityUnreadOnly: () => set((s) => {
        const effective = s.priorityShowUnreadOnly && !s.unreadFallbackActive;
        return { priorityShowUnreadOnly: !effective, unreadFallbackActive: false };
      }),
      setPriorityShowUnreadOnly: (value: boolean) =>
        set({ priorityShowUnreadOnly: value, unreadFallbackActive: false }),
      setUnreadFallbackActive: (value: boolean) => set({ unreadFallbackActive: value }),
      toggleMarkReadOnScroll: () => set((s) => ({ markReadOnScroll: !s.markReadOnScroll })),
      setMarkReadOnScroll: (value: boolean) => set({ markReadOnScroll: value }),
      // Manual per-day toggle also drops out of collapse-all mode so it stops
      // fighting the user's individual choices.
      toggleDayCollapsed: (dayKey: string) =>
        set((s) => ({
          collapsedDays: s.collapsedDays.includes(dayKey)
            ? s.collapsedDays.filter((k) => k !== dayKey)
            : [...s.collapsedDays, dayKey],
          collapseAllMode: false,
        })),
      collapseAllDays: (dayKeys: string[]) =>
        set({ collapsedDays: [...dayKeys], collapseAllMode: true }),
      expandAllDays: () => set({ collapsedDays: [], collapseAllMode: false }),
      // Fold newly-loaded days into the set while collapse-all is active; no-op
      // (returns unchanged state) when there's nothing new, to avoid re-renders.
      mergeCollapsedDays: (dayKeys: string[]) =>
        set((s) => {
          const have = new Set(s.collapsedDays);
          let changed = false;
          for (const k of dayKeys) {
            if (!have.has(k)) {
              have.add(k);
              changed = true;
            }
          }
          return changed ? { collapsedDays: [...have] } : {};
        }),
      setActivePanel: (panel) => set({ activePanel: panel }),
      setEntryListWidth: (width) => set({ entryListWidth: Math.max(200, Math.min(800, width)) }),
      // Manual toggle takes ownership: the auto-collapse restore in
      // setActiveReaderPanel must not override an explicit user choice.
      setEntryListCollapsed: (collapsed) => set({ entryListCollapsed: collapsed, entryListAutoCollapsed: false }),
      setSidePanelWidth: (width) => set({ sidePanelWidth: Math.max(280, Math.min(2400, width)) }),
      toggleSettingsNav: () => set((s) => ({ settingsNavCollapsed: !s.settingsNavCollapsed })),
      toggleDocsNav: () => set((s) => ({ docsNavCollapsed: !s.docsNavCollapsed })),
      toggleAutomationShowDisabled: () =>
        set((s) => ({ automationShowDisabled: !s.automationShowDisabled })),
      toggleDashboardLocked: () => set((s) => ({ dashboardLocked: !s.dashboardLocked })),
      setActiveReaderPanel: (panel) => set((s) => {
        if (panel) {
          // Collapse both left columns to make room for the panel, but only
          // claim ownership (auto flag) of ones the user hadn't collapsed
          // themselves — closing the panel restores exactly what it took.
          return {
            activeReaderPanel: panel,
            entryListCollapsed: true,
            entryListAutoCollapsed: s.entryListCollapsed ? s.entryListAutoCollapsed : true,
            sidebarCollapsed: true,
            sidebarAutoCollapsed: s.sidebarCollapsed ? s.sidebarAutoCollapsed : true,
          };
        }
        // Reader is still open, so leave the sidebar in reading mode
        // (collapsed) and only give back the entry list if we auto-took it.
        return {
          activeReaderPanel: null,
          entryListCollapsed: s.entryListAutoCollapsed ? false : s.entryListCollapsed,
          entryListAutoCollapsed: false,
        };
      }),
      loadSavedSearch: (saved) => set({ pendingSavedSearch: saved }),
      clearPendingSavedSearch: () => set({ pendingSavedSearch: null }),
      setPendingNoteSearch: (query) => set({ pendingNoteSearch: query }),
      clearPendingNoteSearch: () => set({ pendingNoteSearch: null }),
      toggleEntrySelection: (id) => set((s) => {
        const next = new Set(s.selectedEntryIds);
        if (next.has(id)) {
          next.delete(id);
        } else {
          next.add(id);
        }
        return { selectedEntryIds: next };
      }),
      setEntrySelection: (ids) => set({ selectedEntryIds: new Set(ids) }),
      clearEntrySelection: () => set({ selectedEntryIds: new Set<string>(), lastSelectedIndex: null }),
      setLastSelectedIndex: (index) => set({ lastSelectedIndex: index }),
      setNavSectionCollapsed: (collapsed) => set({ navSectionCollapsed: collapsed }),
      setFeedsSectionCollapsed: (collapsed) => set({ feedsSectionCollapsed: collapsed }),
      setToolsSectionCollapsed: (collapsed) => set({ toolsSectionCollapsed: collapsed }),
      setKeywordsSectionCollapsed: (collapsed) => set({ keywordsSectionCollapsed: collapsed }),
      setSavedSearchesSectionCollapsed: (collapsed) => set({ savedSearchesSectionCollapsed: collapsed }),
      setAllItemsCollapsed: (collapsed) => set({ allItemsCollapsed: collapsed }),
      markArticlesSeen: (count) => set({ articlesSeenCount: count, articlesSeenAt: Date.now() }),
      entryNavigationIds: [],
      entryNavTrail: [],
      entryNavTrailIndex: -1,
      setEntryNavigationIds: (ids) => set({ entryNavigationIds: ids }),
      navigateEntry: (direction) => set((s) => {
        const nextId = adjacentEntryId(
          direction,
          s.selectedEntryId,
          s.entryNavigationIds,
          s.entryNavTrail,
          s.entryNavTrailIndex,
        );
        if (!nextId) return s;
        return {
          ...recordNavTrail(s, nextId),
          selectedEntryId: nextId,
          readerOpen: true,
          activeReaderPanel: null,
          entryListCollapsed: false,
          entryListAutoCollapsed: false,
          sidebarCollapsed: true,
          sidebarAutoCollapsed: true,
        };
      }),
      readerFontSize: 16,
      readerLineHeight: 1.7,
      readerMaxWidth: 720,
      readerHighlightEntities: true,
      articleSummaryCollapsed: false,
      readAloudEngine: "piper",
      setReaderFontSize: (size) => set({ readerFontSize: size }),
      setReaderLineHeight: (height) => set({ readerLineHeight: height }),
      setReaderMaxWidth: (width) => set({ readerMaxWidth: width }),
      setReaderHighlightEntities: (enabled) => set({ readerHighlightEntities: enabled }),
      setArticleSummaryCollapsed: (collapsed) => set({ articleSummaryCollapsed: collapsed }),
      setReadAloudEngine: (engine) => set({ readAloudEngine: engine }),
      reportWizardState: null,
      openReportWizard: (state) => set({ reportWizardState: { ...state, isOpen: true } }),
      closeReportWizard: () => set({ reportWizardState: null }),
      sendToReportState: null,
      openSendToReport: (payload) => set({ sendToReportState: { isOpen: true, payload } }),
      closeSendToReport: () => set({ sendToReportState: null }),
      addFeedOpen: false,
      openAddFeed: () => set({ addFeedOpen: true }),
      closeAddFeed: () => set({ addFeedOpen: false }),
      ingestOpen: false,
      openIngest: () => set({ ingestOpen: true }),
      closeIngest: () => set({ ingestOpen: false }),
      shortcutsHelpOpen: false,
      openShortcutsHelp: () => set({ shortcutsHelpOpen: true }),
      closeShortcutsHelp: () => set({ shortcutsHelpOpen: false }),
      toggleShortcutsHelp: () => set((s) => ({ shortcutsHelpOpen: !s.shortcutsHelpOpen })),
      commandPaletteOpen: false,
      closeCommandPalette: () => set({ commandPaletteOpen: false }),
      toggleCommandPalette: () => set((s) => ({ commandPaletteOpen: !s.commandPaletteOpen })),
      // Global copilot dock defaults
      copilotOpen: false,
      copilotWidth: 420,
      copilotCollapsed: false,
      copilotActiveConversationId: null,
      copilotSeed: null,
      copilotSeedNonce: 0,
      openCopilot: () => set({ copilotOpen: true, copilotCollapsed: false }),
      closeCopilot: () => set({ copilotOpen: false }),
      toggleCopilot: () =>
        set((s) => ({ copilotOpen: !s.copilotOpen, copilotCollapsed: false })),
      setCopilotWidth: (width) =>
        set({ copilotWidth: Math.max(320, Math.min(720, width)) }),
      setCopilotCollapsed: (collapsed) => set({ copilotCollapsed: collapsed }),
      toggleCopilotPanel: () =>
        set((s) =>
          s.copilotOpen
            ? { copilotCollapsed: !s.copilotCollapsed }
            : { copilotOpen: true, copilotCollapsed: false },
        ),
      setCopilotActiveConversationId: (id) => set({ copilotActiveConversationId: id }),
      openCopilotWith: (seed) =>
        set((s) => ({
          copilotOpen: true,
          copilotCollapsed: false,
          // Fresh thread so the seeded question doesn't append to an old one.
          copilotActiveConversationId: null,
          copilotSeed: seed,
          copilotSeedNonce: s.copilotSeedNonce + 1,
        })),
      clearCopilotSeed: () => set({ copilotSeed: null }),
      docsChat: { conversationId: null, messages: [], streaming: false, lastDocSlug: null },
      setDocsChat: (update) => set((state) => ({ docsChat: update(state.docsChat) })),
      resetDocsChat: () =>
        set((state) => ({
          // Keep lastDocSlug: a new question asked right after reading a page is
          // still about that page.
          docsChat: { conversationId: null, messages: [], streaming: false, lastDocSlug: state.docsChat.lastDocSlug },
        })),
    }),
    {
      name: "intelfeed-ui",
      version: 5,
      migrate: (persisted, version) => {
        if (!persisted || typeof persisted !== "object") return persisted;
        let s = persisted as Record<string, unknown>;

        // v0 → v1: the entry table's flat column/filter fields became the
        // per-table `tables` map, so existing users keep the layout they built.
        if (version < 1) {
          const {
            tableColumnVisibility, tableColumnWidths, tableColumnOrder,
            tableTextFilters, tableHasFilters, tableStatusFilter, tableClientSort,
            ...rest
          } = s;
          s = {
            ...rest,
            tables: {
              entries: {
                ...EMPTY_TABLE_LAYOUT,
                columnVisibility: (tableColumnVisibility as TableLayout["columnVisibility"]) ?? {},
                columnWidths: (tableColumnWidths as TableLayout["columnWidths"]) ?? {},
                columnOrder: (tableColumnOrder as string[]) ?? [],
                textFilters: (tableTextFilters as TableLayout["textFilters"]) ?? {},
                hasFilters: (tableHasFilters as TableLayout["hasFilters"]) ?? {},
                choiceFilters: tableStatusFilter ? { status: tableStatusFilter as string } : {},
                clientSort: (tableClientSort as TableLayout["clientSort"]) ?? null,
              },
            },
          };
        }

        // v1 → v2: layouts gained `layoutUpdatedAt` for profile sync. Stamp the
        // arrangements already on this device so they upload on next load
        // instead of sitting at timestamp 0 and losing every tiebreak. Tables
        // sitting at defaults stay unstamped so they aren't pushed at all.
        if (version < 2) {
          const tables = (s.tables as Record<string, TableLayout>) ?? {};
          const now = Date.now();
          s = {
            ...s,
            tables: Object.fromEntries(
              Object.entries(tables).map(([id, t]) => {
                const merged = { ...EMPTY_TABLE_LAYOUT, ...t };
                const arranged =
                  Object.keys(merged.columnVisibility).length > 0 ||
                  Object.keys(merged.columnWidths).length > 0 ||
                  merged.columnOrder.length > 0;
                return [id, { ...merged, layoutUpdatedAt: arranged ? now : 0 }];
              })
            ),
          };
        }

        // v2 → v3: the entity search scope was called "intelligence" while the
        // surface it searches is called the workbench everywhere else in the
        // app. One name, and the chip now matches the nav.
        if (version < 3 && s.searchScope === "intelligence") {
          s = { ...s, searchScope: "workbench" };
        }

        // v3 → v4: Feeds no longer starts collapsed. Everyone who has opened
        // the app is carrying a persisted `true` written by the old default,
        // which would keep the section shut forever — drop the stored value so
        // the new default applies. A deliberate collapse is indistinguishable
        // from the default here, so this does re-open it for those users once.
        if (version < 4) {
          s = { ...s };
          delete s.feedsSectionCollapsed;
        }

        // v4 → v5: "Why it's ranked" collapses per entry now and no longer
        // stores a preference, so drop the stranded key; and Radar left the sort
        // dropdown (the Priority Queue is its surface), so land anyone parked on
        // the removed option back on Newest.
        if (version < 5) {
          s = { ...s };
          delete s.whyRankedCollapsed;
          if (s.sortOrder === "radar") s.sortOrder = "newest";
        }

        return s;
      },
      partialize: (state) => ({
        viewMode: state.viewMode,
        sortOrder: state.sortOrder,
        tables: state.tables,
        tablesOwnerId: state.tablesOwnerId,
        showUnreadOnly: state.showUnreadOnly,
        priorityShowUnreadOnly: state.priorityShowUnreadOnly,
        markReadOnScroll: state.markReadOnScroll,
        collapsedDays: state.collapsedDays,
        collapseAllMode: state.collapseAllMode,
        sidebarWidth: state.sidebarWidth,
        entryListWidth: state.entryListWidth,
        sidePanelWidth: state.sidePanelWidth,
        navSectionCollapsed: state.navSectionCollapsed,
        feedsSectionCollapsed: state.feedsSectionCollapsed,
        toolsSectionCollapsed: state.toolsSectionCollapsed,
        keywordsSectionCollapsed: state.keywordsSectionCollapsed,
        savedSearchesSectionCollapsed: state.savedSearchesSectionCollapsed,
        allItemsCollapsed: state.allItemsCollapsed,
        articlesSeenCount: state.articlesSeenCount,
        articlesSeenAt: state.articlesSeenAt,
        readerFontSize: state.readerFontSize,
        readerLineHeight: state.readerLineHeight,
        readerMaxWidth: state.readerMaxWidth,
        readerHighlightEntities: state.readerHighlightEntities,
        articleSummaryCollapsed: state.articleSummaryCollapsed,
        readAloudEngine: state.readAloudEngine,
        searchScope: state.searchScope,
        searchFacetsCollapsed: state.searchFacetsCollapsed,
        ruleFacetsCollapsed: state.ruleFacetsCollapsed,
        ransomwareFacetsCollapsed: state.ransomwareFacetsCollapsed,
        railWidths: state.railWidths,
        copilotWidth: state.copilotWidth,
        copilotCollapsed: state.copilotCollapsed,
        settingsNavCollapsed: state.settingsNavCollapsed,
        docsNavCollapsed: state.docsNavCollapsed,
        automationShowDisabled: state.automationShowDisabled,
        dashboardLocked: state.dashboardLocked,
        // Capped: AI turns are long, and this store also carries table
        // layouts and dashboards that must not be squeezed out.
        docsChat: {
          conversationId: state.docsChat.conversationId,
          messages: state.docsChat.messages.slice(-DOCS_CHAT_PERSIST_LIMIT),
          lastDocSlug: state.docsChat.lastDocSlug,
        },
      }),
    }
  )
);
