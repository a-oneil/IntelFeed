import { create } from "zustand";
import { persist } from "zustand/middleware";

export type WorkspaceSection =
  | "threat_actors"
  | "malware"
  | "cves"
  | "cwes"
  | "ttps"
  | "countries"
  | "mitigations"
  | "observables"
  | "tools"
  | "vendors"
  | "products"

  | "rules"
  | "telemetry"
  | "attack_matrix"
  | "campaigns"
  | "reports"
  | "requirements"
  | "glossary"
  | "telegram_mentions"
  | "watchlist"
  | "ransomware";

// "campaign" is a profile type, not an extraction type: it never comes out of
// an article, but it pivots and renders through the same shell as the rest.
export type EntityType =
  | "threat_actor"
  | "malware"
  | "cve"
  | "cwe"
  | "ttp"
  | "country"
  | "mitigation"
  | "tool"
  | "vendor"
  | "product"
  | "observable"
  | "campaign";

export interface RuleLibraryState {
  search: string;
  /** Which indexed attributes the search box looks at. */
  scope: "both" | "metadata" | "content";
  /** Facet selections keyed by Meilisearch attribute. */
  facetSel: Record<string, string[]>;
  lens: "flat" | "technique" | "repo" | "product";
  activeView: string;
  draftFilter?: boolean;
  authoredLocal?: boolean;
  createdAfter?: string;
  sortField: string;
  sortOrder: "asc" | "desc";
}

export const DEFAULT_RULE_LIBRARY: RuleLibraryState = {
  search: "",
  scope: "both",
  facetSel: {},
  lens: "flat",
  activeView: "all",
  sortField: "created_at",
  sortOrder: "desc",
};

export interface PivotHistoryItem {
  type: string;
  id: string;
  label: string;
  timestamp: number;
}

interface IntelState {
  // Workspace navigation
  activeSection: WorkspaceSection;
  setActiveSection: (section: WorkspaceSection) => void;

  // Entity selection
  selectedEntityType: EntityType | null;
  selectedEntityId: string | null;
  comparisonEntityId: string | null;
  selectEntity: (type: EntityType, id: string, label?: string) => void;
  setComparisonEntity: (id: string | null) => void;
  clearSelectedEntity: () => void;

  // Recent pivots (last 20)
  recentPivots: PivotHistoryItem[];
  addToRecentPivots: (item: PivotHistoryItem) => void;

  // Per-entity last-visit timestamps (powers the "since your last visit" ribbon)
  entityLastVisit: Record<string, number>;
  markEntityVisited: (entityId: string) => void;

  // Extraction preferences
  autoExtractOnOpen: boolean;
  toggleAutoExtract: () => void;
  autoOpenIntelPanel: boolean;
  toggleAutoOpenIntelPanel: () => void;
  preferredRuleFormats: string[];
  setPreferredRuleFormats: (formats: string[]) => void;

  // Workbench sidebar collapsed (whole sidebar, persisted user preference).
  // The auto flag records that a detail route (profile/rule/report) collapsed
  // it, so returning to the workbench index restores it; a manual toggle
  // clears the flag so the user's choice always wins.
  /**
   * Create-Entity modal state. It lives in the store because two surfaces open
   * it and only one renders it: the entity table's header (desktop) and the
   * mobile workbench toolbar. `createEntityType` preselects the type tab, so the
   * button in the Malware table opens on Malware.
   */
  createEntityOpen: boolean;
  createEntityType: EntityType | null;
  openCreateEntity: (type?: EntityType) => void;
  closeCreateEntity: () => void;
  /** The rule library's whole filter set, kept so opening a rule and coming
   *  back restores the list you were looking at rather than resetting it. */
  ruleLibrary: RuleLibraryState;
  setRuleLibrary: (patch: Partial<RuleLibraryState>) => void;

  /** The workbench's docked reader: any workbench surface (workspace intel
   *  column, board drawer) opens an entry on the right without leaving the
   *  page — the workbench acts as the entry list, the way the rest of the app
   *  pairs a list with the reader. Deliberately not persisted. */
  workbenchReaderEntryId: string | null;
  /** A story thread can take the same dock — one occupant at a time, so
   *  opening either clears the other. */
  workbenchReaderThreadSlug: string | null;
  openWorkbenchReader: (entryId: string) => void;
  openWorkbenchThread: (slug: string) => void;
  closeWorkbenchReader: () => void;

  // Workspace sidebar collapsed sections
  entitiesSectionCollapsed: boolean;
  detectionSectionCollapsed: boolean;
  intelligenceSectionCollapsed: boolean;
  exploreSectionCollapsed: boolean;
  systemSectionCollapsed: boolean;
  setEntitiesSectionCollapsed: (collapsed: boolean) => void;
  setDetectionSectionCollapsed: (collapsed: boolean) => void;
  setIntelligenceSectionCollapsed: (collapsed: boolean) => void;
  setExploreSectionCollapsed: (collapsed: boolean) => void;
  setSystemSectionCollapsed: (collapsed: boolean) => void;

  // Search within workspace
  workspaceSearchQuery: string;
  setWorkspaceSearchQuery: (query: string) => void;

  // Report drafting
  activeReportDraft: string | null;
  setActiveReportDraft: (id: string | null) => void;

  // Recent search queries
  recentSearches: string[];
  addRecentSearch: (query: string) => void;

  // Workbench table scroll positions (session-scoped, keyed by entityType+sort+filters)
  tableScrollPositions: Record<string, number>;
  setTableScrollPosition: (key: string, scrollTop: number) => void;
}

export const useIntelStore = create<IntelState>()(
  persist(
    (set) => ({
      activeSection: "threat_actors",
      setActiveSection: (section) => set({ activeSection: section }),

      selectedEntityType: null,
      selectedEntityId: null,
      comparisonEntityId: null,
      selectEntity: (type, id, label) =>
        set((s) => {
          const pivot: PivotHistoryItem = {
            type,
            id,
            label: label || id,
            timestamp: Date.now(),
          };
          const pivots = [pivot, ...s.recentPivots.filter((p) => !(p.type === type && p.id === id))].slice(0, 20);
          return {
            selectedEntityType: type,
            selectedEntityId: id,
            recentPivots: pivots,
          };
        }),
      setComparisonEntity: (id) => set({ comparisonEntityId: id }),
      clearSelectedEntity: () =>
        set({ selectedEntityType: null, selectedEntityId: null, comparisonEntityId: null }),

      recentPivots: [],
      addToRecentPivots: (item) =>
        set((s) => ({
          recentPivots: [
            item,
            ...s.recentPivots.filter((p) => !(p.type === item.type && p.id === item.id)),
          ].slice(0, 20),
        })),

      entityLastVisit: {},
      markEntityVisited: (entityId) =>
        set((s) => {
          const next = { ...s.entityLastVisit, [entityId]: Date.now() };
          // Keep the map bounded — retain the 100 most recent visits.
          const ids = Object.keys(next);
          if (ids.length > 100) {
            ids
              .sort((a, b) => next[a] - next[b])
              .slice(0, ids.length - 100)
              .forEach((id) => delete next[id]);
          }
          return { entityLastVisit: next };
        }),

      autoExtractOnOpen: false,
      toggleAutoExtract: () => set((s) => ({ autoExtractOnOpen: !s.autoExtractOnOpen })),
      autoOpenIntelPanel: false,
      toggleAutoOpenIntelPanel: () => set((s) => ({ autoOpenIntelPanel: !s.autoOpenIntelPanel })),
      preferredRuleFormats: ["sigma"],
      setPreferredRuleFormats: (formats) => set({ preferredRuleFormats: formats }),

      createEntityOpen: false,
      createEntityType: null,
      openCreateEntity: (type) => set({ createEntityOpen: true, createEntityType: type ?? null }),
      closeCreateEntity: () => set({ createEntityOpen: false, createEntityType: null }),
      ruleLibrary: DEFAULT_RULE_LIBRARY,
      setRuleLibrary: (patch) => set((st) => ({ ruleLibrary: { ...st.ruleLibrary, ...patch } })),
      workbenchReaderEntryId: null,
      workbenchReaderThreadSlug: null,
      openWorkbenchReader: (entryId) =>
        set({ workbenchReaderEntryId: entryId, workbenchReaderThreadSlug: null }),
      openWorkbenchThread: (slug) =>
        set({ workbenchReaderThreadSlug: slug, workbenchReaderEntryId: null }),
      closeWorkbenchReader: () => set({ workbenchReaderEntryId: null, workbenchReaderThreadSlug: null }),

      entitiesSectionCollapsed: false,
      detectionSectionCollapsed: false,
      intelligenceSectionCollapsed: false,
      exploreSectionCollapsed: false,
      systemSectionCollapsed: false,
      setEntitiesSectionCollapsed: (collapsed) => set({ entitiesSectionCollapsed: collapsed }),
      setDetectionSectionCollapsed: (collapsed) => set({ detectionSectionCollapsed: collapsed }),
      setIntelligenceSectionCollapsed: (collapsed) => set({ intelligenceSectionCollapsed: collapsed }),
      setExploreSectionCollapsed: (collapsed) => set({ exploreSectionCollapsed: collapsed }),
      setSystemSectionCollapsed: (collapsed) => set({ systemSectionCollapsed: collapsed }),

      workspaceSearchQuery: "",
      setWorkspaceSearchQuery: (query) => set({ workspaceSearchQuery: query }),

      activeReportDraft: null,
      setActiveReportDraft: (id) => set({ activeReportDraft: id }),

      recentSearches: [],
      addRecentSearch: (query) =>
        set((s) => ({
          recentSearches: [query, ...s.recentSearches.filter((q) => q !== query)].slice(0, 10),
        })),

      tableScrollPositions: {},
      setTableScrollPosition: (key, scrollTop) =>
        set((s) => ({
          tableScrollPositions: { ...s.tableScrollPositions, [key]: scrollTop },
        })),
    }),
    {
      name: "intelfeed-intel",
      version: 1,
      migrate: (persisted) => {
        // v0→v1: hygiene moved to Settings → Engine; reset stale selections
        const state = (persisted ?? {}) as Record<string, unknown>;
        if (state.activeSection === "hygiene") state.activeSection = "threat_actors";
        return state as unknown as IntelState;
      },
      partialize: (state) => ({
        activeSection: state.activeSection,
        autoExtractOnOpen: state.autoExtractOnOpen,
        autoOpenIntelPanel: state.autoOpenIntelPanel,
        preferredRuleFormats: state.preferredRuleFormats,
        ruleLibrary: state.ruleLibrary,
        entitiesSectionCollapsed: state.entitiesSectionCollapsed,
        detectionSectionCollapsed: state.detectionSectionCollapsed,
        intelligenceSectionCollapsed: state.intelligenceSectionCollapsed,
        exploreSectionCollapsed: state.exploreSectionCollapsed,
        systemSectionCollapsed: state.systemSectionCollapsed,
        recentPivots: state.recentPivots,
        recentSearches: state.recentSearches,
        entityLastVisit: state.entityLastVisit,
      }),
    }
  )
);
