import { useIntelStore } from "@/stores/intelStore";
import { entityProfilePath } from "@/components/entityProfile/entityProfileConfig";
import type { EntityType } from "@/stores/intelStore";

export interface EntityDestination {
  /** Router path to navigate to. */
  path: string;
  /**
   * Store mutation that must run *before* the navigation, for the section-scoped
   * destinations that land on `/workbench/explore` and need the workspace to
   * already be pointing at the right section.
   */
  before?: () => void;
}

/** Canonical entity types that have a full-width profile route (`App.tsx:198-207`). */
const PROFILE_TYPES: readonly EntityType[] = [
  "threat_actor",
  "malware",
  "cve",
  "ttp",
  "country",
  "sector",
  "tool",
  "mitigation",
  "cwe",
  "vendor",
  "product",
  "observable",
];

/**
 * Pre-canonical spellings still produced by saved queries, the workbench
 * `type:` filter (`TYPE_FILTER_MAP`) and old search-index rows.
 * `actor` is the pre-2026-08 `threat_actor` slug — `App.tsx:104` still keeps a
 * redirect route alive for it.
 */
const TYPE_ALIASES: Record<string, string> = {
  actor: "threat_actor",
  rule: "detection_rule",
};

/**
 * The single "where does clicking this search result go?" table.
 *
 * ---------------------------------------------------------------------------
 * NOT YET WIRED UP. Created by step 0 of the search consolidation;
 * a later step replaces the remaining copies with it. That rollout is a deliberate
 * behaviour change, because the copies disagree:
 *
 * 1. `UnifiedSearchBar.handleEntityClick` — GONE. That component was deleted
 *    when search moved to the `/search` route; its results are now drawn by
 *    `components/search/SearchResults.tsx`, which calls copy 2 below. So the
 *    behaviour change this entry anticipated (risk R7) has already landed on
 *    that path: a search entity click opens `/workbench/<type>/<id>` instead of
 *    `/workbench/explore` + `intelStore.selectEntity(...)`. The one capability
 *    lost with it is `pir`, which copy 2 does not handle and which therefore
 *    silently does nothing — this function is where that gets fixed.
 *
 * 2. `useEntityResultNavigate` (`components/search/EntityResults.tsx`)
 *    — the current convention, used by both `/search` and the workbench's
 *      mobile overlay, and the base this function was ported from:
 *      profile types go to `entityProfilePath(type, id)`.
 *    — it also calls `intelStore.addToRecentPivots(...)` for profile types. That
 *      is a *side effect of the surface*, not of the destination, so it is NOT
 *      folded in here — the call site must keep making it.
 *    — handles `entry` as `uiStore.setSelectedEntry(id)` + `navigate("/")`
 *      (store write, no query param).
 *    — has no `pir` case; a `pir` result would silently do nothing.
 *
 * 3. `CommandPalette.entityRoute` / `entityRouteFromPivotType`
 *    (`components/CommandPalette.tsx:245-271`)
 *    — two near-duplicate tables. `entityRoute` covers only 7 types (no
 *      `country`, no `mitigation`), so country/mitigation results fall to
 *      `/workbench/explore`; `entityRouteFromPivotType` covers all 9 but has no
 *      `detection_rule`, so a pivot to a rule falls to `/workbench/explore`.
 *    — neither has `campaign`, `intel_report` or `pir`: all three land on
 *      `/workbench/explore` with no `setActiveSection`, so the workspace shows
 *      whatever section was last open.
 *    — handles `entry` as `navigate("/?entry=" + id)` (query param, consumed by
 *      `MainLayout.tsx:74-81`) rather than the store write copy 2 uses. This
 *      function keeps the query-param form, because it is expressible as a path
 *      and survives a hard reload.
 *    ⇒ Adopting this function CHANGES the palette: country/mitigation/rule
 *      results reach their profiles, and campaign/report/PIR results reach their
 *      section instead of an arbitrary one.
 *
 * Two further notes for whoever does Step 5:
 * - `campaign` keeps the union behaviour (`/workbench/explore` + section
 *   `campaigns`) even though a real `/workbench/campaign/:id` route exists
 *   (`App.tsx:207`). Switching to it would be a fourth behaviour change; make it
 *   its own decision.
 * - `ransomware_victim` is a canonical entity type (`backend/app/entity_types.py`)
 *   with no frontend profile route, so it falls back to `/workbench/explore`.
 * ---------------------------------------------------------------------------
 */
export function entityDestination(type: string, id: string): EntityDestination {
  const t = TYPE_ALIASES[type] ?? type;

  if (PROFILE_TYPES.includes(t as EntityType)) {
    return { path: entityProfilePath(t as EntityType, id) };
  }

  switch (t) {
    case "detection_rule":
      return { path: `/workbench/rule/${id}` };
    case "intel_report":
      return { path: `/workbench/report/${id}` };
    case "campaign":
      return {
        path: "/workbench/explore",
        before: () => useIntelStore.getState().setActiveSection("campaigns"),
      };
    case "pir":
      return {
        path: "/workbench/explore",
        before: () => useIntelStore.getState().setActiveSection("requirements"),
      };
    case "entry":
      return { path: `/?entry=${id}` };
    default:
      return { path: "/workbench/explore" };
  }
}
