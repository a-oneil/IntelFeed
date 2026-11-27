import { useIntelStore } from "@/stores/intelStore";
import { entityProfilePath } from "@/components/entityProfile/entityProfileConfig";
import type { EntityType } from "@/stores/intelStore";

export interface EntityDestination {
  /** Router path to navigate to. */
  path: string;
  /** Store mutation that must run *before* the navigation, for the section-scoped destinations that land on `/workbench/explore` and need the workspace to already be on the right section. */
  before?: () => void;
}

/** Canonical entity types that have a full-width profile route (the `/workbench/<type>/:id` routes in `App.tsx`). Campaign also has one but is routed to its section below. */
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

/** Pre-canonical spellings still produced by saved queries, the workbench `type:` filter (`TYPE_FILTER_MAP`) and old search-index rows. `actor` is the pre-2026-08 `threat_actor` slug; `App.tsx` still keeps redirect routes for it. */
const TYPE_ALIASES: Record<string, string> = {
  actor: "threat_actor",
  rule: "detection_rule",
};

/**
 * The single "where does clicking this search result go?" table.
 *
 * NOT YET WIRED UP: only its tests import it. It was added by the search consolidation so the remaining routing copies can be replaced with it, and that replacement changes behavior, because the copies disagree:
 *
 * 1. `useEntityResultNavigate` (`components/search/EntityResults.tsx`) is the current convention, used by `/search` and the workbench's mobile overlay, and the base this function was ported from. Profile types go to `entityProfilePath(type, id)`. It also calls `intelStore.addToRecentPivots(...)` for profile types. That is a side effect of the search surface, not of the destination, so it is NOT folded in here; the call site must keep making it. It handles `entry` as `uiStore.setSelectedEntry(id)` + `navigate("/")` (a store write, no query param). It has no `pir` case, so a `pir` result does nothing. This function is where that gets fixed.
 *
 * 2. `entityRouteFromPivotType` (`components/CommandPalette.tsx`) routes the palette's recent pivots. It sends eleven profile types (all of PROFILE_TYPES except `observable`) to their profiles; anything else (`detection_rule`, `campaign`, `intel_report`, `pir`) lands on `/workbench/explore` with no `setActiveSection`, so the workspace shows whatever section was last open. Adopting this function CHANGES the palette: rule and report results reach their pages, and campaign/PIR results reach their section.
 *
 * `entry` goes to `/?entry=<id>` (a query param, read by `pages/MainLayout.tsx`) rather than the store write copy 1 uses, because it is expressible as a path and survives a hard reload.
 *
 * Two further notes for whoever wires this up:
 * - `campaign` goes to `/workbench/explore` + section `campaigns`, as copy 1 does, even though a `/workbench/campaign/:id` profile route exists in `App.tsx`. Switching to it would be another behavior change; make it its own decision.
 * - `ransomware_victim` is a canonical entity type (`backend/app/entity_types.py`) with no frontend profile route, so it falls back to `/workbench/explore`.
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
