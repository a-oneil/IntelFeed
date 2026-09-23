import { useMemo } from "react";
import { useLocation, useParams } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import { useIntelStore } from "@/stores/intelStore";
import type { CopilotContext } from "@/hooks/useAI";

/**
 * Route slugs are the canonical entity_type since the 2026-08 vocabulary
 * unification, so no translation table is needed.
 */

/**
 * Extracts an entity slug + id from a workbench-style pathname. Handles routes
 * like `/workbench/threat_actor/<id>` and `/intelligence/malware/<id>`. Returns null
 * for the campaign slug (handled separately as campaign_id) and non-entity paths.
 */
function parseEntityFromPath(pathname: string): { slug: string; id: string } | null {
  const match = pathname.match(
    /\/(actor|threat_actor|malware|cve|ttp|country|tool|mitigation|vendor|product)\/([^/?#]+)/,
  );
  if (!match) return null;
  return { slug: match[1], id: decodeURIComponent(match[2]) };
}

function parseCampaignFromPath(pathname: string): string | null {
  const match = pathname.match(/\/campaign\/([^/?#]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Assembles the ambient `context` object for a copilot request from the current
 * route + UI/intel store state. Sources, in priority order per field:
 *   - entry_id: uiStore.selectedEntryId
 *   - entity_type/entity_id: the URL entity slug (preferred, always fresh on
 *     navigation), falling back to intelStore.selectedEntityType/Id
 *   - campaign_id: the URL campaign slug
 *   - search_query: uiStore.headerSearchQuery / intelStore.workspaceSearchQuery
 *   - route: the current pathname
 *
 * Returns null when no context is available so the request body sends an
 * explicit null (per the frozen contract).
 */
export function useCopilotContext(): CopilotContext | null {
  const location = useLocation();
  const params = useParams();

  const selectedEntryId = useUIStore((s) => s.selectedEntryId);
  const headerSearchQuery = useUIStore((s) => s.headerSearchQuery);
  const selectedEntityType = useIntelStore((s) => s.selectedEntityType);
  const selectedEntityId = useIntelStore((s) => s.selectedEntityId);
  const workspaceSearchQuery = useIntelStore((s) => s.workspaceSearchQuery);

  const pathname = location.pathname;
  const routeId = params.id;

  return useMemo(() => {
    const context: CopilotContext = {};

    if (selectedEntryId) context.entry_id = selectedEntryId;

    // Prefer the entity encoded in the URL — it always reflects the page the
    // user is actually on. Fall back to the intel store's selected entity.
    const fromPath = parseEntityFromPath(pathname);
    if (fromPath) {
      const entityType = fromPath.slug;
      if (entityType) {
        context.entity_type = entityType;
        context.entity_id = routeId ?? fromPath.id;
      }
    } else if (selectedEntityType && selectedEntityId) {
      context.entity_type = selectedEntityType;
      context.entity_id = selectedEntityId;
    }

    const campaignId = parseCampaignFromPath(pathname);
    if (campaignId) context.campaign_id = campaignId;

    const searchQuery = (headerSearchQuery || workspaceSearchQuery || "").trim();
    if (searchQuery) context.search_query = searchQuery;

    if (pathname) context.route = pathname;

    return Object.keys(context).length > 0 ? context : null;
  }, [
    pathname,
    routeId,
    selectedEntryId,
    headerSearchQuery,
    selectedEntityType,
    selectedEntityId,
    workspaceSearchQuery,
  ]);
}
