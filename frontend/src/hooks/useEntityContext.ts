import { useQuery, useQueries, type UseQueryResult } from "@tanstack/react-query";
import api from "@/api/client";

/**
 * Entity context — what the enabled enrichment sources say about one entity,
 * shaped by each source's manifest (GET /entities/{type}/{id}/context).
 * Lives in its own file, beside useEnrichment.ts, so the console and the
 * profile panel don't fight over one module.
 */

export type ContextDisplay = "fact" | "chips" | "table" | "timeline" | "link" | "badge";

export interface ContextTableValue {
  columns: string[];
  rows: Array<Array<string | number | null>>;
}

export interface ContextTimelineEvent {
  date: string;
  text: string;
}

/** A link item's value: always an object; the label is optional. */
export interface ContextLinkValue {
  url: string;
  label?: string;
}

interface ContextItemBase {
  key: string;
  label: string;
}

export type EntityContextItem =
  | (ContextItemBase & { display: "fact"; value: string | number })
  | (ContextItemBase & { display: "chips"; value: string[] })
  | (ContextItemBase & { display: "timeline"; value: ContextTimelineEvent[] })
  | (ContextItemBase & { display: "table"; value: ContextTableValue })
  | (ContextItemBase & { display: "link"; value: ContextLinkValue })
  | (ContextItemBase & { display: "badge"; value: unknown });

export interface EntityContextSource {
  source_type: string;
  label: string;
  license: { name: string; attribution: string | null } | null;
  observed_at: string | null;
  /** Past the row's expires_at. */
  stale: boolean;
  items: EntityContextItem[];
}

export interface EntityContextUnavailable {
  source_type: string;
  label: string;
  /** The missing requirement, e.g. "api_key". */
  needs: string;
}

export interface EntityContextBadge {
  source_type: string;
  key: string;
  label: string;
  tone: string;
  /** The entity column the badge mirrors, for its provenance marker. */
  field?: string;
}

export interface EntityContext {
  sources: EntityContextSource[];
  /** Admins only; empty for everyone else. */
  unavailable: EntityContextUnavailable[];
  badges: EntityContextBadge[];
  can_enrich: boolean;
}

export const entityContextKey = (entityType: string, entityId: string) =>
  ["entity-context", entityType, entityId] as const;

/** Shared by the header badges and the Overview Context panel (one request). */
export function useEntityContext(entityType: string, entityId: string) {
  return useQuery({
    queryKey: entityContextKey(entityType, entityId),
    queryFn: async () => {
      const { data } = await api.get<EntityContext>(`/entities/${entityType}/${entityId}/context`);
      return data;
    },
    enabled: !!entityType && !!entityId,
    // Supplementary: a failure hides the panel rather than toasting on every visit.
    meta: { silenceToast: true },
    staleTime: 60_000,
  });
}

/** An enrichment value the entity table can show as a column (GET /entities/{type}/context-columns). */
export interface ContextColumn {
  /** `ctx:<source_type>:<key>` — the list endpoint's sort_by value and filter parameter. */
  id: string;
  source_type: string;
  source_label: string;
  key: string;
  label: string;
  display: "fact" | "badge" | "chips";
}

export function useContextColumns(entityType: string) {
  return useQuery({
    queryKey: ["context-columns", entityType],
    queryFn: async () => {
      const { data } = await api.get<ContextColumn[]>(`/entities/${entityType}/context-columns`);
      return data;
    },
    enabled: !!entityType,
    meta: { silenceToast: true },
    staleTime: 5 * 60_000,
  });
}

type ContextValues = Record<string, Record<string, unknown>>;

/** Module-level so useQueries keeps the merged map's identity until a page changes. */
function mergeContextValues(results: UseQueryResult<ContextValues>[]): ContextValues {
  return Object.assign({}, ...results.map((r) => r.data ?? {}));
}

/**
 * `{entity_id: {column_id: value}}` for a paged table's rows; rows with nothing
 * are absent. One request per page of ids, so a page is fetched once as it
 * loads and earlier pages stay cached, however far the table scrolls.
 */
export function useContextValues(entityType: string, pages: string[][], enabled: boolean) {
  return useQueries({
    queries: pages.map((ids) => ({
      queryKey: ["context-values", entityType, ids.join(",")],
      queryFn: async () => {
        const { data } = await api.post<ContextValues>(`/entities/${entityType}/context-values`, { ids });
        return data;
      },
      enabled: enabled && !!entityType && ids.length > 0,
      meta: { silenceToast: true },
      staleTime: 60_000,
    })),
    combine: mergeContextValues,
  });
}
