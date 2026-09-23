import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import api from "@/api/client";
import type { EntityRelationship, PaginatedResponse } from "@/api/types";

/** One entry→entity autolink row, normalized across all junction tables. */
export interface EntityLink {
  entity_type: string;
  entity_id: string;
  entity_name: string | null;
  entry_id: string;
  entry_title: string | null;
  confidence: string | null;
  source: string | null;
  matched_names: string[] | null;
  paragraph_indices: number[] | null;
  extracted_at: string;
}

export interface EntityLinkStats {
  total: number;
  by_source: Record<string, number>;
  by_type: Record<string, number>;
  pending: number;
  pending_ready: number;
  relationships_total: number;
}

export interface LinkRef {
  entity_type: string;
  entity_id: string;
  entry_id: string;
}

export interface EntityLinkFilters {
  entity_type?: string;
  entry_id?: string;
  source?: string;
  confidence?: string;
  search?: string;
  days?: number;
  limit: number;
  offset: number;
}

export function useEntityLinks(filters: EntityLinkFilters, enabled = true) {
  return useQuery({
    queryKey: ["entity-links", filters],
    queryFn: async () => {
      const params: Record<string, string | number> = {
        limit: filters.limit,
        offset: filters.offset,
      };
      if (filters.entity_type) params.entity_type = filters.entity_type;
      if (filters.entry_id) params.entry_id = filters.entry_id;
      if (filters.source) params.source = filters.source;
      if (filters.confidence) params.confidence = filters.confidence;
      if (filters.search) params.search = filters.search;
      if (filters.days) params.days = filters.days;
      const { data } = await api.get<PaginatedResponse<EntityLink>>("/entity-links", { params });
      return data;
    },
    staleTime: 30_000,
    enabled,
  });
}

export function useEntityLinkStats() {
  return useQuery({
    queryKey: ["entity-links", "stats"],
    queryFn: async () => (await api.get<EntityLinkStats>("/entity-links/stats")).data,
    staleTime: 60_000,
  });
}

const refKey = (r: LinkRef | EntityLink) => `${r.entity_type}|${r.entity_id}|${r.entry_id}`;

/** Drop the given links from every cached list page immediately, so the table
 *  updates on click instead of waiting on the (slow) 380k-row list refetch.
 *  Returns the prior cache snapshot for rollback on error. */
function optimisticallyRemoveLinks(qc: ReturnType<typeof useQueryClient>, refs: LinkRef[]) {
  const kill = new Set(refs.map(refKey));
  const prev = qc.getQueriesData<PaginatedResponse<EntityLink>>({ queryKey: ["entity-links"] });
  qc.setQueriesData<PaginatedResponse<EntityLink>>({ queryKey: ["entity-links"] }, (old) => {
    // Skip the stats cache and anything that isn't a link list page.
    if (!old || !Array.isArray(old.items)) return old;
    const items = old.items.filter((l) => !kill.has(refKey(l)));
    const removed = old.items.length - items.length;
    return removed ? { ...old, items, total: Math.max(0, (old.total ?? 0) - removed) } : old;
  });
  return prev;
}

export function useUnlink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (ref: LinkRef) => {
      await api.delete(`/entity-links/${ref.entity_type}/${ref.entity_id}/${ref.entry_id}`);
    },
    onMutate: async (ref) => {
      await qc.cancelQueries({ queryKey: ["entity-links"] });
      return { prev: optimisticallyRemoveLinks(qc, [ref]) };
    },
    onError: (_e, _v, ctx) => ctx?.prev?.forEach(([key, data]) => qc.setQueryData(key, data)),
    // Reconcile in the background — do NOT return the promise, or mutateAsync
    // would stay pending through the heavy list refetch and block the caller.
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ["entity-links"] });
    },
  });
}

export function useBulkUnlink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (items: LinkRef[]) => {
      const { data } = await api.post<{ deleted: number }>("/entity-links/bulk-unlink", { items });
      return data;
    },
    onMutate: async (items) => {
      await qc.cancelQueries({ queryKey: ["entity-links"] });
      return { prev: optimisticallyRemoveLinks(qc, items) };
    },
    onError: (_e, _v, ctx) => ctx?.prev?.forEach(([key, data]) => qc.setQueryData(key, data)),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ["entity-links"] });
    },
  });
}

export interface RelationshipFilters {
  entity_type?: string;
  relationship_type?: string;
  evidence_entry_id?: string;
  limit: number;
  offset: number;
}

/** Global paginated relationships list for the Autolinking tab.
 * Keyed under the shared "relationships" prefix so the existing
 * confirm/reject/delete mutations invalidate it. */
export function useAllRelationships(filters: RelationshipFilters, enabled = true) {
  return useQuery({
    queryKey: ["relationships", "all", filters],
    queryFn: async () => {
      const params: Record<string, string | number | boolean> = {
        limit: filters.limit,
        offset: filters.offset,
        // Management view: show every stored edge regardless of the
        // relationship_min_confidence display setting.
        all_confidence: true,
      };
      if (filters.entity_type) params.entity_type = filters.entity_type;
      if (filters.relationship_type) params.relationship_type = filters.relationship_type;
      if (filters.evidence_entry_id) params.evidence_entry_id = filters.evidence_entry_id;
      const { data } = await api.get<PaginatedResponse<EntityRelationship>>("/entity-relationships", { params });
      return data;
    },
    staleTime: 30_000,
    enabled,
  });
}
