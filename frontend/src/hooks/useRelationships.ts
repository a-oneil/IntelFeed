import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  EntityRelationship,
  EntityRelationshipCreate,
  EntityRelationshipUpdate,
  PaginatedResponse,
} from "@/api/types";

/** Which enrichment sources claim an entity's connections
 *  (GET /entity-relationships/claims/{type}/{id}). */
export interface RelationClaims {
  entity_type: string;
  entity_id: string;
  /** Linked claims per source, most first. */
  sources: Array<{ source_type: string; label: string; linked: number }>;
  /** `<type>-<id>` of a connected entity → the sources whose claim names it. */
  by_target: Record<string, string[]>;
  /** Names a source gave that matched no entity, or several, held for review. */
  held: Array<{
    source_type: string;
    source_label: string;
    relation: string;
    target_name: string;
    target_type: string | null;
    held_reason: "unknown" | "ambiguous" | string | null;
    evidence: string | null;
  }>;
  held_count: number;
}

/** Signed-in only: held names can come from sources a visitor doesn't see. */
export function useRelationClaims(entityType: string | undefined, entityId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["relation-claims", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<RelationClaims>(`/entity-relationships/claims/${entityType}/${entityId}`);
      return data;
    },
    enabled: enabled && !!entityType && !!entityId,
    // Supplementary: without it the rows simply carry no source tag.
    meta: { silenceToast: true },
    staleTime: 60_000,
  });
}

export function useEntityRelationships(
  entityType: string | undefined,
  entityId: string | undefined,
) {
  return useQuery({
    queryKey: ["relationships", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<EntityRelationship>>(
        "/entity-relationships",
        {
          params: {
            entity_type: entityType,
            entity_id: entityId,
            limit: 100,
          },
        },
      );
      return data;
    },
    enabled: !!entityType && !!entityId,
  });
}

export function useCreateRelationship() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: EntityRelationshipCreate) => {
      const { data } = await api.post<EntityRelationship>(
        "/entity-relationships",
        body,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["relationships"] });
      qc.invalidateQueries({ queryKey: ["pivot"] });
      qc.invalidateQueries({ queryKey: ["entity-graph"] });
    },
  });
}

export function useUpdateRelationship() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      ...body
    }: EntityRelationshipUpdate & { id: string }) => {
      const { data } = await api.put<EntityRelationship>(
        `/entity-relationships/${id}`,
        body,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["relationships"] });
    },
  });
}

export function useDeleteRelationship() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entity-relationships/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["relationships"] });
    },
  });
}

export interface RelationshipSignalTop {
  verb: string;
  direction: "outbound" | "inbound";
  other_type: string;
  other_label: string | null;
  confidence: string;
}

export interface RelationshipSignals {
  count: number;
  top: RelationshipSignalTop[];
}

/** Batched relationship signals for table columns — one request per loaded page.
 * POST body, not query params: the id list grows with every infinite-scroll page
 * and overflows the server's request-line limit (414) as a GET. */
export function useRelationshipSignals(entityType: string | undefined, ids: string[]) {
  return useQuery({
    queryKey: ["relationship-signals", entityType, ids.join(",")],
    queryFn: async () => {
      const { data } = await api.post<Record<string, RelationshipSignals>>(
        `/entity-relationships/signals/${entityType}`,
        { ids },
      );
      return data;
    },
    enabled: !!entityType && ids.length > 0,
    staleTime: 60_000,
  });
}

export function useConfirmRelationship() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.post<EntityRelationship>(`/entity-relationships/${id}/confirm`);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["relationships"] });
      qc.invalidateQueries({ queryKey: ["pivot"] });
    },
  });
}

export function useRejectRelationship() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.post<EntityRelationship>(`/entity-relationships/${id}/reject`);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["relationships"] });
      qc.invalidateQueries({ queryKey: ["pivot"] });
    },
  });
}
