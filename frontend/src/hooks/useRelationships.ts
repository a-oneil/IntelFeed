import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  EntityRelationship,
  EntityRelationshipCreate,
  EntityRelationshipUpdate,
  PaginatedResponse,
} from "@/api/types";

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
