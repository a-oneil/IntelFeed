import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { EntityNote, EntityNoteCreate } from "@/api/types";

export function useAllEntityNotes(params?: { limit?: number; offset?: number; note_type?: string; entity_type?: string; q?: string }) {
  return useQuery({
    queryKey: ["entity-notes", "all", params],
    queryFn: async () => {
      const { data } = await api.get<{ items: EntityNote[]; total: number; has_more: boolean }>(
        "/entity-notes/search",
        { params },
      );
      return data;
    },
  });
}

export function useEntityNotes(entityType: string, entityId: string | undefined) {
  return useQuery({
    queryKey: ["entity-notes", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<{ items: EntityNote[] }>("/entity-notes", {
        params: { entity_type: entityType, entity_id: entityId },
      });
      return data.items;
    },
    enabled: !!entityId,
  });
}

export function useCreateEntityNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: EntityNoteCreate) => {
      const { data } = await api.post<EntityNote>("/entity-notes", body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({
        queryKey: ["entity-notes", vars.entity_type, vars.entity_id],
      });
      qc.invalidateQueries({ queryKey: ["entity-notes", "all"] });
    },
  });
}

export function useUpdateEntityNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      ...body
    }: { id: string; title?: string | null; content?: string; note_type?: string; tags?: string[] }) => {
      const { data } = await api.put<EntityNote>(`/entity-notes/${id}`, body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity-notes"] });
    },
  });
}

export function useDeleteEntityNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/entity-notes/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity-notes"] });
    },
  });
}
