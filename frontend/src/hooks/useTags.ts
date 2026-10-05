import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { Tag } from "@/api/types";

/** How a tag looks and who sees it: colour, chip rendering, chip tooltip, and scope. */
export interface TagPresentation {
  color?: string;
  display_as_chip?: boolean;
  description?: string;
  /** Global tags have one shared assignment per entry; personal tags are each user's own. */
  is_global?: boolean;
}

export function useTags() {
  return useQuery({
    queryKey: ["tags"],
    queryFn: async () => {
      const res = await api.get<Tag[]>("/tags");
      return res.data;
    },
  });
}

export function useEntryTags(entryId: string | null) {
  return useQuery({
    queryKey: ["entry-tags", entryId],
    queryFn: async () => {
      const res = await api.get<Tag[]>(`/tags/entries/${entryId}`);
      return res.data;
    },
    enabled: !!entryId,
  });
}

export function useCreateTag() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: TagPresentation & { name: string }) => {
      const res = await api.post<Tag>("/tags", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
    },
  });
}

export function useUpdateTag() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ tagId, data }: { tagId: string; data: TagPresentation & { name?: string } }) => {
      const res = await api.put<Tag>(`/tags/${tagId}`, data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
      // Promoting/demoting or recolouring changes how every card draws the tag;
      // a scope flip changes which cards carry it and what the facet rail counts.
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entry"] });
      queryClient.invalidateQueries({ queryKey: ["entry-tags"] });
      queryClient.invalidateQueries({ queryKey: ["unified-search"] });
    },
  });
}

export function useDeleteTag() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (tagId: string) => {
      await api.delete(`/tags/${tagId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
    },
  });
}

export function useAddTagsToEntry() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ entryId, tagIds }: { entryId: string; tagIds: string[] }) => {
      const res = await api.post(`/tags/entries/${entryId}`, { tag_ids: tagIds });
      return res.data;
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
      queryClient.invalidateQueries({ queryKey: ["entry-tags", variables.entryId] });
      queryClient.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}

export function useRemoveTagFromEntry() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ entryId, tagId }: { entryId: string; tagId: string }) => {
      await api.delete(`/tags/entries/${entryId}/${tagId}`);
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
      queryClient.invalidateQueries({ queryKey: ["entry-tags", variables.entryId] });
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      // The chip × lives on the reader and search cards too.
      queryClient.invalidateQueries({ queryKey: ["entry", variables.entryId] });
      queryClient.invalidateQueries({ queryKey: ["unified-search"] });
    },
  });
}

export function useBulkTag() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ entryIds, tagIds }: { entryIds: string[]; tagIds: string[] }) => {
      const res = await api.post("/tags/entries/bulk-tag", {
        entry_ids: entryIds,
        tag_ids: tagIds,
      });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
      queryClient.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}

export function useBulkUntag() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ entryIds, tagIds }: { entryIds: string[]; tagIds: string[] }) => {
      const res = await api.post("/tags/entries/bulk-untag", {
        entry_ids: entryIds,
        tag_ids: tagIds,
      });
      return res.data as { removed: number };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entry-tags"] });
    },
  });
}

export function useMergeTags() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ sourceIds, targetId }: { sourceIds: string[]; targetId: string }) => {
      const res = await api.post<Tag>("/tags/merge", {
        source_ids: sourceIds,
        target_id: targetId,
      });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags"] });
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["entry-tags"] });
    },
  });
}
