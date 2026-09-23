import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { Comment, CommentCreate } from "@/api/types";

export function useComments(commentableType: string, commentableId: string | undefined) {
  return useQuery({
    queryKey: ["comments", commentableType, commentableId],
    queryFn: async () => {
      const { data } = await api.get<{ items: Comment[] }>("/comments", {
        params: { commentable_type: commentableType, commentable_id: commentableId },
      });
      return data.items;
    },
    enabled: !!commentableId,
  });
}

export function useCreateComment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: CommentCreate) => {
      const { data } = await api.post<Comment>("/comments", body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({
        queryKey: ["comments", vars.commentable_type, vars.commentable_id],
      });
    },
  });
}

export function useUpdateComment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, content }: { id: string; content: string }) => {
      const { data } = await api.patch<Comment>(`/comments/${id}`, { content });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["comments"] });
    },
  });
}

export function useDeleteComment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/comments/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["comments"] });
    },
  });
}
