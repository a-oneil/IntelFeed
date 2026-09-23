import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { StoryThread, StoryThreadDetail, ThreadListResponse } from "@/api/types";

/**
 * Open story threads — one unfolding story instead of the twenty-three articles
 * that reported it. Used by the entry list to fold the pile into a single row
 * and by the threads page to browse what is running.
 */
export function useOpenThreads(enabled = true, limit = 40) {
  return useQuery({
    queryKey: ["threads", "open", limit],
    queryFn: async () => {
      const res = await api.get<ThreadListResponse>("/threads", { params: { status: "open", limit } });
      return res.data;
    },
    enabled,
    staleTime: 60_000,
    refetchInterval: 300_000,
  });
}

export function useThread(slug: string | null) {
  return useQuery({
    queryKey: ["thread", slug],
    queryFn: async () => {
      const res = await api.get<StoryThreadDetail>(`/threads/${slug}`);
      return res.data;
    },
    enabled: !!slug,
    staleTime: 60_000,
  });
}

/** Stamps the thread as seen, which is what "N new" is measured from. */
export function useOpenThreadMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (threadId: string) => {
      await api.post(`/threads/${threadId}/open`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["threads"] });
    },
  });
}

export type { StoryThread, StoryThreadDetail };
