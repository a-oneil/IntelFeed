import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { PlaybackInProgressItem, PlaybackProgress, PodcastShow } from "@/api/types";

export function usePodcasts() {
  return useQuery({
    queryKey: ["podcasts"],
    queryFn: async () => {
      const res = await api.get<PodcastShow[]>("/podcasts");
      return res.data;
    },
  });
}

export function usePodcast(feedId: string | null) {
  return useQuery({
    queryKey: ["podcast", feedId],
    queryFn: async () => {
      const res = await api.get<PodcastShow>(`/podcasts/${feedId}`);
      return res.data;
    },
    enabled: !!feedId,
  });
}

export function usePlaybackProgress(mediaId: string | null) {
  return useQuery({
    queryKey: ["playback", mediaId],
    queryFn: async () => {
      const res = await api.get<PlaybackProgress | null>(`/playback/${mediaId}/progress`);
      return res.data;
    },
    enabled: !!mediaId,
  });
}

export function useUpdatePlayback() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ mediaId, position }: { mediaId: string; position: number }) => {
      const res = await api.put<PlaybackProgress>(`/playback/${mediaId}/progress`, {
        position_seconds: position,
      });
      return res.data;
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["playback", variables.mediaId] });
    },
  });
}

export function useMarkPlaybackComplete() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (mediaId: string) => {
      const res = await api.put<PlaybackProgress>(`/playback/${mediaId}/complete`);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["playback"] });
    },
  });
}

export function useInProgressMedia() {
  return useQuery({
    queryKey: ["playback", "in-progress"],
    queryFn: async () => {
      const res = await api.get<PlaybackInProgressItem[]>("/playback/in-progress");
      return res.data;
    },
  });
}
