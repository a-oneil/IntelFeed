import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

interface DateRangeParams {
  date_from?: string;
  date_to?: string;
}

export interface TriageQueueStats {
  unread: number;
  starred: number;
  total: number;
}

export interface SavedSearchHit {
  id: string;
  name: string;
  query: string | null;
  unread: number;
  total: number;
}

export interface TopTagItem {
  id: string;
  name: string;
  color: string;
  entry_count: number;
}

export interface TelegramMentionItem {
  handle: string;
  display_handle: string | null;
  canonical_url: string;
  mention_count: number;
  last_seen_at: string | null;
  primary_link_type: string;
}

export function useTriageQueueStats() {
  return useQuery({
    queryKey: ["widgets", "triage-queue-stats"],
    queryFn: async () => {
      const res = await api.get<TriageQueueStats>("/widgets/triage-queue-stats");
      return res.data;
    },
    refetchInterval: 60_000,
  });
}

export function useSavedSearchHits() {
  return useQuery({
    queryKey: ["widgets", "saved-search-hits"],
    queryFn: async () => {
      const res = await api.get<SavedSearchHit[]>("/widgets/saved-search-hits");
      return res.data;
    },
  });
}

export function useTopTags(params?: DateRangeParams & { limit?: number }) {
  return useQuery({
    queryKey: ["widgets", "top-tags", params],
    queryFn: async () => {
      const res = await api.get<TopTagItem[]>("/widgets/top-tags", { params });
      return res.data;
    },
  });
}

export function useTelegramMentionsWidget(params?: DateRangeParams & { limit?: number }) {
  return useQuery({
    queryKey: ["widgets", "telegram-mentions", params],
    queryFn: async () => {
      const res = await api.get<TelegramMentionItem[]>("/widgets/telegram-mentions", { params });
      return res.data;
    },
  });
}
