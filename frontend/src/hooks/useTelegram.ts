import { useMutation, useQuery } from "@tanstack/react-query";
import api from "@/api/client";

export interface TelegramDiscoveredChannel {
  channel_id: number;
  username: string | null;
  title: string;
  subscribers: number | null;
  verified: boolean;
  scam: boolean;
  fake: boolean;
  is_private: boolean;
  is_subscribed: boolean;
  feed_id: string | null;
}

export interface TelegramDiscoveryResponse {
  items: TelegramDiscoveredChannel[];
  total: number;
  subscribed_count: number;
  unsubscribed_count: number;
}

export interface TelegramFeedHealth {
  feed_id: string;
  title: string;
  is_active: boolean;
  last_fetched_at: string | null;
  fetch_interval_minutes: number;
  error_count: number;
  last_error: string | null;
  channel: {
    channel_id: number | null;
    channel_username: string | null;
    configured_handle: string | null;
  };
  session: { name: string };
  watermark: { last_seen_id: number | null };
  attribution: {
    threat_actor_id: string | null;
    campaign_id: string | null;
  };
  media: { include_media: boolean; extract_forwards: boolean };
  realtime_enabled: boolean;
  recent_7d: { total: number; edited: number; deleted: number };
  flood_wait_seconds: number | null;
  live: {
    available: boolean;
    title?: string;
    subscribers?: number | null;
    verified?: boolean;
    scam?: boolean;
    fake?: boolean;
    error?: string;
  };
}

export interface TelegramListenerStatus {
  running: boolean;
  last_heartbeat_age_seconds?: number;
  subscribed_channels?: number;
  error?: string;
}

export function useDiscoverTelegramChannels(enabled: boolean, sessionName: string = "") {
  return useQuery({
    queryKey: ["telegram-discover", sessionName],
    queryFn: async () => {
      const res = await api.get<TelegramDiscoveryResponse>("/telegram/discover", {
        params: sessionName ? { session_name: sessionName } : undefined,
      });
      return res.data;
    },
    enabled,
    staleTime: 60_000,
    retry: false,
  });
}

export function useDiscoverTelegramChannelsLazy() {
  return useMutation({
    mutationFn: async (sessionName: string = "") => {
      const res = await api.get<TelegramDiscoveryResponse>("/telegram/discover", {
        params: sessionName ? { session_name: sessionName } : undefined,
      });
      return res.data;
    },
  });
}

export function useTelegramFeedHealth(feedId: string | null) {
  return useQuery({
    queryKey: ["telegram-health", feedId],
    queryFn: async () => {
      const res = await api.get<TelegramFeedHealth>(`/telegram/feeds/${feedId}/health`);
      return res.data;
    },
    enabled: !!feedId,
    staleTime: 30_000,
    retry: false,
  });
}

export function useTelegramListenerStatus(enabled: boolean = true) {
  return useQuery({
    queryKey: ["telegram-listener-status"],
    queryFn: async () => {
      const res = await api.get<TelegramListenerStatus>("/telegram/listener/status");
      return res.data;
    },
    enabled,
    refetchInterval: 30_000,
    retry: false,
  });
}

// ---------------------------------------------------------------------------
// Telegram link mentions (Workbench panel)
// ---------------------------------------------------------------------------

export interface TelegramMention {
  id: string;
  handle: string;
  display_handle: string | null;
  canonical_url: string;
  primary_link_type: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  mention_count: number;
  distinct_feed_count: number;
  is_subscribed: boolean;
  feed_id: string | null;
  is_dismissed: boolean;
  dismissed_at: string | null;
  notes: string | null;
}

export interface TelegramMentionDetail extends TelegramMention {
  samples: Array<{
    link_id: string;
    url: string;
    link_type: string;
    message_id: number | null;
    discovered_at: string | null;
    entry: {
      id: string;
      title: string | null;
      url: string | null;
      published_at: string | null;
    };
    feed: { id: string; title: string | null; feed_type: string } | null;
  }>;
}

export interface TelegramMentionsListResponse {
  items: TelegramMention[];
  total: number;
  limit: number;
  offset: number;
}

export interface TelegramMentionsFilters {
  only_unsubscribed?: boolean;
  only_active?: boolean;
  link_type?: string;
  sort?: "last_seen" | "first_seen" | "mentions" | "feeds";
  limit?: number;
  offset?: number;
}

export function useTelegramMentions(filters: TelegramMentionsFilters = {}) {
  return useQuery({
    queryKey: ["telegram-mentions", filters],
    queryFn: async () => {
      const res = await api.get<TelegramMentionsListResponse>("/telegram/mentions", {
        params: filters,
      });
      return res.data;
    },
    staleTime: 30_000,
  });
}

export function useTelegramMentionDetail(mentionId: string | null) {
  return useQuery({
    queryKey: ["telegram-mention-detail", mentionId],
    queryFn: async () => {
      const res = await api.get<TelegramMentionDetail>(`/telegram/mentions/${mentionId}`);
      return res.data;
    },
    enabled: !!mentionId,
    staleTime: 30_000,
  });
}

export function useDismissTelegramMention() {
  return useMutation({
    mutationFn: async (mentionId: string) => {
      const res = await api.post(`/telegram/mentions/${mentionId}/dismiss`);
      return res.data;
    },
  });
}

export function useUndismissTelegramMention() {
  return useMutation({
    mutationFn: async (mentionId: string) => {
      const res = await api.post(`/telegram/mentions/${mentionId}/undismiss`);
      return res.data;
    },
  });
}

export function useSubscribeToTelegramMention() {
  return useMutation({
    mutationFn: async (mentionId: string) => {
      const res = await api.post<{
        id: string;
        subscribed?: boolean;
        already_subscribed?: boolean;
        feed_id: string;
        url?: string;
      }>(`/telegram/mentions/${mentionId}/subscribe`);
      return res.data;
    },
  });
}
