import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

interface DateRangeParams {
  date_from?: string;
  date_to?: string;
}

export interface FeedHealthItem {
  id: string;
  name: string;
  last_fetched_at: string | null;
  error_count: number;
  last_error: string | null;
  is_muted: boolean;
  hours_since_fetch: number | null;
}

export function useFeedHealth(params?: { limit?: number }) {
  return useQuery({
    queryKey: ["widgets", "feed-health", params],
    queryFn: async () => {
      const res = await api.get<FeedHealthItem[]>("/widgets/feed-health", { params });
      return res.data;
    },
    refetchInterval: 60_000,
  });
}

export interface WorkerQueueData {
  queues: Array<{ name: string; pending: number }>;
  total_pending: number;
  redis_ok: boolean;
}

export function useWorkerQueue() {
  return useQuery({
    queryKey: ["widgets", "worker-queue"],
    queryFn: async () => {
      const res = await api.get<WorkerQueueData>("/widgets/worker-queue");
      return res.data;
    },
    refetchInterval: 30_000,
  });
}

export interface AIUsageProvider {
  provider_id: string | null;
  provider_name: string;
  model_name: string | null;
  calls: number;
  tokens_input: number;
  tokens_output: number;
  cost_estimate: number;
}

export interface AIUsageData {
  providers: AIUsageProvider[];
  totals: {
    calls: number;
    tokens_input: number;
    tokens_output: number;
    cost_estimate: number;
  };
}

export function useAIUsage(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "ai-usage", params],
    queryFn: async () => {
      const res = await api.get<AIUsageData>("/widgets/ai-usage", { params });
      return res.data;
    },
  });
}
