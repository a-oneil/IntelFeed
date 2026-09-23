import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  AnalyticsOverview,
  TrendingEntity,
  DetectionCoverageResponse,
  VelocityResponse,
  EntryInsight,
  FeedHealthResponse,
  FeedValueResponse,
} from "@/api/types";

export function useAnalyticsOverview(params?: { date_from?: string; date_to?: string }) {
  return useQuery({
    queryKey: ["analytics", "overview", params],
    queryFn: async () => {
      const { data } = await api.get<AnalyticsOverview>("/analytics/overview", { params });
      return data;
    },
  });
}

export function useTrendingEntities(
  entityType: string,
  params?: { days?: number; limit?: number },
) {
  return useQuery({
    queryKey: ["analytics", "trending", entityType, params],
    queryFn: async () => {
      const { data } = await api.get<TrendingEntity[]>(
        `/analytics/trending/${entityType}`,
        { params },
      );
      return data;
    },
  });
}

export function useDetectionCoverageAnalytics(includeGaps = true) {
  return useQuery({
    queryKey: ["analytics", "detection-coverage", includeGaps],
    queryFn: async () => {
      const { data } = await api.get<DetectionCoverageResponse>(
        "/analytics/detection-coverage",
        { params: { include_gaps: includeGaps } },
      );
      return data;
    },
  });
}

export function useIntelVelocity(days = 30) {
  return useQuery({
    queryKey: ["analytics", "velocity", days],
    queryFn: async () => {
      const { data } = await api.get<VelocityResponse>("/analytics/velocity", {
        params: { days },
      });
      return data;
    },
  });
}

export function useEntryInsights(entryId: string | undefined) {
  return useQuery({
    queryKey: ["analytics", "entry-insights", entryId],
    queryFn: async () => {
      const { data } = await api.get<EntryInsight[]>(
        `/analytics/entries/${entryId}/insights`,
      );
      return data;
    },
    enabled: !!entryId,
  });
}

export function useFeedValueScores(days = 90) {
  return useQuery({
    queryKey: ["analytics", "feed-value", days],
    queryFn: async () => {
      const { data } = await api.get<FeedValueResponse>(
        "/analytics/feed-value",
        { params: { days } },
      );
      return data;
    },
  });
}

export function useFeedHealth(staleDays = 7) {
  return useQuery({
    queryKey: ["feed-health", staleDays],
    queryFn: async () => {
      const { data } = await api.get<FeedHealthResponse>("/feeds/health", {
        params: { stale_days: staleDays },
      });
      return data;
    },
  });
}
