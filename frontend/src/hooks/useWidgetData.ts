import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  AttackHeatmapItem,
  AttackTechnique,
  CVESeverityItem,
  FeedActivityItem,
  ThreatTimelineItem,
  TrendingCVEItem,
  WidgetStats,
} from "@/api/types";

interface DateRangeParams {
  date_from?: string;
  date_to?: string;
}

export function useWidgetStats(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "stats", params],
    queryFn: async () => {
      const res = await api.get<WidgetStats>("/widgets/stats", { params });
      return res.data;
    },
  });
}

export function useFeedActivity(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "feed-activity", params],
    queryFn: async () => {
      const res = await api.get<FeedActivityItem[]>("/widgets/feed-activity", { params });
      return res.data;
    },
  });
}

export function useCVESeverity(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "cve-severity", params],
    queryFn: async () => {
      const res = await api.get<CVESeverityItem[]>("/widgets/cve-severity", { params });
      return res.data;
    },
  });
}

export function useThreatTimeline(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "threat-timeline", params],
    queryFn: async () => {
      const res = await api.get<ThreatTimelineItem[]>("/widgets/threat-timeline", { params });
      return res.data;
    },
  });
}

export function useTrendingCVEs(params?: DateRangeParams & { limit?: number }) {
  return useQuery({
    queryKey: ["widgets", "trending-cves", params],
    queryFn: async () => {
      const res = await api.get<TrendingCVEItem[]>("/widgets/trending-cves", { params });
      return res.data;
    },
  });
}

export function useAttackHeatmap(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "attack-heatmap", params],
    queryFn: async () => {
      const res = await api.get<AttackHeatmapItem[]>("/widgets/attack-heatmap", { params });
      return res.data;
    },
  });
}

export function useAttackTechniques(params?: DateRangeParams & { limit?: number }) {
  return useQuery({
    queryKey: ["attack", "techniques", params],
    queryFn: async () => {
      const res = await api.get<AttackTechnique[]>("/attack/techniques", { params });
      return res.data;
    },
  });
}

export function useNewActors(days = 7) {
  return useQuery({
    queryKey: ["widgets", "new-actors", days],
    queryFn: async () => {
      const res = await api.get<Array<{
        id: string; name: string; country: string | null;
        motivation: string | null; article_count: number; first_seen_at: string | null;
      }>>("/widgets/new-actors", { params: { days } });
      return res.data;
    },
  });
}

export function useNewCVEs(days = 7) {
  return useQuery({
    queryKey: ["widgets", "new-cves", days],
    queryFn: async () => {
      const res = await api.get<Array<{
        id: string;
        cve_id: string;
        cvss_score: number | null;
        exploit_availability: string | null;
        mention_count: number;
        first_seen_at: string | null;
      }>>("/widgets/new-cves", { params: { days } });
      return res.data;
    },
  });
}

export function useDetectionCoverage(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "detection-coverage", params],
    queryFn: async () => {
      const res = await api.get<{ total_ttps: number; covered_ttps: number; coverage_pct: number }>(
        "/widgets/detection-coverage",
        { params },
      );
      return res.data;
    },
  });
}

export interface AutomationLogItem {
  id: string;
  rule_id: string;
  rule_name: string;
  trigger_type: string;
  status: string;
  actions_executed: Array<{ type?: string; status?: string; [key: string]: unknown }>;
  error_message: string | null;
  executed_at: string | null;
}

export interface AutomationLogsWidgetData {
  summary: { success: number; error: number; skipped: number; total: number };
  logs: AutomationLogItem[];
}

export function useAutomationLogsWidget(
  params?: { limit?: number; status?: string } & DateRangeParams,
) {
  return useQuery({
    queryKey: ["widgets", "automation-logs", params],
    queryFn: async () => {
      const res = await api.get<AutomationLogsWidgetData>("/widgets/automation-logs", { params });
      return res.data;
    },
    refetchInterval: 30_000,
  });
}

export interface NewDetectionItem {
  id: string;
  title: string;
  rule_type: string;
  severity: string | null;
  is_draft: boolean;
  tags: string[];
  entry_id: string | null;
  entry_title: string | null;
  created_at: string | null;
}

export interface NewDetectionsWidgetData {
  summary: { total: number; draft: number; published: number; window_days: number };
  rules: NewDetectionItem[];
}

export function useNewDetections(params?: { limit?: number; days?: number; include_drafts?: boolean }) {
  return useQuery({
    queryKey: ["widgets", "new-detections", params],
    queryFn: async () => {
      const res = await api.get<NewDetectionsWidgetData>("/widgets/new-detections", { params });
      return res.data;
    },
    refetchInterval: 60_000,
  });
}

export function useRecentCorrelationEvents(
  limit = 10,
  range?: DateRangeParams,
) {
  const params: Record<string, unknown> = { limit, ...(range || {}) };
  return useQuery({
    queryKey: ["widgets", "correlation-events", limit, range],
    queryFn: async () => {
      const res = await api.get<Array<{
        id: string; event_type: string; context: string;
        is_read: boolean; created_at: string | null;
        entry_id: string | null; entry_title: string | null;
      }>>("/widgets/correlation-events", { params });
      return res.data;
    },
  });
}
