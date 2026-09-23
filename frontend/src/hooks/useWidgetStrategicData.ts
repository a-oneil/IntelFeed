import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

interface DateRangeParams {
  date_from?: string;
  date_to?: string;
}

export interface WeeklyRecapMetric {
  count: number;
  previous: number;
  trend_pct: number;
}

export interface WeeklyRecapData {
  entries: WeeklyRecapMetric;
  cves: WeeklyRecapMetric;
  actors: WeeklyRecapMetric;
  detections: WeeklyRecapMetric;
  window_days: number;
}

export function useWeeklyRecap(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "weekly-recap", params],
    queryFn: async () => {
      const res = await api.get<WeeklyRecapData>("/widgets/weekly-recap", { params });
      return res.data;
    },
  });
}

export interface ActorActivityPoint {
  date: string;
  count: number;
}

export interface ActorActivityRow {
  id: string;
  name: string;
  country: string | null;
  total: number;
  points: ActorActivityPoint[];
}

export interface ActorActivityData {
  actors: ActorActivityRow[];
}

export function useActorActivity(params?: DateRangeParams & { limit?: number; actor_ids?: string[] }) {
  const query: Record<string, unknown> = {};
  if (params?.date_from) query.date_from = params.date_from;
  if (params?.date_to) query.date_to = params.date_to;
  if (params?.limit) query.limit = params.limit;
  if (params?.actor_ids && params.actor_ids.length > 0) query.actor_ids = params.actor_ids.join(",");

  return useQuery({
    queryKey: ["widgets", "actor-activity", query],
    queryFn: async () => {
      const res = await api.get<ActorActivityData>("/widgets/actor-activity", { params: query });
      return res.data;
    },
  });
}

export interface HotCorrelationActorMalware {
  pair_type: "actor_malware";
  actor_id: string;
  actor_name: string;
  malware_id: string;
  malware_name: string;
  co_occurrences: number;
}

export interface HotCorrelationActorCVE {
  pair_type: "actor_cve";
  actor_id: string;
  actor_name: string;
  cve_id: string;
  cve_uuid: string;
  co_occurrences: number;
}

export type HotCorrelationItem = HotCorrelationActorMalware | HotCorrelationActorCVE;

export function useHotCorrelations(params?: DateRangeParams & { limit?: number }) {
  return useQuery({
    queryKey: ["widgets", "hot-correlations", params],
    queryFn: async () => {
      const res = await api.get<HotCorrelationItem[]>("/widgets/hot-correlations", { params });
      return res.data;
    },
  });
}
