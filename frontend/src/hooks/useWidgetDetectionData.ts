import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

interface DateRangeParams {
  date_from?: string;
  date_to?: string;
}

export interface DetectionFormatBreakdownItem {
  rule_type: string;
  count: number;
}

export interface AttackCoverageGapItem {
  ttp_id: string;
  technique_id: string;
  technique_name: string;
  tactic: string | null;
  mention_count: number;
}

export interface KEVMatchItem {
  id: string;
  cve_id: string;
  cvss_score: number | null;
  epss_score: number | null;
  exploit_status: string | null;
  exploit_availability: string | null;
  mention_count: number;
  first_seen_at: string | null;
}

export function useDetectionFormatBreakdown(params?: DateRangeParams) {
  return useQuery({
    queryKey: ["widgets", "detection-format-breakdown", params],
    queryFn: async () => {
      const res = await api.get<DetectionFormatBreakdownItem[]>(
        "/widgets/detection-format-breakdown",
        { params },
      );
      return res.data;
    },
  });
}

export function useAttackCoverageGap(params?: DateRangeParams & { limit?: number }) {
  return useQuery({
    queryKey: ["widgets", "attack-coverage-gap", params],
    queryFn: async () => {
      const res = await api.get<AttackCoverageGapItem[]>(
        "/widgets/attack-coverage-gap",
        { params },
      );
      return res.data;
    },
  });
}

export function useKEVMatches(params?: DateRangeParams & { limit?: number }) {
  return useQuery({
    queryKey: ["widgets", "kev-matches", params],
    queryFn: async () => {
      const res = await api.get<KEVMatchItem[]>("/widgets/kev-matches", { params });
      return res.data;
    },
  });
}
