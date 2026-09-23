import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

export interface DailySummaryFilters {
  feed_id?: string;
  category_id?: string;
  is_read?: boolean;
  is_starred?: boolean;
  is_bookmarked?: boolean;
  content_type?: string;
  change_type?: string;
  country_id?: string;
  country_role?: string;
  campaign_id?: string;
  dedup?: boolean;
}

export interface DailySummaryResult {
  summary: string | null;
  cached: boolean;
  generated_at: string | null;
  entry_count?: number | null;
}

interface GenerateArgs {
  day_key: string;
  since: string;
  before: string;
  filters: DailySummaryFilters;
  force?: boolean;
}

/** Fetch the cached daily summary for (day_key + filters). Never generates. */
export function useDailySummary(day_key: string, filters: DailySummaryFilters) {
  return useQuery({
    queryKey: ["daily-summary", day_key, filters],
    queryFn: async () => {
      const res = await api.get<DailySummaryResult>("/entries/daily-summary", {
        params: { day_key, ...filters },
      });
      return res.data;
    },
    staleTime: 5 * 60_000,
  });
}

/** Generate (or force-regenerate) the daily summary; cache lookup happens server-side. */
export function useGenerateDailySummary() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (args: GenerateArgs) => {
      const res = await api.post<DailySummaryResult>(
        "/entries/daily-summary",
        {
          day_key: args.day_key,
          since: args.since,
          before: args.before,
          ...args.filters,
          force: args.force ?? false,
        },
        // AI generation on a busy day (60 articles, 8K-token output) can take
        // well past the 15s global axios timeout. Give it ample headroom.
        { timeout: 180_000 },
      );
      return res.data;
    },
    onSuccess: (data, args) => {
      qc.setQueryData(["daily-summary", args.day_key, args.filters], data);
    },
  });
}
