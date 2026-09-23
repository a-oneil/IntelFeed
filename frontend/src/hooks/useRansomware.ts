import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";

import api from "@/api/client";
import type { PaginatedResponse } from "@/api/types";

// --- types (mirror app/schemas/ransomware.py) ---

export interface Disclosure {
  id: string;
  victim_id: string;
  victim_name: string;
  domain: string | null;
  watched: boolean;
  group_id: string | null;
  group_name: string | null;
  group_color: string;
  sector: string | null;
  sector_label: string | null;
  country_id: string | null;
  country_name: string | null;
  country_code: string | null;
  posted_at: string;
  published_at: string | null;
  claimed_data: string | null;
  leak_site_url: string | null;
  source: string;
  is_new: boolean;
}

export interface TimeseriesPoint {
  week_start: string;
  label: string;
  count: number;
}
export interface GroupStat {
  id: string | null;
  name: string;
  color: string;
  victims: number;
  share: number;
  wow_trend: number;
  trend_up: boolean;
}
export interface SectorStat {
  sector: string;
  label: string;
  victims: number;
  share: number;
}
export interface CountryStat {
  id: string | null;
  name: string;
  iso_code: string | null;
  victims: number;
}
export interface ExposureItem {
  name: string;
  kind: string;
  status: string;
  detail: string;
  hit: boolean;
}
export interface StatsTotals {
  victims: number;
  prior_victims: number;
  victims_wow: number;
  groups_active: number;
  sectors_hit: number;
  watchlist_hits: number;
}
export interface RansomwareStats {
  days: number;
  totals: StatsTotals;
  timeseries: TimeseriesPoint[];
  groups: GroupStat[];
  sectors: SectorStat[];
  countries: CountryStat[];
  watchlist_exposure: ExposureItem[];
  most_active_group: GroupStat | null;
  fastest_riser: GroupStat | null;
}

export interface DisclosureFilters {
  group?: string[];
  sector?: string[];
  country?: string[];
  watched_only?: boolean;
  since?: number | null;
  q?: string;
  sort?: "recent" | "group" | "sector";
}

const PAGE_SIZE = 60;

export function useDisclosures(filters: DisclosureFilters) {
  return useInfiniteQuery({
    queryKey: ["ransomware", "disclosures", filters],
    queryFn: async ({ pageParam = 0 }) => {
      const params: Record<string, unknown> = {
        limit: PAGE_SIZE,
        offset: pageParam,
        sort: filters.sort ?? "recent",
      };
      if (filters.group?.length) params.group = filters.group;
      if (filters.sector?.length) params.sector = filters.sector;
      if (filters.country?.length) params.country = filters.country;
      if (filters.watched_only) params.watched_only = true;
      if (filters.since != null) params.since = filters.since;
      if (filters.q) params.q = filters.q;
      const { data } = await api.get<PaginatedResponse<Disclosure>>("/ransomware/disclosures", {
        params,
        // repeat array params as ?group=A&group=B
        paramsSerializer: { indexes: null },
      });
      return data;
    },
    initialPageParam: 0,
    getNextPageParam: (last) => (last.has_more ? last.offset + last.limit : undefined),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}

export function useRansomwareStats(days: number) {
  return useQuery({
    queryKey: ["ransomware", "stats", days],
    queryFn: async () => (await api.get<RansomwareStats>("/ransomware/stats", { params: { days } })).data,
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  });
}
