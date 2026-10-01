import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

export interface DayIntelEntity {
  id: string;
  name: string;
  count: number;
}

export interface DayIntelTtp {
  id: string;
  technique_id: string;
  name: string;
  count: number;
}

export interface DayIntelSector {
  id: string;
  slug: string;
  name: string;
  count: number;
}

export interface DayIntelCve {
  id: string;
  name: string;
  count: number;
  cvss_score: number | null;
  severity: string | null;
  kev: boolean;
}

export interface DayIntelNew {
  type: "threat_actor" | "malware";
  id: string;
  name: string;
  total: number;
}

export interface DayIntelSignals {
  actively_exploited: number;
  new: DayIntelNew | null;
}

export interface DayIntelResult {
  threat_actor: DayIntelEntity | null;
  malware: DayIntelEntity | null;
  cve: DayIntelCve | null;
  ttp: DayIntelTtp | null;
  sector: DayIntelSector | null;
  product: DayIntelEntity | null;
  country: DayIntelEntity | null;
  signals: DayIntelSignals;
}

export interface DayIntelFilters {
  feed_id?: string;
  category_id?: string;
}

/** Local-time [start, end] ISO window for a `YYYY-MM-DD` day key. */
export function dayWindowIso(dayKey: string): { since: string; before: string } | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dayKey);
  if (!m) return null;
  const [, y, mo, d] = m;
  const start = new Date(Number(y), Number(mo) - 1, Number(d), 0, 0, 0, 0);
  const end = new Date(Number(y), Number(mo) - 1, Number(d), 23, 59, 59, 999);
  return { since: start.toISOString(), before: end.toISOString() };
}

/** Top entities + urgency signals for a single day window. */
export function useDayIntel(
  dayKey: string,
  since: string | null,
  before: string | null,
  filters: DayIntelFilters,
  enabled = true,
) {
  return useQuery({
    queryKey: ["day-intel", dayKey, filters],
    queryFn: async () => {
      const res = await api.get<DayIntelResult>("/entries/day-intel", {
        params: { since, before, ...filters },
      });
      return res.data;
    },
    enabled: enabled && !!since && !!before,
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
  });
}
