import type { DisclosureFilters } from "@/hooks/useRansomware";

/** The leak-watch filter set, owned by RansomwareSection and shared by its rail and feed. */
export interface LeakFilters {
  days: number;
  q: string;
  watchedOnly: boolean;
  groups: string[];
  sectors: string[];
  countries: string[];
  sort: "recent" | "group" | "sector";
}

/** `days: 3650` is the rail's "All" preset — the API wants no window at all. */
export const ALL_TIME_DAYS = 3650;

export const DEFAULT_LEAK_FILTERS: LeakFilters = {
  days: 7,
  q: "",
  watchedOnly: false,
  groups: [],
  sectors: [],
  countries: [],
  sort: "recent",
};

export function toDisclosureFilters(f: LeakFilters): DisclosureFilters {
  return {
    group: f.groups,
    sector: f.sectors,
    country: f.countries,
    watched_only: f.watchedOnly,
    since: f.days >= ALL_TIME_DAYS ? null : f.days,
    q: f.q.trim() || undefined,
    sort: f.sort,
  };
}
