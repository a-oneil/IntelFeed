import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

export interface DayCVE {
  id: string;
  cve_id: string;
  cvss_score: number | null;
  severity: string | null;
  description: string | null;
  exploit_status: string | null;
  epss_score: number | null;
  is_kev: boolean;
  github_poc_count: number | null;
  metasploit_module: string | null;
  first_seen_at: string | null;
}

export interface DayTTP {
  id: string;
  technique_id: string;
  technique_name: string;
  tactic: string | null;
  description: string | null;
  article_count: number;
  first_seen_at: string | null;
}

/** Fields shared by every named-entity type — mirror the entry reader's
 *  popover so the daily-summary tooltip renders the same metadata. */
export interface DayNamedEntity {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  article_count: number;
  first_seen_at: string | null;
  wikipedia_url: string | null;
  wikipedia_image_url: string | null;
  /** Surface forms the autolinker actually found in source articles —
   *  most likely to match the AI summary's wording verbatim. */
  matched_names: string[];
}

export interface DayActor extends DayNamedEntity {
  mitre_id: string | null;
  country: string | null;
  motivation: string | null;
  targeted_sectors: string[];
}

export interface DayMalware extends DayNamedEntity {
  malware_type: string | null;
  malpedia_url: string | null;
}

export interface DayVendor extends DayNamedEntity {
  vendor_type: string | null;
  website: string | null;
}

export interface DayProduct extends DayNamedEntity {
  product_type: string | null;
  website: string | null;
}

export interface DayCountry extends DayNamedEntity {
  region: string | null;
}

export interface DayTool extends DayNamedEntity {
  tool_type: string | null;
  platforms: string[];
  github_url: string | null;
  malpedia_url: string | null;
  detection_artifacts: Record<string, unknown>;
}

export interface DayMitigation {
  id: string;
  name: string;
  mitre_id: string | null;
  mitre_url: string | null;
  description: string | null;
  article_count: number;
  first_seen_at: string | null;
  wikipedia_url: string | null;
  wikipedia_image_url: string | null;
}

export interface DayEntitiesResult {
  cves: DayCVE[];
  ttps: DayTTP[];
  actors: DayActor[];
  malware: DayMalware[];
  vendors: DayVendor[];
  products: DayProduct[];
  countries: DayCountry[];
  tools: DayTool[];
  mitigations: DayMitigation[];
}

export interface DayEntitiesFilters {
  feed_id?: string;
  category_id?: string;
}

/** Distinct entities mentioned by all articles in a day window —
 * used to drive inline highlighting on the day's AI summary. */
export function useDayEntities(
  dayKey: string,
  since: string | null,
  before: string | null,
  filters: DayEntitiesFilters,
  enabled = true,
) {
  return useQuery({
    queryKey: ["day-entities", dayKey, filters],
    queryFn: async () => {
      const res = await api.get<DayEntitiesResult>("/entries/day-entities", {
        params: { since, before, ...filters },
      });
      return res.data;
    },
    enabled: enabled && !!since && !!before,
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
  });
}
