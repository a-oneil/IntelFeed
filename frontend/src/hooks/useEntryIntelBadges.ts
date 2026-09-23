import { useQueries } from "@tanstack/react-query";
import { useMemo } from "react";
import api from "@/api/client";

export interface PIRMatch {
  id: string;
  title: string;
  priority: "critical" | "high" | "medium" | "low";
  category: "strategic" | "operational" | "tactical" | "technical";
  /** Why this entry matched: keyword | entity | manual */
  match_type?: string;
  /** The keyword or entity name that triggered the match */
  matched_on?: string;
  relevance?: "high" | "medium" | "low" | null;
}

export interface EntryIntelCounts {
  ttps: number;
  cves: number;
  rules: number;
  notes: number;
  ai_results: number;
  total: number;
  has_detection_gap: boolean;
  /**
   * Telemetry-aware refinement of has_detection_gap:
   * - "actionable_gap": no rule exists for observed TTPs/CVEs — writing one closes the gap
   * - "telemetry_gap": library rules exist but required data sources aren't in telemetry
   * - null: coverage is satisfiable — no opportunity badge
   */
  detection_opportunity?: "actionable_gap" | "telemetry_gap" | null;
  /** Entry references a KEV or high-EPSS/weaponized CVE */
  has_high_risk_cve?: boolean;
  /** Entry references a CISA KEV CVE */
  has_kev_cve?: boolean;
  high_value: boolean;
  pir_matches?: PIRMatch[];
  /** Named threat actors linked to the entry (up to 3), plus the full count */
  actors?: string[];
  actor_count?: number;
  /** Named malware families linked to the entry (up to 3), plus the full count */
  malware?: string[];
  malware_count?: number;
  /** Worst CVE severity referenced, by CVSS band */
  cve_max_severity?: "critical" | "high" | "medium" | "low" | null;
}

const BATCH_SIZE = 100; // API limit

/**
 * Fetch intel counts for a batch of entry IDs.
 * Automatically splits into batches of 100 (the API limit) and merges results.
 * Returns a map of entry_id -> counts. Only entries with extracted entities are included.
 */
export function useEntryIntelBadges(entryIds: string[]) {
  // Split entry IDs into stable batches of 100
  const batches = useMemo(() => {
    const result: string[][] = [];
    for (let i = 0; i < entryIds.length; i += BATCH_SIZE) {
      result.push(entryIds.slice(i, i + BATCH_SIZE));
    }
    return result;
  }, [entryIds]);

  const queries = useQueries({
    queries: batches.map((batch) => ({
      queryKey: ["entry-intel-badges", batch],
      queryFn: async () => {
        if (batch.length === 0) return {};
        const { data } = await api.post<Record<string, EntryIntelCounts>>(
          "/entries/intel-counts",
          batch
        );
        return data;
      },
      enabled: batch.length > 0,
      staleTime: 60_000,
      refetchOnWindowFocus: false,
    })),
  });

  // Merge all batch results into a single map
  const data = useMemo(() => {
    const merged: Record<string, EntryIntelCounts> = {};
    for (const q of queries) {
      if (q.data) {
        Object.assign(merged, q.data);
      }
    }
    return Object.keys(merged).length > 0 ? merged : undefined;
  }, [queries]);

  return { data };
}
