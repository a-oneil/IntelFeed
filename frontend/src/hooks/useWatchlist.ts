import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import api from "@/api/client";

export type WatchMode = "watch" | "mute" | "stack";

export interface EntityWatch {
  id: string;
  entity_type: string;
  entity_id: string;
  mode: WatchMode;
  boost: number;
  entity_name?: string | null;
}

export function useWatchlist(mode?: WatchMode) {
  return useQuery({
    queryKey: ["watchlist", mode ?? "all"],
    queryFn: async () => {
      const res = await api.get<EntityWatch[]>("/intelligence/watchlist", {
        params: mode ? { mode } : undefined,
      });
      return res.data;
    },
    staleTime: 60_000,
  });
}

/** The user's declared exposure set — vendors/products they run (mode=stack). */
export function useStack() {
  return useWatchlist("stack");
}

export interface StackAsset {
  name: string;
  type: "vendor" | "product";
  cve_count: number;
  kev_count: number;
}

export interface StackExposureItem {
  cve_id: string;
  description: string | null;
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  exploited: boolean;
  kev_due_date: string | null;
  published_at: string | null;
  asset_name: string | null;
  asset_type: "vendor" | "product" | null;
  posture: "blind" | "no_rule" | "defended" | null;
  missing_data_sources: string[];
  entry_count: number;
  lift: number;
  attack_visibility?: {
    detectable: boolean;
    data_sources: string[];
    available: string[];
    missing: string[];
  } | null;
}

export interface StackExposureResponse {
  stack: { vendors: string[]; products: string[]; count: number };
  counts: Record<string, number>;
  matrix: Record<string, number>;
  assets: StackAsset[];
  items: StackExposureItem[];
}

/** Exposure Board: every CVE affecting what you run, with a detection posture. */
export function useExposureBoard(opts?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["exposure-board"],
    queryFn: async () => {
      const res = await api.get<StackExposureResponse>("/intelligence/exposure");
      return res.data;
    },
    staleTime: 60_000,
    enabled: opts?.enabled ?? true,
  });
}

export function useUpsertWatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { entity_type: string; entity_id: string; mode: WatchMode; boost?: number }) => {
      const res = await api.put<EntityWatch>("/intelligence/watchlist", body);
      return res.data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watchlist"] });
      qc.invalidateQueries({ queryKey: ["triage"] });
      // Stack membership re-ranks the Radar (list_entries sort=radar).
      qc.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}

export function useDeleteWatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entity_type, entity_id }: { entity_type: string; entity_id: string }) => {
      await api.delete(`/intelligence/watchlist/${entity_type}/${entity_id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watchlist"] });
      qc.invalidateQueries({ queryKey: ["triage"] });
      qc.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}
