import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import api from "@/api/client";
import { useIsVisitor } from "@/stores/authStore";
import { entityContextKey } from "@/hooks/useEntityContext";
import type {
  EnrichmentSource,
  UserEnrichmentOverride,
} from "@/api/types";

// --- Sources ---

export function useEnrichmentSources(enabled = true) {
  // Signed-in only; the route answers 401 to a visitor.
  const isVisitor = useIsVisitor();
  return useQuery({
    queryKey: ["enrichment-sources"],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentSource[]>(
        "/enrichment/sources"
      );
      return data;
    },
    enabled: enabled && !isVisitor,
  });
}

export function useUpdateEnrichmentSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      sourceId,
      ...body
    }: {
      sourceId: string;
      is_enabled?: boolean;
      trigger_mode?: string;
      api_key?: string;
      rate_limit_config?: Record<string, number>;
      config?: Record<string, unknown>;
      min_confidence_threshold?: string;
      daily_budget?: number | null;
      clear_daily_budget?: boolean;
    }) => {
      const { data } = await api.put<EnrichmentSource>(
        `/enrichment/sources/${sourceId}`,
        body
      );
      return data;
    },
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["enrichment-sources"] }),
  });
}

export function useTestEnrichmentSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (sourceId: string) => {
      const { data } = await api.post<{
        source_type: string;
        health_status: string;
      }>(`/enrichment/sources/${sourceId}/test`);
      return data;
    },
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["enrichment-sources"] }),
  });
}

// --- User Overrides ---

export function useUserEnrichmentOverrides() {
  return useQuery({
    queryKey: ["enrichment-user-overrides"],
    queryFn: async () => {
      const { data } = await api.get<UserEnrichmentOverride[]>(
        "/enrichment/user-overrides"
      );
      return data;
    },
  });
}

export function useUpsertUserOverride() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      sourceId,
      ...body
    }: {
      sourceId: string;
      api_key?: string;
    }) => {
      const { data } = await api.put(
        `/enrichment/user-overrides/${sourceId}`,
        body
      );
      return data;
    },
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["enrichment-user-overrides"] }),
  });
}

export function useDeleteUserOverride() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (sourceId: string) => {
      await api.delete(`/enrichment/user-overrides/${sourceId}`);
    },
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["enrichment-user-overrides"] }),
  });
}

// --- Entity Enrichment ---

export function useEnrichEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entityType,
      entityId,
      sourceTypes,
    }: {
      entityType: string;
      entityId: string;
      sourceTypes?: string[];
    }) => {
      const { data } = await api.post<{
        entity_type: string;
        entity_id: string;
        results: Array<{
          source_type: string;
          status: string;
          parsed_data?: Record<string, unknown>;
          error?: string;
        }>;
        /** Sources that refused for now; each lookup is queued to retry. */
        queued: string[];
      }>("/enrichment/enrich", {
        entity_type: entityType,
        entity_id: entityId,
        source_types: sourceTypes,
      });
      return data;
    },
    onSuccess: (data) => {
      if (data.queued?.length) {
        toast(`Queued to retry when the source allows: ${data.queued.join(", ")}`);
      }
      return qc.invalidateQueries({ queryKey: entityContextKey(data.entity_type, data.entity_id) });
    },
  });
}

export function useEnrichValue() {
  return useMutation({
    mutationFn: async ({
      value,
      sourceTypes,
      entryId,
    }: {
      value: string;
      sourceTypes?: string[];
      entryId?: string;
    }) => {
      const { data } = await api.post<{
        entity_type: string;
        entity_id: string;
        value: string;
        results: Array<{ source_type: string; status: string; parsed_data?: Record<string, unknown>; error?: string }>;
      }>("/enrichment/enrich-value", {
        value,
        source_types: sourceTypes,
        entry_id: entryId,
      });
      return data;
    },
  });
}

// --- Console (Settings → Engine → Enrichment) ---

export type EnrichmentSourceStatus = "ok" | "failing" | "off" | "needs_key";

export interface EnrichmentConsoleSummary {
  sources_on: number;
  sources_total: number;
  needs_attention: number;
  paused: boolean;
  redis_ok: boolean;
  activity_24h: {
    requests: number;
    queued: number;
    deferred: number;
    iocs_sent_off_box: number;
  };
}

export interface EnrichmentConsoleEntityType {
  entity_type: string;
  label: string;
  source_count: number;
}

export interface EnrichmentConsoleSource {
  /** The enrichment_sources row id, for PUT /enrichment/sources/{id}. */
  id: string;
  source_type: string;
  label: string;
  kind: "lookup" | "catalog";
  status: EnrichmentSourceStatus;
  enabled: boolean;
  /** Plain-words summary of what the source writes. */
  fills: string;
  applies_to: string[];
  /** Why the source needs a look; null when it's fine. */
  attention: string | null;
}

export interface EnrichmentConsole {
  summary: EnrichmentConsoleSummary;
  entity_types: EnrichmentConsoleEntityType[];
  sources: EnrichmentConsoleSource[];
}

export type EnrichmentLane = "manual" | "new" | "refresh" | "backfill";

export interface EnrichmentSourceDetail {
  limits: {
    requests_per_period: number;
    period_seconds: number;
    ceiling_per_period: number | null;
    daily_budget: number | null;
    used_today: number;
    backfill_share: number | null;
    refresh_days: number | null;
    /** "global" | "none" | "user_overrides:N" */
    key: string;
    triggers: string[];
    scope: string | null;
  };
  /** 24 hourly request counts, oldest first. */
  trend_24h: number[];
  queue: {
    waiting: number;
    by_lane: Partial<Record<EnrichmentLane, number>>;
    retrying: number;
    failed: number;
  };
  outputs: Array<{
    field: string;
    target: string;
    kind: "column" | "context";
    policy?: string | null;
    rank?: number | null;
    filled_pct: number | null;
  }>;
  /** Null when the source has no column output. */
  gap: {
    entity_type: string;
    field: string;
    missing: number;
    in_scope: number;
    eta_days: number | null;
  } | null;
  jobs: Array<{
    key: string;
    schedule: string;
    runs_30d: number;
    ok_30d: number;
    last_status: string | null;
    last_error: string | null;
    last_detail: Record<string, unknown> | null;
  }>;
}

const CONSOLE_KEY = ["enrichment-console"] as const;

export function useEnrichmentConsole(entityType?: string) {
  return useQuery({
    queryKey: [...CONSOLE_KEY, entityType ?? "all"],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentConsole>("/enrichment/console", {
        params: entityType ? { entity_type: entityType } : undefined,
      });
      return data;
    },
    // Switching tabs keeps the last table up instead of flashing a spinner.
    placeholderData: (prev) => prev,
    refetchInterval: 60_000,
  });
}

export function useEnrichmentSourceDetail(sourceType: string | null) {
  return useQuery({
    queryKey: [...CONSOLE_KEY, "detail", sourceType],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentSourceDetail>(
        `/enrichment/sources/${sourceType}/detail`
      );
      return data;
    },
    enabled: !!sourceType,
  });
}

export function usePauseEnrichment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (paused: boolean) => {
      const { data } = await api.post<{ paused: boolean }>("/enrichment/pause", { paused });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: CONSOLE_KEY }),
  });
}

export function useQueueBackfill() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      sourceType,
      entityType,
      limit,
    }: {
      sourceType: string;
      entityType: string;
      limit: number;
    }) => {
      const { data } = await api.post<{ queued: number }>(
        `/enrichment/sources/${sourceType}/backfill`,
        { entity_type: entityType, limit }
      );
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: CONSOLE_KEY }),
  });
}
