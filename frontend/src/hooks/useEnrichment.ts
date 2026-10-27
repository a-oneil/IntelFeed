import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useIsVisitor } from "@/stores/authStore";
import type {
  EnrichmentSource,
  EnrichmentBudgetSummary,
  EnrichmentResult,
  UserEnrichmentOverride,
  EnrichmentStatus,
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
      schedule_interval_hours?: number;
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
      }>("/enrichment/enrich", {
        entity_type: entityType,
        entity_id: entityId,
        source_types: sourceTypes,
      });
      return data;
    },
    onSuccess: (data) =>
      qc.invalidateQueries({
        queryKey: [
          "enrichment-results",
          data.entity_type,
          data.entity_id,
        ],
      }),
  });
}

export function useEnrichmentResults(
  entityType: string | undefined,
  entityId: string | undefined
) {
  return useQuery({
    queryKey: ["enrichment-results", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentResult[]>(
        "/enrichment/results",
        { params: { entity_type: entityType, entity_id: entityId } }
      );
      return data;
    },
    enabled: !!entityType && !!entityId,
  });
}

export function useEnrichmentStatus() {
  return useQuery({
    queryKey: ["enrichment-status"],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentStatus>(
        "/enrichment/status"
      );
      return data;
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

export function useEnrichmentBudgetSummary() {
  return useQuery({
    queryKey: ["enrichment-budget-summary"],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentBudgetSummary[]>(
        "/enrichment/budget-summary"
      );
      return data;
    },
    refetchInterval: 60000,
  });
}
