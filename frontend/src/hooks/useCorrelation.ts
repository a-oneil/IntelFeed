import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  PivotResponse,
  GraphResponse,
  EntitySearchResponse,
  TimelineResponse,
  DetectionSummaryRequest,
  DetectionSummaryResponse,
  CorrelationEventListResponse,
  GroupedCorrelationEventListResponse,
} from "@/api/types";

export function useUnlinkRelatedEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entityType,
      entityId,
      otherType,
      otherId,
    }: {
      entityType: string;
      entityId: string;
      otherType: string;
      otherId: string;
    }) => {
      await api.delete(
        `/intelligence/related/${entityType}/${entityId}/${otherType}/${otherId}`
      );
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["pivot", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entity-timeline", vars.entityType, vars.entityId] });
      // Invalidate graph views for both sides of the relationship
      qc.invalidateQueries({ queryKey: ["entity-graph", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["entity-graph", vars.otherType, vars.otherId] });
    },
  });
}

export interface PivotParams {
  limit_per_type?: number;
  min_tier?: "weak" | "moderate" | "strong";
  window_days?: number;
  offset?: number;
  sort?: "strength" | "recent" | "articles";
}

export function usePivot(
  entityType: string | undefined,
  entityId: string | undefined,
  params?: PivotParams,
) {
  return useQuery({
    queryKey: ["pivot", entityType, entityId, params ?? null],
    queryFn: async () => {
      const { data } = await api.get<PivotResponse>(
        `/intelligence/pivot/${entityType}/${entityId}`,
        { params },
      );
      return data;
    },
    enabled: !!entityType && !!entityId,
  });
}

export function useEntityGraph(
  entityType: string | undefined,
  entityId: string | undefined,
  depth: number = 1,
  windowDays?: number,
) {
  return useQuery({
    queryKey: ["entity-graph", entityType, entityId, depth, windowDays ?? null],
    queryFn: async () => {
      const { data } = await api.get<GraphResponse>(
        `/intelligence/graph/${entityType}/${entityId}`,
        { params: { depth, window_days: windowDays || undefined } }
      );
      return data;
    },
    enabled: !!entityType && !!entityId,
  });
}

export function useEntryGraph(entryId: string | undefined, includeObservables = false) {
  return useQuery({
    queryKey: ["entry-graph", entryId, includeObservables],
    queryFn: async () => {
      const { data } = await api.get<GraphResponse>(`/intelligence/entry-graph/${entryId}`, {
        params: includeObservables ? { include_observables: true } : undefined,
      });
      return data;
    },
    enabled: !!entryId,
  });
}

export function useEntitySearch(query: string, limit: number = 50, entityTypes?: string) {
  return useQuery({
    queryKey: ["entity-search", query, limit, entityTypes],
    queryFn: async () => {
      const params: Record<string, unknown> = { q: query, limit };
      if (entityTypes) params.entity_types = entityTypes;
      const { data } = await api.get<EntitySearchResponse>(
        "/intelligence/search",
        { params }
      );
      return data;
    },
    enabled: query.length > 0,
  });
}

export function useEntityTimeline(
  entityType: string | undefined,
  entityId: string | undefined
) {
  return useQuery({
    queryKey: ["entity-timeline", entityType, entityId],
    queryFn: async () => {
      const { data } = await api.get<TimelineResponse>(
        `/intelligence/timeline/${entityType}/${entityId}`
      );
      return data;
    },
    enabled: !!entityType && !!entityId,
  });
}

export function useClearEntityTimeline() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ entityType, entityId }: { entityType: string; entityId: string }) => {
      await api.delete(`/intelligence/timeline/${entityType}/${entityId}`);
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["entity-timeline", vars.entityType, vars.entityId] });
      qc.invalidateQueries({ queryKey: ["correlation-events"] });
    },
  });
}

export function useDetectionSummary() {
  return useMutation({
    mutationFn: async (request: DetectionSummaryRequest) => {
      const { data } = await api.post<DetectionSummaryResponse>(
        "/intelligence/detection-summary",
        request
      );
      return data;
    },
  });
}

export function useGroupedCorrelationEvents(params?: {
  category?: string;
  event_type?: string;
  event_types?: string;
  exclude_types?: string[];
  severity?: string;
  source_entity_type?: string;
  since?: string;
  until?: string;
  is_read?: boolean;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["correlation-events-grouped", params],
    queryFn: async () => {
      const { exclude_types, ...rest } = params || {};
      const { data } = await api.get<GroupedCorrelationEventListResponse>(
        "/intelligence/events/grouped",
        { params: { ...rest, exclude_types: exclude_types?.join(",") } }
      );
      return data;
    },
  });
}

export function useCorrelationEvents(params?: {
  event_type?: string;
  event_types?: string[];
  is_read?: boolean;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["correlation-events", params],
    queryFn: async () => {
      const { event_types, ...rest } = params || {};
      const { data } = await api.get<CorrelationEventListResponse>(
        "/intelligence/events",
        { params: { ...rest, event_types: event_types?.join(",") } }
      );
      return data;
    },
  });
}

export function useUnreadEventCount(eventTypes?: string[]) {
  return useQuery({
    queryKey: ["correlation-events-unread", eventTypes],
    queryFn: async () => {
      const { data } = await api.get<{ unread_count: number }>(
        "/intelligence/events/unread-count",
        { params: eventTypes ? { event_types: eventTypes.join(",") } : undefined }
      );
      return data.unread_count;
    },
    refetchInterval: 30000,
  });
}

export function useMarkEventRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (eventId: string) => {
      await api.put(`/intelligence/events/${eventId}/read`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["correlation-events"] });
      qc.invalidateQueries({ queryKey: ["correlation-events-unread"] });
      qc.invalidateQueries({ queryKey: ["correlation-events-grouped"] });
    },
  });
}

export function useMarkAllEventsRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      await api.put("/intelligence/events/read-all");
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["correlation-events"] });
      qc.invalidateQueries({ queryKey: ["correlation-events-unread"] });
      qc.invalidateQueries({ queryKey: ["correlation-events-grouped"] });
    },
  });
}
