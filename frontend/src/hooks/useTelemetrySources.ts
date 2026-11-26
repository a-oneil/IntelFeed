import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  PaginatedResponse,
  TelemetrySource,
  TelemetrySourceCreate,
  TelemetrySourceUpdate,
  CatalogItem,
  TelemetrySyncResponse,
  TelemetrySourceNote,
  TelemetrySourceNoteInput,
} from "@/api/types";

export function useTelemetrySources(params?: {
  category?: string;
  enabled?: boolean;
  sort_by?: string;
  sort_order?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["telemetry-sources", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<TelemetrySource>>(
        "/telemetry-sources",
        { params }
      );
      return data;
    },
  });
}

export function useTelemetryCatalog() {
  return useQuery({
    queryKey: ["telemetry-catalog"],
    queryFn: async () => {
      const { data } = await api.get<CatalogItem[]>(
        "/telemetry-sources/catalog"
      );
      return data;
    },
    staleTime: Infinity,
  });
}

export function useSyncTelemetrySources() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (selectedNames: string[]) => {
      const { data } = await api.post<TelemetrySyncResponse>(
        "/telemetry-sources/sync",
        { selected_names: selectedNames }
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["telemetry-sources"] });
    },
  });
}

export function useCreateTelemetrySource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: TelemetrySourceCreate) => {
      const { data } = await api.post<TelemetrySource>("/telemetry-sources", body);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["telemetry-sources"] }),
  });
}

export function useUpdateTelemetrySource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: TelemetrySourceUpdate & { id: string }) => {
      const { data } = await api.put<TelemetrySource>(`/telemetry-sources/${id}`, body);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["telemetry-sources"] }),
  });
}

export function useDeleteTelemetrySource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/telemetry-sources/${id}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["telemetry-sources"] }),
  });
}

// ── Notes and saved links per source ────────────────────────────────────

export function useTelemetryNotes(source: string | null) {
  return useQuery({
    queryKey: ["telemetry-notes", source],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<TelemetrySourceNote>>("/telemetry-sources/notes", {
        params: { source, limit: 200 },
      });
      return data;
    },
    enabled: !!source,
  });
}

/** Number of notes per source name, for the catalog's badges. */
export function useTelemetryNoteCounts() {
  return useQuery({
    queryKey: ["telemetry-notes", "counts"],
    queryFn: async () => {
      const { data } = await api.get<Record<string, number>>("/telemetry-sources/notes/counts");
      return data;
    },
  });
}

export function useCreateTelemetryNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: TelemetrySourceNoteInput & { source_name: string }) => {
      const { data } = await api.post<TelemetrySourceNote>("/telemetry-sources/notes", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["telemetry-notes"] });
      // A rule's page shows each source's note count.
      qc.invalidateQueries({ queryKey: ["detection-rule"] });
    },
  });
}

export function useUpdateTelemetryNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: TelemetrySourceNoteInput & { id: string }) => {
      const { data } = await api.put<TelemetrySourceNote>(`/telemetry-sources/notes/${id}`, body);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["telemetry-notes"] }),
  });
}

export function useDeleteTelemetryNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/telemetry-sources/notes/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["telemetry-notes"] });
      // A rule's page shows each source's note count.
      qc.invalidateQueries({ queryKey: ["detection-rule"] });
    },
  });
}

/** Every source's notes, for the Notes page; `limit: 0` skips the request. */
export function useAllTelemetryNotes(params: { q?: string; limit: number }) {
  return useQuery({
    queryKey: ["telemetry-notes", "all", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<TelemetrySourceNote>>("/telemetry-sources/notes", {
        params: { q: params.q, limit: params.limit },
      });
      return data;
    },
    enabled: params.limit > 0,
  });
}
