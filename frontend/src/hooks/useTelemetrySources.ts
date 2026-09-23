import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  PaginatedResponse,
  TelemetrySource,
  TelemetrySourceCreate,
  TelemetrySourceUpdate,
  CatalogItem,
  TelemetrySyncResponse,
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
