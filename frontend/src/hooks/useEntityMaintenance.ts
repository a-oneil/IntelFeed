import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { EntityMaintenanceLogRow } from "@/api/types";

export interface ApplyProposalResult {
  log_id: string;
  attempted: number;
  succeeded: number;
  failed: number;
  skipped: number;
  errors: Array<{ target_id: string; source_id: string; error: string }>;
}

export interface MaintenanceLogFilters {
  entity_type?: string;
  action?: string;
  mode?: "shadow" | "apply";
  applied?: boolean;
  limit?: number;
  offset?: number;
}

export function useEntityMaintenanceLog(filters: MaintenanceLogFilters) {
  return useQuery({
    queryKey: ["entity-maintenance-log", filters],
    queryFn: async () => {
      const params: Record<string, string | number | boolean> = {};
      if (filters.entity_type) params.entity_type = filters.entity_type;
      if (filters.action) params.action = filters.action;
      if (filters.mode) params.mode = filters.mode;
      if (filters.applied !== undefined) params.applied = filters.applied;
      params.limit = filters.limit ?? 100;
      params.offset = filters.offset ?? 0;
      const { data } = await api.get<EntityMaintenanceLogRow[]>(
        "/entity-maintenance/log",
        { params }
      );
      return data;
    },
    staleTime: 30 * 1000,
  });
}

export interface ApplyAllProposalsResult {
  rows_processed: number;
  rows_skipped: number;
  total_attempted: number;
  total_succeeded: number;
  total_failed: number;
  total_skipped: number;
  errors: Array<{ target_id: string; source_id: string; error: string; log_id?: string }>;
}

export function useDeleteMaintenanceLog() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (logId: string) => {
      await api.delete(`/entity-maintenance/log/${logId}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity-maintenance-log"] });
    },
  });
}
