import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { Dashboard, DashboardWidget, PaginatedResponse } from "@/api/types";

export function useDashboards() {
  return useQuery({
    queryKey: ["dashboards"],
    queryFn: async () => {
      const res = await api.get<PaginatedResponse<Dashboard>>("/dashboards", {
        params: { limit: 100 },
      });
      return res.data;
    },
  });
}

export function useDashboard(id: string | null) {
  return useQuery({
    queryKey: ["dashboards", id],
    queryFn: async () => {
      const res = await api.get<Dashboard>(`/dashboards/${id}`);
      return res.data;
    },
    enabled: !!id,
  });
}

/**
 * Seed a user who owns no dashboards with the instance default board set.
 * No-op (returns what they already have) for anyone with boards of their own.
 */
export function useSeedDefaultDashboards() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await api.post<PaginatedResponse<Dashboard>>("/dashboards/seed-defaults");
      return res.data;
    },
    onSuccess: (data) => {
      queryClient.setQueryData(["dashboards"], data);
      queryClient.invalidateQueries({ queryKey: ["dashboards"] });
    },
  });
}

export function useCreateDashboard() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (body: { name: string; is_default?: boolean }) => {
      const res = await api.post<Dashboard>("/dashboards", body);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dashboards"] });
    },
  });
}

export function useUpdateDashboard() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: string; name?: string; is_default?: boolean }) => {
      const res = await api.put<Dashboard>(`/dashboards/${id}`, body);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dashboards"] });
    },
  });
}

export function useReorderDashboards() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: string[]) => {
      await api.put("/dashboards/reorder", { ids });
    },
    // Reordering is a direct-manipulation gesture — without an optimistic write
    // the tab snaps back to its old slot until the round-trip lands.
    onMutate: async (ids: string[]) => {
      await queryClient.cancelQueries({ queryKey: ["dashboards"] });
      const previous = queryClient.getQueryData<PaginatedResponse<Dashboard>>(["dashboards"]);
      if (previous) {
        const rank = new Map(ids.map((id, i) => [id, i]));
        // Only the passed ids are re-ranked; boards outside this strip (other
        // prefixes) keep the sort_order they already had.
        const items = previous.items.map((d) =>
          rank.has(d.id) ? { ...d, sort_order: rank.get(d.id)! } : d,
        );
        items.sort(
          (a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || a.created_at.localeCompare(b.created_at),
        );
        queryClient.setQueryData<PaginatedResponse<Dashboard>>(["dashboards"], { ...previous, items });
      }
      return { previous };
    },
    onError: (_err, _ids, context) => {
      if (context?.previous) queryClient.setQueryData(["dashboards"], context.previous);
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["dashboards"] });
    },
  });
}

export function useDeleteDashboard() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/dashboards/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dashboards"] });
    },
  });
}

export function useAddWidget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      dashboardId,
      ...body
    }: {
      dashboardId: string;
      widget_type: string;
      title?: string;
      config?: Record<string, unknown>;
      position_x?: number;
      position_y?: number;
      width?: number;
      height?: number;
    }) => {
      const res = await api.post<DashboardWidget>(`/dashboards/${dashboardId}/widgets`, body);
      return res.data;
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ["dashboards", vars.dashboardId] });
    },
  });
}

export function useUpdateWidget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      dashboardId,
      widgetId,
      ...body
    }: {
      dashboardId: string;
      widgetId: string;
      title?: string;
      config?: Record<string, unknown>;
    }) => {
      const res = await api.put<DashboardWidget>(`/dashboards/${dashboardId}/widgets/${widgetId}`, body);
      return res.data;
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ["dashboards", vars.dashboardId] });
    },
  });
}

export function useRemoveWidget() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ dashboardId, widgetId }: { dashboardId: string; widgetId: string }) => {
      await api.delete(`/dashboards/${dashboardId}/widgets/${widgetId}`);
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ["dashboards", vars.dashboardId] });
    },
  });
}

export function useUpdateLayout() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      dashboardId,
      items,
    }: {
      dashboardId: string;
      items: Array<{ id: string; position_x: number; position_y: number; width: number; height: number }>;
    }) => {
      await api.put(`/dashboards/${dashboardId}/layout`, { items });
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ["dashboards", vars.dashboardId] });
    },
  });
}
