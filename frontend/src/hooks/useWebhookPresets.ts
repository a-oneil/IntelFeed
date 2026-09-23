import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { WebhookPreset, PaginatedResponse } from "@/api/types";

export function useWebhookPresets(presetType?: string) {
  return useQuery({
    queryKey: ["webhook-presets", presetType],
    queryFn: async () => {
      const res = await api.get<PaginatedResponse<WebhookPreset>>(
        "/webhook-presets",
        { params: { limit: 100, ...(presetType ? { preset_type: presetType } : {}) } }
      );
      return res.data;
    },
  });
}

export function useCreateWebhookPreset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: {
      name: string;
      preset_type?: string;
      url?: string;
      payload?: string;
      headers?: Record<string, string>;
      config?: Record<string, unknown>;
    }) => {
      const res = await api.post<WebhookPreset>("/webhook-presets", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhook-presets"] });
    },
  });
}

export function useUpdateWebhookPreset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      data,
    }: {
      id: string;
      data: Partial<{
        name: string;
        preset_type: string;
        url: string;
        payload: string;
        headers: Record<string, string>;
        config: Record<string, unknown>;
      }>;
    }) => {
      const res = await api.put<WebhookPreset>(`/webhook-presets/${id}`, data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhook-presets"] });
    },
  });
}

export function useDeleteWebhookPreset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/webhook-presets/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhook-presets"] });
    },
  });
}
