import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import type { WebhookPreset, PaginatedResponse } from "@/api/types";

/** Presets the current user can load into an action: their own, or every
 *  one for an admin. The API redacts the URL, headers and recipients of
 *  anyone else's preset, so loading one would fill the action with
 *  "<REDACTED>". */
export function useWebhookPresets(presetType?: string) {
  const user = useAuthStore((s) => s.user);
  return useQuery({
    queryKey: ["webhook-presets", presetType],
    queryFn: async () => {
      const res = await api.get<PaginatedResponse<WebhookPreset>>(
        "/webhook-presets",
        { params: { limit: 100, ...(presetType ? { preset_type: presetType } : {}) } }
      );
      return res.data;
    },
    select: (data) =>
      user?.role === "admin"
        ? data
        : { ...data, items: data.items.filter((p) => p.created_by === user?.id) },
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

/** The send_email fields an `email` preset carries. A preset has no URL; the
 *  recipients and templates live in its `config`. */
export const EMAIL_PRESET_KEYS = ["to", "cc", "subject_template", "body_template", "body_format"] as const;

/** An email preset's fields as action config, to merge into a send_email action. */
export function emailPresetConfig(preset: WebhookPreset): Record<string, unknown> {
  return Object.fromEntries(EMAIL_PRESET_KEYS.map((k) => [k, preset.config[k] ?? ""]));
}
