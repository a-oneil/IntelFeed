import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

export interface SettingValue {
  value: unknown;
  is_secret: boolean;
  is_set?: boolean;
  source: "database" | "env" | "default";
  env_default?: unknown;
  label: string;
  description: string;
  group: string;
  /** When present, the setting renders as a select of these values. */
  options?: string[];
}

export interface SystemSettingsResponse {
  settings: Record<string, SettingValue>;
  groups: Record<string, string>;
}

export function useSystemSettings() {
  return useQuery({
    queryKey: ["system-settings"],
    queryFn: async () => {
      const { data } = await api.get<SystemSettingsResponse>(
        "/system-settings"
      );
      return data;
    },
    staleTime: 60_000,
  });
}

export function useUpdateSystemSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (settings: Record<string, unknown>) => {
      const { data } = await api.patch<SystemSettingsResponse>(
        "/system-settings",
        { settings }
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["system-settings"] });
      // Surfaces that summarize settings (Engine › Publishing policy line)
      // read their own endpoints — refresh them with the save.
      qc.invalidateQueries({ queryKey: ["publish-status"] });
      // The personal-key policy is a system setting too: My AI, the reader
      // panel's key dots and the copilot header all read it from their own
      // endpoints.
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

export function useResetSystemSetting() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (key: string) => {
      const { data } = await api.delete<SystemSettingsResponse>(
        `/system-settings/${key}`
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["system-settings"] });
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

export function usePublicRssToken() {
  return useQuery({
    queryKey: ["public-rss-token"],
    queryFn: async () => {
      const { data } = await api.get<{ token: string }>(
        "/system-settings/public-rss/token"
      );
      return data.token;
    },
    staleTime: 60_000,
  });
}

export function useRegeneratePublicRssToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post<{ token: string }>(
        "/system-settings/public-rss/regenerate-token"
      );
      return data.token;
    },
    onSuccess: (token) => {
      qc.setQueryData(["public-rss-token"], token);
    },
  });
}
