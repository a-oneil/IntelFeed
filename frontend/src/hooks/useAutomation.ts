import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  AutomationLog,
  AutomationRule,
  AutomationVariableContexts,
  PaginatedResponse,
  RuleExportPayload,
  RuleImportResponse,
} from "@/api/types";

/** Template variables each automation action injects, for builder hints.
 *  Static metadata — cache indefinitely. */
export function useAutomationVariableContexts() {
  return useQuery({
    queryKey: ["automation-variable-contexts"],
    queryFn: async () => {
      const res = await api.get<AutomationVariableContexts>(
        "/automation/variable-contexts"
      );
      return res.data;
    },
    staleTime: Infinity,
  });
}

export function useAutomationRules(label?: string) {
  return useQuery({
    queryKey: ["automation-rules", label],
    queryFn: async () => {
      const params: Record<string, unknown> = { limit: 100 };
      if (label) params.label = label;
      const res = await api.get<PaginatedResponse<AutomationRule>>(
        "/automation/rules",
        { params }
      );
      return res.data;
    },
  });
}

export function useAutomationRule(ruleId: string | null) {
  return useQuery({
    queryKey: ["automation-rules", ruleId],
    queryFn: async () => {
      const res = await api.get<AutomationRule>(
        `/automation/rules/${ruleId}`
      );
      return res.data;
    },
    enabled: !!ruleId,
  });
}

export function useCreateAutomationRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: {
      name: string;
      description?: string;
      trigger_type: string;
      trigger_config?: Record<string, unknown>;
      conditions?: Record<string, unknown>;
      actions: Array<Record<string, unknown>>;
      labels?: string[];
      is_enabled?: boolean;
    }) => {
      const res = await api.post<AutomationRule>("/automation/rules", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["automation-rules"] });
    },
  });
}

export function useUpdateAutomationRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      ruleId,
      data,
    }: {
      ruleId: string;
      data: Partial<{
        name: string;
        description: string;
        trigger_type: string;
        trigger_config: Record<string, unknown>;
        conditions: Record<string, unknown>;
        actions: Array<Record<string, unknown>>;
        labels: string[];
        is_enabled: boolean;
      }>;
    }) => {
      const res = await api.put<AutomationRule>(
        `/automation/rules/${ruleId}`,
        data
      );
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["automation-rules"] });
    },
  });
}

export function useDeleteAutomationRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ruleId: string) => {
      await api.delete(`/automation/rules/${ruleId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["automation-rules"] });
    },
  });
}

export function useToggleAutomationRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ruleId: string) => {
      const res = await api.post<AutomationRule>(
        `/automation/rules/${ruleId}/toggle`
      );
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["automation-rules"] });
    },
  });
}

export interface AutomationRunResult {
  logs: AutomationLog[];
  entries_evaluated: number;
  entries_matched: number;
  message: string;
}

export function useRunAutomationRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      ruleId,
      limit = 50,
      hours = 24,
    }: {
      ruleId: string;
      limit?: number;
      hours?: number;
    }) => {
      const res = await api.post<AutomationRunResult>(
        `/automation/rules/${ruleId}/run`,
        null,
        // Batch rules run their AI task inline — a briefing over a few
        // hundred entries takes well over the client's 15s default, and
        // aborting client-side reports a failure for a run that succeeds.
        { params: { limit, hours }, timeout: 300000 }
      );
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["automation-rules"] });
      queryClient.invalidateQueries({ queryKey: ["automation-logs"] });
    },
  });
}

export function useTestAutomationRule() {
  return useMutation({
    mutationFn: async ({
      ruleId,
      entryId,
    }: {
      ruleId: string;
      entryId: string;
    }) => {
      const res = await api.post<AutomationLog>(
        `/automation/rules/${ruleId}/test`,
        null,
        { params: { entry_id: entryId } }
      );
      return res.data;
    },
  });
}

export function useClearAutomationLogs() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      await api.delete("/automation/logs");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["automation-logs"] });
    },
  });
}

export function useExportAutomationRules() {
  return useMutation({
    mutationFn: async ({
      ruleIds,
      includeSecrets = false,
    }: {
      ruleIds?: string[];
      includeSecrets?: boolean;
    } = {}) => {
      const params: Record<string, string | boolean> = {
        include_secrets: includeSecrets,
      };
      if (ruleIds?.length) {
        params.rule_ids = ruleIds.join(",");
      }
      const res = await api.get<RuleExportPayload>("/automation/rules/export", {
        params,
      });
      return res.data;
    },
  });
}

export function useImportAutomationRules() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      payload,
      enabledOnImport = false,
      overwriteExisting = false,
    }: {
      payload: RuleExportPayload;
      enabledOnImport?: boolean;
      overwriteExisting?: boolean;
    }) => {
      const res = await api.post<RuleImportResponse>(
        "/automation/rules/import",
        payload,
        {
          params: {
            enabled_on_import: enabledOnImport,
            overwrite_existing: overwriteExisting,
          },
        }
      );
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["automation-rules"] });
    },
  });
}

export function useAutomationLogs(ruleId?: string, page = 0, pageSize = 20, excludeStatus?: string) {
  return useQuery({
    queryKey: ["automation-logs", ruleId, page, pageSize, excludeStatus],
    queryFn: async () => {
      const url = ruleId
        ? `/automation/rules/${ruleId}/logs`
        : "/automation/logs";
      const params: Record<string, unknown> = { limit: pageSize, offset: page * pageSize };
      if (excludeStatus) params.exclude_status = excludeStatus;
      const res = await api.get<PaginatedResponse<AutomationLog>>(url, { params });
      return res.data;
    },
  });
}
