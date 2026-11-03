import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useAuthStore, useIsVisitor } from "@/stores/authStore";
import type {
  AIProvider,
  AIProviderCommissionResult,
  AIProviderTestResult,
  AITask,
  AITaskAssignment,
  AIPromptTemplate,
  AICostSummary,
  AIResult,
  UserAIOverview,
  UserAIPolicyStatus,
  UserAIRoute,
  AIConversation,
  AIConversationScope,
  AIConversationSummary,
  AIConversationMessage,
  PaginatedResponse,
  CursorPaginatedResponse,
  Entry,
} from "@/api/types";

// --- Providers ---

export function useAIProviders() {
  return useQuery({
    queryKey: ["ai-providers"],
    queryFn: async () => {
      const { data } = await api.get<AIProvider[]>("/ai/providers");
      return data;
    },
    staleTime: 10 * 60 * 1000,
  });
}

export function useCreateAIProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      test,
      ...body
    }: {
      name: string;
      provider_type: string;
      base_url?: string;
      api_key?: string;
      config?: Record<string, unknown>;
      /** A personal key, owned by the caller (implied for non-admins). */
      personal?: boolean;
      /** Contact the provider first; nothing is saved unless it answers. */
      test?: boolean;
    }) => {
      const { data } = await api.post<AIProvider>("/ai/providers", body, {
        params: test ? { test: true } : undefined,
        timeout: 60000,
      });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

/** Every personal key on the instance with its owner (admin only). */
export function useUserKeys(enabled = true) {
  return useQuery({
    queryKey: ["ai-providers", "user-keys"],
    queryFn: async () => {
      const { data } = await api.get<AIProvider[]>("/ai/providers/user-keys");
      return data;
    },
    enabled,
  });
}

export function useUpdateAIProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      ...body
    }: {
      id: string;
      name?: string;
      base_url?: string;
      api_key?: string;
      is_active?: boolean;
      config?: Record<string, unknown>;
    }) => {
      const { data } = await api.put<AIProvider>(`/ai/providers/${id}`, body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      // A personal key's name or state shows on My AI and in the copilot header.
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

export function useDeleteAIProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/ai/providers/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

// --- Personal AI (Settings → My AI) ---

export function useMyAIPolicy(enabled = true) {
  // The cheap read: the admin's policy and whether I have any routes. Keyed
  // under "my-ai" so every mutation that invalidates the overview refreshes
  // this too.
  return useQuery({
    queryKey: ["my-ai", "policy"],
    queryFn: async () => {
      const { data } = await api.get<UserAIPolicyStatus>("/ai/me/policy");
      return data;
    },
    enabled,
    staleTime: 5 * 60 * 1000,
  });
}

export function useMyAI(enabled = true) {
  return useQuery({
    queryKey: ["my-ai"],
    queryFn: async () => {
      const { data } = await api.get<UserAIOverview>("/ai/me/overview");
      return data;
    },
    enabled,
    // Read on every reader AI panel for the key dots; the mutations that
    // change it invalidate it, so it can stay fresh for a while.
    staleTime: 5 * 60 * 1000,
  });
}

export function useUpdateMyAIPreferences() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { fallback_to_site?: boolean; monthly_cap_usd?: string | null }) => {
      const { data } = await api.patch<UserAIOverview>("/ai/me/preferences", body);
      return data;
    },
    onSuccess: (data) => {
      qc.setQueryData(["my-ai"], data);
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

export function useUpsertMyRoute() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      task_id: string | null;
      /** null with a task_id = send that task to the instance's provider despite a default key. */
      provider_id: string | null;
      model_name?: string;
      config?: Record<string, unknown>;
    }) => {
      const { data } = await api.put<UserAIRoute>("/ai/me/routes", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

export function useDeleteMyRoute() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (routeId: string) => {
      await api.delete(`/ai/me/routes/${routeId}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

/**
 * Test a provider and route the AI tasks at it, in one call.
 *
 * Creating a provider configures nothing — work runs off task assignments, and
 * the startup seeder only fills those from a provider that already existed when
 * the API booted. Without this, a provider added through the UI did nothing
 * until the next restart.
 */
export function useCommissionAIProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, takeOver }: { id: string; takeOver?: boolean }) => {
      const { data } = await api.post<AIProviderCommissionResult>(
        `/ai/providers/${id}/commission`,
        null,
        { params: { take_over: takeOver ?? false } },
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      qc.invalidateQueries({ queryKey: ["ai-task-assignments-all"] });
      qc.invalidateQueries({ queryKey: ["onboarding"] });
    },
  });
}

export function useTestAIProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.post<AIProviderTestResult>(
        `/ai/providers/${id}/test`,
        {},
        { timeout: 60000 }
      );
      return data;
    },
    // Test refreshes the provider's cached model list server-side — refetch so
    // newly pulled models show up in the assignment dropdowns immediately.
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-providers"] }),
  });
}

export function useResumeAIProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.post<AIProvider>(`/ai/providers/${id}/resume`);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      // A resumed personal key changes what a click runs on.
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

// --- Tasks ---

export function useAITasks() {
  return useQuery({
    queryKey: ["ai-tasks"],
    queryFn: async () => {
      const { data } = await api.get<AITask[]>("/ai/tasks");
      return data;
    },
    staleTime: 10 * 60 * 1000, // tasks rarely change — don't refetch on every navigation
  });
}

export function useCreateAITask() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      name: string;
      display_name: string;
      description?: string;
      category?: string;
      default_prompt_template: string;
      default_system_template?: string;
      output_schema?: Record<string, unknown>;
      variables?: string[];
    }) => {
      const { data } = await api.post<AITask>("/ai/tasks", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-tasks"] });
    },
  });
}

export function useUpdateAITask() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      taskId,
      ...body
    }: {
      taskId: string;
      show_in_entry_actions?: boolean;
      entry_action_order?: number | null;
      show_in_entity_actions?: boolean;
      category?: string;
      /** Custom tasks only — schema edited in place; null makes it free-form. */
      output_schema?: Record<string, unknown> | null;
      /** Explicit null clears the override; omit to leave untouched. */
      output_schema_override?: Record<string, unknown> | null;
      /** Open or close the task to personal keys (admin; refused on pipeline tasks). */
      allows_user_provider?: boolean;
    }) => {
      const { data } = await api.patch<AITask>(`/ai/tasks/${taskId}`, body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-tasks"] });
      qc.invalidateQueries({ queryKey: ["my-ai"] });
    },
  });
}

export function useDeleteAITask() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (taskId: string) => {
      await api.delete(`/ai/tasks/${taskId}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-tasks"] });
    },
  });
}

export function useTaskAssignment(taskId: string | undefined) {
  return useQuery({
    queryKey: ["ai-task-assignment", taskId],
    queryFn: async () => {
      const { data } = await api.get<AITaskAssignment | null>(
        `/ai/tasks/${taskId}/assignments`
      );
      return data;
    },
    enabled: !!taskId,
  });
}

/** One registered agent tool (from the backend tool registry). */
export interface AgentToolDef {
  name: string;
  description: string;
  mutating?: boolean;
}

/**
 * The backend agent-tool registry (GET /api/tools/tools). Used by the Prompt
 * Workspace's Ollama tools editor; `mutating` tools are never offered there.
 */
export function useAgentTools(opts?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["agent-tools"],
    queryFn: async () => {
      const { data } = await api.get<AgentToolDef[]>("/tools/tools");
      return data;
    },
    staleTime: 10 * 60 * 1000, // registry only changes on deploy
    enabled: opts?.enabled ?? true,
  });
}

export function useAllTaskAssignments() {
  return useQuery({
    queryKey: ["ai-task-assignments-all"],
    queryFn: async () => {
      const { data } = await api.get<AITaskAssignment[]>("/ai/tasks/assignments/all");
      const results: Record<string, AITaskAssignment> = {};
      for (const a of data) {
        results[a.task_id] = a;
      }
      return results;
    },
    staleTime: 5 * 60 * 1000,
  });
}

export function useUpsertTaskAssignment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      taskId,
      ...body
    }: {
      taskId: string;
      provider_id: string;
      model_name: string;
      is_enabled?: boolean;
      config?: Record<string, unknown>;
    }) => {
      const { data } = await api.put<AITaskAssignment>(
        `/ai/tasks/${taskId}/assignments`,
        body
      );
      return data;
    },
    onMutate: async (vars) => {
      // Cancel in-flight refetches so they don't overwrite our optimistic update
      await qc.cancelQueries({ queryKey: ["ai-task-assignments-all"] });

      // Snapshot previous value for rollback
      const previousAssignments = qc.getQueriesData<Record<string, AITaskAssignment>>({
        queryKey: ["ai-task-assignments-all"],
      });

      // Optimistically update the cache
      qc.setQueriesData<Record<string, AITaskAssignment>>(
        { queryKey: ["ai-task-assignments-all"] },
        (old) => {
          if (!old) return old;
          return {
            ...old,
            [vars.taskId]: {
              ...old[vars.taskId],
              provider_id: vars.provider_id,
              model_name: vars.model_name,
              is_enabled: vars.is_enabled ?? true,
            } as AITaskAssignment,
          };
        }
      );

      return { previousAssignments };
    },
    onError: (_err, _vars, context) => {
      // Rollback on error
      if (context?.previousAssignments) {
        for (const [key, data] of context.previousAssignments) {
          qc.setQueryData(key, data);
        }
      }
    },
    onSettled: (_, _err, vars) => {
      qc.invalidateQueries({ queryKey: ["ai-task-assignment", vars.taskId] });
      qc.invalidateQueries({ queryKey: ["ai-task-assignments-all"] });
    },
  });
}

// --- Prompts ---

export function useActivePrompt(taskId: string | undefined) {
  return useQuery({
    queryKey: ["ai-prompt", taskId],
    queryFn: async () => {
      const { data } = await api.get<AIPromptTemplate>(
        `/ai/prompts/${taskId}`
      );
      return data;
    },
    enabled: !!taskId,
  });
}

export function useUpdatePrompt() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      taskId,
      ...body
    }: {
      taskId: string;
      name?: string;
      template_text?: string;
      // Pass "" to clear the system block; omit to leave unchanged.
      system_text?: string | null;
    }) => {
      const { data } = await api.put<AIPromptTemplate>(
        `/ai/prompts/${taskId}`,
        body
      );
      return data;
    },
    onSuccess: (_, vars) =>
      qc.invalidateQueries({ queryKey: ["ai-prompt", vars.taskId] }),
  });
}

export function useResetPrompt() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (taskId: string) => {
      const { data } = await api.post<AIPromptTemplate>(
        `/ai/prompts/${taskId}/reset`
      );
      return data;
    },
    onSuccess: (_, taskId) =>
      qc.invalidateQueries({ queryKey: ["ai-prompt", taskId] }),
  });
}

export function usePromptHistory(taskId: string | undefined) {
  return useQuery({
    queryKey: ["ai-prompt-history", taskId],
    queryFn: async () => {
      const { data } = await api.get<AIPromptTemplate[]>(
        `/ai/prompts/${taskId}/history`
      );
      return data;
    },
    enabled: !!taskId,
  });
}

// --- Cost ---

export function useRunAIOnEntry() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entryId,
      taskName,
      focus,
    }: {
      entryId: string;
      taskName: string;
      focus?: string;
    }) => {
      const { data } = await api.post<{
        task_name: string;
        entry_id: string;
        result: Record<string, unknown>;
        model_name: string | null;
        cost_estimate: string | null;
      }>(
        `/entries/${entryId}/run-ai-task`,
        { task_name: taskName, ...(focus ? { focus } : {}) },
        { timeout: 120000 }
      );
      return data;
    },
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["ai-results", data.entry_id] });
    },
    // Every call, failed ones included, counts toward the personal caps the
    // My AI overview and the copilot config report.
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

export function useRunAIOnText() {
  return useMutation({
    mutationFn: async ({ taskName, text }: { taskName: string; text: string }) => {
      const { data } = await api.post<{ task_name: string; result: Record<string, unknown> }>(
        "/ai/run-text",
        { task_name: taskName, text },
        { timeout: 120000 }
      );
      return data;
    },
  });
}

// --- Polymorphic AI Results ---

export function useAIResults(targetType: string | undefined, targetId: string | undefined) {
  // Saved AI output is never shown to a visitor; the route answers 401.
  const isVisitor = useIsVisitor();
  return useQuery({
    queryKey: ["ai-results", targetType, targetId],
    queryFn: async () => {
      const { data } = await api.get<AIResult[]>(`/ai/results/${targetType}/${targetId}`);
      return data;
    },
    enabled: !!targetType && !!targetId && !isVisitor,
    staleTime: 30_000,
  });
}

export function useAIResultHistory(targetType: string, targetId: string, taskName: string) {
  return useQuery({
    queryKey: ["ai-results", targetType, targetId, taskName, "history"],
    queryFn: async () => {
      const { data } = await api.get<AIResult[]>(`/ai/results/${targetType}/${targetId}/${taskName}/history`);
      return data;
    },
    enabled: !!targetType && !!targetId && !!taskName,
  });
}

export function useRunAIOnEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      targetType,
      targetId,
      taskName,
      force = false,
      focus,
    }: {
      targetType: string;
      targetId: string;
      taskName: string;
      force?: boolean;
      focus?: string;
    }) => {
      const { data } = await api.post<{
        task_name: string;
        target_type: string;
        target_id: string;
        result: Record<string, unknown>;
      }>(`/ai/results/${targetType}/${targetId}/run`, {
        task_name: taskName,
        force,
        ...(focus ? { focus } : {}),
      }, { timeout: 120000 });
      return data;
    },
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["ai-results", data.target_type, data.target_id] });
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["my-ai"] });
      qc.invalidateQueries({ queryKey: ["copilot-config"] });
    },
  });
}

// --- Bulk Summarize ---

export function useBulkSummarize() {
  return useMutation({
    mutationFn: async (entryIds: string[]) => {
      const { data } = await api.post<{ summary: string; entry_count: number }>(
        "/entries/bulk-summarize",
        { entry_ids: entryIds },
        { timeout: 120000 }
      );
      return data;
    },
  });
}

// --- Ask Agent ---

export interface AskAgentMessage {
  role: "user" | "assistant";
  content: string;
}

// --- Global Copilot (Streaming, SSE-over-fetch) ---

/** Ambient context sent to the copilot so it knows what the user is looking at. */
export interface CopilotContext {
  entry_id?: string;
  /** Multi-article pinning (bulk selection). entry_id wins if both set. */
  entry_ids?: string[];
  entity_type?: string;
  entity_id?: string;
  campaign_id?: string;
  search_query?: string;
  route?: string;
  /** Documentation page being read — puts the copilot in docs mode. */
  doc_slug?: string;
}

/**
 * A pending "write-with-confirm" action proposed by the agent. Arrives on the
 * copilot stream (right before `done`) as a `confirm_request` event, one per
 * write the model asked for. Nothing has run: the user must approve/cancel it
 * via {@link CopilotConfirmResponse}.
 */
export interface CopilotConfirmRequest {
  action_id: string;
  action_type: string;
  /** The registry tool that will run; absent for a legacy fenced proposal. */
  tool_name?: string;
  description: string;
  proposed: Record<string, unknown>;
  /** Deletes and admin-only changes: shown with a warning, never edited. */
  destructive?: boolean;
}

/** Response from POST /api/ai/copilot/confirm. */
export interface CopilotConfirmResponse {
  status: "executed" | "cancelled" | "error";
  result?: { summary: string; link?: string };
  message?: string;
}

/** The reply footer: which provider answered a copilot turn, whose key, and what it cost. */
export interface CopilotAnsweredBy {
  provider_name: string | null;
  provider_type: string | null;
  source: "site" | "user";
  model: string | null;
  cost_usd: number | null;
  fallback_reason: string | null;
  supports_tools: boolean;
}

export interface StreamCopilotOptions {
  question: string;
  /** Existing conversation id to continue, or null to let the backend mint one. */
  conversationId: string | null;
  /** Ambient context, or null when none is available. */
  context: CopilotContext | null;
  /** Assistant text delta — append progressively. */
  onChunk: (text: string) => void;
  /** A tool started — render a pending trace chip. */
  onToolCall?: (call: { id: string; name: string; args: Record<string, unknown> }) => void;
  /** A tool finished — resolve the chip. */
  onToolResult?: (result: { id: string; status: "success" | "error"; summary: string }) => void;
  /** The agent proposed a write requiring confirmation before it commits. */
  onConfirmRequest?: (req: CopilotConfirmRequest) => void;
  /** Terminal success — adopt/persist the returned conversation id, and who answered. */
  onDone: (conversationId: string | null, answeredBy?: CopilotAnsweredBy) => void;
  /** Terminal failure. */
  onError: (message: string) => void;
}

/**
 * Streams the global copilot answer via SSE-over-fetch. EventSource can't set
 * an Authorization header, so we use fetch() + a ReadableStream reader that
 * parses SSE `data:` frames.
 *
 * Backend events (discriminated by `type`):
 *   - {type:"chunk", text}                                        → onChunk
 *   - {type:"tool_call", id, name, args}                          → onToolCall
 *   - {type:"tool_result", id, status, summary}                   → onToolResult
 *   - {type:"confirm_request", action_id, action_type, ...}       → onConfirmRequest
 *   - {type:"done", conversation_id}                              → onDone
 *   - {type:"error", message}                                     → onError
 *
 * Tolerates absence of tool_call/tool_result frames (degrades to plain text).
 * Resolves the base URL the same way api/client.ts does (baseURL "/api").
 */
export async function streamCopilotChat(
  options: StreamCopilotOptions,
  signal?: AbortSignal,
): Promise<void> {
  const token = useAuthStore.getState().accessToken;

  const body = {
    question: options.question,
    conversation_id: options.conversationId,
    context: options.context,
  };

  let resp: Response;
  try {
    resp = await fetch("/api/ai/copilot/stream", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
      signal,
    });
  } catch (err) {
    if (signal?.aborted) return;
    options.onError(err instanceof Error ? err.message : "Request failed");
    return;
  }

  if (!resp.ok) {
    const errText = await resp.text();
    let msg = "Copilot request failed";
    try {
      const errJson = JSON.parse(errText);
      msg = errJson.detail?.message || errJson.detail || errJson.error?.message || msg;
    } catch {
      // use default
    }
    options.onError(msg);
    return;
  }

  const reader = resp.body?.getReader();
  if (!reader) {
    options.onError("No response stream");
    return;
  }

  const decoder = new TextDecoder();
  let buffer = "";
  let doneEmitted = false;

  try {
    // eslint-disable-next-line no-constant-condition -- stream read loop, exits on `done`
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const dataStr = line.slice(5).trim();
        if (!dataStr) continue;
        try {
          const data = JSON.parse(dataStr);
          switch (data.type) {
            case "chunk":
              if (typeof data.text === "string") options.onChunk(data.text);
              break;
            case "tool_call":
              options.onToolCall?.({
                id: String(data.id ?? ""),
                name: String(data.name ?? "tool"),
                args: (data.args ?? {}) as Record<string, unknown>,
              });
              break;
            case "tool_result":
              options.onToolResult?.({
                id: String(data.id ?? ""),
                status: data.status === "error" ? "error" : "success",
                summary: String(data.summary ?? ""),
              });
              break;
            case "confirm_request":
              options.onConfirmRequest?.({
                action_id: String(data.action_id ?? ""),
                action_type: String(data.action_type ?? ""),
                tool_name: typeof data.tool_name === "string" ? data.tool_name : undefined,
                description: String(data.description ?? ""),
                proposed: (data.proposed ?? {}) as Record<string, unknown>,
                destructive: data.destructive === true,
              });
              break;
            case "done":
              doneEmitted = true;
              options.onDone(
                typeof data.conversation_id === "string" ? data.conversation_id : null,
                data.answered_by && typeof data.answered_by === "object"
                  ? (data.answered_by as CopilotAnsweredBy)
                  : undefined,
              );
              return;
            case "error":
              options.onError(data.message || "Stream error");
              return;
            default:
              // Tolerate untyped chunk frames (plain-text fallback).
              if (typeof data.text === "string") options.onChunk(data.text);
          }
        } catch {
          // skip malformed SSE data
        }
      }
    }
  } catch (err) {
    if (signal?.aborted) return;
    options.onError(err instanceof Error ? err.message : "Stream read failed");
    return;
  }

  // Stream ended without an explicit `done` frame — still resolve gracefully.
  if (!doneEmitted) options.onDone(null);
}

// --- AI Conversations (persistence) ---

const conversationKeys = {
  all: ["ai-conversations"] as const,
  list: (params: ConversationListParams) =>
    ["ai-conversations", "list", params] as const,
  detail: (id: string) => ["ai-conversations", "detail", id] as const,
};

export interface ConversationListParams {
  scope_type?: AIConversationScope;
  scope_id?: string | null;
  limit?: number;
  offset?: number;
}

export function useConversations(params: ConversationListParams, enabled = true) {
  return useQuery({
    queryKey: conversationKeys.list(params),
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<AIConversationSummary>>(
        "/ai/conversations/",
        {
          params: {
            scope_type: params.scope_type,
            scope_id: params.scope_id ?? undefined,
            limit: params.limit ?? 50,
            offset: params.offset ?? 0,
          },
        },
      );
      return data;
    },
    enabled,
    staleTime: 30_000,
  });
}

export function useConversation(id: string | undefined) {
  return useQuery({
    queryKey: conversationKeys.detail(id ?? ""),
    queryFn: async () => {
      const { data } = await api.get<AIConversation>(`/ai/conversations/${id}`);
      return data;
    },
    enabled: !!id,
  });
}

export function useCreateConversation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      scope_type: AIConversationScope;
      scope_id?: string | null;
      entry_ids?: string[];
      title?: string;
      messages?: AIConversationMessage[];
    }) => {
      const { data } = await api.post<AIConversation>("/ai/conversations/", body);
      return data;
    },
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: conversationKeys.all });
      qc.setQueryData(conversationKeys.detail(data.id), data);
    },
  });
}

export function useAppendConversation(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      title?: string;
      append_messages?: AIConversationMessage[];
    }) => {
      const { data } = await api.patch<AIConversation>(
        `/ai/conversations/${id}`,
        body,
      );
      return data;
    },
    onSuccess: (data) => {
      qc.setQueryData(conversationKeys.detail(data.id), data);
      qc.invalidateQueries({ queryKey: conversationKeys.all });
    },
  });
}

export function useDeleteConversation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/ai/conversations/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: conversationKeys.all });
    },
  });
}

// --- Cost ---

export function useAICostSummary() {
  return useQuery({
    queryKey: ["ai-cost-summary"],
    queryFn: async () => {
      const { data } = await api.get<AICostSummary>("/ai/cost-summary");
      return data;
    },
  });
}

export interface AICostBreakdownRow {
  label: string;
  requests: number;
  tokens_input: number;
  tokens_output: number;
  cost: string;
}
export interface AITaskBudgetRow {
  task_id: string;
  task_name: string;
  display_name: string;
  provider_name: string | null;
  model_name: string | null;
  max_budget_usd: string | null;
  spend_30d: string;
  requests_30d: number;
  percent_of_budget: number | null;
}
export interface AICallerCostRow {
  caller_kind: "user" | "system" | "automation" | "share" | "unattributed";
  user_id: string | null;
  username: string | null;
  requests: number;
  tokens_input: number;
  tokens_output: number;
  instance_cost: string;
  own_key_cost: string;
  /** Calls on a personal key; counts people on unpriced keys too. */
  own_key_requests: number;
  requests_today: number;
}
export interface AICostBreakdown {
  total_cost_30d: string;
  total_requests_30d: number;
  total_tokens_30d: Record<string, number>;
  instance_cost_30d: string;
  user_key_cost_30d: string;
  unpriced_requests_30d: number;
  site_allowance_per_user: number;
  by_task: AICostBreakdownRow[];
  by_model: AICostBreakdownRow[];
  by_caller: AICallerCostRow[];
  budgets: AITaskBudgetRow[];
}
export interface AIPromptPreviewResponse {
  rendered_system: string | null;
  rendered_user: string | null;
  sample_source: string;
  error: string | null;
  line: number | null;
}

/** Recent entries for the prompt workspace's Preview & Test entry picker. */
export function usePromptBenchEntries(enabled: boolean) {
  return useQuery({
    queryKey: ["prompt-bench-entries"],
    queryFn: async () => {
      const { data } = await api.get<CursorPaginatedResponse<Entry>>("/entries", {
        params: { limit: 15 },
      });
      return data.items;
    },
    enabled,
    staleTime: 60_000,
  });
}

export function useAICostBreakdown() {
  return useQuery({
    queryKey: ["ai-cost-breakdown"],
    queryFn: async () => {
      const { data } = await api.get<AICostBreakdown>("/ai/cost-breakdown");
      return data;
    },
  });
}

export function usePromptPreview() {
  return useMutation({
    mutationFn: async (args: {
      taskId: string;
      systemText?: string;
      templateText?: string;
      entryId?: string;
      useSample?: boolean;
    }) => {
      const { data } = await api.post<AIPromptPreviewResponse>(
        `/ai/prompts/${args.taskId}/preview`,
        {
          system_text: args.systemText,
          template_text: args.templateText,
          entry_id: args.entryId,
          use_sample: args.useSample ?? false,
        },
      );
      return data;
    },
  });
}
