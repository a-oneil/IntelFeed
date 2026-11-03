import { useMutation, useQuery } from "@tanstack/react-query";

import api from "@/api/client";

/** Cached credential health snapshot (from GET /status). */
export interface CopilotAuthStatus {
  state?: "known" | "unknown";
  exists?: boolean;
  valid?: boolean;
  expires_at?: number | null;
  expires_at_iso?: string | null;
  subscription_type?: string | null;
  scopes?: string[] | null;
  checked_at?: string | null;
  message?: string;
}

/** State of an in-flight re-auth run (from GET /session/{id}). */
export interface CopilotAuthSession {
  state:
    | "starting"
    | "awaiting_code"
    | "exchanging"
    | "success"
    | "error"
    | "timeout"
    | "cancelled"
    | "expired";
  url?: string;
  message?: string;
  expires_at_iso?: string;
  subscription_type?: string;
  transcript_tail?: string;
}

const TERMINAL_STATES = ["success", "error", "timeout", "cancelled", "expired"];

export function isTerminalAuthState(state: string | undefined): boolean {
  return !!state && TERMINAL_STATES.includes(state);
}

/** Which provider the copilot task is assigned to (from GET /copilot/config). */
export interface CopilotConfig {
  configured: boolean;
  provider_type: string | null;
  provider_name: string | null;
  /** Tools shown directly when the assignment sets no agent_tools; the rest stay reachable via find_tools/call_tool. */
  default_tools?: string[];
  /** Writes the "Skip Confirm for" setting may name: never admin-only tools or deletes. */
  auto_approvable_tools?: string[];
  /**
   * The assignment's actual effective tool allowlist (override or default),
   * or null when the provider is unrestricted. Used to hide "/" commands in
   * the dock whose backing tool isn't currently enabled.
   */
  enabled_tools?: string[] | null;
  /** Whose provider answers: a personal key ("user") or the instance's ("site"). */
  source?: "site" | "user" | null;
  model?: string | null;
  /** False on a provider with tool calling turned off. */
  supports_tools?: boolean;
  /** Set when the person has a key that can't answer and the instance's provider took over. */
  fallback_reason?: string | null;
  /** Set when the policy refuses the turn; the dock shows what to fix. */
  refused?: { reason: string; message: string } | null;
}

/**
 * Reports the copilot's assigned provider so the dock can decide whether the
 * Claude-Code OAuth re-auth banner is relevant (only for provider_type
 * "claude_code"). On Ollama there is no OAuth session to expire.
 */
export function useCopilotConfig() {
  return useQuery({
    queryKey: ["copilot-config"],
    queryFn: async () => {
      const { data } = await api.get<CopilotConfig>("/ai/copilot/config");
      return data;
    },
    staleTime: 5 * 60 * 1000,
  });
}

export function useCopilotAuthStatus(opts?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["copilot-auth-status"],
    queryFn: async () => {
      const { data } = await api.get<CopilotAuthStatus>("/ai/copilot-auth/status");
      return data;
    },
    staleTime: 60 * 1000,
    enabled: opts?.enabled ?? true,
  });
}

export function useStartCopilotAuth() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post<{ session_id: string }>("/ai/copilot-auth/start");
      return data;
    },
  });
}

/** Polls a re-auth session until it reaches a terminal state. */
export function useCopilotAuthSession(sessionId: string | null) {
  return useQuery({
    queryKey: ["copilot-auth-session", sessionId],
    enabled: !!sessionId,
    queryFn: async () => {
      const { data } = await api.get<CopilotAuthSession>(`/ai/copilot-auth/session/${sessionId}`);
      return data;
    },
    refetchInterval: (query) => (isTerminalAuthState(query.state.data?.state) ? false : 2500),
    retry: false,
  });
}

export function useSubmitCopilotAuthCode() {
  return useMutation({
    mutationFn: async ({ sessionId, code }: { sessionId: string; code: string }) => {
      await api.post(`/ai/copilot-auth/session/${sessionId}/code`, { code });
    },
  });
}

export function useCancelCopilotAuth() {
  return useMutation({
    mutationFn: async (sessionId: string) => {
      await api.post(`/ai/copilot-auth/session/${sessionId}/cancel`);
    },
  });
}
