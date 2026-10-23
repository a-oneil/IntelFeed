import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { AIResult } from "@/api/types";

const authState = { user: { id: "me", username: "mreyes", role: "user" } };
vi.mock("@/stores/authStore", () => {
  const useAuthStore = (selector: (s: typeof authState) => unknown) => selector(authState);
  useAuthStore.getState = () => authState;
  return { useAuthStore };
});
vi.mock("@/stores/uiStore", () => ({
  useUIStore: (selector: (s: Record<string, unknown>) => unknown) => selector({ openCopilotWith: vi.fn() }),
}));
vi.mock("@/hooks/useAI", () => ({
  useAIResults: () => ({ data: undefined, isLoading: false }),
  useAIResultHistory: () => ({ data: [] }),
  useRunAIOnEntity: () => ({ mutate: vi.fn(), isPending: false }),
}));
vi.mock("@/hooks/useNotes", () => ({ useCreateEntryNote: () => ({ mutate: vi.fn(), isPending: false }) }));

import { AIResultsDisplay } from "../AIResultsDisplay";

const result = (over: Partial<AIResult>): AIResult => ({
  id: "r1",
  entry_id: "e1",
  target_type: "entry",
  target_id: "e1",
  is_current: true,
  task_id: "t1",
  task_name: "detection_rules",
  provider_id: "k1",
  model_name: "claude-sonnet-4-6",
  parsed_result: { _extraction_status: "success", rules: [] },
  tokens_input: 3100,
  tokens_output: 1200,
  cost_estimate: "0.021",
  processing_time_ms: 900,
  caller_kind: "user",
  user_id: "me",
  key_owner_id: "me",
  provider_name: "Anthropic work key",
  created_at: "2026-10-23T10:00:00Z",
  ...over,
});

describe("AIResultsDisplay provenance", () => {
  it("says a result came from my key", () => {
    render(<AIResultsDisplay targetType="entry" targetId="e1" staticResults={[result({})]} />, { wrapper: MemoryRouter });
    expect(screen.getByText("Anthropic work key · your key")).toBeInTheDocument();
    expect(screen.queryByText(/ran on the instance's provider/)).toBeNull();
  });

  it("labels the instance's provider without claiming it is mine", () => {
    render(
      <AIResultsDisplay targetType="entry" targetId="e1" staticResults={[result({ key_owner_id: null, provider_name: "Ollama Lab", user_id: "me" })]} />,
      { wrapper: MemoryRouter },
    );
    expect(screen.getByText("Ollama Lab")).toBeInTheDocument();
    expect(screen.queryByText(/your key/)).toBeNull();
  });

  it("shows a fallback with the reason and the way to fix it", () => {
    render(
      <AIResultsDisplay
        targetType="entry"
        targetId="e1"
        staticResults={[
          result({
            key_owner_id: null,
            provider_name: "Ollama Lab",
            model_name: "qwen3.5:9b",
            parsed_result: { _extraction_status: "success", _fallback_reason: "monthly_cap", summary: "x" },
          }),
        ]}
      />,
      { wrapper: MemoryRouter },
    );
    expect(screen.getByText("Ollama Lab · fallback")).toBeInTheDocument();
    expect(screen.getByText(/reached its monthly spend cap/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Raise my cap" })).toHaveAttribute("href", "/settings?section=myai");
  });
});
