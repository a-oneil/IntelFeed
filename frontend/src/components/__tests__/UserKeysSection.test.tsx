import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";

const mockUpdateSettings = vi.fn(() => Promise.resolve({}));
const mockUpdateTask = vi.fn();

const setting = (value: unknown) => ({ value, is_secret: false, source: "default", label: "", description: "", group: "ai" });

vi.mock("@/hooks/useSystemSettings", () => ({
  useSystemSettings: () => ({
    data: {
      settings: {
        allow_user_ai_providers: setting(true),
        require_user_ai_provider: setting(false),
        user_ai_provider_types: setting("claude,openai_compatible"),
        user_ai_allow_private_endpoints: setting(false),
        user_ai_default_monthly_usd: setting(25),
        user_ai_daily_request_cap: setting(300),
        site_ai_user_daily_requests: setting(150),
        share_ai_daily_requests: setting(20),
      },
      groups: {},
    },
    isLoading: false,
  }),
  useUpdateSystemSettings: () => ({ mutateAsync: mockUpdateSettings, isPending: false }),
}));

const task = (over: Record<string, unknown>) => ({
  id: "t",
  name: "x",
  display_name: "X",
  description: null,
  category: "generation",
  variables: [],
  is_system: true,
  requires_tools: false,
  is_deprecated: false,
  show_in_entry_actions: true,
  entry_action_order: null,
  show_in_entity_actions: true,
  output_schema: null,
  output_schema_override: null,
  allows_user_provider: true,
  user_provider_locked: false,
  created_at: "2026-01-01",
  ...over,
});

vi.mock("@/hooks/useAI", () => ({
  useAITasks: () => ({
    data: [
      task({ id: "t1", name: "copilot", display_name: "Copilot", category: "chat", requires_tools: true }),
      task({ id: "t2", name: "entry_analysis", display_name: "Entry analysis", category: "extraction", allows_user_provider: false, user_provider_locked: true }),
      task({ id: "t3", name: "old", display_name: "Old", is_deprecated: true }),
    ],
  }),
  useAllTaskAssignments: () => ({ data: { t1: { provider_id: "p1", model_name: "qwen3.5:9b" } } }),
  useAIProviders: () => ({ data: [{ id: "p1", name: "Ollama Lab", provider_type: "ollama", user_id: null }] }),
  useUserKeys: () => ({
    data: [
      { id: "k1", name: "OpenRouter personal", provider_type: "openai_compatible", base_url: "https://openrouter.ai/api/v1", is_active: true, user_id: "u2", owner_username: "mreyes", models: [] },
    ],
  }),
  useUpdateAITask: () => ({ mutate: mockUpdateTask }),
  useUpdateAIProvider: () => ({ mutate: vi.fn() }),
  useDeleteAIProvider: () => ({ mutate: vi.fn() }),
}));

vi.mock("@/hooks/useUndoableDelete", () => ({ useUndoableDelete: () => vi.fn() }));

import { UserKeysSection } from "../UserKeysSection";

beforeEach(() => vi.clearAllMocks());

describe("UserKeysSection", () => {
  it("shows the policy as one control and the allowed types", () => {
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByRole("button", { name: "Optional" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("claude")).toBeInTheDocument();
    expect(screen.getByText("claude_code")).toBeInTheDocument();
    expect(screen.getByLabelText("Site-key allowance per user")).toHaveValue("150");
    expect(screen.getByLabelText("Share link daily limit")).toHaveValue("20");
  });

  it("writes both policy flags from the segmented control", async () => {
    const user = userEvent.setup();
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    await user.click(screen.getByRole("button", { name: "Required" }));
    expect(mockUpdateSettings).toHaveBeenCalledWith({
      allow_user_ai_providers: true,
      require_user_ai_provider: true,
    });
    await user.click(screen.getByRole("button", { name: "Off" }));
    expect(mockUpdateSettings).toHaveBeenCalledWith({
      allow_user_ai_providers: false,
      require_user_ai_provider: false,
    });
  });

  it("lists live tasks with a toggle, locks pipeline tasks, and hides deprecated ones", async () => {
    const user = userEvent.setup();
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByText("1 of 2 live tasks")).toBeInTheDocument();
    expect(screen.getByText("Ollama Lab / qwen3.5:9b")).toBeInTheDocument();
    expect(screen.getByText(/Site only/)).toBeInTheDocument();
    expect(screen.queryByText("Old")).toBeNull();
    await user.click(screen.getByLabelText("Copilot"));
    expect(mockUpdateTask).toHaveBeenCalledWith({ taskId: "t1", allows_user_provider: false }, expect.anything());
  });

  it("lists everyone's keys with their owner, to disable or delete but not use", () => {
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByText("mreyes")).toBeInTheDocument();
    expect(screen.getByText("OpenRouter personal")).toBeInTheDocument();
    expect(screen.getByText("Disable")).toBeInTheDocument();
    expect(screen.queryByText("Test")).toBeNull();
  });
});
