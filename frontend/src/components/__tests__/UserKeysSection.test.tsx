import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";

const mockUpdateSettings = vi.fn(() => Promise.resolve({}));
const mockUpdatePrompt = vi.fn();
const mockResume = vi.fn();

const setting = (value: unknown) => ({ value, is_secret: false, source: "default", label: "", description: "", group: "ai" });

let allowUserProviders = true;
vi.mock("@/hooks/useSystemSettings", () => ({
  useSystemSettings: () => ({
    data: {
      settings: {
        allow_user_ai_providers: setting(allowUserProviders),
        require_user_ai_provider: setting(false),
        user_ai_provider_types: setting("claude,openai_compatible"),
        user_ai_allow_private_endpoints: setting(false),
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

const prompt = (over: Record<string, unknown>) => ({
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
      prompt({ id: "t1", name: "copilot", display_name: "Copilot", category: "chat", requires_tools: true }),
      prompt({ id: "t2", name: "entry_analysis", display_name: "Entry analysis", category: "extraction", allows_user_provider: false, user_provider_locked: true }),
      prompt({ id: "t3", name: "old", display_name: "Old", is_deprecated: true }),
    ],
  }),
  useAllTaskAssignments: () => ({ data: { t1: { provider_id: "p1", model_name: "qwen3.5:9b" } } }),
  useAIProviders: () => ({ data: [{ id: "p1", name: "Ollama Lab", provider_type: "ollama", user_id: null }] }),
  useUserKeys: () => ({
    data: [
      { id: "k1", name: "OpenRouter personal", provider_type: "openai_compatible", base_url: "https://openrouter.ai/api/v1", is_active: true, user_id: "u2", owner_username: "mreyes", models: [] },
      { id: "k2", name: "Paused Ollama", provider_type: "ollama", base_url: "https://ollama.example.com", is_active: true, user_id: "u3", owner_username: "jlee", models: [], paused_until: new Date(Date.now() + 3600_000).toISOString(), paused_reason: "429 from upstream" },
    ],
  }),
  useUpdateAITask: () => ({ mutate: mockUpdatePrompt }),
  useUpdateAIProvider: () => ({ mutate: vi.fn() }),
  useDeleteAIProvider: () => ({ mutate: vi.fn() }),
  useResumeAIProvider: () => ({ mutate: mockResume, isPending: false }),
}));

vi.mock("@/hooks/useUndoableDelete", () => ({ useUndoableDelete: () => vi.fn() }));

import { UserKeysSection } from "../UserKeysSection";

beforeEach(() => {
  vi.clearAllMocks();
  allowUserProviders = true;
});

describe("UserKeysSection", () => {
  it("shows the policy as one control and the allowed types", () => {
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByRole("button", { name: "Optional" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("claude")).toBeInTheDocument();
    expect(screen.getByText("claude_code")).toBeInTheDocument();
    expect(screen.getByLabelText("Site-key allowance per user")).toHaveValue("150");
    expect(screen.getByLabelText("Share link daily limit")).toHaveValue("20");
  });

  it("offers no monthly dollar cap on a person's own keys, only the request cap", () => {
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.queryByLabelText(/monthly cap/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Daily request cap per user")).toHaveValue("300");
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

  it("lists live prompts with a toggle, locks pipeline prompts, and hides deprecated ones", async () => {
    const user = userEvent.setup();
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByText("1 of 2 prompts")).toBeInTheDocument();
    expect(screen.getByText("Ollama Lab / qwen3.5:9b")).toBeInTheDocument();
    expect(screen.getByText(/Site only/)).toBeInTheDocument();
    expect(screen.queryByText("Old")).toBeNull();
    await user.click(screen.getByLabelText("Copilot"));
    expect(mockUpdatePrompt).toHaveBeenCalledWith({ taskId: "t1", allows_user_provider: false }, expect.anything());
  });

  it("announces each allowed type as pressed", () => {
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByRole("button", { name: "claude" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "ollama" })).toHaveAttribute("aria-pressed", "false");
  });

  it("dims the eligibility table when the policy is Off", () => {
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByTestId("prompt-eligibility").className).not.toMatch(/tableOff/);
    allowUserProviders = false;
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    const tables = screen.getAllByTestId("prompt-eligibility");
    expect(tables[1].className).toMatch(/tableOff/);
    expect(tables[1]).toHaveAttribute("aria-disabled", "true");
  });

  it("lists everyone's keys with their owner, to disable or delete but not use", () => {
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByText("mreyes")).toBeInTheDocument();
    expect(screen.getByText("OpenRouter personal")).toBeInTheDocument();
    expect(screen.getAllByText("Disable")).toHaveLength(2);
    expect(screen.queryByText("Test")).toBeNull();
  });

  it("marks a paused key with its reason and lets the admin resume it", async () => {
    const user = userEvent.setup();
    render(<UserKeysSection />, { wrapper: MemoryRouter });
    expect(screen.getByText("paused")).toHaveAttribute("title", "429 from upstream");
    // Only the paused key offers Resume.
    const resume = screen.getAllByRole("button", { name: "Resume" });
    expect(resume).toHaveLength(1);
    await user.click(resume[0]);
    expect(mockResume).toHaveBeenCalledWith("k2");
  });
});
