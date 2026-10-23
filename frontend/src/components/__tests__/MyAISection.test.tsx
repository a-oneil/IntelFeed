import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import type { AIProvider, UserAIOverview } from "@/api/types";

const authState = { user: { id: "me", username: "mreyes", role: "user" } };
vi.mock("@/stores/authStore", () => {
  const useAuthStore = (selector: (s: typeof authState) => unknown) => selector(authState);
  useAuthStore.getState = () => authState;
  return { useAuthStore };
});

const key = (over: Partial<AIProvider>): AIProvider => ({
  id: "k1",
  name: "OpenRouter personal",
  provider_type: "openai_compatible",
  base_url: "https://openrouter.ai/api/v1",
  models: ["anthropic/claude-sonnet-4.6"],
  is_active: true,
  config: {},
  supports_tools: false,
  paused_until: null,
  paused_reason: null,
  user_id: "me",
  created_at: "2026-10-01",
  updated_at: "2026-10-01",
  ...over,
});

const overview = (over: Partial<UserAIOverview> = {}): UserAIOverview => ({
  policy: {
    allow_user_ai_providers: true,
    require_user_ai_provider: false,
    provider_types: ["claude", "openai_compatible"],
    allow_private_endpoints: false,
    default_monthly_usd: "25.0000",
    daily_request_cap: 300,
    site_allowance_per_user: 150,
  },
  fallback_to_site: true,
  monthly_cap_usd: null,
  usage: {
    month_cost: "6.42",
    monthly_cap_usd: "25",
    requests_today: 41,
    daily_request_cap: 300,
    site_requests_today: 118,
    site_allowance_per_user: 150,
    month_resets_at: "2026-11-01T00:00:00Z",
    by_key: [
      { provider_id: "k1", provider_name: "OpenRouter personal", provider_type: "openai_compatible", month_cost: "5.61", month_requests: 30 },
      { provider_id: "k2", provider_name: "Anthropic work key", provider_type: "claude", month_cost: "0.81", month_requests: 11 },
    ],
  },
  tasks: [
    {
      task_id: "t-copilot",
      task_name: "copilot",
      display_name: "Copilot",
      category: "chat",
      requires_tools: true,
      site_provider_name: "Ollama Lab",
      site_model_name: "qwen3.5:9b",
      route: { id: "r1", task_id: "t-copilot", task_name: "copilot", provider_id: "k1", provider_name: "OpenRouter personal", model_name: "anthropic/claude-sonnet-4.6", config: {}, updated_at: "2026-10-20" },
      month_cost: "4.18",
    },
    {
      task_id: "t-rules",
      task_name: "detection_rules",
      display_name: "Detection rules",
      category: "generation",
      requires_tools: false,
      site_provider_name: "Ollama Lab",
      site_model_name: "qwen3.5:9b",
      // The API puts only a task's own route on its row; the default key lives on default_route.
      route: null,
      month_cost: "0.81",
    },
  ],
  default_route: { id: "r0", task_id: null, task_name: null, provider_id: "k2", provider_name: "Anthropic work key", model_name: "claude-sonnet-4-6", config: {}, updated_at: "2026-10-20" },
  ...over,
});

const mockUseMyAI = vi.fn();
const mockUseAIProviders = vi.fn();
const mockUpsertRoute = vi.fn();
const mockDeleteRoute = vi.fn();
const mockPrefs = vi.fn();

vi.mock("@/hooks/useAI", () => ({
  useMyAI: () => mockUseMyAI(),
  useAIProviders: () => mockUseAIProviders(),
  useCreateAIProvider: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useUpdateAIProvider: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
  useTestAIProvider: () => ({ mutate: vi.fn(), isPending: false, variables: undefined }),
  useDeleteAIProvider: () => ({ mutate: vi.fn() }),
  useUpsertMyRoute: () => ({ mutate: mockUpsertRoute, isPending: false }),
  useDeleteMyRoute: () => ({ mutate: mockDeleteRoute }),
  useUpdateMyAIPreferences: () => ({ mutate: mockPrefs, mutateAsync: mockPrefs }),
}));

vi.mock("@/hooks/useUndoableDelete", () => ({ useUndoableDelete: () => vi.fn() }));

import { MyAISection } from "../MyAISection";

beforeEach(() => {
  vi.clearAllMocks();
  mockUseMyAI.mockReturnValue({ data: overview(), isLoading: false });
  mockUseAIProviders.mockReturnValue({
    data: [
      key({}),
      key({ id: "k2", name: "Anthropic work key", provider_type: "claude", base_url: null, models: ["claude-sonnet-4-6"] }),
      key({ id: "site", name: "Ollama Lab", provider_type: "ollama", user_id: null, supports_tools: true }),
    ],
  });
});

describe("MyAISection", () => {
  it("shows this month's spend against the cap and the keys that are mine", () => {
    render(<MyAISection />, { wrapper: MemoryRouter });
    expect(screen.getByText("$6.42")).toBeInTheDocument();
    expect(screen.getByText("of $25.00 cap")).toBeInTheDocument();
    expect(screen.getByText("41")).toBeInTheDocument();
    expect(screen.getByText("118")).toBeInTheDocument();
    // Only my keys are listed; the instance's provider is not mine to see here.
    expect(screen.getAllByText("OpenRouter personal").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Anthropic work key").length).toBeGreaterThan(0);
    expect(screen.queryByText("Ollama Lab")).toBeNull();
    // The default key is marked.
    expect(screen.getByText("Default")).toBeInTheDocument();
  });

  it("says which key each task runs on, and that copilot on this key has no tools", () => {
    render(<MyAISection />, { wrapper: MemoryRouter });
    const copilot = screen.getByLabelText("Copilot route") as HTMLSelectElement;
    expect(copilot.value).toBe("k1");
    expect(screen.getByText("no tools")).toBeInTheDocument();
    // Detection rules has no route of its own: it follows the default key.
    const rules = screen.getByLabelText("Detection rules route") as HTMLSelectElement;
    expect(rules.value).toBe("");
    expect(screen.getByText(/follows default/)).toBeInTheDocument();
  });

  it("offers an explicit instance option once a default key exists", async () => {
    const user = userEvent.setup();
    render(<MyAISection />, { wrapper: MemoryRouter });
    await user.selectOptions(screen.getByLabelText("Detection rules route"), "instance");
    expect(mockUpsertRoute).toHaveBeenCalledWith({ task_id: "t-rules", provider_id: null });
  });

  it("routes a task to a key with its first model", async () => {
    const user = userEvent.setup();
    render(<MyAISection />, { wrapper: MemoryRouter });
    await user.selectOptions(screen.getByLabelText("Detection rules route"), "k1");
    expect(mockUpsertRoute).toHaveBeenCalledWith({
      task_id: "t-rules",
      provider_id: "k1",
      model_name: "anthropic/claude-sonnet-4.6",
    });
  });

  it("hides the fallback switch under the Required policy", () => {
    render(<MyAISection />, { wrapper: MemoryRouter });
    expect(screen.getByLabelText("Fall back to the instance's providers")).toBeInTheDocument();

    const data = overview();
    data.policy.require_user_ai_provider = true;
    mockUseMyAI.mockReturnValue({ data, isLoading: false });
    render(<MyAISection />, { wrapper: MemoryRouter });
    expect(screen.getAllByLabelText("Fall back to the instance's providers")).toHaveLength(1);
    expect(screen.getByText(/requires your own key/)).toBeInTheDocument();
  });

  it("explains when the admin has personal keys off", () => {
    const data = overview();
    data.policy.allow_user_ai_providers = false;
    mockUseMyAI.mockReturnValue({ data, isLoading: false });
    render(<MyAISection />, { wrapper: MemoryRouter });
    expect(screen.getByText(/Personal keys are off on this instance/)).toBeInTheDocument();
    expect(screen.queryByText("+ Add key")).toBeNull();
  });

  it("refuses Claude Code as a personal key in the add form, with the reason", async () => {
    const user = userEvent.setup();
    render(<MyAISection />, { wrapper: MemoryRouter });
    await user.click(screen.getByText("+ Add key"));
    await user.selectOptions(screen.getByLabelText("Provider type"), "claude_code");
    expect(screen.getByText(/Claude Code can't be a personal key/)).toBeInTheDocument();
    expect(screen.getByText("Test and save")).toHaveProperty("disabled", true);
  });
});
