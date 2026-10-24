import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import type { AIProvider, AITask, UserAIOverview, UserAIPolicyStatus, UserAIPromptRow } from "@/api/types";

const authState = { user: { id: "me", username: "mreyes", role: "user" }, accessToken: "t" };
vi.mock("@/stores/authStore", () => {
  const useAuthStore = (selector: (s: typeof authState) => unknown) => selector(authState);
  useAuthStore.getState = () => authState;
  return { useAuthStore };
});

vi.mock("@tanstack/react-query", () => ({ useQueryClient: () => ({ invalidateQueries: vi.fn() }) }));

const task = (over: Partial<AITask> = {}): AITask => ({
  id: "t-sum",
  name: "article_summary",
  display_name: "Summary",
  description: null,
  category: "analysis",
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

const providers: AIProvider[] = [
  { id: "site", name: "Site Claude", provider_type: "claude", base_url: null, models: ["claude-haiku-4-5"], is_active: true, config: {}, supports_tools: false, paused_until: null, paused_reason: null, user_id: null, created_at: "", updated_at: "" },
  { id: "k1", name: "My Claude", provider_type: "claude", base_url: null, models: ["claude-sonnet-4-6"], is_active: true, config: {}, supports_tools: false, paused_until: null, paused_reason: null, user_id: "me", created_at: "", updated_at: "" },
];

const policy = (over: Partial<UserAIPolicyStatus> = {}): UserAIPolicyStatus => ({
  allow_user_ai_providers: true,
  require_user_ai_provider: false,
  provider_types: ["claude"],
  allow_private_endpoints: false,
  daily_request_cap: 0,
  site_allowance_per_user: 0,
  has_routes: true,
  ...over,
});

const row = (over: Partial<UserAIPromptRow> = {}): UserAIPromptRow => ({
  task_id: "t-sum",
  task_name: "article_summary",
  display_name: "Summary",
  category: "analysis",
  requires_tools: false,
  site_provider_name: "Site Claude",
  site_model_name: "claude-haiku-4-5",
  route: { id: "r1", task_id: "t-sum", task_name: "article_summary", provider_id: "k1", provider_name: "My Claude", model_name: "claude-sonnet-4-6", config: {}, updated_at: "" },
  month_cost: "0",
  will_run_on: "user",
  blocked_reason: null,
  ...over,
});

const overview = (rows: UserAIPromptRow[], over: Partial<UserAIOverview> = {}): UserAIOverview => ({
  policy: policy(),
  fallback_to_site: true,
  monthly_cap_usd: null,
  usage: { month_cost: "0", monthly_cap_usd: "0", requests_today: 0, daily_request_cap: 0, site_requests_today: 0, site_allowance_per_user: 0, month_resets_at: "", by_key: [] },
  tasks: rows,
  default_route: null,
  ...over,
});

const mockPolicy = vi.fn();
const mockMyAI = vi.fn();
const mockRunEntry = vi.fn();

vi.mock("@/hooks/useAI", () => ({
  useAITasks: () => ({ data: [task()] }),
  useRunAIOnEntry: () => ({ mutateAsync: mockRunEntry }),
  useRunAIOnEntity: () => ({ mutateAsync: vi.fn() }),
  useAllTaskAssignments: () => ({ data: { "t-sum": { provider_id: "site", model_name: "claude-haiku-4-5" } } }),
  useAIProviders: () => ({ data: providers }),
  useMyAIPolicy: () => mockPolicy(),
  useMyAI: (enabled: boolean) => (enabled ? mockMyAI() : { data: undefined }),
}));

import { AIAnalysisSection } from "../AIAnalysisSection";

const renderIt = () => render(<AIAnalysisSection entryId="e1" />, { wrapper: MemoryRouter });
const rowButton = () => screen.getByRole("button", { name: /Summary/ });

beforeEach(() => {
  vi.clearAllMocks();
  mockPolicy.mockReturnValue({ data: policy() });
  mockMyAI.mockReturnValue({ data: overview([row()]) });
});

describe("AIAnalysisSection row labels", () => {
  it("says 'your key' with the personal estimate when the click runs on my key", () => {
    renderIt();
    // Sonnet on a 4000-in / 600-out summary: $0.012 + $0.009.
    expect(rowButton()).toHaveTextContent(/your key · ~\$0\.02/);
    expect(screen.getByLabelText("your key")).toBeInTheDocument();
  });

  it("says why the instance answers when my key is paused", () => {
    mockMyAI.mockReturnValue({ data: overview([row({ will_run_on: "site", blocked_reason: "key_paused" })]) });
    renderIt();
    expect(rowButton()).toHaveTextContent("instance · key paused");
    expect(screen.getByLabelText("instance")).toBeInTheDocument();
    expect(rowButton().title).toMatch(/your key paused/);
  });

  it("warns 'needs a key' when the policy would refuse the click, and 'over cap' for a cap", () => {
    mockMyAI.mockReturnValue({ data: overview([row({ route: null, will_run_on: "refused", blocked_reason: "no_key" })]) });
    renderIt();
    expect(rowButton()).toHaveTextContent("needs a key");
    expect(screen.getByText("needs a key").className).toMatch(/hintWarn/);

    mockMyAI.mockReturnValue({ data: overview([row({ will_run_on: "refused", blocked_reason: "daily_cap" })]) });
    renderIt();
    expect(screen.getByText("over cap")).toBeInTheDocument();
  });

  it("keeps the plain instance estimate when the server sees no reason to fall back", () => {
    mockMyAI.mockReturnValue({ data: overview([row({ route: null, will_run_on: "site", blocked_reason: null })]) });
    renderIt();
    expect(rowButton()).toHaveTextContent(/instance · <\$0\.01/);
  });

  it("without routes: a required key shows 'needs a key'; optional shows the instance estimate without a dot", () => {
    mockPolicy.mockReturnValue({ data: policy({ has_routes: false, require_user_ai_provider: true }) });
    renderIt();
    expect(screen.getByText("needs a key")).toBeInTheDocument();

    mockPolicy.mockReturnValue({ data: policy({ has_routes: false }) });
    renderIt();
    const buttons = screen.getAllByRole("button", { name: /Summary/ });
    expect(buttons[1]).toHaveTextContent(/<\$0\.01/);
    expect(buttons[1]).not.toHaveTextContent("instance");
    expect(screen.queryByLabelText("instance")).toBeNull();
  });
});

describe("AIAnalysisSection refusal link", () => {
  it("offers the fix the reason calls for", async () => {
    const user = userEvent.setup();
    mockRunEntry.mockRejectedValue({
      response: { data: { error: { code: "user_ai_key_required", message: "Your key is over its monthly cap", details: { reason: "monthly_cap" } } } },
    });
    renderIt();
    await user.click(rowButton());
    await waitFor(() => expect(screen.getByText("Your key is over its monthly cap")).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Raise my cap" })).toHaveAttribute("href", "/settings?section=myai");
  });

  it("still says 'Add a key' when there is none", async () => {
    const user = userEvent.setup();
    mockRunEntry.mockRejectedValue({
      response: { data: { error: { code: "user_ai_key_required", message: "A personal key is required", details: { reason: "no_key" } } } },
    });
    renderIt();
    await user.click(rowButton());
    await waitFor(() => expect(screen.getByRole("link", { name: "Add a key" })).toBeInTheDocument());
  });
});
