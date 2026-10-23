import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";

const mockUseAIProviders = vi.fn(() => ({ data: [] as Record<string, unknown>[], isLoading: false }));
const mockUseAITasks = vi.fn(() => ({ data: [] as Record<string, unknown>[] }));
const mockUpdateProviderMutate = vi.fn();

// The User keys tab has its own test file; here it only needs to be reachable.
vi.mock("../UserKeysSection", () => ({ UserKeysSection: () => <div>User keys section</div> }));

// Mock hooks
vi.mock("@/hooks/useAI", () => ({
  useAIProviders: (...args: unknown[]) => mockUseAIProviders(...(args as [])),
  useCreateAIProvider: vi.fn(() => ({
    mutateAsync: vi.fn(),
    isPending: false,
  })),
  useUpdateAIProvider: vi.fn(() => ({ mutate: mockUpdateProviderMutate, isPending: false })),
  useTestAIProvider: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useResumeAIProvider: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useDeleteAIProvider: vi.fn(() => ({ mutate: vi.fn() })),
  useAITasks: (...args: unknown[]) => mockUseAITasks(...(args as [])),
  useCreateAITask: vi.fn(() => ({ mutateAsync: vi.fn(), isPending: false })),
  useUpdateAITask: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useDeleteAITask: vi.fn(() => ({ mutate: vi.fn() })),
  useUpsertTaskAssignment: vi.fn(() => ({ mutate: vi.fn() })),
  useAllTaskAssignments: vi.fn(() => ({ data: [], isLoading: false })),
  useAICostSummary: vi.fn(() => ({
    data: {
      total_cost_30d: 12.45,
      total_requests_30d: 342,
      total_tokens_30d: { input: 125000, output: 18000 },
    },
    isLoading: false,
  })),
  useActivePrompt: vi.fn(() => ({
    data: {
      id: "p1",
      task_id: "t1",
      user_id: null,
      name: "Default",
      template_text: "Test prompt",
      variables: ["entry"],
      is_active: true,
      version: 1,
      created_at: "2026-01-01",
    },
    isLoading: false,
  })),
  useUpdatePrompt: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useResetPrompt: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  usePromptHistory: vi.fn(() => ({ data: [] })),
  useAICostBreakdown: vi.fn(() => ({
    data: {
      total_cost_30d: "57.94",
      total_requests_30d: 48200,
      total_tokens_30d: { input: 125000, output: 18000 },
      instance_cost_30d: "38.10",
      user_key_cost_30d: "19.84",
      unpriced_requests_30d: 44000,
      site_allowance_per_user: 150,
      by_task: [],
      by_model: [],
      budgets: [],
      by_caller: [
        { caller_kind: "system", user_id: null, username: null, requests: 43906, tokens_input: 0, tokens_output: 0, instance_cost: "31.72", own_key_cost: "0", own_key_requests: 0, requests_today: 0 },
        { caller_kind: "user", user_id: "u1", username: "kchen", requests: 902, tokens_input: 0, tokens_output: 0, instance_cost: "2.41", own_key_cost: "0", own_key_requests: 0, requests_today: 141 },
        { caller_kind: "user", user_id: "u2", username: "mreyes", requests: 1384, tokens_input: 0, tokens_output: 0, instance_cost: "0.88", own_key_cost: "12.06", own_key_requests: 300, requests_today: 40 },
      ],
    },
    isLoading: false,
  })),
  useUserKeys: vi.fn(() => ({ data: [] })),
  usePromptPreview: vi.fn(() => ({ mutate: vi.fn(), isPending: false, data: undefined })),
  useRunAIOnEntry: vi.fn(() => ({ mutateAsync: vi.fn(), isPending: false })),
  usePromptBenchEntries: vi.fn(() => ({ data: [] })),
}));

vi.mock("@/hooks/useUndoableDelete", () => ({
  useUndoableDelete: vi.fn(() => vi.fn()),
}));

vi.mock("@/hooks/useAutomation", () => ({
  useAutomationRules: vi.fn(() => ({ data: { items: [] } })),
}));

import AISettings from "../AISettings";

beforeEach(() => {
  mockUseAIProviders.mockReturnValue({ data: [], isLoading: false });
  mockUseAITasks.mockReturnValue({ data: [] });
});

describe("AISettings", () => {
  it("renders tab buttons", () => {
    render(<AISettings />, { wrapper: MemoryRouter });
    const buttons = screen.getAllByRole("button");
    const tabTexts = buttons.map((b) => b.textContent?.trim());
    expect(tabTexts).toContain("Providers");
    expect(tabTexts).toContain("Prompts");
    expect(tabTexts).toContain("Cost Dashboard");
  });

  it("renders all tab buttons including Prompts", () => {
    render(<AISettings />, { wrapper: MemoryRouter });
    const buttons = screen.getAllByRole("button");
    const tabTexts = buttons.map((b) => b.textContent?.trim());
    expect(tabTexts).toContain("Providers");
    expect(tabTexts).toContain("Prompts");
    expect(tabTexts).toContain("Cost Dashboard");
  });

  it("has a User keys tab", () => {
    render(<AISettings />, { wrapper: MemoryRouter });
    expect(screen.getByRole("button", { name: "User keys" })).toBeInTheDocument();
  });

  it("opens the tab a settings deep link names", () => {
    render(
      <MemoryRouter initialEntries={["/settings?section=ai&tab=keys"]}>
        <AISettings />
      </MemoryRouter>,
    );
    expect(screen.getByText("User keys section")).toBeInTheDocument();
  });

  it("cost dashboard splits instance from user-key spend and lists who asked", async () => {
    const user = userEvent.setup();
    render(<AISettings />, { wrapper: MemoryRouter });
    await user.click(screen.getByRole("button", { name: "Cost Dashboard" }));
    expect(screen.getByText("$38.10")).toBeInTheDocument();
    expect(screen.getByText("$19.84")).toBeInTheDocument();
    expect(screen.getByText("Pipeline")).toBeInTheDocument();
    expect(screen.getByText("mreyes")).toBeInTheDocument();
    expect(screen.getByText("$12.06")).toBeInTheDocument();
    // A person near the site allowance gets a warning.
    expect(screen.getByText(/has used 141 of 150 instance requests today/)).toBeInTheDocument();
  });

  it("renders add provider button", () => {
    render(<AISettings />, { wrapper: MemoryRouter });
    expect(screen.getByText("+ Add")).toBeDefined();
  });

  it("add form switches between claude and ollama fields", async () => {
    const user = userEvent.setup();
    render(<AISettings />, { wrapper: MemoryRouter });
    await user.click(screen.getByText("+ Add"));

    // Claude by default: API key required, no base URL field
    expect(screen.getByPlaceholderText("Anthropic API Key")).toBeDefined();
    expect(screen.queryByPlaceholderText(/Base URL/)).toBeNull();

    await user.selectOptions(screen.getByRole("combobox"), "ollama");
    expect(screen.getByPlaceholderText(/Base URL/)).toBeDefined();
    expect(screen.getByPlaceholderText(/Bearer token \(optional/)).toBeDefined();
  });

  it("add form shows an optional-key openai_compatible option with base URL required", async () => {
    const user = userEvent.setup();
    render(<AISettings />, { wrapper: MemoryRouter });
    await user.click(screen.getByText("+ Add"));

    await user.selectOptions(screen.getByRole("combobox"), "openai_compatible");
    expect(screen.getByPlaceholderText(/Base URL/)).toBeDefined();
    expect(screen.getByPlaceholderText("API key (optional for local servers)")).toBeDefined();

    // Save stays disabled until a base URL is entered — no API key required.
    const saveBtn = screen.getByText("Save");
    expect(saveBtn).toHaveProperty("disabled", true);
    await user.type(screen.getByPlaceholderText(/Base URL/), "http://localhost:1234/v1");
    await user.type(screen.getByPlaceholderText("Name (e.g. LM Studio)"), "LM Studio");
    expect(saveBtn).toHaveProperty("disabled", false);
  });

  it("shows hint text for providers", () => {
    render(<AISettings />, { wrapper: MemoryRouter });
    expect(
      screen.getByText(/Add a provider to enable AI features/)
    ).toBeDefined();
  });

  it("renders providers when data available, leaving personal keys to My AI", () => {
    mockUseAIProviders.mockReturnValue({
      data: [
        {
          id: "1",
          name: "Claude Production",
          provider_type: "claude",
          models: ["claude-sonnet-4-6"],
          is_active: true,
          config: {},
          user_id: null,
          created_at: "2026-01-01",
          updated_at: "2026-01-01",
        },
        {
          id: "2",
          name: "My OpenRouter",
          provider_type: "openai_compatible",
          models: [],
          is_active: true,
          config: {},
          user_id: "me",
          created_at: "2026-01-01",
          updated_at: "2026-01-01",
        },
      ],
      isLoading: false,
    });

    render(<AISettings />, { wrapper: MemoryRouter });
    expect(screen.getByText("Claude Production")).toBeDefined();
    expect(screen.getByText("claude")).toBeDefined();
    expect(screen.queryByText("My OpenRouter")).toBeNull();
  });

  it("ollama provider Configure panel edits per-model overrides", async () => {
    mockUseAIProviders.mockReturnValue({
      data: [
        {
          id: "ol1",
          name: "Ollama Lab",
          provider_type: "ollama",
          base_url: "https://ollama.example.com",
          models: ["llama3.2:latest", "qwen3.5:9b"],
          is_active: true,
          config: { keep_alive: "30m" },
          created_at: "2026-01-01",
          updated_at: "2026-01-01",
        },
      ],
      isLoading: false,
    });

    const user = userEvent.setup();
    render(<AISettings />, { wrapper: MemoryRouter });
    await user.click(screen.getByText("Configure"));

    // Defaults row + one row per model
    expect(screen.getByText("All models")).toBeDefined();
    expect(screen.getByText("qwen3.5:9b")).toBeDefined();
    expect(screen.getByText("Keep alive")).toBeDefined();
    // Existing keep_alive from provider config surfaces in the defaults row
    expect(screen.getByDisplayValue("30m")).toBeDefined();
    // Server tuning guide is present (env vars, not editable controls)
    expect(screen.getByText(/Server-side tuning/)).toBeDefined();

    // Turn thinking on for qwen only, then save
    const thinkSelects = screen.getAllByRole("combobox");
    await user.selectOptions(thinkSelects[2], "on"); // 0=all models, 1=llama, 2=qwen
    await user.click(screen.getByText("Save"));

    expect(mockUpdateProviderMutate).toHaveBeenCalledWith(
      {
        id: "ol1",
        config: {
          keep_alive: "30m", // untouched keys preserved
          model_overrides: { "qwen3.5:9b": { think: true } },
        },
      },
      expect.anything()
    );
  });

  it("openai_compatible Configure panel refuses an Extra body that isn't a JSON object", async () => {
    mockUpdateProviderMutate.mockReset();
    mockUseAIProviders.mockReturnValue({
      data: [
        {
          id: "oa1",
          name: "LM Studio",
          provider_type: "openai_compatible",
          base_url: "http://localhost:1234/v1",
          models: ["qwen3-8b"],
          is_active: true,
          config: { default_model: "qwen3-8b" },
          created_at: "2026-01-01",
          updated_at: "2026-01-01",
        },
      ],
      isLoading: false,
    });

    const user = userEvent.setup();
    render(<AISettings />, { wrapper: MemoryRouter });
    await user.click(screen.getByText("Configure"));
    expect(screen.getByDisplayValue("qwen3-8b")).toBeDefined();

    // Valid JSON, but merged into every request with dict.update() — an array
    // would break every call on this provider.
    const extraBody = screen.getByRole("textbox", { name: /Extra body/ });
    await user.click(extraBody);
    await user.paste('[{"chat_template_kwargs": {}}]');
    await user.click(screen.getByText("Save"));

    expect(screen.getByText(/Must be a JSON object/)).toBeDefined();
    expect(mockUpdateProviderMutate).not.toHaveBeenCalled();

    await user.clear(extraBody);
    await user.paste('{"chat_template_kwargs": {"enable_thinking": false}}');
    await user.click(screen.getByText("Save"));
    expect(mockUpdateProviderMutate).toHaveBeenCalledWith(
      {
        id: "oa1",
        config: {
          default_model: "qwen3-8b",
          extra_body: { chat_template_kwargs: { enable_thinking: false } },
        },
      },
      expect.anything()
    );
  });

  it("renders prompts tab content when clicked", async () => {
    mockUseAITasks.mockReturnValue({
      data: [
        {
          id: "task-1",
          name: "ioc_extraction",
          display_name: "IOC Extraction",
          description: "Extract IOCs from text",
          category: "extraction",
          is_system: true,
          created_at: "2026-01-01",
        },
      ],
    });

    render(<AISettings />, { wrapper: MemoryRouter });
    const user = userEvent.setup();
    await user.click(screen.getByText("Prompts"));
    // Master–detail workspace: task appears in the rail and the detail header
    expect(screen.getAllByText("IOC Extraction").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByPlaceholderText("Filter tasks…")).toBeDefined();
    expect(screen.getByRole("tab", { name: "Prompt" })).toBeDefined();
  });
});
