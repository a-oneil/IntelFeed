import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";

const mockUseAIProviders = vi.fn(() => ({ data: [] as Record<string, unknown>[], isLoading: false }));
const mockUseAITasks = vi.fn(() => ({ data: [] as Record<string, unknown>[] }));
const mockUpdateProviderMutate = vi.fn();

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
  useAICostBreakdown: vi.fn(() => ({ data: undefined, isLoading: false })),
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

  it("shows hint text for providers", () => {
    render(<AISettings />, { wrapper: MemoryRouter });
    expect(
      screen.getByText(/Add an API key provider/)
    ).toBeDefined();
  });

  it("renders providers when data available", () => {
    mockUseAIProviders.mockReturnValue({
      data: [
        {
          id: "1",
          name: "Claude Production",
          provider_type: "claude",
          models: ["claude-sonnet-4-6"],
          is_active: true,
          config: {},
          created_at: "2026-01-01",
          updated_at: "2026-01-01",
        },
      ],
      isLoading: false,
    });

    render(<AISettings />, { wrapper: MemoryRouter });
    expect(screen.getByText("Claude Production")).toBeDefined();
    expect(screen.getByText("claude")).toBeDefined();
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
