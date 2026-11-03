import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";

const mockUpdateTaskMutate = vi.fn();
const mockUpsertAssignmentMutate = vi.fn();

const tasks = [
  {
    id: "t-analysis",
    name: "threat_assessment",
    display_name: "Threat Assessment",
    description: "Assess threat level for a single article.",
    category: "analysis",
    is_system: true,
    requires_tools: false,
    is_deprecated: false,
    show_in_entry_actions: true,
    show_in_entity_actions: true,
    entry_action_order: 0,
    variables: [],
    output_schema: { type: "object", properties: { rating: { type: "string" } } },
    output_schema_override: null,
    created_at: "2026-01-01",
  },
  {
    id: "t-generation",
    name: "detection_rules",
    display_name: "Detection Rules",
    description: "Generate detection rules.",
    category: "generation",
    is_system: true,
    requires_tools: false,
    is_deprecated: false,
    show_in_entry_actions: false,
    show_in_entity_actions: false,
    entry_action_order: null,
    variables: [],
    output_schema: { type: "object", properties: { rules: { type: "array" } } },
    output_schema_override: null,
    created_at: "2026-01-01",
  },
  {
    id: "t-custom",
    name: "my_custom",
    display_name: "My Custom Task",
    description: null,
    category: "custom",
    is_system: false,
    requires_tools: false,
    is_deprecated: false,
    show_in_entry_actions: true,
    show_in_entity_actions: true,
    entry_action_order: null,
    variables: [],
    output_schema: null,
    output_schema_override: null,
    created_at: "2026-01-01",
  },
];

const providers = [
  {
    id: "prov-1",
    name: "ollama",
    provider_type: "ollama",
    models: ["qwen3:14b"],
    is_active: true,
    supports_tools: false,
    config: { num_ctx_max: 8192 },
  },
];

const activePrompt = {
  id: "p2",
  task_id: "t-analysis",
  created_by: "user-1",
  name: "Threat assessment — sector focus",
  template_text: "Assess {{ entry.title }}\nline two",
  system_text: "You are an analyst.",
  variables: [],
  is_active: true,
  version: 2,
  created_at: "2026-08-10",
};

const historyVersions = [
  activePrompt,
  {
    ...activePrompt,
    id: "p1",
    created_by: null,
    name: "System default",
    template_text: "Assess {{ entry.title }}\nold line",
    is_active: false,
    version: 1,
  },
];

vi.mock("@/hooks/useAI", () => ({
  useAITasks: vi.fn(() => ({ data: tasks, isLoading: false })),
  useAIProviders: vi.fn(() => ({ data: providers })),
  useAllTaskAssignments: vi.fn(() => ({
    data: {
      "t-analysis": {
        id: "a1",
        task_id: "t-analysis",
        provider_id: "prov-1",
        model_name: "qwen3:14b",
        is_enabled: true,
        config: {},
        created_by: null,
      },
    },
  })),
  useUpsertTaskAssignment: vi.fn(() => ({ mutate: mockUpsertAssignmentMutate })),
  useCreateAITask: vi.fn(() => ({ mutateAsync: vi.fn(), isPending: false })),
  useUpdateAITask: vi.fn(() => ({ mutate: mockUpdateTaskMutate, isPending: false })),
  useDeleteAITask: vi.fn(() => ({ mutate: vi.fn() })),
  useActivePrompt: vi.fn(() => ({ data: activePrompt, isLoading: false })),
  useUpdatePrompt: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  useResetPrompt: vi.fn(() => ({ mutate: vi.fn(), isPending: false })),
  usePromptHistory: vi.fn(() => ({ data: historyVersions })),
  usePromptPreview: vi.fn(() => ({ mutate: vi.fn(), isPending: false, data: undefined })),
  useRunAIOnEntry: vi.fn(() => ({ mutateAsync: vi.fn(), isPending: false })),
  usePromptBenchEntries: vi.fn(() => ({
    data: [{ id: "e1", title: "Scattered Spider pivots to ESXi" }],
  })),
  useAgentTools: vi.fn(() => ({ data: [], isLoading: false })),
}));

// AgentToolsRow reads the copilot config; without this the real hook runs and
// blows up on the missing QueryClientProvider.
vi.mock("@/hooks/useCopilotAuth", () => ({
  useCopilotConfig: vi.fn(() => ({ data: undefined, isLoading: false })),
}));

vi.mock("@/hooks/useAutomation", () => ({
  useAutomationRules: vi.fn(() => ({
    data: {
      items: [
        {
          id: "rule-1",
          name: "Weekday Morning Briefing",
          actions: [{ type: "run_ai_task", config: { task_id: "threat_assessment" } }],
        },
      ],
    },
  })),
}));

vi.mock("@/hooks/useUndoableDelete", () => ({
  useUndoableDelete: vi.fn(() => vi.fn()),
}));

import PromptWorkspace from "../PromptWorkspace";

beforeEach(() => {
  vi.clearAllMocks();
});

function renderWorkspace() {
  return render(<PromptWorkspace />, { wrapper: MemoryRouter });
}

describe("PromptWorkspace", () => {
  it("renders tasks in the rail grouped by category with model chips", () => {
    renderWorkspace();
    expect(screen.getByText("Analysis")).toBeDefined();
    expect(screen.getByText("Generation")).toBeDefined();
    expect(screen.getAllByText("Custom").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Threat Assessment").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("ollama / qwen3:14b")).toBeDefined();
    expect(screen.getAllByText("not assigned").length).toBe(2);
  });

  it("selects the first task and shows its header badges and Used by line", () => {
    renderWorkspace();
    expect(screen.getByText("System task")).toBeDefined();
    expect(screen.getByText(/Custom prompt · v2/)).toBeDefined();
    expect(screen.getByText("Weekday Morning Briefing")).toBeDefined();
    expect(screen.getByText(/Article actions #1/)).toBeDefined();
  });

  it("shows the prompt editor toolbar with versioned save", () => {
    renderWorkspace();
    expect(screen.getByDisplayValue("Threat assessment — sector focus")).toBeDefined();
    expect(screen.getByText("Save as v3")).toBeDefined();
    expect(screen.getByText("Reset to default")).toBeDefined();
  });

  it("filters the rail by search", async () => {
    const user = userEvent.setup();
    renderWorkspace();
    await user.type(screen.getByPlaceholderText("Filter tasks…"), "detection");
    expect(screen.queryByText("My Custom Task")).toBeNull();
    expect(screen.getAllByText("Detection Rules").length).toBeGreaterThanOrEqual(1);
  });

  it("toggles article-action visibility from the Routing tab", async () => {
    const user = userEvent.setup();
    renderWorkspace();
    await user.click(screen.getByRole("tab", { name: /Routing & Visibility/ }));
    await user.click(screen.getByLabelText("Show in article actions"));
    expect(mockUpdateTaskMutate).toHaveBeenCalledWith({
      taskId: "t-analysis",
      show_in_entry_actions: false,
    });
  });

  it("disables the task-enabled toggle when unassigned", async () => {
    const user = userEvent.setup();
    renderWorkspace();
    // Select the unassigned generation task (rail row, not the narrow-mode
    // select option), then open Routing
    await user.click(screen.getByRole("button", { name: /Detection Rules/ }));
    await user.click(screen.getByRole("tab", { name: /Routing & Visibility/ }));
    expect(screen.getByLabelText("Task enabled")).toHaveProperty("disabled", true);
  });

  it("shows a line diff between versions in the History tab", async () => {
    const user = userEvent.setup();
    renderWorkspace();
    await user.click(screen.getByRole("tab", { name: /History/ }));
    await user.click(screen.getByText("System default"));
    expect(screen.getByText(/Comparing/)).toBeDefined();
    expect(screen.getByText(/old line/)).toBeDefined();
    expect(screen.getByText(/line two/)).toBeDefined();
    expect(screen.getByText("Restore v1 as new version")).toBeDefined();
  });

  it("opens the create pane from + New", async () => {
    const user = userEvent.setup();
    renderWorkspace();
    await user.click(screen.getByText("+ New"));
    expect(screen.getByText("New custom task")).toBeDefined();
    expect(screen.getByPlaceholderText("e.g. my_custom_analysis")).toBeDefined();
  });
});
