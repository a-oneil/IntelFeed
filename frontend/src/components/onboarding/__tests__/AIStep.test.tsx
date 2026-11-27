import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { AIProvider, AIProviderCommissionResult } from "@/api/types";

/* These tests guard against an AI step that only calls `POST /ai/providers` and reports "Provider saved." That message is wrong twice: nothing has contacted the host, and a provider row runs no AI on its own; work runs only once tasks are routed to it. */

const createProvider = vi.fn();
const updateProvider = vi.fn();
const commissionProvider = vi.fn();
let providers: AIProvider[] = [];

const OK: AIProviderCommissionResult = {
  success: true,
  message: "Connected",
  models: ["qwen3.5:9b", "gemma4:12b"],
  model: "qwen3.5:9b",
  tasks_assigned: 24,
  tasks_reassigned: 4,
  tasks_skipped_agentic: ["copilot", "entity_enrichment_research"],
};

vi.mock("@/hooks/useAI", () => ({
  useAIProviders: () => ({ data: providers }),
  useCreateAIProvider: () => ({ mutateAsync: createProvider, isPending: false }),
  useUpdateAIProvider: () => ({ mutateAsync: updateProvider, isPending: false }),
  useCommissionAIProvider: () => ({ mutateAsync: commissionProvider, isPending: false }),
}));
vi.mock("@/hooks/useFeeds", () => ({
  useStarterPacks: () => ({ data: [] }),
  useImportStarterPacks: () => ({ mutateAsync: vi.fn(), isPending: false, isSuccess: false }),
  useAddFeed: () => ({ mutateAsync: vi.fn() }),
}));
vi.mock("@/hooks/useOnboarding", () => ({ useOnboardingStatus: () => ({ data: undefined }) }));
vi.mock("@tanstack/react-query", () => ({ useQueryClient: () => ({ invalidateQueries: vi.fn() }) }));
vi.mock("@/api/client", () => ({ default: { post: vi.fn() } }));
vi.mock("react-router-dom", () => ({
  Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
}));

const { StepBody } = await import("../StepBody");

function renderAIStep() {
  return render(
    <StepBody
      step="ai"
      status={undefined}
      refetchStatus={vi.fn()}
      isAdmin
      username="analyst"
      Logo={() => <span />}
      themes={{ list: [], current: undefined, apply: vi.fn() }}
    />,
  );
}

describe("the onboarding AI step", () => {
  beforeEach(() => {
    createProvider.mockReset().mockResolvedValue({ id: "p1" });
    updateProvider.mockReset().mockResolvedValue({ id: "existing" });
    commissionProvider.mockReset().mockResolvedValue(OK);
    providers = [];
  });

  it("routes the AI tasks at the provider, not just registers it", async () => {
    const user = userEvent.setup();
    renderAIStep();
    await user.click(screen.getByRole("button", { name: /^Connect$/ }));

    expect(createProvider).toHaveBeenCalledWith(
      expect.objectContaining({ provider_type: "ollama", base_url: "http://ollama:11434" }),
    );
    // take_over matters: a fresh install's tasks are assigned to the startup CLI provider, and if they stay there no AI runs.
    expect(commissionProvider).toHaveBeenCalledWith({ id: "p1", takeOver: true });
  });

  it("reports what is now running, rather than that something was saved", async () => {
    const user = userEvent.setup();
    renderAIStep();
    await user.click(screen.getByRole("button", { name: /^Connect$/ }));

    await waitFor(() => expect(screen.getByText(/AI tasks are assigned/i)).toBeInTheDocument());
    expect(screen.getByText(/28 tasks now run on/)).toBeInTheDocument();
    expect(screen.getByText("qwen3.5:9b")).toBeInTheDocument();
    // Agentic tasks staying on the CLI is expected behavior, so say so.
    expect(screen.getByText(/2 agentic tasks stayed where they were/)).toBeInTheDocument();
  });

  it("surfaces the provider's own reason when it can't be reached", async () => {
    commissionProvider.mockResolvedValue({
      success: false,
      message: "Connection refused",
      models: [],
      model: null,
      tasks_assigned: 0,
      tasks_reassigned: 0,
      tasks_skipped_agentic: [],
    });
    const user = userEvent.setup();
    renderAIStep();
    await user.click(screen.getByRole("button", { name: /^Connect$/ }));

    // The error shows the provider's own message instead of a generic connection failure the UI cannot know about.
    await waitFor(() => expect(screen.getByText(/Connection refused/)).toBeInTheDocument());
    expect(screen.queryByText(/AI tasks are assigned/i)).not.toBeInTheDocument();
  });

  it("reuses a provider of the same type instead of minting duplicates", async () => {
    // Without the reuse, revisiting the step or replaying the tour adds another provider row each time.
    providers = [{ id: "existing", provider_type: "ollama" } as AIProvider];
    const user = userEvent.setup();
    renderAIStep();
    await user.click(screen.getByRole("button", { name: /^Connect$/ }));

    expect(createProvider).not.toHaveBeenCalled();
    expect(updateProvider).toHaveBeenCalledWith(
      expect.objectContaining({ id: "existing", is_active: true }),
    );
    expect(commissionProvider).toHaveBeenCalledWith({ id: "existing", takeOver: true });
  });

  it("never mistakes the admin's own personal key for the instance provider", async () => {
    // GET /ai/providers lists the caller's personal keys too; reusing one here would make a private key the provider every pipeline task runs on.
    providers = [{ id: "mine", provider_type: "ollama", user_id: "u1" } as AIProvider];
    const user = userEvent.setup();
    renderAIStep();
    await user.click(screen.getByRole("button", { name: /^Connect$/ }));

    expect(updateProvider).not.toHaveBeenCalled();
    expect(createProvider).toHaveBeenCalledWith(expect.objectContaining({ provider_type: "ollama" }));
    expect(commissionProvider).toHaveBeenCalledWith({ id: "p1", takeOver: true });
  });

  it("makes an OpenAI-compatible endpoint name its model rather than guessing one", async () => {
    // /v1/models on api.openai.com lists babbage-002 first; picking from that list would move every task onto a model that can't chat.
    const user = userEvent.setup();
    renderAIStep();
    await user.click(screen.getByRole("button", { name: /OpenAI-compatible/ }));
    await user.type(screen.getByLabelText("Base URL"), "https://api.openai.com/v1");

    const connect = screen.getByRole("button", { name: /^Connect$/ });
    expect(connect).toBeDisabled();

    await user.type(screen.getByLabelText("Model"), "gpt-4o-mini");
    await user.click(connect);

    expect(createProvider).toHaveBeenCalledWith(
      expect.objectContaining({
        provider_type: "openai_compatible",
        base_url: "https://api.openai.com/v1",
        config: { default_model: "gpt-4o-mini" },
      }),
    );
    expect(commissionProvider).toHaveBeenCalledWith({ id: "p1", takeOver: true });
  });

  it("still lets an admin decline AI outright", async () => {
    const user = userEvent.setup();
    renderAIStep();
    await user.click(screen.getByRole("button", { name: /Skip: run without AI/ }));

    expect(screen.getByText(/Nothing to configure/)).toBeInTheDocument();
    expect(commissionProvider).not.toHaveBeenCalled();
  });
});
