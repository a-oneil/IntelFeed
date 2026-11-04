import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { OnboardingStatus } from "@/api/types";

const saveProgress = vi.fn();
let status: OnboardingStatus | undefined;
let role = "admin";
let settings: Record<string, unknown> = {};

const READY: OnboardingStatus = {
  reference_data: { ok: true, checks: [], missing: [], remedy: "", consequence: "" },
  feeds: { total: 37, polled_ok: 34, errored: 0, never_polled: 3 },
  entries: { total: 1284, last_24h: 1284 },
  autolink: { entity_links: 412 },
  ai: { providers: 1, active: "ollama", tasks_assigned: 28 },
  ready: true,
};

vi.mock("@/hooks/useOnboarding", () => ({
  useOnboardingStatus: () => ({ data: status, refetch: vi.fn(), isLoading: false }),
  useSaveOnboardingProgress: () => ({ mutate: saveProgress, isPending: false }),
}));
vi.mock("@/hooks/useThemes", () => ({
  useThemes: () => ({ data: [] }),
  useSetThemePreference: () => ({ mutate: vi.fn() }),
}));
vi.mock("@/hooks/useFeeds", () => ({
  useStarterPacks: () => ({ data: [] }),
  useImportStarterPacks: () => ({ mutateAsync: vi.fn(), isPending: false, isSuccess: false }),
  useAddFeed: () => ({ mutateAsync: vi.fn() }),
}));
vi.mock("@/hooks/useAI", () => ({ useCreateAIProvider: () => ({ mutateAsync: vi.fn(), isPending: false }) }));
vi.mock("@tanstack/react-query", () => ({ useQueryClient: () => ({ invalidateQueries: vi.fn() }) }));
vi.mock("@/api/client", () => ({ default: { post: vi.fn() } }));
vi.mock("react-router-dom", () => ({
  Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
}));
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) =>
    selector({ user: { id: "u1", username: "analyst", role, settings } }),
}));

const { OnboardingWizard } = await import("../OnboardingWizard");

describe("OnboardingWizard", () => {
  beforeEach(() => {
    saveProgress.mockReset();
    status = READY;
    role = "admin";
    settings = {};
  });

  it("closing defers instead of completing", async () => {
    // The old wizard set onboarding_completed on dismiss, so one stray close
    // permanently burned the flow for that account.
    const user = userEvent.setup();
    render(<OnboardingWizard />);
    await user.click(screen.getByRole("button", { name: /close/i }));

    expect(saveProgress).toHaveBeenCalledTimes(1);
    const arg = saveProgress.mock.calls[0][0];
    expect(arg.onboarding_step).toBeTruthy();
    expect(arg.onboarding_completed).toBeUndefined();
    // ...and the deferral is persisted, or the next hard refresh reopens the
    // tour over someone who already closed it — `dismissed` dies with the page.
    expect(arg.onboarding_deferred_at).toBeTruthy();
  });

  it("Escape also defers rather than completing", async () => {
    const user = userEvent.setup();
    render(<OnboardingWizard />);
    await user.keyboard("{Escape}");
    expect(saveProgress.mock.calls[0][0].onboarding_completed).toBeUndefined();
  });

  it("only finishing marks onboarding complete, and clears the saved step", async () => {
    const user = userEvent.setup();
    render(<OnboardingWizard />);
    // Walk to the end. Read the label before each click — the footer button is
    // re-rendered every step, so a reference taken earlier goes stale.
    for (let i = 0; i < 30; i += 1) {
      const btn = screen.getByRole("button", { name: /^(Next|Finish)$/ });
      const wasLast = btn.textContent === "Finish";
      await user.click(btn);
      if (wasLast) break;
    }
    const finish = saveProgress.mock.calls.at(-1)![0];
    expect(finish.onboarding_completed).toBe(true);
    expect(finish.onboarding_step).toBeNull();
    expect(finish.onboarding_deferred_at).toBeNull();
  });

  it("is a labelled modal dialog", () => {
    render(<OnboardingWizard />);
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-labelledby");
  });

  it("gives a non-admin the usage chapters, not a stub", async () => {
    role = "user";
    render(<OnboardingWizard />);
    expect(screen.getByText(/Step 1 of 10/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reference data" })).not.toBeInTheDocument();
  });

  it("names the reason a setup step was dropped", () => {
    role = "user";
    render(<OnboardingWizard />);
    expect(screen.getAllByText("admin only").length).toBeGreaterThan(0);
  });

  it("resumes at the saved step", async () => {
    settings = { onboarding_step: "queue" };
    render(<OnboardingWizard />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "The Priority Queue" })).toBeInTheDocument());
  });

  it("disables Back on the first step", () => {
    render(<OnboardingWizard />);
    expect(screen.getByRole("button", { name: "Back" })).toBeDisabled();
  });

  it("stays on the same step when the flow changes underneath it", async () => {
    // The setup steps disappear as the user satisfies them — they run the
    // seeder and re-check, a feed finishes polling. Position is tracked by step
    // id for exactly this reason: an index would quietly point at a different
    // step once the list shrank, teleporting the reader mid-sentence.
    status = {
      ...READY,
      reference_data: { ...READY.reference_data, ok: false },
      feeds: { total: 0, polled_ok: 0, errored: 0, never_polled: 0 },
      ready: false,
    };
    const user = userEvent.setup();
    const { rerender } = render(<OnboardingWizard />);

    await user.click(screen.getByRole("button", { name: "Priority Queue" }));
    expect(screen.getByRole("heading", { name: /Priority Queue/ })).toBeInTheDocument();

    // Setup completes out of band; four steps vanish from the flow.
    status = READY;
    rerender(<OnboardingWizard />);

    expect(screen.getByRole("heading", { name: /Priority Queue/ })).toBeInTheDocument();
  });

  it.each([
    ["Reference data", "readiness", "Optional services, and your team"],
    ["Verify it works", "verify", "The reading loop"],
  ])("advances when the current %s step becomes satisfied", async (label, id, nextHeading) => {
    status = { ...READY, reference_data: { ...READY.reference_data, ok: false }, ready: false };
    const user = userEvent.setup();
    const { rerender } = render(<OnboardingWizard />);
    await user.click(screen.getByRole("button", { name: label }));
    settings = { onboarding_step: id };
    status = READY;
    rerender(<OnboardingWizard />);
    expect(screen.getByRole("heading", { name: nextHeading })).toBeInTheDocument();
    // A later readiness change must not take the user back to the old step.
    status = { ...READY, reference_data: { ...READY.reference_data, ok: false }, ready: false };
    rerender(<OnboardingWizard />);
    expect(screen.getByRole("heading", { name: nextHeading })).toBeInTheDocument();
  });

  it("replays a deferred tour from the beginning, including repeated replays", async () => {
    settings = { onboarding_step: "queue" };
    const user = userEvent.setup();
    const { rerender } = render(<OnboardingWizard />);
    for (const runId of ["first-replay", "second-replay"]) {
      await user.click(screen.getByRole("button", { name: /close/i }));
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      settings = { onboarding_completed: false, onboarding_step: null, onboarding_run_id: runId };
      rerender(<OnboardingWizard />);
      expect(screen.getByRole("heading", { name: "Welcome to IntelFeed" })).toBeInTheDocument();
    }
  });

  it("restores focus and stops handling Escape after dismissal", async () => {
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();
    try {
      const user = userEvent.setup();
      render(<OnboardingWizard />);
      expect(screen.getByRole("dialog")).toHaveFocus();
      await user.click(screen.getByRole("button", { name: /close/i }));
      expect(trigger).toHaveFocus();
      saveProgress.mockReset();
      const event = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
      fireEvent(document, event);
      expect(event.defaultPrevented).toBe(false);
      expect(saveProgress).not.toHaveBeenCalled();
    } finally {
      trigger.remove();
    }
  });

});
