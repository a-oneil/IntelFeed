import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { OnboardingStatus } from "@/api/types";

const saveProgress = vi.fn();
let status: OnboardingStatus | undefined;
let role = "admin";

const READY: OnboardingStatus = {
  reference_data: { ok: true, checks: [], missing: [], remedy: "", consequence: "" },
  feeds: { total: 37, polled_ok: 34, errored: 0, never_polled: 3 },
  entries: { total: 1284, last_24h: 1284 },
  autolink: { entity_links: 412 },
  ai: { providers: 1, active: "ollama" },
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
    selector({ user: { id: "u1", username: "aoneil", role, settings: {} } }),
}));

const { OnboardingWizard } = await import("../OnboardingWizard");

describe("OnboardingWizard", () => {
  beforeEach(() => {
    saveProgress.mockReset();
    status = READY;
    role = "admin";
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
    render(<OnboardingWizard />);
    // Default start is the first step of the visible flow.
    await waitFor(() => expect(screen.getByText(/Step 1 of/)).toBeInTheDocument());
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
});
