import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const authState = { user: { id: "me", username: "admin", role: "admin" } };
vi.mock("@/stores/authStore", () => {
  const useAuthStore = (selector: (s: typeof authState) => unknown) => selector(authState);
  useAuthStore.getState = () => authState;
  return { useAuthStore };
});

const get = vi.fn();
const post = vi.fn();
vi.mock("@/api/client", () => ({
  default: {
    get: (...args: unknown[]) => get(...args),
    post: (...args: unknown[]) => post(...args),
  },
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { EntryPipelineStatus, type StageRun } from "../EntryPipelineStatus";

function renderIt() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <EntryPipelineStatus entryId="e1">Oct 23, 2026</EntryPipelineStatus>
    </QueryClientProvider>,
  );
}

const run = (over: Partial<StageRun>): StageRun => ({
  stage: "autolink",
  label: "Entity autolink",
  status: "success",
  duration_ms: 12,
  error: null,
  created_at: null,
  retryable: true,
  detail: null,
  ...over,
});

describe("EntryPipelineStatus", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
  });

  it("opens from the timestamp and lists every stage in pipeline order", async () => {
    get.mockResolvedValue({
      data: {
        status: "in_flight",
        runs: [
          run({}),
          run({ stage: "score", label: "Signal scoring", duration_ms: 629 }),
          run({
            stage: "analyze",
            label: "AI analysis",
            status: "queued",
            duration_ms: null,
            retryable: false,
            detail: { waiting_on: "ai_worker" },
          }),
          run({ stage: "adjudicate", label: "AI review", status: "not_run", duration_ms: null, retryable: false }),
        ],
      },
    });
    renderIt();
    const trigger = screen.getByRole("button", { name: "Oct 23, 2026" });
    expect(get).not.toHaveBeenCalled(); // nothing fetched until opened
    await userEvent.click(trigger);
    expect(get).toHaveBeenCalledWith("/engine/entries/e1/runs");
    expect((await screen.findAllByTestId("stage-label")).map((el) => el.textContent)).toEqual([
      "Entity autolink",
      "Signal scoring",
      "AI analysis",
      "AI review",
    ]);
    expect(screen.getByText("waiting on the AI worker")).toBeInTheDocument();
    expect(screen.getByText("629ms")).toBeInTheDocument();
    expect(screen.getByText("not run")).toBeInTheDocument();
  });

  it("shows the error and lets an admin retry a failed stage", async () => {
    get.mockResolvedValue({
      data: {
        status: "errored",
        runs: [run({ stage: "extract", label: "Intel extraction", status: "error", error: "boom", duration_ms: null })],
      },
    });
    post.mockResolvedValue({ data: {} });
    renderIt();
    await userEvent.click(screen.getByRole("button", { name: "Oct 23, 2026" }));
    expect(await screen.findByText("boom")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "retry" }));
    expect(post).toHaveBeenCalledWith("/engine/entries/e1/stages/extract/retry");
  });

  it("says when an entry predates run logging", async () => {
    get.mockResolvedValue({ data: { status: "unknown", runs: [] } });
    renderIt();
    await userEvent.click(screen.getByRole("button", { name: "Oct 23, 2026" }));
    expect(await screen.findByText(/ingested before pipeline/)).toBeInTheDocument();
  });
});
