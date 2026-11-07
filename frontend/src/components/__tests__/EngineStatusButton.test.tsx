import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const get = vi.fn();
vi.mock("@/api/client", () => ({ default: { get: (...args: unknown[]) => get(...args) } }));
let admin = true;
vi.mock("@/stores/authStore", () => ({ useIsAdmin: () => admin }));

import { EngineStatusButton } from "../EngineStatusButton";

const runs = (error = 0, retry = 0, newCounts?: { new_error: number; new_retry: number }) => ({
  success: 10,
  error,
  retry,
  ...newCounts,
});

function mockApi(
  stopped: boolean,
  stages: { name: string; runs_24h: ReturnType<typeof runs> }[],
  clearedAt: string | null = null,
) {
  get.mockImplementation((url: string) =>
    Promise.resolve({
      data:
        url === "/engine/state"
          ? { stopped, queued: {}, health_cleared_at: clearedAt }
          : { pipeline_engine_enabled: true, run_logging_enabled: true, health_cleared_at: clearedAt, stages },
    }),
  );
}

function renderIt() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <EngineStatusButton />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("EngineStatusButton", () => {
  beforeEach(() => {
    get.mockReset();
    admin = true;
  });

  it("is green when every stage ran clean", async () => {
    mockApi(false, [{ name: "extract", runs_24h: runs() }]);
    renderIt();
    expect(await screen.findByRole("button", { name: "Engine healthy" })).toHaveAttribute("data-level", "ok");
  });

  it("is amber when stages retried", async () => {
    mockApi(false, [{ name: "extract", runs_24h: runs(0, 2) }]);
    renderIt();
    expect(await screen.findByRole("button", { name: "Engine retrying" })).toHaveAttribute("data-level", "warn");
  });

  it("is red when entries are stuck on a stage", async () => {
    mockApi(false, [{ name: "extract", runs_24h: runs(13, 2) }]);
    renderIt();
    expect(await screen.findByRole("button", { name: "Engine errors" })).toHaveAttribute("data-level", "err");
  });

  it("stays green with fewer than ten stuck entries", async () => {
    mockApi(false, [
      { name: "extract", runs_24h: runs(5) },
      { name: "enrich", runs_24h: runs(4) },
    ]);
    renderIt();
    expect(await screen.findByRole("button", { name: "Engine healthy" })).toHaveAttribute("data-level", "ok");
  });

  it("turns red at ten stuck entries across stages", async () => {
    mockApi(false, [
      { name: "extract", runs_24h: runs(6) },
      { name: "enrich", runs_24h: runs(4) },
    ]);
    renderIt();
    expect(await screen.findByRole("button", { name: "Engine errors" })).toHaveAttribute("data-level", "err");
  });

  it("is green after a clear while only older errors remain", async () => {
    mockApi(false, [{ name: "extract", runs_24h: runs(13, 2, { new_error: 0, new_retry: 0 }) }], "2026-11-04T09:00:00Z");
    renderIt();
    expect(await screen.findByRole("button", { name: "Engine healthy" })).toHaveAttribute("data-level", "ok");
  });

  it("turns red again when ten new errors come in after a clear", async () => {
    mockApi(false, [{ name: "extract", runs_24h: runs(23, 2, { new_error: 10, new_retry: 0 }) }], "2026-11-04T09:00:00Z");
    renderIt();
    expect(await screen.findByRole("button", { name: "Engine errors" })).toHaveAttribute("data-level", "err");
  });

  it("shows stopped over errors", async () => {
    mockApi(true, [{ name: "extract", runs_24h: runs(13) }]);
    renderIt();
    expect(await screen.findByRole("button", { name: "Engine stopped" })).toHaveAttribute("data-level", "stopped");
  });

  it("renders nothing and fetches nothing for non-admins", async () => {
    admin = false;
    mockApi(false, []);
    const { container } = renderIt();
    expect(container).toBeEmptyDOMElement();
    expect(get).not.toHaveBeenCalled();
  });
});

describe("EngineStatusButton click", () => {
  it("collapses the settings nav", async () => {
    const { useUIStore } = await import("@/stores/uiStore");
    const { default: userEvent } = await import("@testing-library/user-event");
    useUIStore.setState({ settingsNavCollapsed: false });
    admin = true;
    mockApi(false, [{ name: "extract", runs_24h: runs() }]);
    renderIt();
    await userEvent.click(await screen.findByRole("button", { name: "Engine healthy" }));
    expect(useUIStore.getState().settingsNavCollapsed).toBe(true);
  });
});
