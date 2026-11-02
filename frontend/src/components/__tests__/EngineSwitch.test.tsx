import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const get = vi.fn();
const put = vi.fn();
vi.mock("@/api/client", () => ({
  default: {
    get: (...args: unknown[]) => get(...args),
    put: (...args: unknown[]) => put(...args),
  },
}));
const confirm = vi.fn();
vi.mock("@/utils/dialog", () => ({ confirmDialog: (...args: unknown[]) => confirm(...args) }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { EngineStoppedBanner, EngineSwitch } from "../engine/EngineSwitch";

function renderIt() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <EngineStoppedBanner />
      <EngineSwitch />
    </QueryClientProvider>,
  );
}

const state = (stopped: boolean, celery = 0) => ({ data: { stopped, queued: { celery, ai: 0, enrichment: 0 } } });

describe("EngineSwitch", () => {
  beforeEach(() => {
    get.mockReset();
    put.mockReset();
    confirm.mockReset();
  });

  it("stops the engine after the admin confirms, then shows the banner", async () => {
    get.mockResolvedValue(state(false));
    put.mockResolvedValue(state(true, 3));
    confirm.mockResolvedValue(true);
    renderIt();

    await userEvent.click(await screen.findByRole("button", { name: /stop engine/i }));

    expect(put).toHaveBeenCalledWith("/engine/state", { stopped: true });
    expect(await screen.findByRole("button", { name: /start engine/i })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("3 queued tasks are waiting");
  });

  it("does nothing when the admin cancels", async () => {
    get.mockResolvedValue(state(false));
    confirm.mockResolvedValue(false);
    renderIt();

    await userEvent.click(await screen.findByRole("button", { name: /stop engine/i }));

    expect(put).not.toHaveBeenCalled();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("starts a stopped engine", async () => {
    get.mockResolvedValue(state(true));
    put.mockResolvedValue(state(false));
    confirm.mockResolvedValue(true);
    renderIt();

    await userEvent.click(await screen.findByRole("button", { name: /start engine/i }));

    expect(put).toHaveBeenCalledWith("/engine/state", { stopped: false });
    expect(await screen.findByRole("button", { name: /stop engine/i })).toBeInTheDocument();
  });
});
