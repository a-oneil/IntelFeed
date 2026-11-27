import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const authState = { user: { id: "me", username: "analyst", role: "user" } };
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
    put: vi.fn(),
    delete: vi.fn(),
  },
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { TelemetrySourceDrawer } from "../TelemetrySourceDrawer";

const note = (over: Record<string, unknown>) => ({
  id: "n1",
  source_name: "AWS GuardDuty",
  user_id: "me",
  username: "analyst",
  url: null,
  page_title: null,
  quote: null,
  content: null,
  created_at: "2026-11-24T10:00:00Z",
  updated_at: "2026-11-24T10:00:00Z",
  ...over,
});

function renderIt() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
      <TelemetrySourceDrawer
        source={{ name: "AWS GuardDuty", vendor: "Amazon", product: "GuardDuty", log_types: ["malware_finding"] }}
        onClose={() => {}}
      />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("TelemetrySourceDrawer", () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
  });

  it("splits links from notes, renders markdown, and offers edit only on your own", async () => {
    get.mockResolvedValue({
      data: {
        items: [
          note({ id: "a", url: "https://docs.aws.amazon.com/guardduty/x", page_title: "Finding types", quote: "Needs the agent" }),
          note({ id: "b", content: "**EC2** fleet has no agent", user_id: "someone-else", username: "lee" }),
        ],
        total: 2,
      },
    });
    renderIt();

    const link = await screen.findByRole("link", { name: /Finding types/ });
    expect(link).toHaveAttribute("href", "https://docs.aws.amazon.com/guardduty/x");
    expect(screen.getByText("Needs the agent")).toBeInTheDocument();
    // Rendered as markdown, like every other note.
    expect(screen.getByText("EC2").tagName).toBe("STRONG");
    // One Edit and one Delete, on the current user's note only; lee's note has neither.
    expect(screen.getAllByRole("button", { name: /Edit/ })).toHaveLength(1);
    expect(screen.getAllByTitle("Delete note")).toHaveLength(1);
  });

  it("never renders a non-http link", async () => {
    get.mockResolvedValue({ data: { items: [note({ url: "javascript:alert(1)", page_title: "x" })], total: 1 } });
    renderIt();
    await screen.findByText("Links");
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("saves a link with the source name", async () => {
    get.mockResolvedValue({ data: { items: [], total: 0 } });
    post.mockResolvedValue({ data: note({}) });
    renderIt();
    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/Link to a page/), "https://docs.aws.amazon.com/guardduty/");
    await user.click(screen.getByRole("button", { name: /Save link/ }));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/telemetry-sources/notes", {
        source_name: "AWS GuardDuty",
        url: "https://docs.aws.amazon.com/guardduty/",
        content: null,
      }),
    );
  });
});
