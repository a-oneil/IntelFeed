import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

// Mock the auth store
let mockToken: string | null = null;

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { accessToken: string | null }) => unknown) =>
    selector({ accessToken: mockToken }),
}));

// Mock api client
vi.mock("@/api/client", () => ({
  default: {
    post: vi.fn(),
  },
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import api from "@/api/client";

// Mock EventSource globally
const mockClose = vi.fn();
const mockAddEventListener = vi.fn();
const mockRemoveEventListener = vi.fn();

class MockEventSource {
  url: string;
  close = mockClose;
  addEventListener = mockAddEventListener;
  removeEventListener = mockRemoveEventListener;
  onerror: (() => void) | null = null;
  onopen: (() => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }

  static instances: MockEventSource[] = [];
  static clear() {
    MockEventSource.instances = [];
  }
}

vi.stubGlobal("EventSource", MockEventSource);

import { useSSE } from "../useSSE";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return function Wrapper({ children }: { children: ReactNode }) {
    return createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

describe("useSSE", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    MockEventSource.clear();
    mockToken = null;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("creates EventSource with ticket when authenticated", async () => {
    mockToken = "test-jwt-token";
    mockedApi.post.mockResolvedValueOnce({ data: { ticket: "test-ticket" } });

    renderHook(() => useSSE(), { wrapper: createWrapper() });

    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1));
    expect(MockEventSource.instances[0].url).toBe(
      "/api/events?ticket=test-ticket",
    );
    expect(mockAddEventListener).toHaveBeenCalledWith(
      "feed_fetched",
      expect.any(Function),
    );
    expect(mockAddEventListener).toHaveBeenCalledWith(
      "entry_new",
      expect.any(Function),
    );
  });

  it("does not create EventSource without token", () => {
    mockToken = null;

    renderHook(() => useSSE(), { wrapper: createWrapper() });

    expect(MockEventSource.instances).toHaveLength(0);
  });

  it("closes EventSource on unmount", async () => {
    mockToken = "test-jwt-token";
    mockedApi.post.mockResolvedValueOnce({ data: { ticket: "test-ticket" } });

    const { unmount } = renderHook(() => useSSE(), { wrapper: createWrapper() });

    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1));

    unmount();

    expect(mockClose).toHaveBeenCalled();
  });

  /**
   * The connection is built in two steps — await a ticket, then open the
   * EventSource — so an unmount can land between them. It used to: cleanup ran
   * while the ref was still null, found nothing to close, and the awaited
   * ticket then opened a connection nobody owned. Each orphan held one of the
   * browser's ~6 per-origin HTTP/1.1 slots forever, and once they were gone
   * every request in the app queued until its timeout.
   */
  it("opens nothing when unmounted while the ticket is still in flight", async () => {
    mockToken = "test-jwt-token";
    let releaseTicket: (v: { data: { ticket: string } }) => void = () => {};
    mockedApi.post.mockReturnValueOnce(
      new Promise((resolve) => {
        releaseTicket = resolve;
      }),
    );

    const { unmount } = renderHook(() => useSSE(), { wrapper: createWrapper() });

    // Unmount before the ticket resolves — the race window.
    unmount();
    releaseTicket({ data: { ticket: "late-ticket" } });
    await Promise.resolve();
    await Promise.resolve();

    expect(MockEventSource.instances).toHaveLength(0);
  });
});
