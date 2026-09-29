import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));

import api from "@/api/client";
import { useStaleBundle } from "../useBuildVersion";

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

/** Pose as a stamped production image built from `sha`. */
function stampedImage(sha: string) {
  vi.stubGlobal("__STAMP_SOURCE__", "env");
  vi.stubGlobal("__GIT_SHA__", sha);
}

describe("useStaleBundle", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => vi.unstubAllGlobals());

  it("flags a bundle older than the server's", async () => {
    stampedImage("aaaaaaaa");
    mockedApi.get.mockResolvedValue({
      data: { version: "bbbbbbbb", git_sha: "bbbbbbbb", built_at: null },
    });

    const { result } = renderHook(() => useStaleBundle(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => expect(result.current.stale).toBe(true));
    expect(result.current.serverVersion).toBe("bbbbbbbb");
  });

  it("stays quiet when the bundle matches the server", async () => {
    stampedImage("aaaaaaaa");
    mockedApi.get.mockResolvedValue({
      data: { version: "aaaaaaaa", git_sha: "aaaaaaaa", built_at: null },
    });

    const { result } = renderHook(() => useStaleBundle(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => expect(mockedApi.get).toHaveBeenCalled());
    expect(result.current.stale).toBe(false);
  });

  it("does not even ask under the dev server", async () => {
    // The stamp is frozen at dev-server start while HMR keeps the code
    // current, so a mismatch there is routine and means nothing.
    vi.stubGlobal("__STAMP_SOURCE__", "git");
    vi.stubGlobal("__GIT_SHA__", "aaaaaaaa");

    const { result } = renderHook(() => useStaleBundle(), {
      wrapper: createWrapper(),
    });

    expect(result.current.stale).toBe(false);
    expect(mockedApi.get).not.toHaveBeenCalled();
  });

  it("stays quiet when the server reports no commit", async () => {
    stampedImage("aaaaaaaa");
    mockedApi.get.mockResolvedValue({
      data: { version: "dev", git_sha: null, built_at: null },
    });

    const { result } = renderHook(() => useStaleBundle(), {
      wrapper: createWrapper(),
    });

    await waitFor(() => expect(mockedApi.get).toHaveBeenCalled());
    expect(result.current.stale).toBe(false);
  });
});
