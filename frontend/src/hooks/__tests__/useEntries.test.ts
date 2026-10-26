import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

import api from "@/api/client";
import { useEntries, useMarkRead, useToggleStar } from "../useEntries";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return function Wrapper({ children }: { children: ReactNode }) {
    return createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

describe("useEntries", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns paginated entry data from the API", async () => {
    const entriesResponse = {
      items: [
        {
          id: "entry-1",
          feed_id: "feed-1",
          guid: "guid-1",
          url: "https://example.com/post-1",
          title: "Critical CVE Alert",
          author: "Security Researcher",
          summary: "A new critical vulnerability was discovered.",
          published_at: "2026-03-01T12:00:00Z",
          fetched_at: "2026-03-01T12:05:00Z",
          word_count: 500,
          content_hash: "abc123",
          feed_title: "Security Blog",
          is_read: false,
          is_starred: false,
          is_bookmarked: false,
        },
      ],
      next_cursor: null,
      has_more: false,
    };

    mockedApi.get.mockResolvedValueOnce({ data: entriesResponse });

    const { result } = renderHook(
      () => useEntries({ feed_id: "feed-1", sort: "newest" }),
      { wrapper: createWrapper() },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/entries", {
      params: expect.objectContaining({
        feed_id: "feed-1",
        sort: "newest",
        limit: "50",
      }),
    });

    const entries = result.current.data?.pages.flatMap((p) => p.items) || [];
    expect(entries).toHaveLength(1);
    expect(entries[0].title).toBe("Critical CVE Alert");
  });

  it("useMarkRead calls the correct API endpoint", async () => {
    mockedApi.put.mockResolvedValueOnce({ data: undefined });

    const { result } = renderHook(() => useMarkRead(), { wrapper: createWrapper() });

    result.current.mutate("entry-1");

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.put).toHaveBeenCalledWith("/entries/entry-1/read");
  });

  it("rapid mark-reads share one reconcile once the clicking stops", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      mockedApi.put.mockResolvedValue({ data: undefined });
      const queryClient = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
      const invalidate = vi.spyOn(queryClient, "invalidateQueries");
      const wrapper = ({ children }: { children: ReactNode }) =>
        createElement(QueryClientProvider, { client: queryClient }, children);
      const { result } = renderHook(() => useMarkRead(), { wrapper });

      for (const id of ["a", "b", "c", "d"]) {
        await act(async () => {
          await result.current.mutateAsync(id);
          vi.advanceTimersByTime(300);
        });
      }
      expect(mockedApi.put).toHaveBeenCalledTimes(4);
      expect(invalidate).not.toHaveBeenCalled();

      await act(async () => {
        vi.advanceTimersByTime(1500);
      });
      const keys = invalidate.mock.calls.map(([f]) => (f as { queryKey: unknown[] }).queryKey[0]);
      expect(keys.sort()).toEqual(["entries", "entries-count", "entry", "feeds"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("useToggleStar calls the correct API endpoint", async () => {
    mockedApi.put.mockResolvedValueOnce({ data: { is_starred: true } });

    const { result } = renderHook(() => useToggleStar(), { wrapper: createWrapper() });

    result.current.mutate("entry-1");

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.put).toHaveBeenCalledWith("/entries/entry-1/star");
  });
});
