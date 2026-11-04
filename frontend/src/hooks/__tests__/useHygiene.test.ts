import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));

import api from "@/api/client";
import { useHygieneFeed, useDismissReview, useApplyReview } from "../useHygiene";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return function Wrapper({ children }: { children: ReactNode }) {
    return createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

describe("hygiene proposal queue hooks", () => {
  beforeEach(() => vi.clearAllMocks());

  it("asks the feed for one origin, and for orphaned rows as its own lens", async () => {
    mockedApi.get.mockResolvedValue({ data: { rows: [], has_more: false, next_offset: 0 } });
    const { result } = renderHook(
      () => useHygieneFeed({ pending: true, origin: "adjudicator", orphaned: true, limit: 25 }),
      { wrapper: createWrapper() },
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.get).toHaveBeenCalledWith("/admin/hygiene/feed", {
      params: { limit: 25, offset: 0, pending: "true", origin: "adjudicator", orphaned: "true" },
    });
  });

  it("scopes Dismiss all to the filters on screen, so one view never clears another", async () => {
    mockedApi.post.mockResolvedValue({ data: { cleared_rows: 4 } });
    const { result } = renderHook(() => useDismissReview(), { wrapper: createWrapper() });
    await result.current.mutateAsync({ origin: "adjudicator", q: "linux" });
    expect(mockedApi.post).toHaveBeenCalledWith("/admin/hygiene/review-groups/dismiss", {
      origin: "adjudicator",
      q: "linux",
    });
  });

  it("applies a group in server batches, never sending a row it already tried", async () => {
    mockedApi.post
      .mockResolvedValueOnce({
        data: { applied: 199, skipped: 1, failed: 0, has_more: true, unapplied: ["entity_maintenance:a"], errors: [] },
      })
      .mockResolvedValueOnce({
        data: {
          applied: 4,
          skipped: 0,
          failed: 1,
          has_more: false,
          unapplied: ["link_validator:b"],
          errors: [{ id: "link_validator:b", error: "boom" }],
        },
      });
    const { result } = renderHook(() => useApplyReview(), { wrapper: createWrapper() });
    const body = { action: "adjudication_unlink", items: [{ entity_type: "product", entity_id: "p1" }] };
    const out = await result.current.mutateAsync(body);
    expect(mockedApi.post).toHaveBeenCalledTimes(2);
    expect(mockedApi.post.mock.calls[0][1]).toEqual({ ...body, exclude: [] });
    expect(mockedApi.post.mock.calls[1][1]).toEqual({ ...body, exclude: ["entity_maintenance:a"] });
    expect(out).toEqual({ applied: 203, skipped: 1, failed: 1, errors: [{ id: "link_validator:b", error: "boom" }] });
  });
});
