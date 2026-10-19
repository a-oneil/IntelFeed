import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));

import api from "@/api/client";
import { useHygieneFeed, useDismissProposals, useApplyAdjudicationAll } from "../useHygiene";

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

  it("scopes a bulk dismiss to the origin on screen, so one lens never clears another", async () => {
    mockedApi.post.mockResolvedValue({ data: { dismissed: 4 } });
    const { result } = renderHook(() => useDismissProposals(), { wrapper: createWrapper() });
    await result.current.mutateAsync({ source: "entity_maintenance", origin: "adjudicator" });
    expect(mockedApi.post).toHaveBeenCalledWith("/admin/hygiene/dismiss-proposals", {
      source: "entity_maintenance",
      origin: "adjudicator",
    });
  });

  it("applies every pending adjudicator proposal through the stage's own endpoint", async () => {
    mockedApi.post.mockResolvedValue({ data: { applied: 7, skipped: 1, errors: [] } });
    const { result } = renderHook(() => useApplyAdjudicationAll(), { wrapper: createWrapper() });
    const out = await result.current.mutateAsync({ limit: 500 });
    expect(mockedApi.post).toHaveBeenCalledWith("/admin/hygiene/adjudication/apply-all", { limit: 500 });
    expect(out.applied).toBe(7);
  });
});
