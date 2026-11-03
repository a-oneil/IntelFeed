import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));

import api from "@/api/client";
import { useContextValues } from "../useEntityContext";
import { useRelationshipSignals } from "../useRelationships";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;

function wrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const Wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client: qc }, children);
  return Wrapper;
}

/** Answers each POST with one entry per id it was sent. */
function echo(value: unknown) {
  mockedApi.post.mockImplementation(async (_url: string, body: { ids: string[] }) => ({
    data: Object.fromEntries(body.ids.map((id) => [id, value])),
  }));
}

const page = (n: number) => Array.from({ length: 100 }, (_, i) => `p${n}-${i}`);

describe.each([
  ["context values", (pages: string[][]) => useContextValues("cve", pages, true), { "ctx:epss:epss": 0.5 }],
  ["relationship signals", (pages: string[][]) => useRelationshipSignals("cve", pages), { count: 1, top: [] }],
])("%s for a paged table", (_name, hook, value) => {
  beforeEach(() => vi.clearAllMocks());

  it("asks once per page, never again for a page it has", async () => {
    echo(value);
    const { result, rerender } = renderHook(({ pages }) => hook(pages), {
      wrapper: wrapper(),
      initialProps: { pages: [page(0), page(1)] },
    });
    await waitFor(() => expect(Object.keys(result.current ?? {})).toHaveLength(200));
    expect(mockedApi.post).toHaveBeenCalledTimes(2);

    // Scrolling far past the old 1000-row cap: only the new pages are requested.
    const pages = Array.from({ length: 15 }, (_, n) => page(n));
    rerender({ pages });
    await waitFor(() => expect(Object.keys(result.current ?? {})).toHaveLength(1500));
    expect(mockedApi.post).toHaveBeenCalledTimes(15);
    for (const [, body] of mockedApi.post.mock.calls) expect(body.ids).toHaveLength(100);
    expect(result.current["p14-99"]).toEqual(value);
  });
});
