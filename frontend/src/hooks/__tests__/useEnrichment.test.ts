import { renderHook } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));
vi.mock("sonner", () => ({ toast: vi.fn() }));
vi.mock("@/stores/authStore", () => ({ useIsVisitor: () => false }));

import api from "@/api/client";
import {
  useEnrichEntity,
  useRetryFailedLookups,
  useSetEnrichmentKey,
  useTestEnrichmentKey,
  useUpdateEnrichmentSource,
} from "../useEnrichment";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;
type Runner = { mutateAsync: (v: never) => Promise<unknown> };

function setup() {
  const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  const invalidate = vi.spyOn(qc, "invalidateQueries");
  const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client: qc }, children);
  const keys = () => invalidate.mock.calls.map(([filters]) => (filters as { queryKey: unknown[] }).queryKey);
  return { wrapper, keys };
}

describe("enrichment mutations", () => {
  beforeEach(() => vi.clearAllMocks());

  it.each<[string, () => Runner, unknown]>([
    ["test a key", useTestEnrichmentKey, "nvd_api_key"],
    ["save a shared key", useSetEnrichmentKey, { keyId: "abuse_ch", apiKey: "k" }],
    ["remove my key", useSetEnrichmentKey, { keyId: "abuse_ch", apiKey: null, mine: true }],
    ["retry lookups that gave up", useRetryFailedLookups, "greynoise"],
    ["update a source", useUpdateEnrichmentSource, { sourceId: "s1", is_enabled: true }],
  ])("%s refreshes the console", async (_name, hook, vars) => {
    mockedApi.post.mockResolvedValue({ data: { status: "ok", message: null, queued: 3 } });
    mockedApi.put.mockResolvedValue({ data: {} });
    mockedApi.delete.mockResolvedValue({ data: undefined });
    const { wrapper, keys } = setup();
    const { result } = renderHook(hook, { wrapper });
    await result.current.mutateAsync(vars as never);
    expect(keys()).toContainEqual(["enrichment-console"]);
  });

  it("writes the shared key and the caller's own key to their own routes", async () => {
    mockedApi.put.mockResolvedValue({ data: {} });
    const { wrapper } = setup();
    const { result } = renderHook(() => useSetEnrichmentKey(), { wrapper });
    await result.current.mutateAsync({ keyId: "virustotal", apiKey: "shared" });
    await result.current.mutateAsync({ keyId: "virustotal", apiKey: "mine", mine: true });
    expect(mockedApi.put).toHaveBeenNthCalledWith(1, "/enrichment/keys/virustotal", { api_key: "shared" });
    expect(mockedApi.put).toHaveBeenNthCalledWith(2, "/enrichment/keys/virustotal/mine", { api_key: "mine" });
  });

  it("asks for the manual lane when a person enriches", async () => {
    mockedApi.post.mockResolvedValue({ data: { entity_type: "cve", entity_id: "c1", results: [], queued: [] } });
    const { wrapper } = setup();
    const { result } = renderHook(() => useEnrichEntity(), { wrapper });
    await result.current.mutateAsync({ entityType: "cve", entityId: "c1", sourceTypes: ["nvd"] });
    expect(mockedApi.post).toHaveBeenCalledWith("/enrichment/enrich", {
      entity_type: "cve",
      entity_id: "c1",
      source_types: ["nvd"],
      refresh: undefined,
      lane: "manual",
    });
  });
});
