import { describe, it, expect, vi } from "vitest";

// Mock axios
vi.mock("@/api/client", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: {
    getState: () => ({ accessToken: "test-token", refreshToken: "test-refresh" }),
  },
}));

vi.mock("@tanstack/react-query", () => ({
  useQuery: vi.fn((_opts: { queryKey: unknown[]; queryFn: () => unknown }) => ({
    data: undefined,
    isLoading: false,
    queryKey: _opts.queryKey,
  })),
  useMutation: vi.fn((_opts: { mutationFn: (data: unknown) => unknown }) => ({
    mutate: vi.fn(),
    mutateAsync: vi.fn(),
    isPending: false,
  })),
  useQueryClient: vi.fn(() => ({
    invalidateQueries: vi.fn(),
  })),
}));

import { useSearch, useSavedSearches, useSearchFacets } from "../useSearch";

describe("useSearch hooks", () => {
  it("useSearch returns query structure", () => {
    const result = useSearch({ q: "CVE" });
    expect(result).toBeDefined();
    expect(result.isLoading).toBe(false);
  });

  it("useSavedSearches returns query structure", () => {
    const result = useSavedSearches();
    expect(result).toBeDefined();
  });

  it("useSearchFacets returns query structure", () => {
    const result = useSearchFacets("test");
    expect(result).toBeDefined();
  });
});
