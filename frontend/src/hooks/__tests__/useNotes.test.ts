import { describe, it, expect, vi } from "vitest";

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
  useQuery: vi.fn((opts: { queryKey: unknown[] }) => ({
    data: undefined,
    isLoading: false,
    queryKey: opts.queryKey,
  })),
  useMutation: vi.fn(() => ({
    mutate: vi.fn(),
    mutateAsync: vi.fn(),
    isPending: false,
  })),
  useQueryClient: vi.fn(() => ({
    invalidateQueries: vi.fn(),
  })),
}));

import { useNotes, useNote, useEntryNotes, useCreateNote, useUpdateNote, useDeleteNote } from "../useNotes";

describe("useNotes hooks", () => {
  it("useNotes returns query structure", () => {
    const result = useNotes();
    expect(result).toBeDefined();
    expect(result.isLoading).toBe(false);
  });

  it("useNote returns query structure with id", () => {
    const result = useNote("note-1");
    expect(result).toBeDefined();
  });

  it("useEntryNotes returns query structure", () => {
    const result = useEntryNotes("entry-1");
    expect(result).toBeDefined();
  });

  it("useCreateNote returns mutation", () => {
    const result = useCreateNote();
    expect(result.mutate).toBeDefined();
  });

  it("useUpdateNote returns mutation", () => {
    const result = useUpdateNote();
    expect(result.mutate).toBeDefined();
  });

  it("useDeleteNote returns mutation", () => {
    const result = useDeleteNote();
    expect(result.mutate).toBeDefined();
  });
});
