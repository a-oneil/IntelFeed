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

import {
  useAIProviders,
  useCreateAIProvider,
  useTestAIProvider,
  useDeleteAIProvider,
  useAITasks,
  useTaskAssignment,
  useUpsertTaskAssignment,
  useActivePrompt,
  useUpdatePrompt,
  useResetPrompt,
  usePromptHistory,
  useAICostSummary,
  useMyAIPolicy,
} from "../useAI";

describe("useAI hooks", () => {
  it("useAIProviders returns query structure", () => {
    const result = useAIProviders();
    expect(result).toBeDefined();
    expect(result.isLoading).toBe(false);
  });

  it("useCreateAIProvider returns mutation structure", () => {
    const result = useCreateAIProvider();
    expect(result).toBeDefined();
    expect(result.mutate).toBeDefined();
  });

  it("useTestAIProvider returns mutation structure", () => {
    const result = useTestAIProvider();
    expect(result).toBeDefined();
    expect(result.mutate).toBeDefined();
  });

  it("useDeleteAIProvider returns mutation structure", () => {
    const result = useDeleteAIProvider();
    expect(result).toBeDefined();
    expect(result.mutate).toBeDefined();
  });

  it("useAITasks returns query structure", () => {
    const result = useAITasks();
    expect(result).toBeDefined();
  });

  it("useTaskAssignment returns query structure", () => {
    const result = useTaskAssignment("test-id");
    expect(result).toBeDefined();
  });

  it("useUpsertTaskAssignment returns mutation structure", () => {
    const result = useUpsertTaskAssignment();
    expect(result).toBeDefined();
    expect(result.mutate).toBeDefined();
  });

  it("useActivePrompt returns query structure", () => {
    const result = useActivePrompt("test-id");
    expect(result).toBeDefined();
  });

  it("useUpdatePrompt returns mutation structure", () => {
    const result = useUpdatePrompt();
    expect(result).toBeDefined();
  });

  it("useResetPrompt returns mutation structure", () => {
    const result = useResetPrompt();
    expect(result).toBeDefined();
  });

  it("usePromptHistory returns query structure", () => {
    const result = usePromptHistory("test-id");
    expect(result).toBeDefined();
  });

  it("useAICostSummary returns query structure", () => {
    const result = useAICostSummary();
    expect(result).toBeDefined();
  });

  it("useMyAIPolicy returns query structure", () => {
    const result = useMyAIPolicy();
    expect(result).toBeDefined();
  });
});
