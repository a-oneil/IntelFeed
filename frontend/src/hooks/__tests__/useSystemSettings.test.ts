import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), patch: vi.fn(), delete: vi.fn(), post: vi.fn() },
}));

type MutationOpts = { mutationFn: (v: unknown) => unknown; onSuccess?: (...a: unknown[]) => void };
const captured: MutationOpts[] = [];
const invalidateQueries = vi.fn();

vi.mock("@tanstack/react-query", () => ({
  useQuery: vi.fn(() => ({ data: undefined, isLoading: false })),
  useMutation: vi.fn((opts: MutationOpts) => {
    captured.push(opts);
    return { mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false };
  }),
  useQueryClient: vi.fn(() => ({ invalidateQueries, setQueryData: vi.fn() })),
}));

import { useResetSystemSetting, useUpdateSystemSettings } from "../useSystemSettings";

const invalidatedKeys = () => invalidateQueries.mock.calls.map((c) => JSON.stringify((c[0] as { queryKey: unknown }).queryKey));

beforeEach(() => {
  captured.length = 0;
  invalidateQueries.mockClear();
});

/**
 * The personal-key policy lives in system settings, but My AI, the reader
 * panel's key dots and the copilot header read it from their own endpoints.
 * A save that only refreshed ["system-settings"] left those stale until
 * their own staleTime ran out.
 */
describe("system settings mutations", () => {
  it("refresh My AI and the copilot config on update", () => {
    useUpdateSystemSettings();
    captured[0].onSuccess?.();
    const keys = invalidatedKeys();
    expect(keys).toContain(JSON.stringify(["system-settings"]));
    expect(keys).toContain(JSON.stringify(["publish-status"]));
    expect(keys).toContain(JSON.stringify(["my-ai"]));
    expect(keys).toContain(JSON.stringify(["copilot-config"]));
  });

  it("refresh My AI and the copilot config on reset too", () => {
    useResetSystemSetting();
    captured[0].onSuccess?.();
    const keys = invalidatedKeys();
    expect(keys).toContain(JSON.stringify(["system-settings"]));
    expect(keys).toContain(JSON.stringify(["my-ai"]));
    expect(keys).toContain(JSON.stringify(["copilot-config"]));
  });
});
