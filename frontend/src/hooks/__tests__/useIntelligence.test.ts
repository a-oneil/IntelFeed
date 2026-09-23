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
  useEntryTTPs,
  useExtractTTPs,
  useNavigatorLayer,
  useTTPs,
  useEntryCVEs,
  useExtractCVEs,
  useCVEs,
  useCVE,
  useTrendingCVEs,
  useExtractThreatActors,
  useThreatActors,
  useThreatActor,
  useExtractMalware,
  useMalwareFamilies,
  useGenerateDetectionRules,
  useDetectionRules,
  useDetectionRule,
  useUpdateDetectionRule,
  useDeleteDetectionRule,
} from "../useIntelligence";

describe("useIntelligence hooks", () => {
  // TTPs
  it("useEntryTTPs returns query structure", () => {
    const result = useEntryTTPs("test-entry-id");
    expect(result).toBeDefined();
  });

  it("useExtractTTPs returns mutation structure", () => {
    const result = useExtractTTPs();
    expect(result.mutate).toBeDefined();
  });

  it("useNavigatorLayer returns query structure", () => {
    const result = useNavigatorLayer("test-entry-id");
    expect(result).toBeDefined();
  });

  it("useTTPs returns query structure", () => {
    const result = useTTPs({ tactic: "initial-access" });
    expect(result).toBeDefined();
  });

  // CVEs
  it("useEntryCVEs returns query structure", () => {
    const result = useEntryCVEs("test-entry-id");
    expect(result).toBeDefined();
  });

  it("useExtractCVEs returns mutation structure", () => {
    const result = useExtractCVEs();
    expect(result.mutate).toBeDefined();
  });

  it("useCVEs returns query structure", () => {
    const result = useCVEs({ severity: "CRITICAL" });
    expect(result).toBeDefined();
  });

  it("useCVE returns query structure", () => {
    const result = useCVE("CVE-2024-21762");
    expect(result).toBeDefined();
  });

  it("useTrendingCVEs returns query structure", () => {
    const result = useTrendingCVEs(5);
    expect(result).toBeDefined();
  });

  // Threat Actors
  it("useExtractThreatActors returns mutation", () => {
    const result = useExtractThreatActors();
    expect(result.mutate).toBeDefined();
  });

  it("useThreatActors returns query structure", () => {
    const result = useThreatActors();
    expect(result).toBeDefined();
  });

  it("useThreatActor returns query structure", () => {
    const result = useThreatActor("test-id");
    expect(result).toBeDefined();
  });

  // Malware
  it("useExtractMalware returns mutation", () => {
    const result = useExtractMalware();
    expect(result.mutate).toBeDefined();
  });

  it("useMalwareFamilies returns query structure", () => {
    const result = useMalwareFamilies();
    expect(result).toBeDefined();
  });

  // Detection Rules
  it("useGenerateDetectionRules returns mutation", () => {
    const result = useGenerateDetectionRules();
    expect(result.mutate).toBeDefined();
  });

  it("useDetectionRules returns query structure", () => {
    const result = useDetectionRules({ rule_type: "sigma" });
    expect(result).toBeDefined();
  });

  it("useDetectionRules supports entry_id filter", () => {
    const result = useDetectionRules({ entry_id: "test-entry-id" });
    expect(result).toBeDefined();
  });

  it("useDetectionRule returns query structure", () => {
    const result = useDetectionRule("test-id");
    expect(result).toBeDefined();
  });

  it("useUpdateDetectionRule returns mutation", () => {
    const result = useUpdateDetectionRule();
    expect(result.mutate).toBeDefined();
  });

  it("useDeleteDetectionRule returns mutation", () => {
    const result = useDeleteDetectionRule();
    expect(result.mutate).toBeDefined();
  });
});
