import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

const mockUseEntryTTPs = vi.fn(() => ({ data: [] as Record<string, unknown>[], isLoading: false }));
const mockUseEntryCVEs = vi.fn(() => ({ data: [] as Record<string, unknown>[], isLoading: false }));
const mockUseDetectionRules = vi.fn(() => ({
  data: { items: [] as Record<string, unknown>[], total: 0, limit: 50, offset: 0, has_more: false },
  isLoading: false,
}));

const defaultMutationMock = () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false });
const defaultQueryMock = () => ({ data: [], isLoading: false });

// Mock hooks
vi.mock("@/hooks/useIntelligence", () => ({
  useEntryURLs: vi.fn(() => defaultQueryMock()),
  useEntryTTPs: (...args: unknown[]) => mockUseEntryTTPs(...(args as [])),
  useEntryCVEs: (...args: unknown[]) => mockUseEntryCVEs(...(args as [])),
  useEntryCountries: vi.fn(() => defaultQueryMock()),
  useEntrySectors: vi.fn(() => defaultQueryMock()),
  useEntryThreatActors: vi.fn(() => defaultQueryMock()),
  useEntryMalware: vi.fn(() => defaultQueryMock()),
  useEntryMitigations: vi.fn(() => defaultQueryMock()),
  useEntryTools: vi.fn(() => defaultQueryMock()),
  useEntryVendors: vi.fn(() => defaultQueryMock()),
  useEntryProducts: vi.fn(() => defaultQueryMock()),
  useEntryKillChain: vi.fn(() => defaultQueryMock()),
  useEntryArticleMetadata: vi.fn(() => defaultQueryMock()),
  useEntryObservables: vi.fn(() => ({ data: { items: [] }, isLoading: false })),
  useDetectionRule: vi.fn(() => defaultQueryMock()),
  useExtractTTPs: vi.fn(() => defaultMutationMock()),
  useExtractCVEs: vi.fn(() => defaultMutationMock()),
  useExtractThreatActors: vi.fn(() => defaultMutationMock()),
  useExtractMalware: vi.fn(() => defaultMutationMock()),
  useExtractCountries: vi.fn(() => defaultMutationMock()),
  useExtractMitigations: vi.fn(() => defaultMutationMock()),
  useExtractTools: vi.fn(() => defaultMutationMock()),
  useGenerateDetectionRules: vi.fn(() => defaultMutationMock()),
  useDetectionRules: (...args: unknown[]) => mockUseDetectionRules(...(args as [])),
  useUpdateDetectionRule: vi.fn(() => defaultMutationMock()),
  useDeleteDetectionRule: vi.fn(() => ({ mutate: vi.fn() })),
  useNavigatorLayer: vi.fn(() => ({ refetch: vi.fn(), data: null })),
  useAutolinkEntry: vi.fn(() => defaultMutationMock()),
  useUnlinkEntity: vi.fn(() => defaultMutationMock()),
  useLinkEntity: vi.fn(() => defaultMutationMock()),
}));

vi.mock("@/hooks/useAI", () => ({
  useAITasks: vi.fn(() => ({ data: [] })),
  useRunAIOnEntry: vi.fn(() => defaultMutationMock()),
  useAIResults: vi.fn(() => defaultQueryMock()),
  useRunAIOnEntity: vi.fn(() => defaultMutationMock()),
}));

vi.mock("@/stores/intelStore", () => ({
  useIntelStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      autoOpenIntelPanel: false,
      toggleAutoOpenIntelPanel: vi.fn(),
    })
  ),
}));

vi.mock("@/hooks/useAnalytics", () => ({
  useEntryInsights: vi.fn(() => ({ data: null, isLoading: false })),
}));

vi.mock("react-router-dom", () => ({
  useNavigate: vi.fn(() => vi.fn()),
  // The graph's entry nodes route through useOpenEntry, which reads the route
  // to choose between the feed selection and the workbench's docked reader.
  useLocation: () => ({ pathname: "/" }),
}));

import WorkbenchPanel from "../WorkbenchPanel";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
});

function Wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  mockUseEntryTTPs.mockReturnValue({ data: [], isLoading: false });
  mockUseEntryCVEs.mockReturnValue({ data: [], isLoading: false });
  mockUseDetectionRules.mockReturnValue({
    data: { items: [], total: 0, limit: 50, offset: 0, has_more: false },
    isLoading: false,
  });
});

describe("WorkbenchPanel", () => {
  it("renders panel with extract button", () => {
    render(
      <WorkbenchPanel entryId="test-entry-id" entryTitle="Test Article" />,
      { wrapper: Wrapper }
    );
    expect(screen.getByText("Extract All")).toBeDefined();
  });

  it("renders extract all button", () => {
    render(
      <WorkbenchPanel entryId="test-entry-id" entryTitle="Test Article" />,
      { wrapper: Wrapper }
    );
    expect(screen.getByText("Extract All")).toBeDefined();
  });

  it("renders panel container", () => {
    const { container } = render(
      <WorkbenchPanel entryId="test-entry-id" entryTitle="Test Article" />,
      { wrapper: Wrapper }
    );
    expect(container.querySelector(".panel")).toBeDefined();
  });

  it("renders CVEs when data available", async () => {
    mockUseEntryCVEs.mockReturnValue({
      data: [
        {
          id: "cve-1",
          cve_id: "CVE-2024-21762",
          cvss_score: 9.8,
          severity: "CRITICAL",
          description: "FortiOS out-of-bound write vulnerability",
          affected_products: [],
          exploit_status: "exploitation_detected",
          exploit_sources: ["CISA KEV"],
          nvd_data: {},
          timeline: [],
          first_seen_at: "2024-02-08",
          updated_at: "2024-02-08",
        },
      ],
      isLoading: false,
    });

    render(
      <WorkbenchPanel entryId="test-entry-id" entryTitle="Test Article" />,
      { wrapper: Wrapper }
    );
    // Expand CVEs section
    const user = userEvent.setup();
    const cvesHeader = screen.getAllByRole("button").find(
      (b) => b.textContent?.trim().startsWith("CVEs")
    )!;
    await user.click(cvesHeader);
    expect(screen.getByText("CVE-2024-21762")).toBeDefined();
  });
});
