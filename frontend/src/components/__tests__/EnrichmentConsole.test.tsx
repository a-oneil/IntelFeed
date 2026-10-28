import { render, screen, fireEvent, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import type { EnrichmentConsole as ConsoleData, EnrichmentSourceDetail } from "@/hooks/useEnrichment";
import type { EnrichmentSource } from "@/api/types";
import { EnrichmentConsole } from "../engine/EnrichmentConsole";

// Payloads in the shapes of the build spec's console API (§C).
const consoleData: ConsoleData = {
  summary: {
    sources_on: 11,
    sources_total: 17,
    needs_attention: 1,
    paused: false,
    redis_ok: true,
    activity_24h: { requests: 4212, queued: 1730, deferred: 94, iocs_sent_off_box: 0 },
  },
  entity_types: [
    { entity_type: "cve", label: "CVE", source_count: 3 },
    { entity_type: "observable", label: "Observable", source_count: 1 },
  ],
  sources: [
    {
      id: "id-nvd",
      source_type: "nvd",
      label: "NVD 2.0",
      kind: "lookup",
      status: "failing",
      enabled: true,
      fills: "CVSS, CWE, affected products",
      applies_to: ["cve"],
      attention: "cve-nvd-backfill failed 30 of 33 runs",
    },
    {
      id: "id-epss",
      source_type: "epss",
      label: "EPSS",
      kind: "lookup",
      status: "ok",
      enabled: true,
      fills: "EPSS score, percentile",
      applies_to: ["cve"],
      attention: null,
    },
    {
      id: "id-osv",
      source_type: "osv",
      label: "OSV",
      kind: "lookup",
      status: "off",
      enabled: false,
      fills: "aliases, fixed versions",
      applies_to: ["cve"],
      attention: null,
    },
    {
      id: "id-virustotal",
      source_type: "virustotal",
      label: "VirusTotal",
      kind: "lookup",
      status: "needs_key",
      enabled: false,
      fills: "reputation",
      applies_to: ["observable"],
      attention: null,
    },
  ],
};

const detail: EnrichmentSourceDetail = {
  limits: {
    requests_per_period: 50,
    period_seconds: 30,
    ceiling_per_period: 100,
    daily_budget: 5000,
    used_today: 3100,
    backfill_share: 0.6,
    refresh_days: 30,
    key: "global",
    triggers: ["new", "refresh", "manual", "backfill"],
    scope: "cve with no CVSS, or changed in 7 days",
  },
  trend_24h: Array.from({ length: 24 }, (_, i) => (i % 5) * 10),
  queue: { waiting: 1224, by_lane: { backfill: 898, refresh: 240, manual: 0, new: 0 }, retrying: 86, failed: 0 },
  outputs: [
    { field: "baseScore", target: "cve.cvss_score", kind: "column", policy: "rank", rank: 1, filled_pct: 72.1 },
    { field: "references", target: "context", kind: "context", filled_pct: null },
    {
      field: "tools",
      target: "relationship: uses malware or tool",
      kind: "relationship",
      filled_pct: null,
      linked: 1204,
      held: 37,
    },
  ],
  gap: { entity_type: "cve", field: "cvss_score", missing: 23665, in_scope: 14100, eta_days: 3.4 },
  jobs: [
    {
      key: "cve-nvd-backfill",
      schedule: "daily 01:30",
      runs_30d: 33,
      ok_30d: 3,
      last_status: "error",
      last_error: "TimeLimitExceeded(960)",
      last_detail: { enriched: 0 },
    },
    {
      key: "cve-nvd-refresh",
      schedule: "hourly",
      runs_30d: 30,
      ok_30d: 30,
      last_status: "success",
      last_error: null,
      last_detail: null,
    },
  ],
};

const row = (source_type: string, extra: Partial<EnrichmentSource> = {}) =>
  ({
    id: `id-${source_type}`,
    source_type,
    display_name: source_type,
    is_enabled: true,
    trigger_mode: "auto",
    has_api_key: false,
    requires_api_key: false,
    shared_key_group: null,
    rate_limit_config: { requests_per_period: 50, period_seconds: 30 },
    min_confidence_threshold: "low",
    daily_budget: 5000,
    supported_entity_types: ["cve"],
    last_synced_at: null,
    health_status: "healthy",
    config: {},
    created_at: "",
    updated_at: "",
    ...extra,
  }) as EnrichmentSource;

const consoleSpy = vi.fn();
const pauseMutate = vi.fn();
const backfillMutate = vi.fn();
const updateMutate = vi.fn();
const enrichGapMutate = vi.fn();

vi.mock("@/hooks/useEnrichment", () => ({
  useEnrichmentConsole: (entityType?: string) => {
    consoleSpy(entityType);
    const sources = entityType
      ? consoleData.sources.filter((x) => x.applies_to.includes(entityType))
      : consoleData.sources;
    return { data: { ...consoleData, sources }, isError: false };
  },
  useEnrichmentSources: () => ({
    data: [row("nvd"), row("epss"), row("osv", { is_enabled: false }), row("virustotal", { requires_api_key: true })],
  }),
  useEnrichmentSourceDetail: (sourceType: string | null) => ({
    data: sourceType ? detail : undefined,
    isLoading: false,
    isError: false,
  }),
  usePauseEnrichment: () => ({ mutate: pauseMutate, isPending: false }),
  useQueueBackfill: () => ({ mutate: backfillMutate, isPending: false }),
  useUpdateEnrichmentSource: () => ({ mutate: updateMutate, isPending: false }),
  useTestEnrichmentSource: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useUserEnrichmentOverrides: () => ({ data: [] }),
  useUpsertUserOverride: () => ({ mutate: vi.fn(), isPending: false }),
  useDeleteUserOverride: () => ({ mutate: vi.fn(), isPending: false }),
}));

vi.mock("@/hooks/useHygiene", () => ({
  useEnrichmentGaps: () => ({
    data: { buckets: [{ entity_type: "cve", field: "cvss", missing: 42, sample: [] }] },
    isLoading: false,
  }),
  useEnrichGap: () => ({ mutateAsync: enrichGapMutate }),
}));

vi.mock("@/hooks/useJobSchedules", () => ({
  useJobSchedules: () => ({ data: undefined }),
  useUpdateJobSchedule: () => ({ mutate: vi.fn(), isPending: false }),
  useResetJobSchedule: () => ({ mutate: vi.fn(), isPending: false }),
  useRunJobNow: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

vi.mock("@/components/SystemSettings", async () => {
  const { createContext } = await import("react");
  return {
    default: ({ filterGroups }: { filterGroups?: string[] }) => (
      <div data-testid="system-settings">{filterGroups?.join(",")}</div>
    ),
    SettingsHighlightContext: createContext<{ key: string; nonce: number } | null>(null),
  };
});

vi.mock("sonner", () => ({
  toast: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn(), message: vi.fn() }),
}));

function renderConsole(initialSource?: string) {
  const qc = new QueryClient();
  const wrap = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  return render(<EnrichmentConsole initialSource={initialSource} />, { wrapper: wrap });
}

const bodyRows = () => within(screen.getByRole("table")).getAllByRole("row").slice(1);

describe("EnrichmentConsole", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows the one-line summary and filters to sources needing attention", () => {
    renderConsole();
    expect(screen.getByText(/11 of 17 sources on/)).toBeInTheDocument();
    expect(bodyRows()).toHaveLength(4);
    const attn = screen.getByRole("button", { name: "1 needs attention" });
    fireEvent.click(attn);
    expect(attn).toHaveAttribute("aria-pressed", "true");
    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByRole("button", { name: /NVD 2.0/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "show all" }));
    expect(bodyRows()).toHaveLength(4);
  });

  it("filters by entity-type tab", () => {
    renderConsole();
    const tabs = screen.getByRole("tablist");
    expect(within(tabs).getByRole("tab", { name: "All 17" })).toHaveAttribute("aria-selected", "true");
    fireEvent.click(within(tabs).getByRole("tab", { name: "Observable 1" }));
    expect(consoleSpy).toHaveBeenLastCalledWith("observable");
    expect(within(tabs).getByRole("tab", { name: "Observable 1" })).toHaveAttribute("aria-selected", "true");
    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByRole("button", { name: /VirusTotal/ })).toBeInTheDocument();
  });

  it("shows one status word per source", () => {
    renderConsole();
    const statuses = bodyRows().map((r) => within(r).getAllByRole("cell")[1].textContent);
    expect(statuses).toEqual(["failing", "ok", "off", "needs key"]);
  });

  it("toggles a source on through the settings row id", () => {
    renderConsole();
    fireEvent.click(screen.getByRole("switch", { name: "OSV on" }));
    expect(updateMutate).toHaveBeenCalledWith({ sourceId: "id-osv", is_enabled: true }, expect.anything());
  });

  it("expands a row into Limits, Outputs and Jobs", () => {
    renderConsole();
    const expander = screen.getByRole("button", { name: /NVD 2.0/ });
    expect(expander).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(expander);
    expect(expander).toHaveAttribute("aria-expanded", "true");

    const limits = screen.getByRole("region", { name: "Limits" });
    expect(within(limits).getByText("50 per 30s")).toBeInTheDocument();
    expect(within(limits).getByText(/3,100 of 5,000 · backfill may use 60%/)).toBeInTheDocument();
    expect(within(limits).getByText("global key set")).toBeInTheDocument();
    expect(within(limits).getByText("1,224 waiting: 240 refresh, 898 backfill, 86 retrying")).toBeInTheDocument();
    expect(within(limits).getByRole("img", { name: /requests in the last 24 hours/ })).toBeInTheDocument();

    const outputs = screen.getByRole("region", { name: "Outputs" });
    expect(within(outputs).getByText("cve.cvss_score (rank 1)")).toBeInTheDocument();
    expect(within(outputs).getByText("72%")).toBeInTheDocument();
    expect(within(outputs).getByText("relationship: uses malware or tool")).toBeInTheDocument();
    expect(within(outputs).getByText("1,204 linked · 37 held")).toBeInTheDocument();
    expect(within(outputs).getByText(/23,665 CVEs have no cvss score/)).toBeInTheDocument();

    const jobs = screen.getByRole("region", { name: "Jobs" });
    expect(within(jobs).getByText("3 of 33 ok")).toBeInTheDocument();
    expect(within(jobs).getByText("30 of 30 ok")).toBeInTheDocument();
    expect(within(jobs).getByText("cve-nvd-backfill: TimeLimitExceeded(960)")).toBeInTheDocument();
  });

  it("opens the deep-linked source expanded", () => {
    renderConsole("epss");
    expect(screen.getByRole("button", { name: /EPSS/ })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("region", { name: "Limits" })).toBeInTheDocument();
  });

  it("queues a backfill for the in-scope gap", () => {
    renderConsole("nvd");
    fireEvent.click(screen.getByRole("button", { name: "Backfill 14,100 (about 3.4 days at the cap)" }));
    expect(backfillMutate).toHaveBeenCalledWith(
      { sourceType: "nvd", entityType: "cve", limit: 14100 },
      expect.anything(),
    );
  });

  it("pauses enrichment", () => {
    renderConsole();
    fireEvent.click(screen.getByRole("button", { name: "Pause enrichment" }));
    expect(pauseMutate).toHaveBeenCalledWith(true, expect.anything());
  });

  it("lists sources that are off or need a key under Add source", () => {
    renderConsole();
    const add = screen.getByRole("button", { name: "Add source" });
    fireEvent.click(add);
    expect(add).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(screen.getByRole("button", { name: "Turn on" }));
    expect(updateMutate).toHaveBeenCalledWith({ sourceId: "id-osv", is_enabled: true }, expect.anything());
    fireEvent.click(screen.getByRole("button", { name: "Add key" }));
    // Opens VirusTotal's row with the limits editor showing the key field.
    expect(screen.getByRole("button", { name: /VirusTotal/ })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByLabelText("Global key")).toBeInTheDocument();
  });

  it("saves edited limits with the rate config", () => {
    renderConsole("nvd");
    fireEvent.click(screen.getByRole("button", { name: "Edit limits" }));
    fireEvent.change(screen.getByLabelText("Requests"), { target: { value: "80" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(updateMutate).toHaveBeenCalledWith(
      expect.objectContaining({
        sourceId: "id-nvd",
        rate_limit_config: { requests_per_period: 80, period_seconds: 30 },
        daily_budget: 5000,
        trigger_mode: "auto",
      }),
      expect.anything(),
    );
  });

  it("refuses a rate above the source's ceiling", () => {
    renderConsole("nvd");
    fireEvent.click(screen.getByRole("button", { name: "Edit limits" }));
    fireEvent.change(screen.getByLabelText("Requests"), { target: { value: "500" } });
    expect(screen.getByText(/at most 100 per period/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("keeps AI research for missing fields one click away", async () => {
    enrichGapMutate.mockResolvedValue({ supported: true, enqueued: 10, batch_size: 10, total_missing: 42 });
    renderConsole();
    const summary = screen.getByText("AI research for missing fields");
    const details = summary.closest("details")!;
    details.open = true;
    fireEvent(details, new Event("toggle"));
    fireEvent.click(await screen.findByRole("button", { name: "Research 10" }));
    expect(enrichGapMutate).toHaveBeenCalledWith({ entity_type: "cve", field: "cvss", limit: 10 });
  });

  it("keeps the enrichment system settings on the page", () => {
    renderConsole();
    const details = screen.getByText("Settings").closest("details")!;
    details.open = true;
    fireEvent(details, new Event("toggle"));
    expect(screen.getByTestId("system-settings")).toHaveTextContent("enrichment,api_keys");
  });
});
