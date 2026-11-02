import { render, screen, fireEvent, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import type {
  EnrichmentConsole as ConsoleData,
  EnrichmentConsoleSource,
  EnrichmentKey,
  EnrichmentSourceDetail,
} from "@/hooks/useEnrichment";
import { EnrichmentConsole } from "../engine/EnrichmentConsole";

function source(over: Partial<EnrichmentConsoleSource>): EnrichmentConsoleSource {
  return {
    id: `row-${over.source_type}`,
    source_type: "x",
    label: "X",
    about: "",
    kind: "lookup",
    status: "ok",
    enabled: true,
    fills: "",
    applies_to: ["cve"],
    attention: null,
    egress: "low",
    license: "CC0",
    commercial_ok: true,
    key: null,
    key_status: null,
    trigger_mode: "auto",
    used_today: 0,
    daily_budget: 1000,
    jobs: 0,
    settings_keys: [],
    source_settings: [],
    ...over,
  };
}

const sources = [
  source({
    source_type: "nvd",
    label: "NVD 2.0",
    about: "The US National Vulnerability Database.",
    status: "failing",
    attention: "cve-nvd-backfill failed 30 of 33 runs in 30 days",
    fills: "CVSS score, weaknesses",
    key: "nvd_api_key",
    key_status: "set",
    used_today: 950,
    jobs: 2,
    settings_keys: ["cve_reenrich_batch_size"],
  }),
  source({
    source_type: "threatfox",
    label: "abuse.ch ThreatFox",
    status: "key_rejected",
    applies_to: ["observable"],
    egress: "shares_ioc",
    commercial_ok: false,
    key: "abuse_ch",
    key_status: "rejected",
    trigger_mode: "manual",
  }),
  source({ source_type: "epss", label: "FIRST EPSS", new: true, fills: "EPSS score", egress: "none" }),
  source({
    source_type: "virustotal",
    label: "VirusTotal v3",
    status: "needs_key",
    needs: "key",
    enabled: false,
    applies_to: ["observable"],
    key: "virustotal",
    key_status: "missing",
  }),
];

const consoleData: ConsoleData = {
  summary: {
    sources_on: 3,
    sources_total: 4,
    paused: false,
    redis_ok: true,
    activity_24h: {
      requests: 4212,
      trend: Array(24).fill(1),
      waiting: 1730,
      waiting_backfill: 898,
      deferred: 94,
      iocs_sent: 212,
      ioc_sources: ["abuse.ch ThreatFox"],
    },
  },
  attention: [
    {
      source_type: "threatfox",
      label: "abuse.ch Auth-Key",
      sources: ["abuse.ch ThreatFox", "abuse.ch URLhaus"],
      text: "the source rejected the API key",
      severity: "bad",
      action: { kind: "key", key: "abuse_ch", label: "Replace key" },
    },
    {
      source_type: "nvd",
      label: "NVD 2.0",
      text: "cve-nvd-backfill failed 30 of 33 runs in 30 days",
      severity: "bad",
      action: { kind: "source", source: "nvd", tab: "jobs", label: "Open jobs" },
    },
    {
      source_type: "greynoise",
      label: "GreyNoise Community",
      text: "86 lookups gave up after repeated errors",
      severity: "warn",
      action: { kind: "retry", source: "greynoise", label: "Retry all" },
    },
  ],
  entity_types: [
    { entity_type: "cve", label: "CVE", source_count: 2 },
    { entity_type: "observable", label: "Observable", source_count: 2 },
  ],
  sources,
};

const detail: EnrichmentSourceDetail = {
  limits: {
    rate: { requests_per_period: 5, period_seconds: 30 },
    effective_rate: { requests_per_period: 50, period_seconds: 30 },
    rate_note: "with key",
    ceiling_per_period: 50,
    daily_budget: 1000,
    used_today: 950,
    backfill_share: 0.6,
    refresh_days: 7,
    triggers: ["new", "manual", "backfill", "schedule"],
    scope: "CVE with no CVSS score",
  },
  trend_24h: Array(24).fill(0),
  queue: { waiting: 12, by_lane: { new: 4, backfill: 8 }, retrying: 3, by_reason: { rate_limited: 3 }, failed: 0 },
  settings: { trigger_mode: "auto", rate_limit_config: { requests_per_period: 5, period_seconds: 30 } },
  outputs: [
    { field: "cvss_score", target: "cve.cvss_score", kind: "column", policy: "rank", rank: 1, filled_pct: 72 },
    { field: "references", target: "profile: References", kind: "context", filled_pct: null },
  ],
  gap: { entity_type: "cve", field: "cvss_score", missing: 23665, in_scope: 14100, eta_days: 0.4 },
  jobs: [
    {
      key: "cve-nvd-backfill",
      description: "Backfill NVD data for CVEs missing it",
      settings_keys: [],
      schedule: "Daily at 1:30 AM",
      runs_30d: 33,
      ok_30d: 3,
      last_status: "error",
      last_error: "TimeLimitExceeded(960)",
      last_detail: null,
    },
    {
      key: "reenrich-cve-nvd",
      description: "Ask again about CVEs NVD hadn't analysed",
      settings_keys: ["cve_reenrich_batch_size"],
      schedule: "Daily at 3:05 AM",
      runs_30d: 29,
      ok_30d: 28,
      last_status: "success",
      last_error: null,
      last_detail: { fetched: 200, changed: 41, written: 39 },
    },
  ],
};

const keys: EnrichmentKey[] = [
  {
    id: "abuse_ch",
    label: "abuse.ch Auth-Key",
    note: "Needed. One key for all 3 sources.",
    required: true,
    sources: [
      { source_type: "threatfox", label: "abuse.ch ThreatFox" },
      { source_type: "urlhaus", label: "abuse.ch URLhaus" },
    ],
    also_used_by: null,
    status: "rejected",
    message: "HTTP 401",
    mine: false,
    personal_allowed: true,
    signup_url: "https://auth.abuse.ch/",
  },
  {
    id: "nvd_api_key",
    label: "NVD API Key",
    note: "Optional. Raises the limit from 5 to 50 per 30 seconds.",
    required: false,
    sources: [{ source_type: "nvd", label: "NVD 2.0" }],
    also_used_by: null,
    status: "set",
    message: null,
    mine: true,
    personal_allowed: true,
    signup_url: null,
  },
];

const pauseMutate = vi.fn();
const backfillMutate = vi.fn();
const updateMutate = vi.fn();
const retryMutate = vi.fn();
const setKey = vi.fn().mockResolvedValue(undefined);
const testKey = vi.fn().mockResolvedValue({ status: "ok", message: null });

vi.mock("@/hooks/useEnrichment", () => ({
  useEnrichmentConsole: () => ({ data: consoleData, isError: false }),
  useEnrichmentSourceDetail: (sourceType: string | null) => ({ data: sourceType ? detail : undefined, isError: false }),
  useEnrichmentKeys: () => ({ data: keys, isError: false }),
  useEnrichmentCoverage: () => ({
    data: [
      {
        entity_type: "threat_actor",
        entity_label: "Threat actor",
        field: "country",
        label: "country",
        filled: 43,
        total: 100,
        filled_pct: 43,
        sources: [{ source_type: "etda", label: "ETDA", enabled: true }],
        action: { kind: "ai", field: "country" },
        cadence: null,
      },
    ],
    isError: false,
  }),
  useEnrichmentActivity: () => ({
    data: {
      lanes: [
        { lane: "manual", waiting: 4, deferred: 0 },
        { lane: "backfill", waiting: 898, deferred: 51 },
      ],
      backfill_share: 0.6,
      failed: [{ source_type: "greynoise", label: "GreyNoise Community", count: 86, last_error: "429" }],
      requests: [{ source_type: "nvd", label: "NVD 2.0", requests: 3100 }],
    },
    isError: false,
  }),
  usePauseEnrichment: () => ({ mutate: pauseMutate, isPending: false }),
  useQueueBackfill: () => ({ mutate: backfillMutate, isPending: false }),
  useUpdateEnrichmentSource: () => ({ mutate: updateMutate, isPending: false }),
  useRetryFailedLookups: () => ({ mutate: retryMutate, isPending: false }),
  useSetEnrichmentKey: () => ({ mutateAsync: setKey, isPending: false }),
  useTestEnrichmentKey: () => ({ mutateAsync: testKey, isPending: false }),
}));

const enrichGapMutate = vi.fn();
vi.mock("@/hooks/useHygiene", () => ({
  useEnrichGap: () => ({ mutate: enrichGapMutate, isPending: false }),
}));

vi.mock("@/hooks/useJobSchedules", () => ({
  useJobSchedules: () => ({ data: undefined }),
  useUpdateJobSchedule: () => ({ mutate: vi.fn(), isPending: false }),
  useResetJobSchedule: () => ({ mutate: vi.fn(), isPending: false }),
  useRunJobNow: () => ({ mutate: vi.fn(), isPending: false }),
}));

vi.mock("@/components/SystemSettings", async () => {
  const { createContext } = await import("react");
  return {
    default: ({ filterKeys }: { filterKeys?: string[] }) => (
      <div data-testid="system-settings">{filterKeys?.join(",")}</div>
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

const view = (name: RegExp) => fireEvent.click(screen.getByRole("tab", { name }));
const panel = () => screen.getByRole("complementary");

describe("EnrichmentConsole", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows the 24h strip and the distinct indicators sent out", () => {
    renderConsole();
    const strip = screen.getByLabelText("Last 24 hours");
    expect(within(strip).getByText("4,212")).toBeInTheDocument();
    expect(within(strip).getByText("898 are backfill")).toBeInTheDocument();
    expect(within(strip).getByText("212")).toBeInTheDocument();
    expect(within(strip).getByText("to abuse.ch ThreatFox")).toBeInTheDocument();
    expect(within(strip).getByText("Healthy")).toBeInTheDocument();
  });

  it("names each problem with the one button that fixes it", () => {
    renderConsole();
    const attn = screen.getByRole("region", { name: "Needs attention" });
    expect(within(attn).getByText(/rejected the API key/)).toBeInTheDocument();

    fireEvent.click(within(attn).getByRole("button", { name: "Retry all" }));
    expect(retryMutate).toHaveBeenCalledWith("greynoise", expect.anything());

    fireEvent.click(within(attn).getByRole("button", { name: "Open jobs" }));
    expect(screen.getByRole("tab", { name: "Jobs · 2" })).toHaveAttribute("aria-selected", "true");
    expect(within(panel()).getByText("cve-nvd-backfill")).toBeInTheDocument();

    fireEvent.click(within(attn).getByRole("button", { name: "Replace key" }));
    expect(screen.getByRole("tab", { name: /Keys/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByLabelText("Shared key")).toBeInTheDocument();
  });

  it("lists sources that are on first and the rest under Available", () => {
    renderConsole();
    expect(screen.getByText("On · 3")).toBeInTheDocument();
    expect(screen.getByText("Available · 1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /NVD 2.0.*Failing/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /ThreatFox.*Key rejected/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /VirusTotal.*Needs a key/ })).toBeInTheDocument();
  });

  it("filters the list by entity type", () => {
    renderConsole();
    fireEvent.click(screen.getByRole("button", { name: /^Observable/ }));
    expect(screen.queryByRole("button", { name: /NVD 2.0/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /ThreatFox/ })).toBeInTheDocument();
  });

  it("opens a source in the side panel with what it sends out and its key", () => {
    renderConsole();
    fireEvent.click(screen.getByRole("button", { name: /ThreatFox/ }));
    expect(within(panel()).getByText("your indicators")).toBeInTheDocument();
    expect(within(panel()).getByText(/hidden from public visitors/)).toBeInTheDocument();
    fireEvent.click(within(panel()).getByRole("button", { name: "rejected" }));
    expect(screen.getByRole("tab", { name: /Keys/ })).toHaveAttribute("aria-selected", "true");
  });

  it("asks for a key before a source that needs one can run", () => {
    renderConsole();
    fireEvent.click(screen.getByRole("button", { name: /VirusTotal/ }));
    fireEvent.click(within(panel()).getByRole("button", { name: "Add key" }));
    expect(screen.getByRole("tab", { name: /Keys/ })).toHaveAttribute("aria-selected", "true");
  });

  it("toggles a source through its settings row id", () => {
    renderConsole();
    fireEvent.click(screen.getByRole("button", { name: /FIRST EPSS/ }));
    fireEvent.click(within(panel()).getByRole("switch", { name: "FIRST EPSS on" }));
    expect(updateMutate).toHaveBeenCalledWith({ sourceId: "row-epss", is_enabled: false }, expect.anything());
  });

  it("saves limits with the stored rate and no key fields", () => {
    renderConsole("nvd");
    fireEvent.click(within(panel()).getByRole("tab", { name: "Limits" }));
    expect(within(panel()).queryByLabelText(/key/i)).not.toBeInTheDocument();
    fireEvent.change(within(panel()).getByLabelText("Rate"), { target: { value: "10" } });
    fireEvent.click(within(panel()).getByRole("button", { name: "Save" }));
    expect(updateMutate).toHaveBeenCalledWith(
      expect.objectContaining({
        sourceId: "row-nvd",
        rate_limit_config: { requests_per_period: 10, period_seconds: 30 },
        daily_budget: 1000,
        trigger_mode: "auto",
      }),
      expect.anything(),
    );
  });

  it("refuses a rate above the source's ceiling", () => {
    renderConsole("nvd");
    fireEvent.click(within(panel()).getByRole("tab", { name: "Limits" }));
    fireEvent.change(within(panel()).getByLabelText("Rate"), { target: { value: "500" } });
    expect(within(panel()).getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("shows fill rates and queues the in-scope backfill", () => {
    renderConsole("nvd");
    fireEvent.click(within(panel()).getByRole("tab", { name: "Fields" }));
    expect(within(panel()).getByText("72%")).toBeInTheDocument();
    expect(within(panel()).getByText(/14,100 can be looked up now/)).toBeInTheDocument();
    expect(within(panel()).getByText("under a day at the daily cap")).toBeInTheDocument();
    fireEvent.click(within(panel()).getByRole("button", { name: "Backfill 14,100" }));
    expect(backfillMutate).toHaveBeenCalledWith(
      { sourceType: "nvd", entityType: "cve", limit: 14100 },
      expect.anything(),
    );
  });

  it("puts each job's settings beside the job", () => {
    renderConsole("nvd");
    expect(within(panel()).getByText("TimeLimitExceeded(960)")).toBeInTheDocument();
    expect(within(panel()).getByText("200 fetched · 41 changed · 39 written")).toBeInTheDocument();
    expect(within(panel()).getByTestId("system-settings")).toHaveTextContent("cve_reenrich_batch_size");
  });

  it("sets keys only in Keys, shared and own, and tests a new shared key", async () => {
    renderConsole();
    view(/Keys/);
    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("Rejected")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Yours is used")).toBeInTheDocument();

    fireEvent.click(within(rows[0]).getByRole("button", { name: "Replace key" }));
    fireEvent.change(screen.getByLabelText("Shared key"), { target: { value: "new-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save and test" }));
    await vi.waitFor(() => expect(testKey).toHaveBeenCalledWith("abuse_ch"));
    expect(setKey).toHaveBeenCalledWith({ keyId: "abuse_ch", apiKey: "new-key" });
  });

  it("offers AI research where no lookup source fills a field", () => {
    renderConsole();
    view(/Coverage/);
    fireEvent.click(screen.getByRole("button", { name: "Ask the AI for 10" }));
    expect(enrichGapMutate).toHaveBeenCalledWith(
      { entity_type: "threat_actor", field: "country", limit: 10 },
      expect.anything(),
    );
  });

  it("retries the lookups that gave up from Activity", () => {
    renderConsole();
    view(/Activity/);
    expect(screen.getByText("Gave up · 86")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(retryMutate).toHaveBeenCalledWith("greynoise", expect.anything());
  });

  it("pauses every source from the header", () => {
    renderConsole();
    fireEvent.click(screen.getByRole("button", { name: "Pause all sources" }));
    expect(pauseMutate).toHaveBeenCalledWith(true, expect.anything());
  });
});
