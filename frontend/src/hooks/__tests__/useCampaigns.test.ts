import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}));

import api from "@/api/client";
import {
  useCampaigns,
  useCampaign,
  useCreateCampaign,
  useUpdateCampaign,
  useDeleteCampaign,
  useCampaignTimeline,
  useCampaignAttackLayer,
  useCampaignSuggestions,
  useCampaignSavedSearches,
  useAddCampaignSavedSearch,
  useRemoveCampaignSavedSearch,
  useCampaignDetectionGaps,
  useCampaignEntities,
  useRemoveCampaignEntity,
  useCampaignStats,
  useCampaignCountries,
  useCampaignCountrySuggestions,
  useAddCampaignCountry,
  useRemoveCampaignCountry,
  useAutoDetectCampaigns,
} from "../useCampaigns";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return function Wrapper({ children }: { children: ReactNode }) {
    return createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

describe("useCampaigns hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // --- CRUD ---

  it("useCampaigns fetches campaign list", async () => {
    const response = {
      items: [{ id: "c1", name: "Campaign 1", status: "active" }],
      total: 1,
      limit: 50,
      offset: 0,
      has_more: false,
    };
    mockedApi.get.mockResolvedValueOnce({ data: response });

    const { result } = renderHook(() => useCampaigns(), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns", { params: undefined });
    expect(result.current.data?.items).toHaveLength(1);
  });

  it("useCampaign fetches single campaign", async () => {
    const campaign = { id: "c1", name: "Test Campaign", status: "active" };
    mockedApi.get.mockResolvedValueOnce({ data: campaign });

    const { result } = renderHook(() => useCampaign("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1");
    expect(result.current.data?.name).toBe("Test Campaign");
  });

  it("useCampaign is disabled when id is undefined", () => {
    const { result } = renderHook(() => useCampaign(undefined), { wrapper: createWrapper() });
    expect(result.current.fetchStatus).toBe("idle");
  });

  it("useCreateCampaign posts new campaign", async () => {
    const created = { id: "c2", name: "New Campaign", status: "active" };
    mockedApi.post.mockResolvedValueOnce({ data: created });

    const { result } = renderHook(() => useCreateCampaign(), { wrapper: createWrapper() });
    result.current.mutate({ name: "New Campaign", status: "active" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.post).toHaveBeenCalledWith("/campaigns", { name: "New Campaign", status: "active" });
  });

  it("useUpdateCampaign uses PATCH", async () => {
    const updated = { id: "c1", name: "Updated", status: "active" };
    mockedApi.patch.mockResolvedValueOnce({ data: updated });

    const { result } = renderHook(() => useUpdateCampaign(), { wrapper: createWrapper() });
    result.current.mutate({ id: "c1", name: "Updated" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.patch).toHaveBeenCalledWith("/campaigns/c1", { name: "Updated" });
  });

  it("useDeleteCampaign calls delete", async () => {
    mockedApi.delete.mockResolvedValueOnce({});

    const { result } = renderHook(() => useDeleteCampaign(), { wrapper: createWrapper() });
    result.current.mutate("c1");

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.delete).toHaveBeenCalledWith("/campaigns/c1");
  });

  // --- Extension endpoints ---

  it("useCampaignTimeline fetches timeline", async () => {
    const entries = [
      { entry_id: "e1", title: "Entry 1", published_at: "2026-01-10T00:00:00Z" },
    ];
    mockedApi.get.mockResolvedValueOnce({ data: entries });

    const { result } = renderHook(() => useCampaignTimeline("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/timeline");
    expect(result.current.data).toHaveLength(1);
  });

  it("useCampaignAttackLayer fetches ATT&CK layer", async () => {
    const layer = { name: "Campaign Layer", techniques: [] };
    mockedApi.get.mockResolvedValueOnce({ data: layer });

    const { result } = renderHook(() => useCampaignAttackLayer("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/attack-layer");
  });

  it("useCampaignSuggestions fetches suggestions", async () => {
    const suggestions = [{ entry_id: "e2", title: "Related", overlap_count: 3 }];
    mockedApi.get.mockResolvedValueOnce({ data: suggestions });

    const { result } = renderHook(
      () => useCampaignSuggestions("c1", { min_overlap: 2 }),
      { wrapper: createWrapper() },
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/suggest", {
      params: { min_overlap: 2 },
    });
  });

  // --- Detection Gaps ---

  it("useCampaignDetectionGaps fetches gap analysis", async () => {
    const gaps = {
      total_ttps: 3,
      covered_count: 1,
      gap_count: 2,
      coverage_percentage: 33.3,
      gaps: [
        { ttp_id: "t1", technique_id: "T1566.001", technique_name: "Spearphishing", tactic: "initial-access" },
      ],
      covered: [
        { ttp_id: "t2", technique_id: "T1059.001", technique_name: "PowerShell", tactic: "execution", rules: [] },
      ],
    };
    mockedApi.get.mockResolvedValueOnce({ data: gaps });

    const { result } = renderHook(() => useCampaignDetectionGaps("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/detection-gaps");
    expect(result.current.data?.coverage_percentage).toBe(33.3);
  });

  // --- Entities ---

  it("useCampaignEntities fetches entities", async () => {
    const entities = [
      { id: "ce1", entity_type: "ttp", entity_name: "T1059.001: PowerShell", role: "primary" },
    ];
    mockedApi.get.mockResolvedValueOnce({ data: entities });

    const { result } = renderHook(() => useCampaignEntities("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/entities", {
      params: undefined,
    });
  });

  it("useCampaignEntities filters by type", async () => {
    mockedApi.get.mockResolvedValueOnce({ data: [] });

    const { result } = renderHook(
      () => useCampaignEntities("c1", "threat_actor"),
      { wrapper: createWrapper() },
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/entities", {
      params: { entity_type: "threat_actor" },
    });
  });

  it("useRemoveCampaignEntity calls delete", async () => {
    mockedApi.delete.mockResolvedValueOnce({});

    const { result } = renderHook(() => useRemoveCampaignEntity(), { wrapper: createWrapper() });
    result.current.mutate({ campaignId: "c1", entityId: "ce1" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.delete).toHaveBeenCalledWith("/campaigns/c1/entities/ce1");
  });

  // --- Stats ---

  it("useCampaignStats fetches statistics", async () => {
    const stats = {
      entry_count: 10,
      entity_counts: { ttp: 3, cve: 1, threat_actor: 1, malware: 0 },
      detection_coverage_pct: 66.7,
      date_range: { earliest_entry: "2026-01-01", latest_entry: "2026-03-01" },
      top_sources: [{ feed_name: "Mandiant", entry_count: 5 }],
      entries_over_time: [{ date: "2026-01", count: 4 }],
    };
    mockedApi.get.mockResolvedValueOnce({ data: stats });

    const { result } = renderHook(() => useCampaignStats("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/stats");
    expect(result.current.data?.entry_count).toBe(10);
    expect(result.current.data?.detection_coverage_pct).toBe(66.7);
  });

  // --- Countries ---

  it("useCampaignCountries fetches countries", async () => {
    const countries = [
      { country_id: "co1", country_name: "Russia", country_code: "RU", role: "origin" },
    ];
    mockedApi.get.mockResolvedValueOnce({ data: countries });

    const { result } = renderHook(() => useCampaignCountries("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/countries");
  });

  it("useCampaignCountrySuggestions fetches suggested countries", async () => {
    const suggestions = [
      { country_id: "co1", country_name: "Iran", country_code: "IR", entry_count: 4, suggested_role: "target" },
    ];
    mockedApi.get.mockResolvedValueOnce({ data: suggestions });

    const { result } = renderHook(() => useCampaignCountrySuggestions("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/countries/suggested");
    expect(result.current.data?.[0].suggested_role).toBe("target");
  });

  it("useAddCampaignCountry posts country", async () => {
    mockedApi.post.mockResolvedValueOnce({ data: { country_id: "co1", role: "target" } });

    const { result } = renderHook(() => useAddCampaignCountry(), { wrapper: createWrapper() });
    result.current.mutate({ campaignId: "c1", countryId: "co1", role: "target" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.post).toHaveBeenCalledWith("/campaigns/c1/countries", {
      country_id: "co1",
      role: "target",
    });
  });

  it("useRemoveCampaignCountry calls delete", async () => {
    mockedApi.delete.mockResolvedValueOnce({});

    const { result } = renderHook(() => useRemoveCampaignCountry(), { wrapper: createWrapper() });
    result.current.mutate({ campaignId: "c1", countryId: "co1" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.delete).toHaveBeenCalledWith("/campaigns/c1/countries/co1");
  });

  // --- Saved Searches ---

  it("useCampaignSavedSearches fetches linked searches", async () => {
    const searches = [
      { id: "css1", saved_search_name: "Ransomware", auto_sync: true, entries_added: 5 },
    ];
    mockedApi.get.mockResolvedValueOnce({ data: searches });

    const { result } = renderHook(() => useCampaignSavedSearches("c1"), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/campaigns/c1/saved-searches");
  });

  it("useAddCampaignSavedSearch posts link", async () => {
    const created = { id: "css2", saved_search_name: "APT", auto_sync: true };
    mockedApi.post.mockResolvedValueOnce({ data: created });

    const { result } = renderHook(() => useAddCampaignSavedSearch(), { wrapper: createWrapper() });
    result.current.mutate({ campaignId: "c1", savedSearchId: "ss1", autoSync: true });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.post).toHaveBeenCalledWith("/campaigns/c1/saved-searches", {
      saved_search_id: "ss1",
      auto_sync: true,
    });
  });

  it("useRemoveCampaignSavedSearch calls delete", async () => {
    mockedApi.delete.mockResolvedValueOnce({});

    const { result } = renderHook(() => useRemoveCampaignSavedSearch(), { wrapper: createWrapper() });
    result.current.mutate({ campaignId: "c1", cssId: "css1" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.delete).toHaveBeenCalledWith("/campaigns/c1/saved-searches/css1");
  });

  // --- Auto-Detect ---

  it("useAutoDetectCampaigns calls post with params", async () => {
    const suggestions = [
      {
        suggested_name: "APT29 Activity",
        pivot_entity: { type: "threat_actor", id: "ta1", name: "APT29" },
        entry_count: 5,
        sample_entries: [],
      },
    ];
    mockedApi.post.mockResolvedValueOnce({ data: suggestions });

    const { result } = renderHook(() => useAutoDetectCampaigns(), { wrapper: createWrapper() });
    result.current.mutate({ min_entries: 3, days: 30 });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(mockedApi.post).toHaveBeenCalledWith("/campaigns/auto-detect", null, {
      params: { min_entries: 3, days: 30 },
      timeout: 60000,
    });
  });
});
