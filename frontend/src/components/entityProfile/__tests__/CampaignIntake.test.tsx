import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CampaignSource } from "@/api/types";
import { CampaignIntake } from "../CampaignIntake";

const updateSource = vi.fn();
let sources: CampaignSource[] = [];

const noop = { mutate: vi.fn(), isPending: false };

vi.mock("@/hooks/useCampaigns", () => ({
  useCampaignSources: () => ({ data: sources }),
  useCampaignSavedSearches: () => ({ data: [] }),
  useCampaignSuggestions: () => ({ data: [] }),
  useSuggestedCampaignSources: () => ({ data: [] }),
  useAddCampaignEntries: () => noop,
  useAddCampaignSource: () => noop,
  useUpdateCampaignSource: () => ({ mutate: updateSource, isPending: false }),
  useRemoveCampaignSource: () => noop,
  useSyncCampaignSource: () => noop,
  useAddCampaignSavedSearch: () => noop,
  useUpdateCampaignSavedSearch: () => noop,
  useRemoveCampaignSavedSearch: () => noop,
  useSyncCampaignSavedSearch: () => noop,
}));

vi.mock("@/hooks/useSearch", () => ({ useSavedSearches: () => ({ data: [] }) }));
vi.mock("@/hooks/useUndoableDelete", () => ({ useUndoableDelete: () => vi.fn() }));
vi.mock("../CampaignIntakeComposer", () => ({
  CampaignIntakeComposer: () => <div data-testid="composer" />,
}));

const source = (over: Partial<CampaignSource> = {}): CampaignSource => ({
  id: "s1",
  campaign_id: "c1",
  kind: "query",
  entity_type: null,
  ref_id: null,
  query: 'malware:"Akira"',
  label: 'malware:"Akira"',
  auto_sync: true,
  last_synced_at: null,
  entries_added: 7,
  created_at: "2026-10-01T00:00:00Z",
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  sources = [];
});

describe("CampaignIntake", () => {
  it("still offers intake on a campaign with nothing feeding it", () => {
    // It used to return null here — which is exactly a new campaign, the one
    // that most needs to be told what to collect.
    render(<CampaignIntake campaignId="c1" />);

    expect(screen.getByText("Feeding this campaign")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add intake" })).toBeInTheDocument();
    expect(screen.getByText(/Nothing arrives on its own/)).toBeInTheDocument();
  });

  it("opens the composer and drops the empty-state sentence", () => {
    render(<CampaignIntake campaignId="c1" />);
    fireEvent.click(screen.getByRole("button", { name: "Add intake" }));

    expect(screen.getByTestId("composer")).toBeInTheDocument();
    expect(screen.queryByText(/Nothing arrives on its own/)).not.toBeInTheDocument();
  });

  it("rewrites a query source in place, keeping what it already added", () => {
    sources = [source()];
    render(<CampaignIntake campaignId="c1" />);

    expect(screen.getByText(/7 added/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));

    const input = screen.getByLabelText("Rewrite this query");
    fireEvent.change(input, { target: { value: 'malware:"Akira" AND sector:healthcare' } });
    fireEvent.blur(input);

    expect(updateSource).toHaveBeenCalledWith(
      { campaignId: "c1", sourceId: "s1", query: 'malware:"Akira" AND sector:healthcare' },
      expect.anything(),
    );
  });

  it("discards a rewrite on Escape instead of saving it", () => {
    sources = [source()];
    render(<CampaignIntake campaignId="c1" />);
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));

    const input = screen.getByLabelText("Rewrite this query");
    fireEvent.change(input, { target: { value: "something regretted" } });
    fireEvent.keyDown(input, { key: "Escape" });
    fireEvent.blur(input);

    expect(updateSource).not.toHaveBeenCalled();
  });

  it("saves a rewrite on Enter", () => {
    sources = [source()];
    render(<CampaignIntake campaignId="c1" />);
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));

    const input = screen.getByLabelText("Rewrite this query");
    fireEvent.change(input, { target: { value: "malware:\"Qilin\"" } });
    fireEvent.keyDown(input, { key: "Enter" });
    fireEvent.blur(input);

    expect(updateSource).toHaveBeenCalledWith(
      { campaignId: "c1", sourceId: "s1", query: 'malware:"Qilin"' },
      expect.anything(),
    );
  });

  it("does not offer Edit on a source that has no query", () => {
    sources = [source({ kind: "entity", entity_type: "threat_actor", ref_id: "a1", query: null, label: "APT29" })];
    render(<CampaignIntake campaignId="c1" />);

    expect(screen.getByText("APT29")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
  });

  it("leaves an unchanged query alone instead of writing it back", () => {
    sources = [source()];
    render(<CampaignIntake campaignId="c1" />);
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    fireEvent.blur(screen.getByLabelText("Rewrite this query"));

    expect(updateSource).not.toHaveBeenCalled();
  });
});
