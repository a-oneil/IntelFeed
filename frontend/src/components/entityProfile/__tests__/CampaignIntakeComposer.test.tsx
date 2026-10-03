import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CampaignSourceOptions, CampaignSourcePreview } from "@/api/types";
import { CampaignIntakeComposer } from "../CampaignIntakeComposer";

const addSource = vi.fn();
const addSearch = vi.fn();
let options: CampaignSourceOptions | undefined;
let preview: CampaignSourcePreview | undefined;
let previewTarget: unknown = null;

vi.mock("@/hooks/useCampaigns", () => ({
  useCampaignSourceOptions: () => ({ data: options }),
  useCampaignSourcePreview: (_id: string, target: unknown) => {
    previewTarget = target;
    return { data: target ? preview : undefined, isFetching: false };
  },
  useAddCampaignSource: () => ({ mutate: addSource, isPending: false }),
  useAddCampaignSavedSearch: () => ({ mutate: addSearch, isPending: false }),
}));

vi.mock("@/hooks/useCorrelation", () => ({
  useEntitySearch: (q: string) => ({
    data: q ? { results: [{ id: "actor-1", type: "threat_actor", name: "Scattered Spider" }], total: 1 } : undefined,
    isFetching: false,
  }),
}));

vi.mock("@/hooks/useThreads", () => ({
  useThreadSearch: (q: string) => ({
    data: q
      ? { threads: [{ id: "thread-1", title: "Akira hits hospitals", entry_count: 9, status: "open" }], total: 1 }
      : undefined,
    isFetching: false,
  }),
}));

vi.mock("@/components/search/SearchSyntaxHelp", () => ({
  SearchSyntaxHelp: () => <div data-testid="syntax-help" />,
}));

const dryRun = (over: Partial<CampaignSourcePreview> = {}): CampaignSourcePreview => ({
  kind: "query",
  entity_type: null,
  ref_id: null,
  query: null,
  label: "",
  would_add: 4,
  already_held: 1,
  preview: [{ entry_id: "e1", title: "Akira claims a clinic", published_at: null }],
  error: null,
  unknown_fields: [],
  ...over,
});

function renderComposer(searches: Array<{ id: string; name: string; query: string }> = []) {
  return render(
    <CampaignIntakeComposer
      campaignId="c1"
      availableSearches={searches as never}
      onClose={vi.fn()}
    />,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
  previewTarget = null;
  options = {
    kinds: ["entity", "story", "query"],
    followable_entity_types: ["threat_actor", "malware", "observable"],
    pickable_entity_types: ["threat_actor", "malware"],
  };
  preview = dryRun();
});

describe("CampaignIntakeComposer", () => {
  it("previews a typed query before anything is followed, naming the articles", async () => {
    renderComposer();
    fireEvent.change(screen.getByPlaceholderText(/Scattered Spider/), {
      target: { value: 'malware:"Akira"' },
    });

    await waitFor(() => expect(screen.getByText("Adds 4 articles")).toBeInTheDocument());
    expect(screen.getByText("1 already here")).toBeInTheDocument();
    expect(screen.getByText("Akira claims a clinic")).toBeInTheDocument();
    // Nothing committed by typing.
    expect(addSource).not.toHaveBeenCalled();
  });

  it("follows the query as a campaign-owned source, not a saved search", async () => {
    renderComposer();
    fireEvent.change(screen.getByPlaceholderText(/Scattered Spider/), {
      target: { value: 'malware:"Akira"' },
    });
    await waitFor(() => expect(screen.getByRole("button", { name: "Follow" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Follow" }));

    expect(addSource).toHaveBeenCalledWith(
      expect.objectContaining({ campaignId: "c1", kind: "query", query: 'malware:"Akira"', refId: null }),
      expect.anything(),
    );
    expect(addSearch).not.toHaveBeenCalled();
  });

  it("refuses to follow a query the server could not parse", async () => {
    preview = dryRun({ would_add: 0, already_held: 0, preview: [], error: "Unexpected end of query" });
    renderComposer();
    fireEvent.change(screen.getByPlaceholderText(/Scattered Spider/), { target: { value: "akira AND" } });

    await waitFor(() => expect(screen.getByText("Unexpected end of query")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Follow" })).not.toBeInTheDocument();
  });

  it("warns about a field the query language does not have, without blocking", async () => {
    preview = dryRun({ unknown_fields: ["actor"] });
    renderComposer();
    fireEvent.change(screen.getByPlaceholderText(/Scattered Spider/), {
      target: { value: 'actor:"Scattered Spider"' },
    });

    await waitFor(() => expect(screen.getByText(/actor: is not a field/)).toBeInTheDocument());
    // A caution, not a refusal — the query still runs as text.
    expect(screen.getByRole("button", { name: "Follow" })).toBeEnabled();
  });

  it("offers only the entity types the server says own articles", () => {
    renderComposer();
    fireEvent.click(screen.getByRole("tab", { name: "Entity" }));

    const select = screen.getByLabelText("Entity type") as HTMLSelectElement;
    const slugs = Array.from(select.options).map((o) => o.value);
    expect(slugs).toEqual(["threat_actor", "malware"]);
    // Followable but not findable by name — it must not be offered here.
    expect(slugs).not.toContain("observable");
  });

  it("lets any entity be picked, not only ones the campaign already names", async () => {
    renderComposer();
    fireEvent.click(screen.getByRole("tab", { name: "Entity" }));
    fireEvent.change(screen.getByPlaceholderText(/Search threat actor/i), {
      target: { value: "scattered" },
    });

    const hit = await screen.findByText("Scattered Spider");
    fireEvent.click(hit);

    await waitFor(() =>
      expect(previewTarget).toMatchObject({ kind: "entity", entityType: "threat_actor", refId: "actor-1" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Follow" }));
    expect(addSource).toHaveBeenCalledWith(
      expect.objectContaining({ kind: "entity", entityType: "threat_actor", refId: "actor-1" }),
      expect.anything(),
    );
  });

  it("picks a story thread by title", async () => {
    renderComposer();
    fireEvent.click(screen.getByRole("tab", { name: "Story" }));
    fireEvent.change(screen.getByPlaceholderText(/Search story threads/i), { target: { value: "akira" } });

    fireEvent.click(await screen.findByText("Akira hits hospitals"));
    await waitFor(() => expect(previewTarget).toMatchObject({ kind: "story", refId: "thread-1" }));
  });

  it("hides the saved-search tab when there is no unlinked search to offer", () => {
    renderComposer();
    expect(screen.queryByRole("tab", { name: "Saved search" })).not.toBeInTheDocument();

    renderComposer([{ id: "s1", name: "My ransomware watch", query: "tag:ransomware" }]);
    expect(screen.getByRole("tab", { name: "Saved search" })).toBeInTheDocument();
  });

  it("says nothing is aimed at yet rather than previewing an empty query", () => {
    renderComposer();
    expect(screen.getByText("Nothing aimed at yet.")).toBeInTheDocument();
    expect(previewTarget).toBeNull();
  });
});
