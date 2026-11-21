import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EngineMatrix } from "../engine/EngineMatrix";

// The console's own state: which tab is open, which panels, which window.
// Data hooks and the tabs' bodies are stubbed; each stub shows the props the
// console hands it.
vi.mock("@/hooks/useEngine", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks/useEngine")>()),
  useEngineProcessing: () => ({ data: { pages: [] }, isLoading: false, hasNextPage: false }),
  usePipelineOverview: () => ({ data: undefined }),
  usePipelinePlans: () => ({ data: [] }),
  useUpsertPlan: () => ({ mutateAsync: vi.fn() }),
  useRetryPipelineErrors: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));
vi.mock("@/hooks/useExtraction", () => ({
  useExtractionStats: () => ({
    data: { total_created: 10, by_status: { dupe: 3, review: 4, orphan: 2, stale: 1 } },
  }),
}));
vi.mock("@/hooks/useAutolinking", () => ({
  useEntityLinkStats: () => ({ data: { total: 0, relationships_total: 9, relationships_unreviewed: 5 } }),
}));
vi.mock("@/hooks/useHygiene", () => ({ useHygieneStats: () => ({ data: undefined }) }));
vi.mock("@/hooks/useAnalytics", () => ({ useFeedHealth: () => ({ data: undefined }) }));
vi.mock("@/hooks/useFeeds", () => ({ useFeeds: () => ({ data: [] }) }));
vi.mock("../engine/StagePanel", () => ({
  StagePanel: ({ stage }: { stage: string }) => <div data-testid="stage-panel" data-stage={stage} />,
}));
vi.mock("../engine/ProposalsQueue", () => ({
  ProposalsQueue: ({ onToggleSettings }: { onToggleSettings: () => void }) => (
    <button onClick={onToggleSettings}>tuning</button>
  ),
}));
vi.mock("../engine/ExtractionTab", () => ({
  ExtractionTab: ({ window, status = "all" }: { window: string; status?: string }) => (
    <div data-testid="entities" data-window={window} data-status={status} />
  ),
}));
vi.mock("../engine/AutolinkingSection", () => ({
  AutolinkingSection: ({ hours, unreviewed }: { hours?: number; unreviewed?: boolean }) => (
    <div data-testid="links" data-hours={String(hours)} data-unreviewed={String(!!unreviewed)} />
  ),
}));
vi.mock("../engine/EngineSettingsSearch", () => ({ EngineSettingsSearch: () => null }));
vi.mock("../engine/EngineSwitch", () => ({
  CheckEngineBanner: () => null,
  ClearCheckEngine: () => null,
  EngineSwitch: () => null,
}));
vi.mock("../engine/EntryOutputs", () => ({ EntryOutputs: () => null }));
vi.mock("@/components/FeedHealthView", () => ({ FeedHealthView: () => null }));
vi.mock("@/components/SystemSettings", () => ({ default: () => null }));

function renderMatrix(initialView?: "review" | "entries") {
  const qc = new QueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <EngineMatrix initialView={initialView} onBrowse={vi.fn()} onHighlightSetting={vi.fn()} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const tab = (name: string) => screen.getByRole("button", { name: new RegExp(`^${name}`) });

describe("EngineMatrix", () => {
  beforeEach(() => window.history.replaceState(null, "", "/settings?section=engine"));

  it("closes the adjudicator's settings when you leave Review", () => {
    renderMatrix("review");
    fireEvent.click(screen.getByText("tuning"));
    expect(screen.getByTestId("stage-panel")).toHaveAttribute("data-stage", "adjudicate");
    fireEvent.click(tab("Links"));
    expect(screen.queryByTestId("stage-panel")).toBeNull();
    fireEvent.click(tab("Review"));
    expect(screen.queryByTestId("stage-panel")).toBeNull();
  });

  it("counts the Review lenses on the Review tab, except unconfirmed and unjudged edges", () => {
    renderMatrix();
    // 3 dupe + 2 orphan + 1 stale; the 4 unconfirmed and 5 unjudged edges keep their lens counts only.
    expect(tab("Review")).toHaveTextContent("Review6");
    expect(screen.getByText(/to review/).textContent).toContain("6");
    fireEvent.click(tab("Review"));
    expect(screen.getByRole("button", { name: /^Unconfirmed4/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Relationships5/ })).toBeInTheDocument();
    expect(screen.queryByText(/duplicate candidates/)).toBeNull();
  });

  it("has one Needs you shortcut for Review, opening the first lens with something in it", () => {
    renderMatrix();
    expect(screen.queryByText(/to reclassify/)).toBeNull();
    expect(screen.queryByText(/adjudication verdicts/)).toBeNull();
    fireEvent.click(screen.getByText(/to review/));
    // Proposals is empty here (no hygiene stats) and Unconfirmed isn't counted, so it opens Duplicates.
    expect(new URL(window.location.href).searchParams.get("view")).toBe("review");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "dupe");
  });

  it("opens the duplicate candidates as a Review lens, over all time", () => {
    renderMatrix();
    fireEvent.click(tab("Review"));
    fireEvent.click(screen.getByRole("button", { name: /^Duplicates/ }));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-window", "all");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "dupe");
    expect(new URL(window.location.href).searchParams.get("view")).toBe("review");
    expect(new URL(window.location.href).searchParams.get("lens")).toBe("duplicates");
    // The console's own window is untouched.
    fireEvent.click(tab("Links"));
    expect(screen.getByTestId("links")).toHaveAttribute("data-hours", "24");
    fireEvent.click(tab("Entities"));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-window", "24h");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "all");
  });

  it("lists each entity status and the unjudged edges as their own Review lens, over all time", () => {
    renderMatrix("review");
    fireEvent.click(screen.getByRole("button", { name: /^Unconfirmed/ }));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "review");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-window", "all");
    fireEvent.click(screen.getByRole("button", { name: /^Orphans/ }));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "orphan");
    fireEvent.click(screen.getByRole("button", { name: /^Stale/ }));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "stale");
    expect(new URL(window.location.href).searchParams.get("lens")).toBe("stale");
    fireEvent.click(screen.getByRole("button", { name: /^Relationships5/ }));
    expect(screen.getByTestId("links")).toHaveAttribute("data-unreviewed", "true");
    expect(screen.getByTestId("links")).toHaveAttribute("data-hours", "undefined");
  });

  it("lists every status on Entities, with no status picker of its own", () => {
    renderMatrix();
    fireEvent.click(tab("Entities"));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "all");
  });

  it("writes the open tab into the URL, so Back returns to it", () => {
    renderMatrix();
    fireEvent.click(tab("Links"));
    expect(new URL(window.location.href).searchParams.get("view")).toBe("links");
    expect(new URL(window.location.href).searchParams.get("section")).toBe("engine");
  });
});
