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
  useExtractionStats: () => ({ data: { likely_duplicates: 3, total_created: 10 } }),
}));
vi.mock("@/hooks/useAutolinking", () => ({ useEntityLinkStats: () => ({ data: undefined }) }));
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
  ExtractionTab: ({ window, initialStatus }: { window: string; initialStatus: string }) => (
    <div data-testid="entities" data-window={window} data-status={initialStatus} />
  ),
}));
vi.mock("../engine/AutolinkingSection", () => ({
  AutolinkingSection: ({ hours }: { hours?: number }) => <div data-testid="links" data-hours={String(hours)} />,
}));
vi.mock("../engine/EngineSettingsSearch", () => ({ EngineSettingsSearch: () => null }));
vi.mock("../engine/EngineSwitch", () => ({ ClearCheckEngine: () => null, EngineSwitch: () => null }));
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

  it("puts the window back once the duplicates list closes", () => {
    renderMatrix();
    fireEvent.click(screen.getByText(/duplicate candidates/));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-window", "all");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "dupe");
    fireEvent.click(tab("Links"));
    expect(screen.getByTestId("links")).toHaveAttribute("data-hours", "24");
    fireEvent.click(tab("Entities"));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-window", "24h");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "all");
  });

  it("keeps a window the analyst picked while the duplicates list was open", () => {
    renderMatrix();
    fireEvent.click(screen.getByText(/duplicate candidates/));
    fireEvent.click(screen.getByRole("button", { name: "7d" }));
    fireEvent.click(tab("Links"));
    expect(screen.getByTestId("links")).toHaveAttribute("data-hours", String(7 * 24));
  });

  it("writes the open tab into the URL, so Back returns to it", () => {
    renderMatrix();
    fireEvent.click(tab("Links"));
    expect(new URL(window.location.href).searchParams.get("view")).toBe("links");
    expect(new URL(window.location.href).searchParams.get("section")).toBe("engine");
  });
});
