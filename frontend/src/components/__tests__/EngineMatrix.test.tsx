import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EngineMatrix } from "../engine/EngineMatrix";

// Tests the console's own state: which tab is open, which panels, which time window. Data hooks and the tabs' bodies are stubbed; each stub shows the props the console passes it.
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
    data: { total_created: 10, by_status: { dupe: 3, review: 4, orphan: 2 } },
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
  ProposalsQueue: ({ lens }: { lens: string }) => <div data-testid="queue" data-lens={lens} />,
}));
vi.mock("../engine/AdjudicatorMenu", () => ({
  AdjudicatorMenu: ({ onToggleSettings }: { onToggleSettings: () => void }) => (
    <button onClick={onToggleSettings}>tuning</button>
  ),
}));
vi.mock("../engine/ExtractionTab", () => ({
  ExtractionTab: ({
    window,
    status = "all",
    statusSwitch,
  }: {
    window: string;
    status?: string;
    statusSwitch?: { onChange: (s: string) => void; counts: Record<string, number> };
  }) => (
    <div data-testid="entities" data-window={window} data-status={status}>
      {statusSwitch &&
        ["review", "dupe", "orphan"].map((s) => (
          <button key={s} onClick={() => statusSwitch.onChange(s)}>
            status-{s}
            {statusSwitch.counts[s] ?? ""}
          </button>
        ))}
    </div>
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

  it("counts the Review lenses on the Review tab; the badge leaves out unconfirmed and unjudged edges", () => {
    renderMatrix();
    // 3 dupe + 2 orphan; the 4 unconfirmed and 5 unjudged edges count on their lens only.
    expect(tab("Review")).toHaveTextContent("Review5");
    expect(screen.getByText(/to review/).textContent).toContain("5");
    fireEvent.click(tab("Review"));
    // Entities: 4 unconfirmed + 3 duplicates + 2 orphans.
    expect(screen.getByRole("button", { name: /^Entities9/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Relationships5/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Queue$/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Unconfirmed/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Duplicates/ })).toBeNull();
  });

  it("has one Needs you shortcut for Review, opening the first list with something in it", () => {
    renderMatrix();
    expect(screen.queryByText(/to reclassify/)).toBeNull();
    expect(screen.queryByText(/adjudication verdicts/)).toBeNull();
    fireEvent.click(screen.getByText(/to review/));
    // The queue is empty here (no hygiene stats) and Unconfirmed isn't counted, so it opens Entities at Duplicates.
    expect(new URL(window.location.href).searchParams.get("view")).toBe("review");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "dupe");
  });

  it("opens the duplicate candidates on the Entities lens, over all time", () => {
    renderMatrix();
    fireEvent.click(tab("Review"));
    fireEvent.click(screen.getByRole("button", { name: /^Entities9/ }));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "review");
    fireEvent.click(screen.getByText("status-dupe3"));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-window", "all");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "dupe");
    expect(new URL(window.location.href).searchParams.get("view")).toBe("review");
    expect(new URL(window.location.href).searchParams.get("lens")).toBe("entities");
    expect(new URL(window.location.href).searchParams.get("show")).toBe("dupe");
    // The console's own window is untouched.
    fireEvent.click(tab("Links"));
    expect(screen.getByTestId("links")).toHaveAttribute("data-hours", "24");
    fireEvent.click(tab("Entities"));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-window", "24h");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "all");
    expect(new URL(window.location.href).searchParams.get("show")).toBeNull();
  });

  it("lists each entity status under the Entities lens and the unjudged edges under Relationships, over all time", () => {
    renderMatrix("review");
    expect(screen.getByTestId("queue")).toHaveAttribute("data-lens", "queue");
    fireEvent.click(screen.getByRole("button", { name: /^Entities9/ }));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "review");
    expect(screen.getByTestId("entities")).toHaveAttribute("data-window", "all");
    fireEvent.click(screen.getByText("status-orphan2"));
    expect(screen.getByTestId("entities")).toHaveAttribute("data-status", "orphan");
    expect(new URL(window.location.href).searchParams.get("show")).toBe("orphan");
    fireEvent.click(screen.getByRole("button", { name: /^Relationships5/ }));
    expect(screen.getByTestId("links")).toHaveAttribute("data-unreviewed", "true");
    expect(screen.getByTestId("links")).toHaveAttribute("data-hours", "undefined");
    fireEvent.click(screen.getByRole("button", { name: /^History$/ }));
    expect(screen.getByTestId("queue")).toHaveAttribute("data-lens", "history");
    expect(new URL(window.location.href).searchParams.get("lens")).toBe("history");
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
