import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { EngineSection } from "../engine/EngineSection";

// The console shell delegates to the matrix (which owns the data views and
// stage panels) — mock it and the browse-view children, then test the shell's
// wiring: default matrix, jobs/feeds/plans browse views, legacy deep links.
vi.mock("../engine/EngineMatrix", () => ({
  EngineMatrix: ({
    initialView,
    initialOpenStage,
    initialStage,
    initialStatus,
    onBrowse,
    onHighlightSetting,
  }: {
    initialView?: string;
    initialOpenStage?: string | null;
    initialStage?: string;
    initialStatus?: string;
    onBrowse: (v: string) => void;
    onHighlightSetting: (key: string) => void;
  }) => (
    <div
      data-testid="engine-matrix"
      data-view={initialView ?? ""}
      data-openstage={initialOpenStage ?? ""}
      data-stage={initialStage ?? ""}
      data-status={initialStatus ?? ""}
    >
      <button onClick={() => onBrowse("jobs")}>browse-jobs</button>
      <button onClick={() => onBrowse("plans")}>browse-plans</button>
      <button onClick={() => onHighlightSetting("thread_join_similarity")}>highlight-setting</button>
    </div>
  ),
}));
vi.mock("../engine/PipelinePlans", () => ({
  PipelinePlans: () => <div data-testid="pipeline-plans" />,
}));
vi.mock("@/components/JobSchedules", () => ({
  default: () => <div data-testid="job-schedules" />,
}));
vi.mock("@/components/SystemSettings", async () => {
  const { createContext } = await import("react");
  return {
    default: () => <div data-testid="system-settings" />,
    SettingsHighlightContext: createContext<{ key: string; nonce: number } | null>(null),
  };
});
vi.mock("../engine/MaintenancePanel", () => ({
  MaintenancePanel: () => <div data-testid="maintenance-panel" />,
}));
vi.mock("@/components/EnrichmentSettings", () => ({
  default: () => <div data-testid="enrichment-settings" />,
}));
vi.mock("../engine/EnrichmentGaps", () => ({
  EnrichmentGaps: () => <div data-testid="enrichment-gaps" />,
}));

function renderSection(search = "") {
  return render(
    <MemoryRouter initialEntries={[`/settings${search}`]}>
      <EngineSection />
    </MemoryRouter>,
  );
}

describe("EngineSection", () => {
  it("defaults to the matrix console with no initial state", () => {
    renderSection();
    const matrix = screen.getByTestId("engine-matrix");
    expect(matrix).toHaveAttribute("data-view", "");
    expect(matrix).toHaveAttribute("data-openstage", "");
  });

  it("switches to a browse view and back", () => {
    renderSection();
    fireEvent.click(screen.getByText("browse-jobs"));
    expect(screen.getByTestId("job-schedules")).toBeInTheDocument();
    expect(screen.queryByTestId("engine-matrix")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "← Engine" }));
    expect(screen.getByTestId("engine-matrix")).toBeInTheDocument();
  });

  it("shows the plans editor in the plans browse view", () => {
    renderSection();
    fireEvent.click(screen.getByText("browse-plans"));
    expect(screen.getByTestId("pipeline-plans")).toBeInTheDocument();
  });

  it("routes legacy ?tab=autolinking into the card's links view", () => {
    renderSection("?tab=autolinking");
    expect(screen.getByTestId("engine-matrix")).toHaveAttribute("data-view", "links");
  });

  it("routes legacy ?tab=extraction into the card's review view", () => {
    renderSection("?tab=extraction");
    expect(screen.getByTestId("engine-matrix")).toHaveAttribute("data-view", "review");
  });

  it("routes legacy ?tab=jobs to the jobs browse view", () => {
    renderSection("?tab=jobs");
    expect(screen.getByTestId("job-schedules")).toBeInTheDocument();
  });

  it("routes legacy ?tab=plans to the plans browse view", () => {
    renderSection("?tab=plans");
    expect(screen.getByTestId("pipeline-plans")).toBeInTheDocument();
  });

  it("opens an in-card stage panel from legacy ?tab=pipeline&stage=", () => {
    renderSection("?tab=pipeline&stage=score");
    expect(screen.getByTestId("engine-matrix")).toHaveAttribute("data-openstage", "score");
  });

  it("maps legacy ?tab=pipeline&stage=feeds to the card's feeds view", () => {
    renderSection("?tab=pipeline&stage=feeds");
    expect(screen.getByTestId("engine-matrix")).toHaveAttribute("data-view", "feeds");
  });

  it("pre-filters the matrix from legacy ?tab=processing deep links", () => {
    renderSection("?tab=processing&stage=extract&status=error");
    const matrix = screen.getByTestId("engine-matrix");
    expect(matrix).toHaveAttribute("data-stage", "extract");
    expect(matrix).toHaveAttribute("data-status", "error");
  });

  it("maps legacy ?section=workbench to the autolink stage panel", () => {
    renderSection("?section=workbench");
    expect(screen.getByTestId("engine-matrix")).toHaveAttribute("data-openstage", "autolink");
  });

  it("maps legacy ?section=feed-health to the card's feeds view", () => {
    renderSection("?section=feed-health");
    expect(screen.getByTestId("engine-matrix")).toHaveAttribute("data-view", "feeds");
  });

  it("maps legacy ?section=enrichment to the enrichment browse view", () => {
    renderSection("?section=enrichment");
    expect(screen.getByTestId("enrichment-settings")).toBeInTheDocument();
    expect(screen.getByTestId("enrichment-gaps")).toBeInTheDocument();
    expect(screen.queryByTestId("engine-matrix")).not.toBeInTheDocument();
  });
});
