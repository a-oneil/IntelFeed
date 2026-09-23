import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SignalStats } from "@/hooks/useEngine";
import type { EntityWatch } from "@/hooks/useWatchlist";
import { ScoreStageConfig } from "../engine/ScoreStageConfig";

const stats: SignalStats = {
  health: {
    shadow_enabled: true,
    surface_enabled: true,
    unscored_recent: 2,
    feedback_min_samples: 20,
    feedback_counts: { novelty: 5 },
    feedback_nudges: {},
    last_rate_recompute: { status: "success", finished_at: "2026-07-18T04:20:00Z" },
    last_rescore: null,
  },
  signals: [
    { signal_type: "novel_entity", family: "novelty", firing_rate: 0.016, effective_weight: 1.38 },
    { signal_type: "pir_match", family: "interest", firing_rate: 0.24, effective_weight: 0.47 },
  ],
  family_multipliers: { novelty: 1.0, coverage: 1.0, severity: 1.0, interest: 1.0, content: 1.0 },
  default_family_multipliers: { novelty: 1.0, coverage: 1.0, severity: 1.0, interest: 1.0, content: 1.0 },
  threshold: 1.5,
  threshold_is_auto: true,
};

let watches: EntityWatch[] = [];
const updateMutate = vi.fn();
const deleteMutate = vi.fn();

vi.mock("@/hooks/useEngine", () => ({
  useSignalStats: () => ({ data: stats, isLoading: false }),
  useUpdateSignalSettings: () => ({ mutate: updateMutate, isPending: false }),
}));

vi.mock("@/hooks/useWatchlist", () => ({
  useWatchlist: () => ({ data: watches }),
  useDeleteWatch: () => ({ mutate: deleteMutate, isPending: false }),
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

// The stage now embeds the scoring slice of the system settings form. That
// form fetches on its own and is covered by its own tests; stub it out so
// these stay about the signal readout and the watchlist.
vi.mock("@/components/SystemSettings", () => ({
  default: () => <div data-testid="system-settings" />,
}));

describe("ScoreStageConfig", () => {
  beforeEach(() => {
    updateMutate.mockClear();
    deleteMutate.mockClear();
    watches = [];
  });

  it("renders the self-tuning readout with firing rates and weights", () => {
    render(<ScoreStageConfig />);
    expect(screen.getByText("novel entity")).toBeInTheDocument();
    expect(screen.getByText("1.60%")).toBeInTheDocument();
    expect(screen.getByText("1.38")).toBeInTheDocument();
  });

  it("saves mutated family multipliers", () => {
    render(<ScoreStageConfig />);
    const sliders = screen.getAllByRole("slider");
    fireEvent.change(sliders[0], { target: { value: "1.5" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(updateMutate).toHaveBeenCalledTimes(1);
    const body = updateMutate.mock.calls[0][0];
    expect(body.family_multipliers.novelty).toBeCloseTo(1.5);
  });

  it("sends a threshold override when a value is entered", () => {
    render(<ScoreStageConfig />);
    fireEvent.change(screen.getByPlaceholderText("1.50"), { target: { value: "2.25" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(updateMutate.mock.calls[0][0].threshold_override).toBeCloseTo(2.25);
  });

  it("lists watched and muted entities with a remove action", () => {
    watches = [
      { id: "w1", entity_type: "threat_actor", entity_id: "a1", mode: "watch", boost: 1.0, entity_name: "APT29" },
      { id: "w2", entity_type: "malware", entity_id: "m1", mode: "mute", boost: 1.0, entity_name: "LockBit" },
    ];
    render(<ScoreStageConfig />);
    expect(screen.getByText("APT29")).toBeInTheDocument();
    expect(screen.getByText("LockBit")).toBeInTheDocument();
    expect(screen.getByText("mute")).toBeInTheDocument();
    fireEvent.click(screen.getAllByTitle("Remove")[0]);
    expect(deleteMutate).toHaveBeenCalledWith({ entity_type: "threat_actor", entity_id: "a1" });
  });

  it("shows an empty state when nothing is watched", () => {
    render(<ScoreStageConfig />);
    expect(screen.getByText("No watched or muted entities yet.")).toBeInTheDocument();
  });
});
