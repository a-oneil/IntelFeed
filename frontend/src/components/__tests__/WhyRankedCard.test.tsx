import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { WhyRankedCard } from "@/components/WhyRankedCard";
import type { PrioritySignal } from "@/api/types";

/** Raw strength and real contribution deliberately disagree here: `pir_match`
 *  is the strongest raw signal but the weakest contributor, because it fires on
 *  ~43% of entries. The old card plotted raw scores and drew it longest. */
const SIGNALS: PrioritySignal[] = [
  { type: "pir_match", family: "interest", score: 0.9, weighted: 0.25, explanation: "Matches intelligence requirement: 'Edge Devices'" },
  { type: "new_pairing", family: "novelty", score: 0.6, weighted: 0.92, explanation: "First-ever observed pairing: Salt Typhoon ↔ Puerto Rico" },
  { type: "source_convergence", family: "coverage", score: 0.5, weighted: 0.5, explanation: "3 independent outlets are covering this story" },
  { type: "feed_echo", family: "coverage", score: 0.4, weighted: -0.2, explanation: "Echoes earlier coverage (9/12 shared entities)" },
];

function renderCard(props: Partial<Parameters<typeof WhyRankedCard>[0]> = {}) {
  return render(
    <MemoryRouter>
      <WhyRankedCard score={1.5} signals={SIGNALS} {...props} />
    </MemoryRouter>
  );
}

/** The card always mounts collapsed; expanding is a per-article click. */
async function expand() {
  await userEvent.click(screen.getByRole("button", { name: /Why it's ranked/ }));
}

describe("WhyRankedCard", () => {

  it("collapses to the score plus the top reason", () => {
    renderCard();
    expect(screen.getByText("◆ 1.5")).toBeInTheDocument();
    expect(
      screen.getByText("First-ever observed pairing: Salt Typhoon ↔ Puerto Rico")
    ).toBeInTheDocument();
    expect(screen.getByText("+3 more")).toBeInTheDocument();
  });

  it("orders the ledger by real contribution, not raw strength", async () => {
    renderCard();
    await expand();
    const values = screen.getAllByText(/^[+−]\d\.\d\d$/).map((el) => el.textContent);
    expect(values).toEqual(["+0.92", "+0.50", "+0.25", "−0.20"]);
  });

  it("shows the echo penalty the old card hid entirely", async () => {
    renderCard();
    await expand();
    expect(screen.getByText("Echoes earlier coverage (9/12 shared entities)")).toBeInTheDocument();
    expect(screen.getByText("−0.20")).toBeInTheDocument();
  });

  it("reveals the arithmetic behind each row on demand", async () => {
    renderCard();
    await expand();
    await userEvent.click(screen.getByRole("button", { name: "Show the math" }));
    // 0.6 raw → 0.92 contribution means a ×1.53 rarity weight.
    expect(screen.getByText("0.60 × 1.53 rarity")).toBeInTheDocument();
    expect(screen.getByText(/Shared score/)).toBeInTheDocument();
  });

  it("says so when the stored score predates today's weights", async () => {
    renderCard({ score: 6.6 }); // ledger sums to 1.47 — the stored score is stale
    await expand();
    await userEvent.click(screen.getByRole("button", { name: "Show the math" }));
    expect(screen.getByText("At today’s weights")).toBeInTheDocument();
    expect(screen.getByText(/computed with earlier weights/)).toBeInTheDocument();
  });

  it("keeps the personal lift to one footer line", async () => {
    renderCard({ personal: { lift: -0.27, families: [{ family: "novelty", weight: 0.8, delta: -0.2 }] } });
    await expand();
    expect(screen.getByText("−0.27")).toBeInTheDocument();
    expect(screen.getByText(/in your ordering\s*only/)).toBeInTheDocument();
    // Named for its destination: that screen shows learned weights and can pause
    // or reset them, but nothing there tunes a weight by hand.
    expect(screen.getByRole("button", { name: "Your Radar" })).toBeInTheDocument();
  });

  it("folds the watched-stack posture into its own row, not a stray button", async () => {
    renderCard({
      exposure: {
        lift: 3.75,
        posture: "no_rule",
        asset_name: "Fortinet",
        asset_type: "vendor",
        cve_ids: ["CVE-2018-13379"],
        missing_data_sources: [],
      },
    });
    await expand();
    expect(
      screen.getByText("Fortinet is on your watched stack · CVE-2018-13379 has no detection rule yet")
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /draft one/ })).not.toBeInTheDocument();
  });

  it("renders nothing without signals or exposure", () => {
    const { container } = render(
      <MemoryRouter>
        <WhyRankedCard score={0} signals={[]} />
      </MemoryRouter>
    );
    expect(container.firstChild).toBeNull();
  });
});
