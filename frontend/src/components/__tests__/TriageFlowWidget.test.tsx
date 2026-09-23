import { render } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import TriageFlowWidget from "../widgets/TriageFlowWidget";

const useTriageFlowMock = vi.fn();
vi.mock("@/hooks/useWidgetBoardData", () => ({ useTriageFlow: () => useTriageFlowMock() }));

interface Day {
  date: string;
  arrived: number;
  read: number;
}

function mount(days: Day[]) {
  useTriageFlowMock.mockReturnValue({ data: { days, backlog: 42 }, isLoading: false });
  const { container } = render(<TriageFlowWidget config={{}} />);
  return container;
}

/** Bars are the only rects; the axis is drawn with <line>. */
function barHeights(container: HTMLElement): number[] {
  return [...container.querySelectorAll("rect")].map((r) => Number(r.getAttribute("height")));
}

function day(date: string, arrived: number, read: number): Day {
  return { date, arrived, read };
}

const STEADY = [
  day("2026-08-24", 263, 11),
  day("2026-08-25", 160, 4),
  day("2026-08-26", 190, 6),
  day("2026-08-27", 397, 9),
  day("2026-08-28", 145, 3),
  day("2026-08-29", 137, 5),
  day("2026-08-30", 123, 2),
];

describe("TriageFlowWidget", () => {
  it("scales to the data when every day is comparable", () => {
    const container = mount(STEADY);
    // 500 axis for a 397 peak: the tallest bar reaches most of its arm.
    expect(container.textContent).toContain("500");
    expect(Math.max(...barHeights(container))).toBeGreaterThan(50);
    expect(container.textContent).not.toContain("off-scale");
  });

  it("clips a bulk mark-all-read instead of letting it flatten every real day", () => {
    // One 5,283-read day against ~200/day of intake. Scaling to the spike would
    // squash the normal days to sub-pixel hairlines — the bug this guards.
    const spiked = STEADY.map((d, i) => (i === 2 ? { ...d, read: 5283 } : d));
    const container = mount(spiked);

    // Axis still sized by the real intake days, not the bulk action.
    expect(container.textContent).toContain("500");
    expect(container.textContent).not.toContain("5.0k");
    // The clipped day is still accounted for, in the legend.
    expect(container.textContent).toContain("1 day off-scale");
    expect(container.textContent).toContain("peak 5.3k");
    // Normal days stay well above hairline height.
    expect(Math.max(...barHeights(container))).toBeGreaterThan(50);
  });

  it("renders an empty state with no days", () => {
    useTriageFlowMock.mockReturnValue({ data: { days: [], backlog: 0 }, isLoading: false });
    const { container } = render(<TriageFlowWidget config={{}} />);
    expect(container.textContent).toContain("No triage activity");
  });
});
