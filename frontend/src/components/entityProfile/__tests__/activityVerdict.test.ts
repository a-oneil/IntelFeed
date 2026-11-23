import { describe, expect, it } from "vitest";
import { activityVerdict } from "../activityVerdict";

const series = (counts: number[]) =>
  counts.map((count, i) => ({ date: new Date(Date.UTC(2026, 7, 25 + i)).toISOString(), count, feeds: count ? 1 : 0 }));

describe("activityVerdict", () => {
  it("returns nothing for a series too short to compare", () => {
    expect(activityVerdict(series(Array(20).fill(1)))).toBeNull();
    expect(activityVerdict(undefined)).toBeNull();
  });

  it("calls a surge that faded cooling, and names the busiest day", () => {
    const counts = [...Array(60).fill(8), 27, ...Array(8).fill(8), ...Array(21).fill(0.5).map((_, i) => (i % 4 === 0 ? 1 : 0))];
    const v = activityVerdict(series(counts));
    expect(v?.tone).toBe("cooling");
    expect(v?.detail).toMatch(/The busiest day was Oct 24, with 27 articles\./);
  });

  it("calls three silent weeks quiet", () => {
    const v = activityVerdict(series([...Array(69).fill(2), ...Array(21).fill(0)]));
    expect(v?.tone).toBe("quiet");
  });

  it("calls a first appearance new", () => {
    const v = activityVerdict(series([...Array(86).fill(0), 2, 3, 0, 0]));
    expect(v).toMatchObject({ tone: "new", detail: "First reported in the last 3 weeks: 5 articles" });
  });

  it("compares per-day rates, not raw totals", () => {
    // 21 days at 2/day against 69 days at 2/day: the same pace.
    expect(activityVerdict(series(Array(90).fill(2)))?.tone).toBe("steady");
    expect(activityVerdict(series([...Array(69).fill(1), ...Array(21).fill(4)]))?.tone).toBe("rising");
  });
});
