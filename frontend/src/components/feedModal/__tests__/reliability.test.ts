import { describe, expect, it } from "vitest";
import { reliabilityNote, tagCeiling } from "../reliability";

describe("tagCeiling", () => {
  it("matches the backend's weighting: only A and B reach high", () => {
    expect(tagCeiling("A")).toBe("high");
    expect(tagCeiling("B")).toBe("high");
    expect(tagCeiling("C")).toBe("medium");
    expect(tagCeiling("D")).toBe("medium");
    expect(tagCeiling("E")).toBe("low");
  });

  it("treats F (cannot be judged) like unrated, not worse than E", () => {
    expect(tagCeiling("F")).toBe(tagCeiling(null));
  });

  it("treats an unrated feed like a D", () => {
    expect(tagCeiling(null)).toBe("medium");
    expect(tagCeiling("")).toBe("medium");
  });
});

describe("reliabilityNote", () => {
  it("tells an unrated feed where its tags stop and how to lift that", () => {
    const note = reliabilityNote(null);
    expect(note).toMatch(/^Unrated: catalog-matched tags from this feed top out at medium\./);
    expect(note).toMatch(/Rate it A or B under Assessment/);
  });

  it("names the rating otherwise", () => {
    expect(reliabilityNote("E")).toBe("Rated E: catalog-matched tags from this feed top out at low.");
    expect(reliabilityNote("B")).toMatch(/^Rated B: .*can be high confidence\.$/);
  });
});
