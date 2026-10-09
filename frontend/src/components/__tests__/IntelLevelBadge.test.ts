import { describe, expect, it } from "vitest";
import { deriveIntelLevel } from "../IntelLevelBadge";

describe("deriveIntelLevel", () => {
  it("hides the rail for a feed that is out of the intel system", () => {
    expect(deriveIntelLevel({ mode: "none" }).fill).toBe(-1);
  });

  it("fills completely when all three per-feed stages run", () => {
    const level = deriveIntelLevel({ mode: "full", aiAnalysis: true, autoExtract: true });
    expect(level.fill).toBe(1);
    expect(level.stages).toHaveLength(3);
  });

  it("no longer claims 'known entities only' when the AI is reading the feed", () => {
    // The old model mapped {full, autoExtract:false} to a 0.25 rail labelled
    // "Known entities only — match against existing database", while the AI
    // was reading every article and creating entities from it.
    const level = deriveIntelLevel({ mode: "full", aiAnalysis: true, autoExtract: false });
    expect(level.label).toContain("AI analysis");
    expect(level.label).not.toContain("Known entities only");
  });

  it("drops to catalog matching only when the AI is actually off", () => {
    const level = deriveIntelLevel({ mode: "full", aiAnalysis: false, autoExtract: false });
    expect(level.stages).toEqual(["autolinks everything"]);
    expect(level.label).not.toContain("AI analysis");
  });

  it("shows manual mode as AI-only rather than as nothing running", () => {
    const level = deriveIntelLevel({ mode: "manual", aiAnalysis: true, autoExtract: false });
    expect(level.stages).toEqual(["AI analysis"]);
  });

  it("renders an empty rail when a processed feed has every stage off", () => {
    const level = deriveIntelLevel({ mode: "manual", aiAnalysis: false, autoExtract: false });
    expect(level.fill).toBe(0);
    expect(level.label).toContain("no extraction stage is on");
  });

  it("distinguishes the relevance-gated scan from the unconditional one", () => {
    expect(deriveIntelLevel({ mode: "selective" }).stages[0]).toContain("relevant");
    expect(deriveIntelLevel({ mode: "full" }).stages[0]).toContain("everything");
  });
});
