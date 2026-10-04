import { describe, expect, it } from "vitest";
import { describeStages, summarizeStages, toggleStage } from "../pipelineStages";
import type { FeedFormValues } from "../useFeedForm";

function values(overrides: Partial<FeedFormValues> = {}): FeedFormValues {
  return {
    custom_title: "",
    category_id: "",
    is_muted: false,
    url: "https://example.com/rss",
    feed_type: "rss",
    fetch_interval_minutes: 30,
    retention_days: "",
    is_active: true,
    intel_extraction_mode: "selective",
    auto_extract_on_ingest: false,
    extract_detection_rules: false,
    extract_tools: true,
    reliability_rating: "",
    timeliness_rating: "",
    relevance_rating: "",
    analyst_notes: "",
    adapter: {},
    ...overrides,
  };
}

const stage = (vals: FeedFormValues, id: string, ai = true) =>
  describeStages(vals, ai).find((s) => s.id === id)!;

describe("describeStages", () => {
  it("marks the AI pass as global, because there is no per-feed field for it", () => {
    // The whole reason the old five-way preset lied: `auto_extract_on_ingest`
    // does not gate the AI, so "Known entities only" could not mean what it said.
    const ai = stage(values(), "ai");
    expect(ai.scope).toBe("global");
    expect(ai.disabled).toBe(true);
    expect(ai.writes).toBe(true);
  });

  it("shows the AI running on a feed the old UI called 'manual'", () => {
    const ai = stage(values({ intel_extraction_mode: "manual" }), "ai");
    expect(ai.on).toBe(true);
  });

  it("shows the AI running on a feed the old UI called 'known entities only'", () => {
    const vals = values({ intel_extraction_mode: "full", auto_extract_on_ingest: false });
    expect(stage(vals, "ai").on).toBe(true);
  });

  it("turns everything off when the feed is not processed at all", () => {
    const stages = describeStages(values({ intel_extraction_mode: "none" }), true);
    for (const s of stages) {
      if (s.id === "master") continue;
      expect(s.on, `${s.id} should be off`).toBe(false);
      expect(s.disabled, `${s.id} should be disabled`).toBe(true);
    }
  });

  it("reports the AI off when the engine-wide switch is off", () => {
    expect(stage(values(), "ai", false).on).toBe(false);
  });

  it("treats selective as autolink-plus-relevance-filter", () => {
    const vals = values({ intel_extraction_mode: "selective" });
    expect(stage(vals, "autolink").on).toBe(true);
    expect(stage(vals, "relevance").on).toBe(true);
  });

  it("treats full as autolink with no filter", () => {
    const vals = values({ intel_extraction_mode: "full" });
    expect(stage(vals, "autolink").on).toBe(true);
    expect(stage(vals, "relevance").on).toBe(false);
  });

  it("treats manual as autolink off", () => {
    const vals = values({ intel_extraction_mode: "manual" });
    expect(stage(vals, "autolink").on).toBe(false);
    expect(stage(vals, "relevance").disabled).toBe(true);
  });
});

describe("toggleStage", () => {
  it("switching the feed off writes mode none", () => {
    expect(toggleStage(values(), "master", false)).toEqual({ intel_extraction_mode: "none" });
  });

  it("switching the feed back on lands on the shipped default", () => {
    const vals = values({ intel_extraction_mode: "none" });
    expect(toggleStage(vals, "master", true)).toEqual({ intel_extraction_mode: "selective" });
  });

  it("autolink off becomes manual, not none — the AI still runs", () => {
    expect(toggleStage(values(), "autolink", false)).toEqual({
      intel_extraction_mode: "manual",
    });
  });

  it("dropping the relevance filter becomes full", () => {
    expect(toggleStage(values(), "relevance", false)).toEqual({
      intel_extraction_mode: "full",
    });
  });

  it("the remaining stages each write their own boolean", () => {
    expect(toggleStage(values(), "regex", true)).toEqual({ auto_extract_on_ingest: true });
    expect(toggleStage(values(), "rules", true)).toEqual({ extract_detection_rules: true });
    expect(toggleStage(values(), "tools", false)).toEqual({ extract_tools: false });
  });

  it("a global stage is a no-op rather than a silent write", () => {
    const vals = values();
    expect(toggleStage(vals, "ai", false)).toEqual({
      intel_extraction_mode: vals.intel_extraction_mode,
    });
    expect(toggleStage(vals, "observables", false)).toEqual({
      intel_extraction_mode: vals.intel_extraction_mode,
    });
  });
});

describe("summarizeStages", () => {
  it("says plainly that nothing is extracted", () => {
    const text = summarizeStages(values({ intel_extraction_mode: "none" }), true);
    expect(text).toContain("Nothing is extracted");
  });

  it("warns that the AI may create new entities", () => {
    expect(summarizeStages(values(), true)).toContain("may create entities you do not have yet");
  });

  it("promises nothing new when the AI is off engine-wide", () => {
    const text = summarizeStages(values(), false);
    expect(text).toContain("Nothing new is created");
  });

  it("mentions detection rules only when they are being pulled out", () => {
    expect(summarizeStages(values(), true)).not.toContain("Detection rules");
    expect(
      summarizeStages(values({ extract_detection_rules: true }), true)
    ).toContain("Detection rules");
  });
});
