import { describe, expect, it } from "vitest";
import { describeStages, summarizeStages, toggleStage } from "../pipelineStages";
import type { FeedPipeline } from "@/api/types";
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
    ai_analysis_enabled: true,
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

const ctx = (aiEnabled = true, pipeline?: FeedPipeline) => ({ aiEnabled, pipeline });

const stage = (vals: FeedFormValues, id: string, ai = true) =>
  describeStages(vals, ctx(ai)).find((s) => s.id === id)!;

function plan(
  stages: Record<string, { enabled: boolean }>,
  decided: Record<string, "legacy" | "global" | "category" | "feed">
): FeedPipeline {
  return { engine_enabled: true, stages, decided_by: decided };
}

describe("describeStages", () => {
  it("gives the AI pass its own per-feed switch", () => {
    const ai = stage(values(), "ai");
    expect(ai.scope).toBe("feed");
    expect(ai.disabled).toBe(false);
    expect(ai.on).toBe(true);
    expect(ai.writes).toBe(true);
  });

  it("turns the AI off for one feed without disturbing autolinking", () => {
    // The gap this closes: mode="none" was the only lever, and it killed
    // autolinking and scoring too.
    const vals = values({ ai_analysis_enabled: false });
    expect(stage(vals, "ai").on).toBe(false);
    expect(stage(vals, "autolink").on).toBe(true);
  });

  it("shows the AI running on a feed the old UI called 'manual'", () => {
    const ai = stage(values({ intel_extraction_mode: "manual" }), "ai");
    expect(ai.on).toBe(true);
  });

  it("shows the AI running on a feed the old UI called 'known entities only'", () => {
    const vals = values({ intel_extraction_mode: "full", auto_extract_on_ingest: false });
    expect(stage(vals, "ai").on).toBe(true);
  });

  it("turns off every stage the feed actually controls when it is not processed", () => {
    const stages = describeStages(values({ intel_extraction_mode: "none" }), ctx());
    for (const s of stages) {
      if (s.id === "master") continue;
      expect(s.on, `${s.id} should be off`).toBe(false);
      expect(s.disabled, `${s.id} should be disabled`).toBe(true);
    }
  });

  it("gives no row to the ledger scan, which is not this feed's to switch", () => {
    // `_scan_entry_observables` never reads the Feed, so a checkbox for it was
    // decoration. The sentence below still reports that it happens.
    const ids = describeStages(values(), ctx()).map((s) => s.id);
    expect(ids).not.toContain("observables");
  });

  it("nests tool creation under the AI pass, because that is all that reads it", () => {
    const tools = stage(values(), "tools");
    expect(tools.nested).toBe(true);
    expect(tools.writes).toBe(true);

    // AI off -> the switch is inert, so it must not look live.
    const off = stage(values({ ai_analysis_enabled: false }), "tools");
    expect(off.on).toBe(false);
    expect(off.disabled).toBe(true);
  });

  it("reports the AI off, and not per-feed, when the engine-wide switch is off", () => {
    const ai = stage(values(), "ai", false);
    expect(ai.on).toBe(false);
    expect(ai.scope).toBe("global");
    expect(ai.disabled).toBe(true);
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

  it("the AI switch writes its own field now", () => {
    expect(toggleStage(values(), "ai", false)).toEqual({ ai_analysis_enabled: false });
  });

  it("an unknown stage is a no-op rather than a silent write", () => {
    const vals = values();
    expect(toggleStage(vals, "master", true)).toEqual({
      intel_extraction_mode: "selective",
    });
  });
});

describe("summarizeStages", () => {
  it("says plainly that nothing else is extracted, ledger aside", () => {
    const text = summarizeStages(values({ intel_extraction_mode: "none" }), ctx(true));
    expect(text).toContain("Nothing else is pulled out of them");
    // The ledger scan is ungated, so the sentence must not deny it.
    expect(text).toContain("indicator ledger");
  });

  it("warns that the AI may create new entities", () => {
    expect(summarizeStages(values(), ctx(true))).toContain("can add entities you do not have yet");
  });

  it("promises nothing new when the AI is off engine-wide", () => {
    const text = summarizeStages(values(), ctx(false));
    expect(text).toContain("Nothing new is added");
  });

  it("mentions detection rules only when they are being pulled out", () => {
    expect(summarizeStages(values(), ctx(true))).not.toContain("Detection rules");
    expect(
      summarizeStages(values({ extract_detection_rules: true }), ctx(true))
    ).toContain("Detection rules");
  });
});

describe("pipeline plans", () => {
  it("leaves stages alone while the plan engine is off", () => {
    const rows = describeStages(values(), ctx(true, undefined));
    expect(rows.every((r) => r.scope !== "plan")).toBe(true);
  });

  it("hands a stage to the plan that overrides it", () => {
    const p = plan({ autolink: { enabled: false } }, { autolink: "category", extract: "legacy" });
    const autolink = describeStages(values(), ctx(true, p)).find((r) => r.id === "autolink")!;

    // The plan wins over the Feed booleans, so a checkbox here would write a
    // value nothing reads.
    expect(autolink.scope).toBe("plan");
    expect(autolink.planScope).toBe("category");
    expect(autolink.disabled).toBe(true);
    expect(autolink.on).toBe(false);
  });

  it("leaves a stage no plan touched under this pane's control", () => {
    const p = plan({ autolink: { enabled: false } }, { autolink: "global", extract: "legacy" });
    const rows = describeStages(values({ auto_extract_on_ingest: true }), ctx(true, p));

    const regex = rows.find((r) => r.id === "regex")!;
    expect(regex.scope).toBe("feed");
    expect(regex.disabled).toBe(false);
    expect(regex.on).toBe(true);
  });

  it("the summary follows the plan, not the feed's own setting", () => {
    const p = plan({ autolink: { enabled: false } }, { autolink: "global" });
    const text = summarizeStages(values(), ctx(true, p));
    expect(text).not.toContain("tagged with entities you already track");
  });

  it("always reports the ledger scan, which no switch here controls", () => {
    for (const vals of [values(), values({ intel_extraction_mode: "none" })]) {
      expect(summarizeStages(vals, ctx(true))).toContain("indicator ledger");
    }
  });
});
