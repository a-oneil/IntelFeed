import { describe, expect, it } from "vitest";
import { missingFor, runnableSummary, runsPhrase } from "../HuntPackPanel";
import type { HuntHypothesis, HuntPack } from "@/hooks/useHuntPacks";

const hunt = (over: Partial<HuntHypothesis>): HuntHypothesis => ({
  id: "H1",
  title: "t",
  hypothesis: "h",
  tactic: null,
  techniques: [],
  platform: null,
  data_sources: [],
  telemetry: [],
  runnable: true,
  query: "q",
  query_notes: null,
  false_positives: null,
  ...over,
});

const pack = (hypotheses: HuntHypothesis[]): HuntPack => ({
  entity_type: "cve",
  entity_key: "CVE-2026-1",
  label: "CVE-2026-1",
  window: "all",
  language: "cql",
  language_name: "CQL",
  generated_at: null,
  model: null,
  entry_ids: [],
  hypotheses,
});

/** The Next steps line under the hunts: never a dangling "need ." */
describe("hunt summaries", () => {
  it("names missing log types", () => {
    const p = pack([hunt({}), hunt({ id: "H2", runnable: false, telemetry: [{ source: "auth.failure", have: false }] })]);
    expect(runnableSummary(p)).toBe("1 run on the telemetry you collect; 1 needs auth.failure.");
    expect(runsPhrase(p)).toBe("1 of 2 run on your telemetry");
  });

  it("says logs you don't collect when a hunt's own log is missing, instead of an empty list", () => {
    const blocked = hunt({
      id: "H2",
      runnable: false,
      log_source: "vCenter VCSA SSO logs forwarded via syslog to LogScale",
      source_have: false,
    });
    expect(missingFor(blocked)).toEqual(["vCenter VCSA SSO logs forwarded via syslog to LogScale"]);
    expect(runnableSummary(pack([hunt({}), blocked]))).toBe(
      "1 run on the telemetry you collect; 1 needs logs you don't collect.",
    );
  });

  it("says all run when every hunt does", () => {
    expect(runnableSummary(pack([hunt({}), hunt({ id: "H2" })]))).toBe("All 2 run on the telemetry you collect.");
  });
});
