import { describe, expect, it } from "vitest";
import type { EntityContext, EntityContextSource } from "@/hooks/useEntityContext";
import { contextDigest, contextSourcesWithData } from "../ContextPanel";

/**
 * The Context row's closed-state line, and the hide rule behind it: a null
 * digest means no source applies, and the Overview drops the row entirely.
 */
const source = (label: string, items: EntityContextSource["items"], stale = false): EntityContextSource =>
  ({ source_type: label.toLowerCase(), label, stale, items }) as EntityContextSource;

const fact = (key: string, value: string | number | null): EntityContextSource["items"][number] =>
  ({ key, label: key, display: "fact", value }) as EntityContextSource["items"][number];

const ctx = (sources: EntityContextSource[], unavailable: EntityContext["unavailable"] = []): EntityContext =>
  ({ sources, unavailable, can_enrich: true }) as unknown as EntityContext;

describe("contextDigest", () => {
  it("is null with no data, and null when no source applies (the row hides)", () => {
    expect(contextDigest(undefined)).toBeNull();
    expect(contextDigest(ctx([]))).toBeNull();
  });

  it("names the sources that answered and says how fresh they are", () => {
    const data = ctx([source("NVD", [fact("cvss", 9.8)]), source("EPSS", [fact("score", 0.9)], true)]);
    expect(contextDigest(data)).toBe("NVD · EPSS · 1 stale, 1 fresh");
    expect(contextDigest(ctx([source("NVD", [fact("cvss", 9.8)])]))).toBe("NVD · all fresh");
  });

  it("counts only sources with a value, not every source that applies", () => {
    const data = ctx([source("NVD", [fact("cvss", 9.8)]), source("Shodan", [fact("ports", null)])]);
    expect(contextSourcesWithData(data).map((s) => s.label)).toEqual(["NVD"]);
  });

  it("says nothing has been looked up yet instead of a bare source count", () => {
    const data = ctx([source("NVD", [fact("cvss", null)]), source("EPSS", [])]);
    expect(contextDigest(data)).toBe("Not looked up yet · 2 sources apply");
    expect(contextDigest(ctx([source("NVD", [])]))).toBe("Not looked up yet · 1 source applies");
  });

  it("appends the sources that need a key", () => {
    const unavailable = [{ source_type: "shodan", label: "Shodan", needs: "api_key" }] as EntityContext["unavailable"];
    expect(contextDigest(ctx([], unavailable))).toBe("1 needs a key");
    expect(contextDigest(ctx([source("NVD", [fact("cvss", 9.8)])], unavailable))).toBe("NVD · all fresh · 1 needs a key");
  });
});
