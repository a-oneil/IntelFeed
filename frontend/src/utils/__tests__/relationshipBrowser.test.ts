import { describe, expect, it } from "vitest";
import type { EntitySearchResult } from "@/api/types";
import {
  allowedVerbsForPair,
  buildStoryMap,
  clusterHeading,
  isEarnedRow,
  isEverydaySoftware,
  isImplausibleCveId,
  partitionEarned,
  structurePhrase,
  groupByVerb,
  splitAssertedContext,
  trustOf,
  timeAgo,
  verbChipLabel,
  verbSentence,
  type RelRow,
} from "../relationshipBrowser";

const item = (over: Partial<EntitySearchResult>): EntitySearchResult =>
  ({ id: "x", ...over }) as EntitySearchResult;

describe("verbChipLabel", () => {
  it("reads actively when the viewed entity is the subject (outbound)", () => {
    expect(verbChipLabel(item({ relationship_type: "uses", relationship_direction: "outbound" }))).toBe("uses");
    expect(verbChipLabel(item({ relationship_type: "targets", relationship_direction: "outbound" }))).toBe("targets");
    expect(verbChipLabel(item({ relationship_type: "exploits", relationship_direction: "outbound" }))).toBe("exploits");
  });
  it("inverts to the passive form when the viewed entity is the object (inbound)", () => {
    expect(verbChipLabel(item({ relationship_type: "uses", relationship_direction: "inbound" }))).toBe("used by");
    expect(verbChipLabel(item({ relationship_type: "targets", relationship_direction: "inbound" }))).toBe("targeted by");
    expect(verbChipLabel(item({ relationship_type: "exploits", relationship_direction: "inbound" }))).toBe("exploited by");
  });
  it("keeps symmetric verbs the same in both directions", () => {
    expect(verbChipLabel(item({ relationship_type: "related_to", relationship_direction: "inbound" }))).toBe("related to");
    expect(verbChipLabel(item({ relationship_type: "related_to", relationship_direction: "outbound" }))).toBe("related to");
  });
  it("treats the viewed country as the object of country verbs", () => {
    expect(verbChipLabel(item({ country_relationship: "targets" }))).toBe("targeted by");
    expect(verbChipLabel(item({ country_relationship: "operates_from" }))).toBe("origin of");
    expect(verbChipLabel(item({ country_relationship: "infrastructure" }))).toBe("infrastructure for");
  });
  it("defaults to co-mentioned for untyped rows", () => {
    expect(verbChipLabel(item({}))).toBe("co-mentioned");
  });
});

describe("verbSentence", () => {
  it("orders subject and object by direction", () => {
    const inbound = item({ relationship_type: "targets", relationship_direction: "inbound" });
    expect(verbSentence(inbound, "APT28", "Germany")).toBe("APT28 targets Germany");
    const outbound = item({ relationship_type: "uses", relationship_direction: "outbound" });
    expect(verbSentence(outbound, "Cobalt Strike", "APT28")).toBe("APT28 uses Cobalt Strike");
  });
});

describe("timeAgo", () => {
  it("formats relative day buckets", () => {
    expect(timeAgo(new Date().toISOString())).toBe("today");
    expect(timeAgo(new Date(Date.now() - 5 * 86_400_000).toISOString())).toBe("5d ago");
    expect(timeAgo(null)).toBe("");
  });
});

describe("allowedVerbsForPair", () => {
  it("returns verbs for a tracked pair in either orientation", () => {
    expect(allowedVerbsForPair("threat_actor", "malware")).toEqual(
      expect.arrayContaining(["uses", "delivers", "related_to", "attributed_to"]),
    );
    // reversed order still finds the pair (API stores canonical direction)
    expect(allowedVerbsForPair("country", "threat_actor")).toEqual(
      expect.arrayContaining(["targets", "attributed_to"]),
    );
  });

  it("returns empty for untracked pairs (country as actor, cve↔tool)", () => {
    expect(allowedVerbsForPair("country", "cve")).toEqual([]);
    expect(allowedVerbsForPair("country", "tool")).toEqual([]);
    expect(allowedVerbsForPair("vendor", "malware")).toEqual(
      expect.arrayContaining(["targets"]),
    );
    expect(allowedVerbsForPair("vendor", "cve")).toEqual([]);
  });
});

describe("trust ladder", () => {
  it("maps confidence + source to trust tiers with provenance", () => {
    const base = { id: "x", relationship_id: "r1" } as EntitySearchResult;
    expect(trustOf({ ...base, relationship_confidence: "probable" })).toEqual({ tier: "reported" });
    expect(trustOf({ ...base, relationship_confidence: "possible" })).toEqual({ tier: "signal" });
    expect(
      trustOf({
        ...base,
        relationship_confidence: "confirmed",
        relationship_source: "external_feed",
        relationship_description: "MITRE ATT&CK",
      }),
    ).toEqual({ tier: "corroborated", provenance: "MITRE" });
    expect(
      trustOf({
        ...base,
        relationship_confidence: "confirmed",
        relationship_source: "analyst_confirmed",
      }),
    ).toEqual({ tier: "corroborated", provenance: "you" });
    expect(
      trustOf({
        ...base,
        relationship_confidence: "confirmed",
        relationship_source: "auto_extracted",
        relationship_adjudication: "corroborated",
        relationship_evidence_count: 7,
      }),
    ).toEqual({ tier: "corroborated", provenance: "AI ×7" });
    // co-mention context rows are not claims
    expect(trustOf({ id: "y" } as EntitySearchResult)).toBeNull();
  });
});

describe("splitAssertedContext / groupByVerb", () => {
  const row = (over: Partial<EntitySearchResult>, label = "X"): RelRow =>
    ({ type: "malware", label, item: { id: label, ...over } as EntitySearchResult }) as RelRow;

  it("splits typed claims from co-mention context", () => {
    const rows = [row({ relationship_id: "r1", relationship_type: "uses" }, "A"), row({}, "B")];
    const { asserted, context } = splitAssertedContext(rows);
    expect(asserted.map((r) => r.label)).toEqual(["A"]);
    expect(context.map((r) => r.label)).toEqual(["B"]);
  });

  it("groups by direction+verb, outbound first, trust-sorted within group", () => {
    const rows = [
      row({ relationship_id: "1", relationship_type: "uses", relationship_direction: "inbound" }, "in-uses"),
      row(
        {
          relationship_id: "2",
          relationship_type: "uses",
          relationship_direction: "outbound",
          relationship_confidence: "possible",
          proximity_score: 0.9,
        },
        "signal-row",
      ),
      row(
        {
          relationship_id: "3",
          relationship_type: "uses",
          relationship_direction: "outbound",
          relationship_confidence: "confirmed",
          relationship_source: "external_feed",
          proximity_score: 0.1,
        },
        "corroborated-row",
      ),
      row({ relationship_id: "4", relationship_type: "exploits", relationship_direction: "outbound" }, "cve-row"),
    ];
    const groups = groupByVerb(rows);
    expect(groups.map((g) => g.key)).toEqual(["outbound:uses", "outbound:exploits", "inbound:uses"]);
    expect(groups[0].label).toBe("uses");
    expect(groups[2].label).toBe("used by");
    // corroborated outranks signal despite lower strength score
    expect(groups[0].rows.map((r) => r.label)).toEqual(["corroborated-row", "signal-row"]);
  });
});

describe("evidence structure", () => {
  const row = (over: Partial<EntitySearchResult>): RelRow => ({
    type: "malware",
    item: item(over),
    label: "X",
  });
  const structured = (
    shape: "recurring" | "single_story" | "scattered" | "thin",
    stories: Array<Record<string, unknown>> = [],
  ) => ({ evidence_structure: { shape, stories, loose: 0, sampled: 5 } }) as unknown as Partial<EntitySearchResult>;

  it("phrases recurring evidence with a bold lead and the incident count", () => {
    const es = structured("recurring", [
      { entries: 2, entry_ids: [], first: "2026-01-01", last: "2026-01-05", slug: null, title: null },
      { entries: 3, entry_ids: [], first: "2026-07-01", last: "2026-07-09", slug: null, title: null },
    ]);
    expect(structurePhrase(item(es))).toEqual({ lead: "recurring", rest: "— 2 incidents over 6 months" });
  });

  it("phrases a single story by its thread title and outlet count", () => {
    const titled = structured("single_story", [
      { entries: 6, entry_ids: [], sources: 6, first: null, last: null, slug: "zimbra", title: "Zimbra webmail intrusion" },
    ]);
    expect(structurePhrase(item(titled))).toEqual({
      lead: "one story",
      rest: "— “Zimbra webmail intrusion” · 6 outlets",
    });
    const wave = structured("single_story", [
      { entries: 10, entry_ids: [], sources: 16, first: null, last: null, slug: null, title: null },
    ]);
    expect(structurePhrase(item(wave))).toEqual({ lead: "one story", rest: "— a single 16-outlet wave" });
    const untitled = structured("single_story", [
      { entries: 2, entry_ids: [], first: null, last: null, slug: null, title: null },
    ]);
    expect(structurePhrase(item(untitled))).toEqual({ lead: "one story", rest: "· 2 of 5 articles" });
  });

  it("says scattered plainly and stays silent on thin and missing", () => {
    expect(structurePhrase(item(structured("scattered")))).toEqual({
      lead: "no shared story",
      rest: "— scattered co-mentions",
    });
    expect(structurePhrase(item(structured("thin")))).toBeNull();
    expect(structurePhrase(item({}))).toBeNull();
  });

  it("earns rows for story-backed shapes and folds the rest", () => {
    const ev = [{ entry_id: "e1", score: 0.9 }];
    expect(isEarnedRow(row({ ...structured("recurring"), proximity_entries: ev }))).toBe(true);
    expect(isEarnedRow(row({ ...structured("single_story"), proximity_entries: ev }))).toBe(true);
    expect(isEarnedRow(row({ ...structured("scattered"), proximity_entries: ev }))).toBe(false);
    expect(isEarnedRow(row({ ...structured("thin"), proximity_entries: ev }))).toBe(false);
  });

  it("keeps corroborated rows and pure claims visible regardless of shape", () => {
    const corroborated = row({
      ...structured("scattered"),
      relationship_id: "r1",
      relationship_confidence: "confirmed",
      relationship_source: "external_feed",
      proximity_entries: [{ entry_id: "e1", score: 0.9 }],
    });
    expect(isEarnedRow(corroborated)).toBe(true);
    // MITRE / manual claims have no co-occurrence evidence at all.
    expect(isEarnedRow(row({ relationship_id: "r2", relationship_confidence: "probable" }))).toBe(true);
  });

  it("falls back to article counts when no structure is available", () => {
    const one = row({ proximity_entries: [{ entry_id: "e1", score: 0.9 }] });
    const two = row({ proximity_entries: [{ entry_id: "e1", score: 0.9 }, { entry_id: "e2", score: 0.5 }] });
    expect(isEarnedRow(one)).toBe(false);
    expect(isEarnedRow(two)).toBe(true);
  });

  it("partitions in order", () => {
    const a = row({ ...structured("recurring"), proximity_entries: [{ entry_id: "e", score: 1 }] });
    const b = row({ ...structured("thin"), proximity_entries: [{ entry_id: "e", score: 1 }] });
    const { earned, folded } = partitionEarned([a, b]);
    expect(earned).toEqual([a]);
    expect(folded).toEqual([b]);
  });
});

describe("isImplausibleCveId", () => {
  it("flags junk years and runaway sequences", () => {
    expect(isImplausibleCveId("CVE-2026-5972610")).toBe(true); // 7-digit modern sequence
    expect(isImplausibleCveId("CVE-2026-203165")).toBe(true); // modern-era sequence past MITRE's range
    expect(isImplausibleCveId("CVE-1901-1234")).toBe(true); // pre-CVE year
  });
  it("passes real ids, including DWF-era long sequences", () => {
    expect(isImplausibleCveId("CVE-2026-42897")).toBe(false);
    expect(isImplausibleCveId("CVE-2019-1010218")).toBe(false); // DWF block, legitimately 7 digits
    expect(isImplausibleCveId("not a cve")).toBe(false);
  });
});

describe("isEverydaySoftware", () => {
  const toolRow = (over: Partial<EntitySearchResult>): RelRow => ({
    type: "tool",
    item: item(over),
    label: "GitHub",
  });
  const strength = (specificity: number | null) =>
    ({ score: 0.4, tier: "moderate", closeness: 0.5, specificity, articles: 5, sources: 4, first_seen: null, last_seen: null, trend: [] }) as EntitySearchResult["strength"];

  it("folds low-specificity tools", () => {
    expect(isEverydaySoftware(toolRow({ strength: strength(0.2) }))).toBe(true);
  });
  it("keeps specific tools, corroborated edges, and recurring tradecraft", () => {
    expect(isEverydaySoftware(toolRow({ strength: strength(0.8) }))).toBe(false);
    expect(
      isEverydaySoftware(
        toolRow({ strength: strength(0.2), relationship_id: "r", relationship_confidence: "confirmed" }),
      ),
    ).toBe(false);
    expect(
      isEverydaySoftware(
        toolRow({
          strength: strength(0.2),
          evidence_structure: { shape: "recurring", stories: [], loose: 0, sampled: 5 },
        }),
      ),
    ).toBe(false);
  });
  it("never touches non-tool rows", () => {
    expect(isEverydaySoftware({ type: "vendor", item: item({ strength: strength(0.1) }), label: "Microsoft" })).toBe(false);
  });
});

describe("buildStoryMap", () => {
  const structuredRow = (
    id: string,
    type: RelRow["type"],
    stories: Array<{ ids: string[]; slug?: string; title?: string }>,
  ): RelRow => ({
    type,
    label: id,
    item: item({
      id,
      relationship_id: `rel-${id}`,
      relationship_confidence: "probable",
      evidence_structure: {
        shape: stories.length >= 2 ? "recurring" : "single_story",
        stories: stories.map((s) => ({
          entries: s.ids.length,
          entry_ids: s.ids,
          first: "2026-06-01",
          last: "2026-06-09",
          slug: s.slug ?? null,
          title: s.title ?? null,
        })),
        loose: 0,
        sampled: 5,
      },
    }),
  });

  it("merges overlapping stories from different rows into one cluster", () => {
    const a = structuredRow("zimbra", "tool", [{ ids: ["e1", "e2"], title: "Zimbra intrusion" }]);
    const b = structuredRow("zimreaper", "malware", [{ ids: ["e2", "e3"] }]);
    const c = structuredRow("elsewhere", "cve", [{ ids: ["e9"] }]);
    const clusters = buildStoryMap([a, b, c]);
    expect(clusters).toHaveLength(2);
    expect(clusters[0].title).toBe("Zimbra intrusion");
    expect(clusters[0].members).toHaveLength(2);
    expect(clusters[0].entryIds.sort()).toEqual(["e1", "e2", "e3"]);
  });

  it("assigns a multi-story entity to its strongest cluster only", () => {
    const wide = structuredRow("actor-tool", "tool", [
      { ids: ["a1", "a2", "a3"] },
      { ids: ["b1"] },
    ]);
    const other = structuredRow("other", "malware", [{ ids: ["b1", "b2"] }]);
    const clusters = buildStoryMap([wide, other]);
    const home = clusters.find((c) => c.members.some((m) => m.row.label === "actor-tool"));
    expect(home?.entryIds).toContain("a1");
    const bCluster = clusters.find((c) => c.entryIds.includes("b1"));
    expect(bCluster?.members.map((m) => m.row.label)).toEqual(["other"]);
  });

  it("returns nothing without structured evidence", () => {
    expect(buildStoryMap([{ type: "tool", label: "x", item: item({}) }])).toEqual([]);
  });

  it("names untitled clusters by their newest evidence headline, never a bare 'Story'", () => {
    const row = structuredRow("zimbra", "tool", [{ ids: ["e1", "e2"] }]);
    row.item.proximity_entries = [
      { entry_id: "e1", title: "Old headline", score: 0.9, published_at: "2026-06-01" },
      { entry_id: "e2", title: "Trezor Says ShipMonk Breach Exposed 67,000 Customers", score: 0.8, published_at: "2026-06-09" },
    ];
    const clusters = buildStoryMap([row]);
    expect(clusters[0].headline).toBe("Trezor Says ShipMonk Breach Exposed 67,000 Customers");
    expect(clusterHeading(clusters[0])).toContain("Trezor");
  });
});

describe("observable endpoints (issue #1)", () => {
  it("offers the matrix verbs for actor/malware/tool/campaign → observable and reads controls", () => {
    expect(allowedVerbsForPair("threat_actor", "observable")).toEqual(["uses", "communicates_with", "controls"]);
    expect(allowedVerbsForPair("malware", "observable")).toEqual(["uses", "communicates_with"]);
    expect(allowedVerbsForPair("campaign", "observable")).toEqual(["uses"]);
    // The one observable-first triple: a host exposes a CVE (Shodan InternetDB).
    expect(allowedVerbsForPair("observable", "cve")).toEqual(["exposes"]);
    expect(allowedVerbsForPair("vendor", "sector")).toEqual(["operates_in"]);
    expect(verbChipLabel(item({ relationship_type: "controls", relationship_direction: "outbound" }))).toBe("controls");
    expect(verbChipLabel(item({ relationship_type: "controls", relationship_direction: "inbound" }))).toBe("controlled by");
  });
});
