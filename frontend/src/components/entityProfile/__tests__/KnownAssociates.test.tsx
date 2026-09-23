import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import type { EntitySearchResult, PivotResponse } from "@/api/types";
import { KnownAssociates } from "../KnownAssociates";

const strength = (articles: number, specificity = 0.9) => ({
  score: 0.6,
  tier: "strong" as const,
  closeness: 0.8,
  articles,
  sources: 3,
  specificity,
  first_seen: "2026-01-01",
  last_seen: "2026-06-30",
  trend: [1, 1, 1],
});

const entries = (n: number) =>
  Array.from({ length: n }, (_, i) => ({
    entry_id: `e${i}`,
    title: `article ${i}`,
    score: 0.8,
    published_at: "2026-06-30",
  }));

function item(over: Partial<EntitySearchResult>): EntitySearchResult {
  return {
    id: "x",
    name: "X",
    proximity_score: 0.5,
    strength: strength(4),
    proximity_entries: entries(4),
    ...over,
  } as EntitySearchResult;
}

/** A co-mention with no typed relationship — the kind that used to rank STRONG. */
const coMention = (id: string, name: string) =>
  item({ id, name, strength: strength(40), proximity_entries: entries(40) });

const renderStrip = (related: Partial<PivotResponse["related"]>, onOpen = vi.fn(), onTab = vi.fn()) =>
  render(
    <KnownAssociates
      entityType="threat_actor"
      entityLabel="APT28"
      related={related as PivotResponse["related"]}
      onOpenEntity={onOpen}
      onShowRelationships={onTab}
    />,
  );

describe("KnownAssociates", () => {
  it("shows only the relationships escape hatch when only co-mentions exist", () => {
    const onTab = vi.fn();
    renderStrip(
      {
        vendors: [coMention("v1", "Microsoft Intune")],
        countrys: [coMention("c1", "Palestine")],
      } as never,
      vi.fn(),
      onTab,
    );
    // No chips — co-mentions stay in the tab — but the strip still offers a
    // way in, because the tab count is otherwise the only entry point.
    expect(screen.getByText("No corroborated claims yet")).toBeInTheDocument();
    const link = screen.getByRole("button", { name: /all 2 related entities/ });
    fireEvent.click(link);
    expect(onTab).toHaveBeenCalled();
  });

  it("shows asserted claims as verb + entity, corroborated first", () => {
    renderStrip({
      malwares: [
        item({
          id: "m1",
          name: "Chaos Ransomware",
          relationship_id: "r1",
          relationship_type: "uses",
          relationship_direction: "outbound",
          relationship_confidence: "probable",
          evidence_structure: { sampled: 6, loose: 0, shape: "single_story", stories: [{ entries: 4, sources: 2, first: null, last: null, slug: null, title: null, entry_ids: ["e0"] }] },
        }),
        item({
          id: "m2",
          name: "Sandworm Wiper",
          relationship_id: "r2",
          relationship_type: "uses",
          relationship_direction: "outbound",
          relationship_confidence: "confirmed",
          relationship_source: "external_feed",
        }),
      ],
    } as never);

    const chips = screen.getAllByRole("button");
    expect(chips[0]).toHaveTextContent("Sandworm Wiper");
    expect(chips[0]).toHaveTextContent("MITRE");
    expect(chips[1]).toHaveTextContent("uses");
    expect(chips[1]).toHaveTextContent("Chaos Ransomware");
    // The old co-mention strength words are gone.
    expect(screen.queryByText(/STRONG/i)).toBeNull();
  });

  it("drops story-less claims, junk CVE ids and everyday software", () => {
    renderStrip({
      cves: [
        item({
          id: "cv1",
          cve_id: "CVE-2026-9999999",
          relationship_id: "r3",
          relationship_type: "exploits",
          relationship_direction: "outbound",
          relationship_confidence: "probable",
          evidence_structure: { sampled: 4, loose: 0, shape: "recurring", stories: [] },
        }),
      ],
      tools: [
        item({
          id: "t1",
          name: "GitHub",
          strength: strength(20, 0.2),
          relationship_id: "r4",
          relationship_type: "uses",
          relationship_direction: "outbound",
          relationship_confidence: "probable",
        }),
      ],
      ttps: [
        item({
          id: "tt1",
          technique_id: "T1059",
          technique_name: "Command and Scripting",
          strength: strength(1),
          proximity_entries: entries(1),
          relationship_id: "r5",
          relationship_type: "uses",
          relationship_direction: "outbound",
          relationship_confidence: "probable",
          evidence_structure: { sampled: 1, loose: 0, shape: "thin", stories: [] },
        }),
      ],
    } as never);
    // Every claim filtered → no chips; only the escape-hatch link remains.
    expect(screen.queryByText(/uses|exploits/)).toBeNull();
    expect(screen.getByRole("button", { name: /related entities/ })).toBeInTheDocument();
  });

  it("caps one entity type at two chips so the strip is not all techniques", () => {
    const mitre = (over: Partial<EntitySearchResult>) =>
      item({
        relationship_type: "uses",
        relationship_direction: "outbound",
        relationship_confidence: "confirmed",
        relationship_source: "external_feed",
        ...over,
      });
    renderStrip({
      ttps: Array.from({ length: 6 }, (_, i) =>
        mitre({ id: `tt${i}`, technique_id: `T10${i}`, technique_name: `Technique ${i}`, relationship_id: `rt${i}` }),
      ),
      malwares: [
        mitre({ id: "m1", name: "Chaos Ransomware", relationship_id: "rm1" }),
        mitre({ id: "m2", name: "NotPetya", relationship_id: "rm2" }),
      ],
      tools: [mitre({ id: "t1", name: "Impacket", relationship_id: "rt9" })],
    } as never);
    // Techniques are capped even though six of them outrank the rest.
    expect(screen.getAllByText(/^T10\d Technique /)).toHaveLength(2);
    expect(screen.getByText("Chaos Ransomware")).toBeTruthy();
    expect(screen.getByText("Impacket")).toBeTruthy();
    // Every chip is MITRE-corroborated → the badge is said once in the title.
    expect(screen.queryByText("MITRE")).toBeNull();
    expect(screen.getByText(/all corroborated by MITRE/)).toBeTruthy();
  });

  it("links the overflow chip to the relationships tab", () => {
    const onTab = vi.fn();
    const many = Array.from({ length: 7 }, (_, i) =>
      item({
        id: `m${i}`,
        name: `Malware ${i}`,
        relationship_id: `r${i}`,
        relationship_type: "uses",
        relationship_direction: "outbound",
        relationship_confidence: "probable",
      }),
    );
    renderStrip({ malwares: many } as never, vi.fn(), onTab);
    const more = screen.getByText(/all 7 claims/);
    fireEvent.click(more);
    expect(onTab).toHaveBeenCalled();
  });
});
