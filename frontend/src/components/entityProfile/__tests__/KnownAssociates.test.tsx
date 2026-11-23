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
    // No claim rows — co-mentions stay in the tab — but a way in remains,
    // because the tab count is otherwise the only entry point.
    expect(screen.getByText(/None confirmed yet/)).toBeInTheDocument();
    const link = screen.getByRole("button", { name: /See all 2 related entities/ });
    fireEvent.click(link);
    expect(onTab).toHaveBeenCalled();
  });

  it("shows asserted claims under their verb, corroborated first", () => {
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

    const names = screen.getAllByRole("button");
    expect(names.map((b) => b.textContent)).toEqual(["Sandworm Wiper", "Chaos Ransomware"]);
    expect(names[0]).toHaveAttribute("title", expect.stringMatching(/Confirmed by MITRE ATT&CK/));
    // One row for the shared verb, keyed by it, with no source tag.
    expect(screen.getAllByText("Uses")).toHaveLength(1);
    expect(screen.queryByText("MITRE")).toBeNull();
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
    // Every claim filtered → no claim rows; only the escape-hatch link remains.
    expect(screen.queryByText(/^(Uses|Exploits)$/)).toBeNull();
    expect(screen.getByRole("button", { name: /related entities/ })).toBeInTheDocument();
  });

  it("caps one entity type at four names so the rows are not all techniques", () => {
    const mitre = (over: Partial<EntitySearchResult>) =>
      item({
        relationship_type: "uses",
        relationship_direction: "outbound",
        relationship_confidence: "confirmed",
        relationship_source: "external_feed",
        ...over,
      });
    renderStrip({
      ttps: Array.from({ length: 20 }, (_, i) =>
        mitre({ id: `tt${i}`, technique_id: `T1${100 + i}`, technique_name: `Technique ${i}`, relationship_id: `rt${i}` }),
      ),
      malwares: [
        mitre({ id: "m1", name: "Chaos Ransomware", relationship_id: "rm1" }),
        mitre({ id: "m2", name: "NotPetya", relationship_id: "rm2" }),
      ],
      tools: [mitre({ id: "t1", name: "Impacket", relationship_id: "rt9" })],
    } as never);
    // Twenty techniques outrank the rest, but the cap keeps room for the other
    // types: 12 names, 3 of them not techniques.
    expect(screen.getAllByText(/^T1\d{3} Technique /)).toHaveLength(9);
    expect(screen.getByText("Chaos Ransomware")).toBeTruthy();
    expect(screen.getByText("Impacket")).toBeTruthy();
  });

  it("links the overflow chip to the relationships tab", () => {
    const onTab = vi.fn();
    const many = Array.from({ length: 14 }, (_, i) =>
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
    const more = screen.getByText(/See all 14 relationships/);
    fireEvent.click(more);
    expect(onTab).toHaveBeenCalled();
  });

  it("renders one labelled row per verb", () => {
    render(
      <KnownAssociates
        entityType="threat_actor"
        entityLabel="APT28"
        related={
          {
            malwares: [
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
            sectors: [
              item({
                id: "s1",
                name: "Energy",
                relationship_id: "r6",
                relationship_type: "targets",
                relationship_direction: "outbound",
                relationship_confidence: "confirmed",
                relationship_source: "external_feed",
              }),
            ],
          } as never
        }
        onOpenEntity={vi.fn()}
        onShowRelationships={vi.fn()}
      />,
    );
    expect(screen.getByText("Uses").parentElement).toHaveTextContent("Sandworm Wiper");
    expect(screen.getByText("Targets").parentElement).toHaveTextContent("Energy");
  });
});
