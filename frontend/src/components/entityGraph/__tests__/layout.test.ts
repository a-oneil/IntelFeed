import { describe, expect, it } from "vitest";
import { computeNetworkLayout, computeStoryLayout, type LayoutEdge, type LayoutNode } from "../layout";

const seed: LayoutNode = { id: "threat_actor-seed", type: "threat_actor", label: "APT29", size: 10 };

function fan(n: number, type = "malware"): LayoutNode[] {
  return Array.from({ length: n }, (_, i) => ({ id: `${type}-${i}`, type, label: `${type} number ${i}`, size: (i % 5) + 1 }));
}

function spokes(nodes: LayoutNode[]): LayoutEdge[] {
  return nodes.map((n) => ({ source: seed.id, target: n.id, weight: 1, label: "uses" }));
}

const base = {
  seedId: seed.id,
  hiddenTypes: new Set<string>(),
  hiddenNodes: new Set<string>(),
  spacing: 1,
  labels: true,
};

describe("computeStoryLayout", () => {
  const members = fan(30);
  const clusters = Array.from({ length: 6 }, (_, i) => ({
    id: `c${i}`,
    heading: `Story ${i}`,
    corroborated: i % 2 === 0,
    articles: 3,
    nodeIds: members.slice(i * 5, i * 5 + 5 + (i === 0 ? 3 : 0)).map((n) => n.id),
  }));
  const run = () =>
    computeStoryLayout({
      ...base,
      nodes: [seed, ...members],
      edges: spokes(members),
      clusters,
      expandedGhostTypes: new Set(),
    })!;

  it("places every story in its own box with no two boxes overlapping", () => {
    const { groups } = run();
    expect(groups).toHaveLength(6);
    for (let i = 0; i < groups.length; i++) {
      for (let j = i + 1; j < groups.length; j++) {
        const a = groups[i];
        const b = groups[j];
        const apart = a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y;
        expect(apart, `${a.cluster.id} overlaps ${b.cluster.id}`).toBe(true);
      }
    }
  });

  it("puts each member inside its box, and a node shared by two stories only in the first", () => {
    const { groups, positions, memberOf } = run();
    for (const g of groups) {
      for (const id of g.members) {
        const p = positions.get(id)!;
        expect(p.x).toBeGreaterThan(g.x);
        expect(p.x).toBeLessThan(g.x + g.w);
        expect(p.y).toBeGreaterThan(g.y);
        expect(p.y).toBeLessThan(g.y + g.h);
      }
    }
    // malware-5..7 are listed by c0 and c1; c0 claims them.
    expect(memberOf.get("malware-5")).toBe("c0");
    expect(groups[1].members).not.toContain("malware-5");
  });

  it("is deterministic", () => {
    const a = run();
    const b = run();
    expect([...a.positions]).toEqual([...b.positions]);
  });

  it("collapses story-less nodes into one pill per type until shown", () => {
    const loose = fan(4, "tool");
    const input = {
      ...base,
      nodes: [seed, ...members, ...loose],
      edges: spokes([...members, ...loose]),
      clusters,
      expandedGhostTypes: new Set<string>(),
    };
    const hidden = computeStoryLayout(input)!;
    expect(hidden.ghosts).toEqual([{ type: "tool", count: 4, mitre: false, expanded: false }]);
    expect(hidden.positions.has("tool-0")).toBe(false);

    const shown = computeStoryLayout({ ...input, expandedGhostTypes: new Set(["tool"]) })!;
    expect(shown.positions.has("tool-0")).toBe(true);
  });
});

describe("computeNetworkLayout", () => {
  it("pins the seed at the origin and keeps node bodies apart", () => {
    const nodes = [seed, ...fan(12), ...fan(12, "ttp")];
    const { positions } = computeNetworkLayout({ ...base, nodes, edges: spokes(nodes.slice(1)), nodesPerType: 20 });
    expect(positions.get(seed.id)).toEqual({ x: 0, y: 0 });
    const pts = [...positions.values()];
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        expect(Math.hypot(pts[i].x - pts[j].x, pts[i].y - pts[j].y)).toBeGreaterThan(30);
      }
    }
  });

  it("caps nodes per type, keeping the biggest, and reports the rest as overflow", () => {
    const nodes = [seed, ...fan(10)];
    const { positions, overflow } = computeNetworkLayout({ ...base, nodes, edges: spokes(nodes.slice(1)), nodesPerType: 3 });
    expect(positions.size).toBe(4);
    expect(overflow.get("malware")).toBe(7);
    // size cycles 1..5 — the three kept nodes are size 5, 5 and 4.
    expect(positions.has("malware-4")).toBe(true);
    expect(positions.has("malware-9")).toBe(true);
  });

  it("never caps nodes from an expansion", () => {
    const nodes = [seed, ...fan(10)];
    const { positions } = computeNetworkLayout({
      ...base,
      nodes,
      edges: spokes(nodes.slice(1)),
      nodesPerType: 1,
      capExempt: new Set(["malware-0", "malware-1"]),
    });
    expect(positions.has("malware-0")).toBe(true);
    expect(positions.has("malware-1")).toBe(true);
  });
});
