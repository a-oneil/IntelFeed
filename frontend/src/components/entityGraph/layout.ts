/**
 * Layout engine for the entity graph.
 *
 * Two layouts, both run d3-force to a settled state synchronously (no
 * animation) with collision forces, so nodes, labels and story boxes never
 * overlap:
 *
 * - Story: each story cluster is a box with its members in a grid inside it.
 *   The seed, the boxes and any story-less nodes the user chose to show are
 *   then spread around the seed by the force simulation.
 * - Network: every visible node is a body in the simulation, pulled together
 *   along edges, with the seed pinned at the origin. Nodes per type are
 *   capped; the rest are reported as overflow.
 *
 * Positions are centers in graph coordinates. A previous layout can be passed
 * in so nodes that were already on screen start where they were, which keeps
 * the picture stable when an expansion adds nodes.
 *
 * Pure functions: no React, no DOM, deterministic for the same input.
 */
import {
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force';

// ── Types ──────────────────────────────────────────────────────────

export interface LayoutNode {
  id: string;
  type: string;
  label: string;
  size: number;
  /** Serialized entity payload from the graph endpoint (technique_id,
   * cve_id, …) — carried through for inspector lookups, unused by layout. */
  data?: unknown;
}

export interface LayoutEdge {
  source: string;
  target: string;
  weight: number;
  label: string;
  proximity_score?: number | null;
  confidence?: string | null;
  provenance?: string | null;
  relationship_id?: string | null;
  entries?: Array<{ entry_id: string; title: string; score: number }>;
}

/** A story (incident) grouping for the story layout — nodeIds in graph id
 * format (`${type}-${id}`). Supplied by the relationships tab from the
 * pivot's evidence structure. */
export interface GraphStoryCluster {
  id: string;
  heading: string;
  corroborated: boolean;
  articles: number;
  nodeIds: string[];
  /** Story-thread slug when threading has named this incident. */
  slug?: string | null;
  /** True for clusters belonging to an EXPANDED node — their members aren't
   * rows in the viewed profile's list, so "filter list" doesn't apply. */
  external?: boolean;
}

export interface Point {
  x: number;
  y: number;
}

export interface PlacedGroup {
  cluster: GraphStoryCluster;
  /** Top-left corner, graph coordinates. */
  x: number;
  y: number;
  w: number;
  h: number;
  members: string[];
}

export interface GhostType {
  type: string;
  count: number;
  /** Every node of this type is an external-feed (MITRE) claim. */
  mitre: boolean;
  expanded: boolean;
}

export interface StoryLayout {
  /** Node centers, graph coordinates. */
  positions: Map<string, Point>;
  groups: PlacedGroup[];
  /** nodeId → cluster id for nodes placed inside a story box. */
  memberOf: Map<string, string>;
  /** Story-less nodes, one entry per type. */
  ghosts: GhostType[];
}

export interface NetworkLayout {
  positions: Map<string, Point>;
  /** type → number of nodes left out by the per-type cap. */
  overflow: Map<string, number>;
}

// ── Sizes ──────────────────────────────────────────────────────────

/** Radius of a node's shape. Articles are smaller than entities. */
export function nodeRadius(node: LayoutNode, isSeed = false): number {
  const r = node.type === 'entry'
    ? Math.max(5, Math.min(12, node.size * 2 + 2))
    : Math.max(8, Math.min(18, node.size * 2 + 6));
  return isSeed ? r + 4 : r;
}

/** Collision radius: the shape plus room for the label under it. */
function bodyRadius(node: LayoutNode, isSeed: boolean, labels: boolean): number {
  const r = nodeRadius(node, isSeed);
  if (!labels) return r + 10;
  const chars = Math.min(node.label.length, node.type === 'entry' ? 28 : 20);
  return Math.max(r + 16, chars * 3.4);
}

// Story box geometry.
const CELL_W = 128;
const CELL_H = 68;
const BOX_PAD = 14;
const BOX_HEADER = 42;
const MAX_STORIES = 8;

// ── Simulation ─────────────────────────────────────────────────────

interface Body extends SimulationNodeDatum {
  id: string;
  r: number;
}

const TICKS = 300;

function settle(
  bodies: Body[],
  links: Array<SimulationLinkDatum<Body> & { distance: number }>,
  charge: number,
): void {
  const sim = forceSimulation(bodies)
    .force(
      'link',
      forceLink<Body, SimulationLinkDatum<Body> & { distance: number }>(links)
        .id((b) => b.id)
        .distance((l) => l.distance),
    )
    .force('charge', forceManyBody<Body>().strength(charge))
    .force('collide', forceCollide<Body>((b) => b.r).strength(1).iterations(3))
    // Weak centering keeps nodes with no edges from drifting off.
    .force('x', forceX<Body>(0).strength(0.03))
    .force('y', forceY<Body>(0).strength(0.03))
    .stop();
  for (let i = 0; i < TICKS; i++) sim.tick();
}

/** Start position for a body: where it was last time, or a spot on a circle
 * around the seed. The circle spot is index-based so output is deterministic. */
function startAt(id: string, i: number, n: number, radius: number, previous?: Map<string, Point>): Point {
  const prev = previous?.get(id);
  if (prev) return { x: prev.x, y: prev.y };
  const a = -Math.PI / 2 + (i * 2 * Math.PI) / Math.max(n, 1);
  return { x: radius * Math.cos(a), y: radius * Math.sin(a) };
}

// ── Story layout ───────────────────────────────────────────────────

export interface StoryLayoutInput {
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  clusters: GraphStoryCluster[];
  seedId: string;
  hiddenTypes: Set<string>;
  hiddenNodes: Set<string>;
  /** Story-less types the user chose to show on the graph. */
  expandedGhostTypes: Set<string>;
  /** Nodes brought in by expanding another node → the node expanded. They
   * are always drawn, next to that node, never pooled into a type pill. */
  anchorOf?: Map<string, string>;
  /** Story clusters from an expansion → the node expanded. They sit next
   * to that node and don't count toward the story cap. */
  clusterAnchor?: Map<string, string>;
  /** Spacing multiplier, 0.5–8. */
  spacing: number;
  labels: boolean;
  previous?: Map<string, Point>;
}

export function computeStoryLayout(input: StoryLayoutInput): StoryLayout | null {
  const {
    nodes, edges, clusters, seedId, hiddenTypes, hiddenNodes, expandedGhostTypes,
    anchorOf = new Map(), clusterAnchor = new Map(), spacing, labels, previous,
  } = input;
  if (clusters.length === 0) return null;

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const visible = (id: string) => {
    const n = byId.get(id);
    return !!n && !hiddenTypes.has(n.type) && !hiddenNodes.has(id);
  };

  // Members per story; a node sits in the first story that claims it.
  const claimed = new Set<string>();
  const boxes: Array<{ cluster: GraphStoryCluster; members: string[]; w: number; h: number; cols: number }> = [];
  const shownClusters = [
    ...clusters.filter((c) => !clusterAnchor.has(c.id)).slice(0, MAX_STORIES),
    ...clusters.filter((c) => clusterAnchor.has(c.id)),
  ];
  for (const cluster of shownClusters) {
    const members = cluster.nodeIds.filter((id) => id !== seedId && visible(id) && !claimed.has(id));
    if (members.length === 0) continue;
    members.forEach((id) => claimed.add(id));
    // Wider than tall: story titles run horizontally.
    const cols = Math.min(members.length, Math.max(2, Math.ceil(Math.sqrt(members.length * 1.6))));
    const rows = Math.ceil(members.length / cols);
    boxes.push({
      cluster,
      members,
      cols,
      w: Math.max(cols * CELL_W, 220) + BOX_PAD * 2,
      h: rows * CELL_H + BOX_PAD * 2 + BOX_HEADER,
    });
  }

  // Story-less nodes: one ghost entry per type; shown types get laid out
  // as free bodies.
  const provenance = new Map<string, string | null | undefined>();
  for (const e of edges) {
    if (e.source === seedId) provenance.set(e.target, e.provenance);
    else if (e.target === seedId) provenance.set(e.source, e.provenance);
  }
  const unclaimed = nodes.filter((n) => n.id !== seedId && visible(n.id) && !claimed.has(n.id));
  const rest = unclaimed.filter((n) => !anchorOf.has(n.id));
  const byType = new Map<string, string[]>();
  for (const n of rest) (byType.get(n.type) ?? byType.set(n.type, []).get(n.type)!).push(n.id);
  const ghosts: GhostType[] = [...byType.entries()].map(([type, ids]) => ({
    type,
    count: ids.length,
    mitre: ids.every((id) => provenance.get(id) === 'external_feed'),
    expanded: expandedGhostTypes.has(type),
  }));
  const loose = [...rest.filter((n) => expandedGhostTypes.has(n.type)), ...unclaimed.filter((n) => anchorOf.has(n.id))];

  // Bodies: seed pinned at the origin, one per box, one per loose node.
  const seed = byId.get(seedId);
  const seedR = seed ? bodyRadius(seed, true, labels) : 30;
  const gap = 24 * spacing;
  const total = boxes.length + loose.length;
  const ring = 260 * spacing;
  const bodies: Body[] = [{ id: seedId, r: seedR, x: 0, y: 0, fx: 0, fy: 0 }];
  boxes.forEach((b, i) => {
    const key = `story:${b.cluster.id}`;
    const r = Math.hypot(b.w, b.h) / 2 + gap / 2;
    bodies.push({ id: key, r, ...startAt(key, i, total, ring + r, previous) });
  });
  loose.forEach((n, j) => {
    bodies.push({ id: n.id, r: bodyRadius(n, false, labels) + gap / 4, ...startAt(n.id, boxes.length + j, total, ring * 1.6, previous) });
  });
  // Each body hangs off the seed, except what an expansion brought in: that
  // hangs off the expanded node (its story box when it sits in one).
  const boxOf = new Map<string, string>();
  for (const b of boxes) for (const id of b.members) boxOf.set(id, `story:${b.cluster.id}`);
  const bodyById = new Map(bodies.map((b) => [b.id, b]));
  const bodyFor = (nodeId: string | undefined): Body => {
    if (!nodeId) return bodies[0];
    return bodyById.get(boxOf.get(nodeId) ?? nodeId) ?? bodies[0];
  };
  const parentOf = (b: Body): Body => {
    const anchor = b.id.startsWith('story:') ? clusterAnchor.get(b.id.slice(6)) : anchorOf.get(b.id);
    const parent = bodyFor(anchor);
    return parent === b ? bodies[0] : parent;
  };
  const links = bodies.slice(1).map((b) => {
    const parent = parentOf(b);
    return { source: parent.id, target: b.id, distance: parent.r + b.r + gap };
  });
  // New expansion bodies start beside their parent rather than on the far ring.
  bodies.slice(1).forEach((b, i) => {
    const parent = parentOf(b);
    if (parent === bodies[0] || previous?.has(b.id)) return;
    const a = (i * 2.4) % (2 * Math.PI);
    b.x = (parent.x ?? 0) + (parent.r + b.r) * Math.cos(a);
    b.y = (parent.y ?? 0) + (parent.r + b.r) * Math.sin(a);
  });
  if (seed) settle(bodies, links, -120);

  const positions = new Map<string, Point>();
  const memberOf = new Map<string, string>();
  const groups: PlacedGroup[] = [];
  const at = new Map(bodies.map((b) => [b.id, { x: b.x ?? 0, y: b.y ?? 0 }]));
  if (seed) positions.set(seedId, { x: 0, y: 0 });

  for (const b of boxes) {
    const c = at.get(`story:${b.cluster.id}`) ?? { x: 0, y: 0 };
    const gx = c.x - b.w / 2;
    const gy = c.y - b.h / 2;
    groups.push({ cluster: b.cluster, x: gx, y: gy, w: b.w, h: b.h, members: b.members });
    // Center the last row when it is short.
    const rows = Math.ceil(b.members.length / b.cols);
    b.members.forEach((id, k) => {
      const row = Math.floor(k / b.cols);
      const inRow = row === rows - 1 ? b.members.length - row * b.cols : b.cols;
      const col = k % b.cols;
      const rowW = inRow * CELL_W;
      positions.set(id, {
        x: gx + (b.w - rowW) / 2 + col * CELL_W + CELL_W / 2,
        y: gy + BOX_HEADER + BOX_PAD + row * CELL_H + CELL_H / 2 - 10,
      });
      memberOf.set(id, b.cluster.id);
    });
  }
  for (const n of loose) positions.set(n.id, at.get(n.id) ?? { x: 0, y: 0 });

  return { positions, groups, memberOf, ghosts };
}

// ── Network layout ─────────────────────────────────────────────────

export interface NetworkLayoutInput {
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  seedId: string;
  hiddenTypes: Set<string>;
  hiddenNodes: Set<string>;
  /** Max nodes shown per entity type. */
  nodesPerType: number;
  /** Nodes always shown regardless of the cap (e.g. from an expansion). */
  capExempt?: Set<string>;
  spacing: number;
  labels: boolean;
  previous?: Map<string, Point>;
}

export function computeNetworkLayout(input: NetworkLayoutInput): NetworkLayout {
  const { nodes, edges, seedId, hiddenTypes, hiddenNodes, nodesPerType, capExempt, spacing, labels, previous } = input;

  // Per-type cap: the biggest (most mentioned) nodes win.
  const candidates = nodes.filter((n) => !hiddenTypes.has(n.type) && !hiddenNodes.has(n.id));
  const byType = new Map<string, LayoutNode[]>();
  for (const n of candidates) {
    if (n.id === seedId || capExempt?.has(n.id)) continue;
    (byType.get(n.type) ?? byType.set(n.type, []).get(n.type)!).push(n);
  }
  const shown = new Set<string>();
  const overflow = new Map<string, number>();
  for (const n of candidates) if (n.id === seedId || capExempt?.has(n.id)) shown.add(n.id);
  for (const [type, list] of byType) {
    const sorted = [...list].sort((a, b) => b.size - a.size || a.label.localeCompare(b.label));
    sorted.slice(0, nodesPerType).forEach((n) => shown.add(n.id));
    if (sorted.length > nodesPerType) overflow.set(type, sorted.length - nodesPerType);
  }

  const visibleNodes = candidates.filter((n) => shown.has(n.id));
  const radius = new Map<string, number>();
  const bodies: Body[] = visibleNodes.map((n, i) => {
    const isSeed = n.id === seedId;
    const r = bodyRadius(n, isSeed, labels);
    radius.set(n.id, r);
    if (isSeed) return { id: n.id, r, x: 0, y: 0, fx: 0, fy: 0 };
    return { id: n.id, r, ...startAt(n.id, i, visibleNodes.length, 220 * spacing, previous) };
  });

  const seen = new Set<string>();
  const links: Array<SimulationLinkDatum<Body> & { distance: number }> = [];
  for (const e of edges) {
    if (!shown.has(e.source) || !shown.has(e.target) || e.source === e.target) continue;
    const k = [e.source, e.target].sort().join('|');
    if (seen.has(k)) continue;
    seen.add(k);
    links.push({
      source: e.source,
      target: e.target,
      distance: (radius.get(e.source) ?? 20) + (radius.get(e.target) ?? 20) + 60 * spacing,
    });
  }
  settle(bodies, links, -260 * spacing);

  const positions = new Map<string, Point>();
  for (const b of bodies) positions.set(b.id, { x: b.x ?? 0, y: b.y ?? 0 });
  return { positions, overflow };
}

// ── Shape helpers ──────────────────────────────────────────────────

/** SVG polygon points for a regular polygon centered at (x, y). */
export function polygonPoints(
  x: number, y: number, r: number, sides: number, rotation: number = -Math.PI / 2,
): string {
  const points: string[] = [];
  for (let i = 0; i < sides; i++) {
    const angle = rotation + (Math.PI * 2 * i) / sides;
    points.push(`${x + r * Math.cos(angle)},${y + r * Math.sin(angle)}`);
  }
  return points.join(' ');
}
