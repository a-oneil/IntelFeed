/**
 * Radial/concentric layout engine for the entity graph.
 *
 * Places the seed entity at the center. Direct neighbors form ring 1,
 * grouped by entity type into angular arcs. When a node is expanded,
 * its neighbors fan out as ring 2+ segments radiating from that node.
 *
 * Pure function — no React, no side effects, deterministic output.
 */

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

export interface RadialLayoutInput {
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  seedId: string;
  /** nodeId → parentId (null for seed). Only expanded nodes are keys. */
  expandedNodes: Map<string, string | null>;
  width: number;
  height: number;
  /** Max nodes per entity type per expansion ring (default 8) */
  nodesPerType: number;
  /** Multiplier for ring spacing (0.6–1.5, default 1.0) */
  ringSpacingMultiplier: number;
  /** Entity types to hide */
  hiddenTypes: Set<string>;
}

export interface NodePosition {
  x: number;
  y: number;
  ring: number;
  angle: number;
  parentId: string | null;
}

export interface ArcInfo {
  type: string;
  label: string;
  startAngle: number;
  endAngle: number;
  midAngle: number;
  /** Nodes shown in this arc */
  count: number;
  /** Total nodes available (including overflow) */
  total: number;
  ring: number;
  /** The node whose expansion created this arc (seed for ring 1) */
  expandedById: string;
}

export interface OverflowPill {
  type: string;
  count: number;
  x: number;
  y: number;
  ring: number;
  expandedById: string;
}

export interface RadialLayoutOutput {
  /** Positioned nodes (only visible ones) */
  positions: Map<string, NodePosition>;
  /** Visible node list */
  visibleNodes: LayoutNode[];
  /** Visible edge list */
  visibleEdges: LayoutEdge[];
  /** Arc metadata for rendering arc labels */
  arcs: ArcInfo[];
  /** Overflow pills for "+N more" indicators */
  overflowPills: OverflowPill[];
  /** Radii of each ring (index = ring level) */
  ringRadii: number[];
  /** Center coordinates */
  center: { x: number; y: number };
}

// ── Constants ──────────────────────────────────────────────────────

const MIN_ARC = 0.25; // ~15 degrees minimum per type arc
const START_ANGLE = -Math.PI / 2; // 12 o'clock

// ── Helpers ────────────────────────────────────────────────────────

function buildAdjacency(
  edges: LayoutEdge[],
): { neighbors: Map<string, Set<string>>; edgeWeights: Map<string, number> } {
  const neighbors = new Map<string, Set<string>>();
  const edgeWeights = new Map<string, number>();

  for (const e of edges) {
    if (!neighbors.has(e.source)) neighbors.set(e.source, new Set());
    if (!neighbors.has(e.target)) neighbors.set(e.target, new Set());
    neighbors.get(e.source)!.add(e.target);
    neighbors.get(e.target)!.add(e.source);

    // Store max weight for each node pair (for sorting)
    const key = [e.source, e.target].sort().join('|');
    const existing = edgeWeights.get(key) ?? 0;
    if (e.weight > existing) edgeWeights.set(key, e.weight);
  }

  return { neighbors, edgeWeights };
}

function getEdgeWeight(
  edgeWeights: Map<string, number>,
  a: string,
  b: string,
): number {
  return edgeWeights.get([a, b].sort().join('|')) ?? 0;
}

// allocateArcs is now inlined in the main layout loop for ring-specific arcs

// ── Main Layout Function ───────────────────────────────────────────

export function computeRadialLayout(input: RadialLayoutInput): RadialLayoutOutput {
  const {
    nodes, edges, seedId, expandedNodes, width, height,
    nodesPerType, ringSpacingMultiplier, hiddenTypes,
  } = input;

  const cx = width / 2;
  const cy = height / 2;

  const viewMin = Math.min(width, height);

  // The ring spacing multiplier controls how spread out nodes are.
  // It scales the minimum gap between nodes on a ring — higher = more space.
  const MIN_NODE_GAP_PX = 28 * ringSpacingMultiplier; // 14px at 0.5x, 28px at 1.0x, 84px at 3.0x

  const nodeMap = new Map<string, LayoutNode>();
  for (const n of nodes) nodeMap.set(n.id, n);

  const { neighbors, edgeWeights } = buildAdjacency(edges);

  const positions = new Map<string, NodePosition>();
  const visibleNodeIds = new Set<string>();
  const arcs: ArcInfo[] = [];
  const overflowPills: OverflowPill[] = [];
  const ringRadii: number[] = [0]; // ring 0 = center (radius 0)

  // ── Ring 0: Seed at center ──
  const seedNode = nodeMap.get(seedId);
  if (!seedNode) {
    return {
      positions, visibleNodes: [], visibleEdges: [], arcs,
      overflowPills, ringRadii, center: { x: cx, y: cy },
    };
  }

  positions.set(seedId, { x: cx, y: cy, ring: 0, angle: 0, parentId: null });
  visibleNodeIds.add(seedId);

  // ── Expand each node in the expansion tree ──
  // Process ring by ring (BFS order) to build outward
  const expansionQueue: Array<{ nodeId: string; ring: number; parentAngle: number; parentArc: number }> = [];

  // Seed is always the first expansion
  if (expandedNodes.has(seedId)) {
    expansionQueue.push({ nodeId: seedId, ring: 1, parentAngle: 0, parentArc: Math.PI * 2 });
  }

  // Track which nodes are already placed to avoid duplicates
  const placed = new Set<string>([seedId]);

  while (expansionQueue.length > 0) {
    const { nodeId, ring, parentAngle, parentArc } = expansionQueue.shift()!;

    // Get neighbors, excluding already-placed nodes and hidden types
    const nodeNeighbors = neighbors.get(nodeId);
    if (!nodeNeighbors) continue;

    const candidatesByType = new Map<string, LayoutNode[]>();
    for (const nid of nodeNeighbors) {
      if (placed.has(nid)) continue;
      const n = nodeMap.get(nid);
      if (!n) continue;
      if (hiddenTypes.has(n.type)) continue;

      const arr = candidatesByType.get(n.type) ?? [];
      arr.push(n);
      candidatesByType.set(n.type, arr);
    }

    if (candidatesByType.size === 0) continue;

    // Sort each type by edge weight to the expanding node (descending)
    for (const [, arr] of candidatesByType) {
      arr.sort((a, b) => getEdgeWeight(edgeWeights, nodeId, b.id) - getEdgeWeight(edgeWeights, nodeId, a.id));
    }

    // Determine which arc range this expansion gets
    let arcTotal: number;
    let arcStartAngle: number;

    if (ring === 1) {
      // Ring 1: full circle, arcs allocated proportionally
      arcTotal = Math.PI * 2;
      arcStartAngle = START_ANGLE;
    } else {
      // Ring 2+: sub-arc centered on parent's angle
      arcTotal = Math.min(parentArc * 0.75, Math.PI / 2);
      arcStartAngle = parentAngle - arcTotal / 2;
    }

    // Allocate arcs within the available arc
    const typeCounts = new Map<string, number>();
    for (const [type, arr] of candidatesByType) {
      typeCounts.set(type, Math.min(arr.length, nodesPerType));
    }

    // Custom arc allocation within the available arc
    const totalVisible = Array.from(typeCounts.values()).reduce((s, c) => s + c, 0);
    if (totalVisible === 0) continue;

    // ── Dynamic radius: scale ring size so nodes have enough angular space ──
    // Minimum radius so adjacent nodes are >= MIN_NODE_GAP_PX apart:
    //   arc_length_per_node = arcTotal * radius / totalVisible >= MIN_NODE_GAP_PX
    //   radius >= MIN_NODE_GAP_PX * totalVisible / arcTotal
    const minRadiusForGap = (MIN_NODE_GAP_PX * totalVisible) / arcTotal;
    // Floor: never smaller than 15% of viewport (keeps small graphs centered nicely)
    const minRadius = viewMin * 0.15;
    // For ring 2+, push outward from ring 1
    const ringOffset = ring > 1 ? ringRadii[ring - 1] + MIN_NODE_GAP_PX * 2 : 0;
    const radius = Math.max(minRadius + ringOffset, minRadiusForGap + ringOffset);

    // Ensure ringRadii has this level (use max if multiple expansions on same ring)
    while (ringRadii.length <= ring) ringRadii.push(radius);
    ringRadii[ring] = Math.max(ringRadii[ring], radius);

    let cursor = arcStartAngle;
    const typeEntries = Array.from(candidatesByType.entries());

    for (const [type, arr] of typeEntries) {
      const cap = nodesPerType;
      const visible = arr.slice(0, cap);
      const overflow = arr.slice(cap);
      const visibleCount = visible.length;
      const totalCount = arr.length;

      // Arc proportional to visible count
      const rawArc = Math.max(
        (visibleCount / totalVisible) * arcTotal,
        MIN_ARC * (arcTotal / (Math.PI * 2)), // scale min arc to available arc
      );
      // We'll normalize after
      const arcSpan = rawArc;

      const arcStart = cursor;
      const arcEnd = cursor + arcSpan;
      const arcMid = cursor + arcSpan / 2;

      arcs.push({
        type,
        label: type,
        startAngle: arcStart,
        endAngle: arcEnd,
        midAngle: arcMid,
        count: visibleCount,
        total: totalCount,
        ring,
        expandedById: nodeId,
      });

      // Position visible nodes evenly within arc
      for (let i = 0; i < visible.length; i++) {
        const node = visible[i];
        const angle = arcStart + arcSpan * (i + 1) / (visibleCount + 1);
        const x = cx + radius * Math.cos(angle);
        const y = cy + radius * Math.sin(angle);

        positions.set(node.id, { x, y, ring, angle, parentId: nodeId });
        visibleNodeIds.add(node.id);
        placed.add(node.id);

        // If this node is expanded, queue its children for the next ring
        if (expandedNodes.has(node.id)) {
          expansionQueue.push({
            nodeId: node.id,
            ring: ring + 1,
            parentAngle: angle,
            parentArc: arcSpan,
          });
        }
      }

      // Overflow pill position: at the end of the arc arc
      if (overflow.length > 0) {
        const pillAngle = arcEnd - arcSpan * 0.05;
        overflowPills.push({
          type,
          count: overflow.length,
          x: cx + radius * Math.cos(pillAngle),
          y: cy + radius * Math.sin(pillAngle),
          ring,
          expandedById: nodeId,
        });
      }

      cursor += arcSpan;
    }

    // Normalize: if arcs don't fill the available arc exactly, stretch them
    // This handles the proportional allocation not summing perfectly
    if (typeEntries.length > 0) {
      const actualTotal = cursor - arcStartAngle;
      if (actualTotal > 0 && Math.abs(actualTotal - arcTotal) > 0.01) {
        const scale = arcTotal / actualTotal;
        // Re-position all nodes placed in this expansion
        for (const [, arr] of typeEntries) {
          const visible = arr.slice(0, nodesPerType);
          for (const node of visible) {
            const pos = positions.get(node.id);
            if (pos && pos.ring === ring && pos.parentId === nodeId) {
              const relAngle = pos.angle - arcStartAngle;
              const newAngle = arcStartAngle + relAngle * scale;
              pos.angle = newAngle;
              pos.x = cx + radius * Math.cos(newAngle);
              pos.y = cy + radius * Math.sin(newAngle);
            }
          }
        }
        // Re-position overflow pills
        for (const pill of overflowPills) {
          if (pill.ring === ring && pill.expandedById === nodeId) {
            const relX = pill.x - cx;
            const relY = pill.y - cy;
            const oldAngle = Math.atan2(relY, relX);
            const relAngle = oldAngle - arcStartAngle;
            const newAngle = arcStartAngle + relAngle * scale;
            pill.x = cx + radius * Math.cos(newAngle);
            pill.y = cy + radius * Math.sin(newAngle);
          }
        }
        // Re-compute arc angles
        for (const s of arcs) {
          if (s.ring === ring && s.expandedById === nodeId) {
            const relStart = s.startAngle - arcStartAngle;
            const relEnd = s.endAngle - arcStartAngle;
            s.startAngle = arcStartAngle + relStart * scale;
            s.endAngle = arcStartAngle + relEnd * scale;
            s.midAngle = (s.startAngle + s.endAngle) / 2;
          }
        }
      }
    }
  }

  // ── Collect visible nodes and edges ──
  const visibleNodes = nodes.filter((n) => visibleNodeIds.has(n.id));
  const visibleEdges = edges.filter(
    (e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target),
  );

  return {
    positions,
    visibleNodes,
    visibleEdges,
    arcs,
    overflowPills,
    ringRadii,
    center: { x: cx, y: cy },
  };
}

// ── Edge path helpers ──────────────────────────────────────────────

/**
 * Compute an SVG path for an edge. Uses straight lines for radial edges
 * (seed→ring1, parent→child) and quadratic bezier curves for cross-arc
 * edges to avoid crossing through the center.
 */
export function computeEdgePath(
  x1: number, y1: number,
  x2: number, y2: number,
  cx: number, cy: number,
  baseRadius: number,
): string {
  // Check if the midpoint is too close to center (would cross through it)
  const midX = (x1 + x2) / 2;
  const midY = (y1 + y2) / 2;
  const distToCenter = Math.sqrt((midX - cx) ** 2 + (midY - cy) ** 2);

  if (distToCenter < baseRadius * 0.5) {
    // Curve outward: control point pushed away from center
    const midAngle = Math.atan2(midY - cy, midX - cx);
    const pushRadius = baseRadius * 0.8;
    const ctrlX = cx + pushRadius * Math.cos(midAngle);
    const ctrlY = cy + pushRadius * Math.sin(midAngle);
    return `M ${x1} ${y1} Q ${ctrlX} ${ctrlY} ${x2} ${y2}`;
  }

  // Straight line
  return `M ${x1} ${y1} L ${x2} ${y2}`;
}

// ── Node shape path helpers ────────────────────────────────────────

/** Generate SVG polygon points for a regular polygon centered at (x, y). */
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

/** Diamond (rotated square) points. */
export function diamondPoints(x: number, y: number, r: number): string {
  return `${x},${y - r} ${x + r},${y} ${x},${y + r} ${x - r},${y}`;
}
