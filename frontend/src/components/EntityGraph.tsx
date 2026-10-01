import { useCallback, useEffect, useRef, useState, useLayoutEffect, useMemo } from 'react';
import { getEntityColor, getEntityLabel, getEntityPluralLabel } from '@/utils/entityTheme';
import {
  computeRadialLayout,
  computeEdgePath,
  polygonPoints,
} from './entityGraphLayout';
import type { LayoutNode, LayoutEdge } from './entityGraphLayout';
import styles from './EntityGraph.module.css';

// Re-export for consumers that import from here
export type EntityNode = LayoutNode;
export type EntityEdge = LayoutEdge;

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

/** Row-level facts the inspector shows for a node — supplied by the tab from
 * the pivot payload (trust chip text, evidence shape phrase, counts). */
export interface GraphNodeInfo {
  trust?: string | null;
  phrase?: string | null;
  articles?: number;
  feeds?: number;
  /** Profile description / assessment, shown in the inspector. */
  description?: string | null;
  /** CISA KEV — red outer ring on the node. */
  kev?: boolean;
  /** Detection coverage (ttp/cve only): true = a rule detects it, false = gap. */
  covered?: boolean;
  /** How many rules in the whole library reference this technique/CVE. */
  ruleCount?: number;
}

export interface CoveringRule {
  id: string;
  title: string;
  rule_type: string;
  severity?: string | null;
}

interface EntityGraphProps {
  nodes: Array<EntityNode>;
  edges: Array<EntityEdge>;
  onNodeClick?: (nodeId: string, nodeType: string) => void;
  onEdgeCreate?: (sourceId: string, sourceType: string, targetId: string, targetType: string) => void;
  onEntryClick?: (entryId: string) => void;
  /** When provided, the graph offers a "story clusters" layout (default) that
   * groups nodes by incident inside labeled hulls — same nodes, edges, and
   * interactions as the type-ring layout. */
  storyClusters?: GraphStoryCluster[];
  onClusterClick?: (cluster: GraphStoryCluster) => void;
  /** Inspector facts per node id. */
  nodeInfo?: Map<string, GraphNodeInfo>;
  /** Neighbor sets fetched on demand per node ("Expand connections") —
   * with their own story clusters when the pivot carries evidence structure. */
  expansions?: Map<string, { nodes: EntityNode[]; edges: EntityEdge[]; clusters?: GraphStoryCluster[] }>;
  onToggleExpand?: (nodeId: string, nodeType: string, expand: boolean) => void;
  /** Open the story thread behind a cluster (when it has a slug). */
  onOpenThread?: (slug: string) => void;
  /** Live search text — matching nodes stay lit, everything else dims. */
  highlightQuery?: string;
  /** Fetch the detection rules covering a selected ttp/cve node — the
   * inspector lists them under the coverage line. */
  onFetchCoveringRules?: (node: EntityNode) => Promise<CoveringRule[]>;
  onOpenRule?: (ruleId: string) => void;
  width?: number;
  height?: number;
}

type Selected =
  | { kind: 'node'; id: string }
  | { kind: 'cluster'; id: string }
  | { kind: 'edge'; idx: number }
  | null;

function getNodeColor(type: string): string {
  if (type === 'entry') return '#6b7280';
  return getEntityColor(type);
}

function truncateLabel(label: string, maxLen: number = 18): string {
  if (label.length <= maxLen) return label;
  return label.slice(0, maxLen - 1) + '…';
}

// ── Node shape renderer ────────────────────────────────────────────

function renderNodeShape(
  type: string, x: number, y: number, r: number, color: string,
  extraClass: string = '', key?: string,
) {
  const baseProps = { fill: color, key };

  switch (type) {
    case 'malware':
      return <polygon className={`${styles.nodeShape} ${extraClass}`} points={polygonPoints(x, y, r, 6)} {...baseProps} />;
    case 'ttp':
      return <rect className={`${styles.nodeShape} ${extraClass}`} x={x - r * 0.8} y={y - r * 0.8} width={r * 1.6} height={r * 1.6} rx={3} ry={3} {...baseProps} />;
    case 'cve':
      return <polygon className={`${styles.nodeShape} ${extraClass}`} points={polygonPoints(x, y, r, 3)} {...baseProps} />;
    case 'entry':
      return <rect className={`${styles.nodeShape} ${styles.articleNode} ${extraClass}`} x={x - r * 1.3} y={y - r * 0.8} width={r * 2.6} height={r * 1.6} rx={4} ry={4} {...baseProps} />;
    case 'country':
      return (
        <g key={key}>
          <circle className={`${styles.nodeShape} ${extraClass}`} cx={x} cy={y} r={r} fill={color} />
          <circle cx={x} cy={y} r={r + 3} fill="none" stroke={color} strokeWidth={1.5} opacity={0.4} />
        </g>
      );
    default: // threat_actor, tool, mitigation, etc.
      return <circle className={`${styles.nodeShape} ${extraClass}`} cx={x} cy={y} r={r} {...baseProps} />;
  }
}

// ── Component ──────────────────────────────────────────────────────

export function EntityGraph({
  nodes,
  edges,
  onNodeClick,
  onEdgeCreate,
  onEntryClick,
  storyClusters,
  onClusterClick,
  nodeInfo,
  expansions,
  onToggleExpand,
  onOpenThread,
  highlightQuery,
  onFetchCoveringRules,
  onOpenRule,
  width: widthProp,
  height: heightProp = 500,
}: EntityGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // --- Interaction state ---
  const [draggingId, setDraggingId] = useState<string | null>(null);
  const draggingIdRef = useRef<string | null>(null);
  const dragOffset = useRef<{ dx: number; dy: number }>({ dx: 0, dy: 0 });
  const dragMoved = useRef(false);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Selection is the graph's core interaction: click selects (node, cluster,
  // or edge) and the inspector explains it; double-click navigates. Nothing
  // navigates on a single click.
  const [selected, setSelected] = useState<Selected>(null);

  // Manual position overrides from dragging (nodeId → {x, y})
  const [dragOverrides, setDragOverrides] = useState<Map<string, { x: number; y: number }>>(new Map());
  // Whole-cluster drag offsets in the story layout (clusterId → {dx, dy})
  const [clusterOffsets, setClusterOffsets] = useState<Map<string, { dx: number; dy: number }>>(new Map());
  const clusterDragRef = useRef<{ id: string; lastX: number; lastY: number; moved: boolean } | null>(null);

  // Per-node hide (inspector action); the strip shows a reset pill.
  const [hiddenNodes, setHiddenNodes] = useState<Set<string>>(new Set());

  // --- Fullscreen ---
  const [isFullscreen, setIsFullscreen] = useState(false);
  useEffect(() => {
    if (!isFullscreen) return;
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') setIsFullscreen(false); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [isFullscreen]);
  useEffect(() => {
    if (isFullscreen) {
      document.body.style.overflow = 'hidden';
      return () => { document.body.style.overflow = ''; };
    }
  }, [isFullscreen]);

  // --- Settings ---
  const [showSettings, setShowSettings] = useState(false);
  const [layoutMode, setLayoutMode] = useState<'story' | 'type'>('story');
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [showNodeLabels, setShowNodeLabels] = useState(true);
  const [showEdgeLabels, setShowEdgeLabels] = useState(false);
  const [showRingGuides, setShowRingGuides] = useState(true);
  const [showArcLabels, setShowArcLabels] = useState(true);
  const [nodesPerType, setNodesPerType] = useState(5);
  const [ringSpacing, setRingSpacing] = useState(1.0);

  // --- Expansion state ---
  const [expandedNodes, setExpandedNodes] = useState<Map<string, string | null>>(
    () => new Map(nodes.length > 0 ? [[nodes[0].id, null]] : []),
  );

  // Reset when seed entity changes — node ids recur across profiles (the
  // same country appears on many maps), so stale drags/hull offsets/pill
  // expansions from the previous profile must not carry over.
  const prevSeedRef = useRef(nodes[0]?.id);
  useEffect(() => {
    const newSeed = nodes[0]?.id;
    if (newSeed && newSeed !== prevSeedRef.current) {
      prevSeedRef.current = newSeed;
      setExpandedNodes(new Map([[newSeed, null]]));
      setSelected(null);
      setHiddenNodes(new Set());
      setDragOverrides(new Map());
      setClusterOffsets(new Map());
      setExpandedGhostTypes(new Set());
    }
  }, [nodes]);

  // Shift+drag edge creation
  const [edgeDraft, setEdgeDraft] = useState<{ sourceId: string; mouseX: number; mouseY: number } | null>(null);

  // --- Measure container ---
  const [measuredWidth, setMeasuredWidth] = useState(widthProp ?? 800);
  const [measuredHeight, setMeasuredHeight] = useState(heightProp);
  useLayoutEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        const h = entry.contentRect.height;
        if (w > 0) setMeasuredWidth(w);
        if (h > 0 && isFullscreen) setMeasuredHeight(h);
      }
    });
    observer.observe(el);
    const w = el.clientWidth;
    if (w > 0) setMeasuredWidth(w);
    if (isFullscreen) {
      const h = el.clientHeight;
      if (h > 0) setMeasuredHeight(h);
    }
    return () => observer.disconnect();
  }, [isFullscreen]);

  const width = isFullscreen ? measuredWidth : (widthProp ?? measuredWidth);
  const height = isFullscreen ? measuredHeight : heightProp;

  // --- Zoom & pan ---
  const [scale, setScale] = useState(1);
  const [translate, setTranslate] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const panStart = useRef({ x: 0, y: 0 });
  const translateAtPanStart = useRef({ x: 0, y: 0 });

  // ── Merge on-demand expansions into the base graph ─────────────
  // Expanded nodes' claims and stories join the SAME node/edge/cluster sets
  // the primary layout consumes — no parallel rendering path, so expansion
  // hulls drag, select, and label exactly like every other cluster, and
  // expanding an expansion node just works (any node is a real node).
  const allNodes = useMemo(() => {
    if (!expansions || expansions.size === 0) return nodes;
    const m = new Map(nodes.map((n) => [n.id, n]));
    for (const ex of expansions.values()) for (const n of ex.nodes) if (!m.has(n.id)) m.set(n.id, n);
    return [...m.values()];
  }, [nodes, expansions]);
  const allEdges = useMemo(() => {
    if (!expansions || expansions.size === 0) return edges;
    const seen = new Set(edges.map((e) => [e.source, e.target].sort().join('|')));
    const out = [...edges];
    for (const ex of expansions.values()) {
      for (const e of ex.edges) {
        const k = [e.source, e.target].sort().join('|');
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(e);
      }
    }
    return out;
  }, [edges, expansions]);
  const allClusters = useMemo(() => {
    const base = storyClusters ?? [];
    if (!expansions || expansions.size === 0) return base;
    const out = [...base];
    for (const ex of expansions.values()) out.push(...(ex.clusters ?? []));
    return out;
  }, [storyClusters, expansions]);
  const clusterById = useMemo(() => new Map(allClusters.map((c) => [c.id, c])), [allClusters]);

  // ── Compute radial layout ──────────────────────────────────────

  const layout = useMemo(() => computeRadialLayout({
    nodes: allNodes,
    edges: allEdges,
    seedId: nodes[0]?.id ?? '',
    expandedNodes,
    width,
    height,
    nodesPerType,
    ringSpacingMultiplier: ringSpacing,
    hiddenTypes,
  }), [allNodes, allEdges, nodes, expandedNodes, width, height, nodesPerType, ringSpacing, hiddenTypes]);

  // Story-less claim types the user expanded from their ghost pill.
  const [expandedGhostTypes, setExpandedGhostTypes] = useState<Set<string>>(new Set());

  // ── Story layout (operations map) ──────────────────────────────
  // Same nodes, edges, and interactions — only positions change: each story
  // cluster becomes a labeled hull with its members ringed inside. Story-less
  // nodes NEVER get individual spokes (that's the ring-soup this layout
  // exists to kill) — they collapse to one dashed ghost pill per type,
  // expandable on click. The ring radius is computed from the hull sizes so
  // adjacent hulls cannot overlap; node spacing reuses the settings slider.
  const storyLayout = useMemo(() => {
    if (allClusters.length === 0) return null;
    const cx0 = width / 2;
    const cy0 = height / 2;
    const seed = nodes[0]?.id ?? '';
    const visibleIds = new Set(allNodes.filter((n) => !hiddenTypes.has(n.type)).map((n) => n.id));
    const shown = allClusters.slice(0, 8);

    // First pass: cluster membership and hull sizes.
    const clustered = new Set<string>();
    const pre: Array<{ cluster: GraphStoryCluster; members: string[]; mrx: number; mry: number; rx: number; ry: number }> = [];
    for (const cluster of shown) {
      const members = cluster.nodeIds.filter((id) => visibleIds.has(id) && id !== seed && !clustered.has(id));
      if (members.length === 0) continue;
      members.forEach((id) => clustered.add(id));
      const mrx = 34 + members.length * 7;
      const mry = 24 + members.length * 4;
      pre.push({ cluster, members, mrx, mry, rx: mrx + 44, ry: mry + 38 });
    }

    // Ring radius: clear the center, and keep adjacent hulls (plus their
    // title blocks) from touching.
    const k = pre.length;
    const hullR = (p: (typeof pre)[number]) => Math.max(p.rx, p.ry + 34); // +34 for the title block
    const maxHull = pre.length ? Math.max(...pre.map(hullR)) : 0;
    let R = Math.max(170, maxHull + 80);
    if (k >= 2) {
      for (let i = 0; i < k; i++) {
        const need = (hullR(pre[i]) + hullR(pre[(i + 1) % k]) + 30) / (2 * Math.sin(Math.PI / k));
        R = Math.max(R, need);
      }
    }
    R *= ringSpacing;

    type StoryPos = { x: number; y: number; ring: number; angle: number; parentId: string | null };
    const positions = new Map<string, StoryPos>();
    positions.set(seed, { x: cx0, y: cy0, ring: 0, angle: 0, parentId: null });

    const hulls: Array<{
      cx: number; cy: number; rx: number; ry: number;
      cluster: GraphStoryCluster; titleBelow: boolean;
    }> = [];
    pre.forEach((p, i) => {
      const angle = ((-90 + (i * 360) / k) * Math.PI) / 180;
      const hcx = cx0 + R * Math.cos(angle);
      const hcy = cy0 + R * Math.sin(angle);
      p.members.forEach((id, j) => {
        const a = ((-90 + (j * 360) / p.members.length) * Math.PI) / 180;
        positions.set(id, { x: hcx + p.mrx * Math.cos(a), y: hcy + p.mry * Math.sin(a), ring: 1, angle: a, parentId: seed });
      });
      hulls.push({ cx: hcx, cy: hcy, rx: p.rx, ry: p.ry, cluster: p.cluster, titleBelow: Math.sin(angle) > 0.25 });
    });

    // Story-less claims: one ghost pill per type; expanded types lay their
    // nodes on an outer ring.
    const rest = allNodes.filter((n) => visibleIds.has(n.id) && n.id !== seed && !clustered.has(n.id));
    const byType = new Map<string, string[]>();
    for (const n of rest) (byType.get(n.type) ?? byType.set(n.type, []).get(n.type)!).push(n.id);

    // Which types are pure MITRE/external claims (edge provenance from seed)?
    const provenanceOf = new Map<string, string | null | undefined>();
    for (const e of allEdges) {
      if (e.source === seed) provenanceOf.set(e.target, e.provenance);
      else if (e.target === seed) provenanceOf.set(e.source, e.provenance);
    }

    const R2 = R + maxHull + 120;
    const expandedIds: string[] = [];
    for (const [type, ids] of byType) {
      if (expandedGhostTypes.has(type)) expandedIds.push(...ids);
    }
    expandedIds.forEach((id, i) => {
      const a = ((-90 + (i * 360) / Math.max(expandedIds.length, 1)) * Math.PI) / 180;
      positions.set(id, { x: cx0 + R2 * Math.cos(a), y: cy0 + R2 * Math.sin(a), ring: 2, angle: a, parentId: seed });
    });

    const ghosts = [...byType.entries()].map(([type, ids]) => ({
      type,
      count: ids.length,
      mitre: ids.every((id) => provenanceOf.get(id) === 'external_feed'),
      expanded: expandedGhostTypes.has(type),
    }));

    const clusterOf = new Map<string, string>();
    pre.forEach((p) => {
      p.members.forEach((id) => clusterOf.set(id, p.cluster.id));
    });

    // Fit bounds: hulls, their titles, and any expanded ghost ring.
    let minX = cx0 - 60, minY = cy0 - 60, maxX = cx0 + 60, maxY = cy0 + 60;
    for (const h of hulls) {
      minX = Math.min(minX, h.cx - h.rx - 20);
      maxX = Math.max(maxX, h.cx + h.rx + 20);
      minY = Math.min(minY, h.cy - h.ry - 40);
      maxY = Math.max(maxY, h.cy + h.ry + 40);
    }
    for (const pos of positions.values()) {
      minX = Math.min(minX, pos.x - 30);
      maxX = Math.max(maxX, pos.x + 30);
      minY = Math.min(minY, pos.y - 30);
      maxY = Math.max(maxY, pos.y + 30);
    }
    return { positions, hulls, ghosts, clusterOf, bounds: { minX, minY, maxX, maxY } };
  }, [allClusters, allNodes, allEdges, nodes, width, height, hiddenTypes, ringSpacing, expandedGhostTypes]);

  const storyActive = layoutMode === 'story' && storyLayout !== null;
  const basePositions = storyActive ? storyLayout!.positions : layout.positions;

  // In story layout every non-hidden node is visible (the per-type ring caps
  // are a radial-layout concern); edges follow the visible nodes.
  const visibleNodes = useMemo(() => {
    const base = storyActive ? allNodes.filter((n) => storyLayout!.positions.has(n.id)) : layout.visibleNodes;
    return hiddenNodes.size > 0 ? base.filter((n) => !hiddenNodes.has(n.id)) : base;
  }, [storyActive, allNodes, storyLayout, layout.visibleNodes, hiddenNodes]);
  const visibleEdges = useMemo(() => {
    const ids = new Set(visibleNodes.map((n) => n.id));
    if (!storyActive && hiddenNodes.size === 0) return layout.visibleEdges;
    const source = storyActive ? allEdges : layout.visibleEdges;
    return source.filter((e) => ids.has(e.source) && ids.has(e.target));
  }, [storyActive, allEdges, visibleNodes, layout.visibleEdges, hiddenNodes]);

  // Clear manual placements only when the coordinate SPACE changes (story ↔
  // rings) — story offsets are meaningless in ring coordinates. Expansions
  // merging new nodes reflow the layout but keep drags/hull offsets: they're
  // deltas, and wiping a hand-arranged map on every click-expand would make
  // arranging and exploring mutually exclusive. Seed changes reset above.
  const layoutGenRef = useRef(0);
  useEffect(() => {
    layoutGenRef.current++;
    if (layoutGenRef.current > 1) {
      // Don't clear on first render, only on subsequent mode switches
      setDragOverrides(new Map());
      setClusterOffsets(new Map());
    }
  }, [storyActive]);

  // Merged positions: cluster-drag offsets first, then per-node overrides.
  const positions = useMemo(() => {
    let base = basePositions;
    if (storyActive && clusterOffsets.size > 0) {
      const shifted = new Map(base);
      for (const [id, pos] of base) {
        const cid = storyLayout!.clusterOf.get(id);
        const off = cid ? clusterOffsets.get(cid) : undefined;
        if (off) shifted.set(id, { ...pos, x: pos.x + off.dx, y: pos.y + off.dy });
      }
      base = shifted;
    }
    if (dragOverrides.size === 0) return base;
    const merged = new Map(base);
    for (const [id, pos] of dragOverrides) {
      const existing = merged.get(id);
      if (existing) {
        // Cluster-relative overrides: re-apply the hull's current offset so
        // hand-placed nodes follow later cluster drags.
        let ox = 0, oy = 0;
        if (storyActive) {
          const cid = storyLayout!.clusterOf.get(id);
          const off = cid ? clusterOffsets.get(cid) : undefined;
          if (off) {
            ox = off.dx;
            oy = off.dy;
          }
        }
        merged.set(id, { ...existing, x: pos.x + ox, y: pos.y + oy });
      }
    }
    return merged;
  }, [basePositions, dragOverrides, storyActive, storyLayout, clusterOffsets]);

  // Auto-fit when layout changes
  useEffect(() => {
    if (basePositions.size === 0) return;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    if (storyActive) {
      ({ minX, minY, maxX, maxY } = storyLayout!.bounds);
    } else {
      for (const pos of basePositions.values()) {
        minX = Math.min(minX, pos.x);
        minY = Math.min(minY, pos.y);
        maxX = Math.max(maxX, pos.x);
        maxY = Math.max(maxY, pos.y);
      }
    }
    const pad = 80;
    const bboxW = maxX - minX + pad * 2;
    const bboxH = maxY - minY + pad * 2;
    if (bboxW > 0 && bboxH > 0) {
      const fitScale = Math.max(0.08, Math.min(1.0, Math.min(width / bboxW, height / bboxH)));
      const fitCx = (minX + maxX) / 2;
      const fitCy = (minY + maxY) / 2;
      setScale(fitScale);
      setTranslate({ x: width / 2 - fitCx * fitScale, y: height / 2 - fitCy * fitScale });
    }
  }, [basePositions, storyActive, storyLayout, width, height]);

  // Build lookup maps
  const nodeMap = useMemo(() => {
    const m = new Map<string, EntityNode>();
    for (const n of visibleNodes) m.set(n.id, n);
    return m;
  }, [visibleNodes]);

  // Detection rules covering the selected ttp/cve node — fetched lazily on
  // first selection, cached per node id for the life of the component.
  const [coveringRules, setCoveringRules] = useState<Map<string, CoveringRule[] | 'loading'>>(new Map());
  useEffect(() => {
    if (!onFetchCoveringRules || !selected || selected.kind !== 'node') return;
    const id = selected.id;
    if (!nodeInfo?.get(id)?.covered || coveringRules.has(id)) return;
    const node = nodeMap.get(id);
    if (!node || (node.type !== 'ttp' && node.type !== 'cve')) return;
    setCoveringRules((prev) => new Map(prev).set(id, 'loading'));
    onFetchCoveringRules(node)
      .then((rules) => setCoveringRules((prev) => new Map(prev).set(id, rules)))
      .catch(() => setCoveringRules((prev) => new Map(prev).set(id, [])));
  }, [selected, onFetchCoveringRules, nodeInfo, nodeMap, coveringRules]);

  // Adjacency for hover + expand detection
  const adjacency = useMemo(() => {
    const adj = new Map<string, Set<string>>();
    for (const e of allEdges) {
      if (!adj.has(e.source)) adj.set(e.source, new Set());
      if (!adj.has(e.target)) adj.set(e.target, new Set());
      adj.get(e.source)!.add(e.target);
      adj.get(e.target)!.add(e.source);
    }
    return adj;
  }, [allEdges]);

  // Entity type counts (from ALL nodes, not just visible)
  const entityTypes = useMemo(() => {
    const types = new Map<string, number>();
    for (const n of allNodes) types.set(n.type, (types.get(n.type) ?? 0) + 1);
    return types;
  }, [allNodes]);

  // Hover neighborhood
  const hoverNeighborhood = useMemo(() => {
    if (!hoveredNodeId) return null;
    const neighborNodes = new Set<string>([hoveredNodeId]);
    const neighborEdgeIdxs = new Set<number>();
    for (let i = 0; i < visibleEdges.length; i++) {
      const e = visibleEdges[i];
      if (e.source === hoveredNodeId || e.target === hoveredNodeId) {
        neighborEdgeIdxs.add(i);
        neighborNodes.add(e.source);
        neighborNodes.add(e.target);
      }
    }
    return { nodes: neighborNodes, edges: neighborEdgeIdxs };
  }, [hoveredNodeId, visibleEdges]);

  // Search highlight: matching nodes stay lit, the rest recede. The tab's
  // search box drives this — no separate find UI.
  const hq = (highlightQuery ?? '').trim().toLowerCase();
  const searchMatches = useMemo(() => {
    if (!hq) return null;
    return new Set(visibleNodes.filter((n) => n.label.toLowerCase().includes(hq)).map((n) => n.id));
  }, [hq, visibleNodes]);

  // ── Coordinate conversion ──────────────────────────────────────

  const screenToGraph = useCallback(
    (screenX: number, screenY: number) => {
      const svg = svgRef.current;
      if (!svg) return { x: screenX, y: screenY };
      const rect = svg.getBoundingClientRect();
      const svgScaleX = width / rect.width;
      const svgScaleY = height / rect.height;
      const svgX = (screenX - rect.left) * svgScaleX;
      const svgY = (screenY - rect.top) * svgScaleY;
      return { x: (svgX - translate.x) / scale, y: (svgY - translate.y) / scale };
    },
    [width, height, scale, translate],
  );

  // ── Interaction handlers ───────────────────────────────────────

  const handleNodeMouseDown = useCallback(
    (nodeId: string, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();

      if (e.shiftKey && onEdgeCreate) {
        const pos = positions.get(nodeId);
        if (pos) setEdgeDraft({ sourceId: nodeId, mouseX: pos.x, mouseY: pos.y });
        return;
      }

      const pos = positions.get(nodeId);
      if (!pos) return;
      const graphCoords = screenToGraph(e.clientX, e.clientY);
      dragOffset.current = { dx: pos.x - graphCoords.x, dy: pos.y - graphCoords.y };
      dragMoved.current = false;
      draggingIdRef.current = nodeId;
      setDraggingId(nodeId);
    },
    [positions, screenToGraph, onEdgeCreate],
  );

  const handleSvgMouseDown = useCallback(
    (e: React.MouseEvent) => {
      const target = e.target as SVGElement;
      if (target.tagName === 'svg' || target.classList.contains(styles.ringGuide)) {
        setSelected(null);
        e.preventDefault();
        setIsPanning(true);
        panStart.current = { x: e.clientX, y: e.clientY };
        translateAtPanStart.current = { x: translate.x, y: translate.y };
      }
    },
    [translate],
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (clusterDragRef.current) {
        e.preventDefault();
        const g = screenToGraph(e.clientX, e.clientY);
        const cd = clusterDragRef.current;
        const ddx = g.x - cd.lastX;
        const ddy = g.y - cd.lastY;
        cd.lastX = g.x;
        cd.lastY = g.y;
        if (Math.abs(ddx) + Math.abs(ddy) > 0.5) cd.moved = true;
        setClusterOffsets((prev) => {
          const next = new Map(prev);
          const cur = next.get(cd.id) ?? { dx: 0, dy: 0 };
          next.set(cd.id, { dx: cur.dx + ddx, dy: cur.dy + ddy });
          return next;
        });
        return;
      }
      if (edgeDraft) {
        e.preventDefault();
        const graphCoords = screenToGraph(e.clientX, e.clientY);
        setEdgeDraft((prev) => prev ? { ...prev, mouseX: graphCoords.x, mouseY: graphCoords.y } : null);
        return;
      }
      if (isPanning) {
        e.preventDefault();
        const svg = svgRef.current;
        if (!svg) return;
        const rect = svg.getBoundingClientRect();
        const dx = (e.clientX - panStart.current.x) * (width / rect.width);
        const dy = (e.clientY - panStart.current.y) * (height / rect.height);
        setTranslate({ x: translateAtPanStart.current.x + dx, y: translateAtPanStart.current.y + dy });
        return;
      }
      const currentDragging = draggingIdRef.current;
      if (!currentDragging) return;
      e.preventDefault();
      dragMoved.current = true;
      const graphCoords = screenToGraph(e.clientX, e.clientY);
      let newX = graphCoords.x + dragOffset.current.dx;
      let newY = graphCoords.y + dragOffset.current.dy;
      // Overrides for clustered nodes are stored cluster-relative (minus the
      // hull's current offset) so a hand-placed node still rides along when
      // its story hull is dragged afterwards.
      if (storyActive) {
        const cid = storyLayout!.clusterOf.get(currentDragging);
        const off = cid ? clusterOffsets.get(cid) : undefined;
        if (off) {
          newX -= off.dx;
          newY -= off.dy;
        }
      }
      setDragOverrides((prev) => {
        const next = new Map(prev);
        next.set(currentDragging, { x: newX, y: newY });
        return next;
      });
    },
    [isPanning, screenToGraph, width, height, edgeDraft, storyActive, storyLayout, clusterOffsets],
  );

  const handleMouseUp = useCallback(
    (e: React.MouseEvent) => {
      if (clusterDragRef.current) {
        const cd = clusterDragRef.current;
        clusterDragRef.current = null;
        // Click (no drag) selects the cluster; filtering is an inspector action.
        if (!cd.moved) setSelected({ kind: 'cluster', id: cd.id });
        return;
      }
      if (edgeDraft) {
        // Check for drop target
        const graphCoords = screenToGraph(e.clientX, e.clientY);
        for (const [nid, pos] of positions) {
          if (nid === edgeDraft.sourceId) continue;
          const node = nodeMap.get(nid);
          if (!node) continue;
          const r = Math.max(6, Math.min(16, node.size * 2 + 4));
          if ((graphCoords.x - pos.x) ** 2 + (graphCoords.y - pos.y) ** 2 <= r * r * 2) {
            if (onEdgeCreate) {
              onEdgeCreate(edgeDraft.sourceId, nodeMap.get(edgeDraft.sourceId)?.type ?? '', nid, node.type);
            }
            break;
          }
        }
        setEdgeDraft(null);
        return;
      }

      if (isPanning) { setIsPanning(false); return; }

      const currentDragging = draggingIdRef.current;
      if (currentDragging && !dragMoved.current) {
        const node = nodeMap.get(currentDragging);
        if (node) {
          e.stopPropagation();
          // Click selects; in the ring layout it also expands the node's
          // neighbors (that layout's whole exploration model). Navigation is
          // double-click or the inspector's Open action.
          setSelected({ kind: 'node', id: node.id });
          if (!storyActive && node.type !== 'entry' && !expandedNodes.has(node.id)) {
            setExpandedNodes((prev) => {
              const next = new Map(prev);
              const parentPos = positions.get(node.id);
              next.set(node.id, parentPos?.parentId ?? nodes[0]?.id ?? null);
              return next;
            });
          }
          // Story layout: same one-click exploration — fetch and merge the
          // node's own connections (with their stories). Collapse stays in
          // the inspector.
          if (
            storyActive &&
            node.type !== 'entry' &&
            node.id !== nodes[0]?.id &&
            onToggleExpand &&
            !expansions?.has(node.id)
          ) {
            onToggleExpand(node.id, node.type, true);
          }
        }
      }
      draggingIdRef.current = null;
      setDraggingId(null);
    },
    [isPanning, nodeMap, onEdgeCreate, edgeDraft, positions, screenToGraph, expandedNodes, nodes, storyActive, onToggleExpand, expansions],
  );

  // Double-click opens the node's own page (profile / article).
  const handleNodeDoubleClick = useCallback(
    (nodeId: string, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const node = nodeMap.get(nodeId);
      if (!node) return;
      if (node.type === 'entry') onEntryClick?.(nodeId.replace(/^entry-/, ''));
      else onNodeClick?.(nodeId, node.type);
    },
    [nodeMap, onNodeClick, onEntryClick],
  );

  // Collapse a ring-layout branch (inspector action).
  const collapseBranch = useCallback(
    (nodeId: string) => {
      if (nodeId === nodes[0]?.id) return;
      setExpandedNodes((prev) => {
        const next = new Map(prev);
        const toRemove = new Set<string>([nodeId]);
        let changed = true;
        while (changed) {
          changed = false;
          for (const [id, parent] of next) {
            if (parent !== null && toRemove.has(parent) && !toRemove.has(id)) {
              toRemove.add(id);
              changed = true;
            }
          }
        }
        for (const id of toRemove) next.delete(id);
        return next;
      });
    },
    [nodes],
  );

  // --- Wheel zoom ---
  const scaleRef = useRef(scale);
  scaleRef.current = scale;

  const handleWheel = useCallback((e: WheelEvent) => {
    e.preventDefault();
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left) * (width / rect.width);
    const mouseY = (e.clientY - rect.top) * (height / rect.height);
    const currentScale = scaleRef.current;
    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
    const newScale = Math.max(0.2, Math.min(4.0, currentScale * zoomFactor));
    const ratio = newScale / currentScale;
    setTranslate((prev) => ({
      x: mouseX - ratio * (mouseX - prev.x),
      y: mouseY - ratio * (mouseY - prev.y),
    }));
    setScale(newScale);
  }, [width, height]);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    svg.addEventListener('wheel', handleWheel, { passive: false });
    return () => svg.removeEventListener('wheel', handleWheel);
  }, [handleWheel]);

  // --- Fit to view ---
  const handleResetView = useCallback(() => {
    if (positions.size === 0) { setScale(1); setTranslate({ x: 0, y: 0 }); return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    if (storyActive) {
      ({ minX, minY, maxX, maxY } = storyLayout!.bounds);
    }
    for (const pos of positions.values()) {
      minX = Math.min(minX, pos.x); minY = Math.min(minY, pos.y);
      maxX = Math.max(maxX, pos.x); maxY = Math.max(maxY, pos.y);
    }
    const pad = 60;
    const bboxW = maxX - minX + pad * 2;
    const bboxH = maxY - minY + pad * 2;
    if (bboxW <= 0 || bboxH <= 0) { setScale(1); setTranslate({ x: 0, y: 0 }); return; }
    const newScale = Math.max(0.08, Math.min(2.0, Math.min(width / bboxW, height / bboxH)));
    setScale(newScale);
    setTranslate({ x: width / 2 - ((minX + maxX) / 2) * newScale, y: height / 2 - ((minY + maxY) / 2) * newScale });
  }, [positions, storyActive, storyLayout, width, height]);

  // --- Export the current view as a PNG ---
  const handleExport = useCallback(() => {
    const svg = svgRef.current;
    const container = containerRef.current;
    if (!svg || !container) return;
    const clone = svg.cloneNode(true) as SVGSVGElement;
    // CSS-module classes don't survive serialization — inline the computed
    // presentation of every element.
    const src = svg.querySelectorAll('*');
    const dst = clone.querySelectorAll('*');
    const props = ['fill', 'stroke', 'stroke-width', 'stroke-dasharray', 'stroke-opacity', 'opacity', 'font-size', 'font-family', 'font-weight', 'letter-spacing', 'text-anchor'];
    src.forEach((el, i) => {
      const cs = getComputedStyle(el);
      const d = dst[i] as SVGElement;
      for (const prop of props) {
        const v = cs.getPropertyValue(prop);
        if (v) d.setAttribute(prop, v);
      }
    });
    let bg = getComputedStyle(container).backgroundColor;
    if (!bg || bg === 'rgba(0, 0, 0, 0)') bg = getComputedStyle(document.body).backgroundColor || '#101318';
    const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bgRect.setAttribute('width', String(width));
    bgRect.setAttribute('height', String(height));
    bgRect.setAttribute('fill', bg);
    clone.insertBefore(bgRect, clone.firstChild);
    clone.setAttribute('width', String(width * 2));
    clone.setAttribute('height', String(height * 2));
    const xml = new XMLSerializer().serializeToString(clone);
    const url = URL.createObjectURL(new Blob([xml], { type: 'image/svg+xml;charset=utf-8' }));
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = width * 2;
      canvas.height = height * 2;
      canvas.getContext('2d')!.drawImage(img, 0, 0, width * 2, height * 2);
      URL.revokeObjectURL(url);
      canvas.toBlob((blob) => {
        if (!blob) return;
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        const seedLabel = nodes[0]?.label?.toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'graph';
        a.download = `${seedLabel}-graph.png`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      }, 'image/png');
    };
    img.src = url;
  }, [width, height, nodes]);

  // --- Toggle type filter (the legend is the control) ---
  const toggleType = useCallback((type: string) => {
    setHiddenTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type); else next.add(type);
      return next;
    });
  }, []);

  // --- Stats ---
  const visibleNodeCount = visibleNodes.length;
  const visibleEdgeCount = visibleEdges.length;
  const seedId = nodes[0]?.id;
  const baseRadius = Math.min(width, height) * 0.22;

  const effectiveShowEdgeLabels = showEdgeLabels;

  // ── Empty state ────────────────────────────────────────────────

  if (nodes.length === 0) {
    return (
      <div ref={containerRef} className={styles.container} style={{ width: widthProp, height: heightProp }}>
        <div className={styles.emptyState}>No entities to display</div>
      </div>
    );
  }

  // ── Render ─────────────────────────────────────────────────────

  const svgClassName = [
    styles.graphSvg,
    isPanning ? styles.panning : '',
    draggingId ? styles.draggingNode : '',
    edgeDraft ? styles.drawingEdge : '',
  ].filter(Boolean).join(' ');

  const containerClassName = [
    styles.container,
    isFullscreen ? styles.fullscreen : '',
  ].filter(Boolean).join(' ');

  const selectedNodeId = selected?.kind === 'node' ? selected.id : null;
  const selectedClusterId = selected?.kind === 'cluster' ? selected.id : null;
  const selectedEdgeIdx = selected?.kind === 'edge' ? selected.idx : null;

  return (
    <div
      ref={containerRef}
      className={containerClassName}
      style={isFullscreen ? undefined : { width: widthProp, height: heightProp }}
    >
      <svg
        ref={svgRef}
        className={svgClassName}
        viewBox={`0 0 ${width} ${height}`}
        onMouseDown={handleSvgMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <g transform={`translate(${translate.x}, ${translate.y}) scale(${scale})`}>

          {/* Story hulls — one labeled ellipse per incident, behind everything. */}
          {storyActive && storyLayout!.hulls.map((h, i) => {
            const off = clusterOffsets.get(h.cluster.id) ?? { dx: 0, dy: 0 };
            const hcx = h.cx + off.dx;
            const hcy = h.cy + off.dy;
            const titleY = h.titleBelow ? hcy + h.ry + 18 : hcy - h.ry - 22;
            const sub = [`${h.cluster.articles} articles`, h.cluster.corroborated ? 'corroborated' : null]
              .filter(Boolean)
              .join(' · ');
            const isSel = selectedClusterId === h.cluster.id;
            return (
              <g key={`hull-${i}`}>
                <ellipse
                  className={`${styles.storyHull} ${isSel ? styles.storyHullSelected : ''}`}
                  cx={hcx}
                  cy={hcy}
                  rx={h.rx}
                  ry={h.ry}
                  stroke={h.cluster.corroborated ? 'var(--accent-intel)' : 'var(--border)'}
                  onMouseDown={(e) => {
                    e.stopPropagation();
                    e.preventDefault();
                    const g = screenToGraph(e.clientX, e.clientY);
                    clusterDragRef.current = { id: h.cluster.id, lastX: g.x, lastY: g.y, moved: false };
                  }}
                >
                  <title>{`${h.cluster.heading} — drag to move · click to inspect`}</title>
                </ellipse>
                <text className={styles.storyHullTitle} x={hcx} y={titleY} textAnchor="middle">
                  {truncateLabel(h.cluster.heading, 40).toUpperCase()}
                </text>
                <text className={styles.storyHullSub} x={hcx} y={titleY + 13} textAnchor="middle">
                  {sub}
                </text>
              </g>
            );
          })}

          {/* Ring guides (radial layout only) */}
          {!storyActive && showRingGuides && layout.ringRadii.map((r, i) => (
            i > 0 && r > 0 ? (
              <circle
                key={`ring-${i}`}
                className={styles.ringGuide}
                cx={layout.center.x}
                cy={layout.center.y}
                r={r}
              />
            ) : null
          ))}

          {/* Arc labels (radial layout only) */}
          {!storyActive && showArcLabels && layout.arcs.filter((s) => s.ring === 1).map((arc) => {
            const labelR = (layout.ringRadii[1] ?? baseRadius) + 28;
            const lx = layout.center.x + labelR * Math.cos(arc.midAngle);
            const ly = layout.center.y + labelR * Math.sin(arc.midAngle);
            return (
              <text
                key={`arc-${arc.type}`}
                className={styles.arcLabel}
                x={lx}
                y={ly}
                textAnchor="middle"
                dominantBaseline="central"
              >
                {getEntityLabel(arc.type) || arc.type} ({arc.total})
              </text>
            );
          })}

          {/* Edges */}
          {visibleEdges.map((edge, i) => {
            const sp = positions.get(edge.source);
            const tp = positions.get(edge.target);
            if (!sp || !tp) return null;

            const searchDim = searchMatches && !searchMatches.has(edge.source) && !searchMatches.has(edge.target);
            const isDimmed = (hoverNeighborhood && !hoverNeighborhood.edges.has(i)) || searchDim;
            const isHighlighted = hoverNeighborhood?.edges.has(i);
            const isSelected = selectedEdgeIdx === i;
            const hasEntries = (edge.entries?.length ?? 0) > 0;

            const pathD = computeEdgePath(
              sp.x, sp.y, tp.x, tp.y,
              layout.center.x, layout.center.y, baseRadius,
            );

            const midX = (sp.x + tp.x) / 2;
            const midY = (sp.y + tp.y) / 2;
            const entryCount = edge.entries?.length ?? 0;
            const w = edge.weight;
            // Width encodes relationship strength (0–1 composite) when present;
            // legacy weights fall back to the old scaling. Inferred (engine-only)
            // relationships render dashed; analyst-touched ones solid.
            const strength = edge.proximity_score;
            const strokeWidth = strength != null
              ? Math.max(1, Math.min(4, 1 + strength * 3))
              : Math.max(1, Math.min(4, w <= 2 ? w * 2 : w));
            const inferred = !edge.provenance || edge.provenance === 'co_occurrence';
            // Signal-tier claims stay visible but quiet — same dimming the
            // claims list gives signal rows.
            const signalTier = edge.confidence === 'possible';

            return (
              <g key={`edge-${i}`} opacity={isDimmed ? 0.06 : signalTier && !isHighlighted && !isSelected ? 0.45 : undefined}>
                {/* Hit area */}
                {hasEntries && !isDimmed && (
                  <path
                    d={pathD}
                    fill="none"
                    stroke="transparent"
                    strokeWidth={Math.max(14, strokeWidth + 10)}
                    style={{ cursor: 'pointer' }}
                    onMouseDown={(e) => {
                      e.stopPropagation();
                      setSelected(isSelected ? null : { kind: 'edge', idx: i });
                    }}
                  />
                )}
                <path
                  d={pathD}
                  fill="none"
                  className={`${styles.edgeLine} ${isSelected ? styles.edgeSelected : ''} ${isHighlighted ? styles.edgeHighlighted : ''}`}
                  strokeWidth={isHighlighted ? Math.max(strokeWidth, 2) : strokeWidth}
                  strokeDasharray={inferred ? '5,4' : undefined}
                />
                {effectiveShowEdgeLabels && edge.label && !isDimmed && (
                  <text className={styles.edgeLabel} x={midX} y={midY - 4} textAnchor="middle">
                    {truncateLabel(edge.label, 24)}
                    {entryCount > 0 ? ` (${entryCount})` : ''}
                  </text>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {visibleNodes.map((node) => {
            const pos = positions.get(node.id);
            if (!pos) return null;

            const isArticle = node.type === 'entry';
            const r = isArticle ? Math.max(4, Math.min(12, node.size * 2 + 2)) : Math.max(6, Math.min(16, node.size * 2 + 4));
            const color = getNodeColor(node.type);
            const searchDim = searchMatches && !searchMatches.has(node.id);
            const isDimmed = (hoverNeighborhood && !hoverNeighborhood.nodes.has(node.id)) || searchDim;
            const isHovered = hoveredNodeId === node.id;
            const isSeed = node.id === seedId;
            const isSelectedNode = selectedNodeId === node.id;
            const isExpanded = expandedNodes.has(node.id);
            const showLabel = isDimmed ? false : showNodeLabels;

            // Has hidden connections?
            const fullNeighbors = adjacency.get(node.id);
            const hasHidden = !isArticle && fullNeighbors &&
              Array.from(fullNeighbors).some((nid) => !positions.has(nid) && !hiddenTypes.has(nodeMap.get(nid)?.type ?? allNodes.find((n) => n.id === nid)?.type ?? ''));

            const ni = nodeInfo?.get(node.id);
            return (
              <g
                key={`node-${node.id}`}
                onMouseDown={(e) => handleNodeMouseDown(node.id, e)}
                onDoubleClick={(e) => handleNodeDoubleClick(node.id, e)}
                onMouseEnter={() => setHoveredNodeId(node.id)}
                onMouseLeave={() => setHoveredNodeId(null)}
                opacity={isDimmed ? 0.1 : undefined}
              >
                {/* KEV: known-exploited CVEs wear a red ring */}
                {ni?.kev && (
                  <circle cx={pos.x} cy={pos.y} r={r + 4} fill="none" stroke="var(--danger)" strokeWidth={1.5} opacity={0.85}>
                    <title>CISA KEV — known exploited</title>
                  </circle>
                )}
                {/* Seed / selection rings */}
                {isSeed && (
                  <circle cx={pos.x} cy={pos.y} r={r + 6} fill="none" stroke={color} strokeWidth={2} opacity={0.3} />
                )}
                {isSelectedNode && (
                  <circle cx={pos.x} cy={pos.y} r={r + 5} fill="none" stroke="var(--accent)" strokeWidth={2} opacity={0.85} />
                )}

                {/* Node shape */}
                {renderNodeShape(
                  node.type, pos.x, pos.y,
                  isHovered ? r + 2 : isSeed ? r + 1 : r,
                  color,
                  `${isHovered ? styles.nodeHovered : ''} ${isSeed ? styles.seedNode : ''}`,
                )}

                {/* Expand indicator dot: ring layout = graph data holds unshown
                    neighbors; story layout = the node's own connections can be
                    fetched and merged (one click, same as rings). */}
                {(storyActive
                  ? !!onToggleExpand && !isSeed && !expansions?.has(node.id)
                  : hasHidden && !isExpanded) && !isArticle && !isDimmed && (
                  <circle
                    className={styles.expandDot}
                    cx={pos.x + (pos.ring > 0 ? (r + 4) * Math.cos(pos.angle) : r + 4)}
                    cy={pos.y + (pos.ring > 0 ? (r + 4) * Math.sin(pos.angle) : -(r + 4))}
                    r={4}
                  >
                    <title>Click to expand connections</title>
                  </circle>
                )}

                {/* Detection coverage: filled = a rule detects it, hollow = gap */}
                {ni?.covered !== undefined && !isDimmed && (
                  <circle
                    cx={pos.x + r * 0.95}
                    cy={pos.y - r * 0.95}
                    r={3.5}
                    fill={ni.covered ? 'var(--success)' : 'var(--bg-primary)'}
                    stroke={ni.covered ? 'var(--success)' : 'var(--danger)'}
                    strokeWidth={1.3}
                  >
                    <title>{ni.covered ? 'Detection rule exists' : 'No detection rule — coverage gap'}</title>
                  </circle>
                )}
                {/* Label — the type sub-label is gone: shape + color already
                    say it, and the inspector spells it out. */}
                {showLabel && (
                  <text
                    className={isArticle ? styles.articleLabel : styles.nodeLabel}
                    x={pos.x}
                    y={pos.y + r + 14}
                    fontWeight={isHovered || isSeed || isSelectedNode ? 700 : undefined}
                  >
                    {truncateLabel(node.label, isArticle ? 28 : 20)}
                  </text>
                )}
              </g>
            );
          })}

          {/* Overflow pills: "+N more" (radial layout only) */}
          {!storyActive && layout.overflowPills.map((pill) => (
            <g
              key={`pill-${pill.type}-${pill.ring}-${pill.expandedById}`}
              className={styles.morePillGroup}
              onClick={() => setNodesPerType((prev) => Math.min(prev + 4, 20))}
              style={{ cursor: 'pointer' }}
            >
              <rect
                className={styles.morePill}
                x={pill.x - 16}
                y={pill.y - 9}
                width={32}
                height={18}
                rx={9}
                ry={9}
              />
              <text
                className={styles.morePillText}
                x={pill.x}
                y={pill.y}
                textAnchor="middle"
                dominantBaseline="central"
              >
                +{pill.count}
              </text>
            </g>
          ))}

          {/* Draft edge */}
          {edgeDraft && (() => {
            const sp = positions.get(edgeDraft.sourceId);
            if (!sp) return null;
            return (
              <line
                className={styles.draftEdgeLine}
                x1={sp.x} y1={sp.y}
                x2={edgeDraft.mouseX} y2={edgeDraft.mouseY}
                strokeWidth={2} strokeDasharray="6,4"
              />
            );
          })()}
        </g>
      </svg>

      {/* ── Top strip: pills left, tools right — the graph's one toolbar ── */}
      <div className={styles.topStrip}>
        <div className={styles.stripLeft}>
          {storyActive && storyLayout!.ghosts.map((g) => (
            <button
              key={g.type}
              className={`${styles.ghostBarPill} ${g.expanded ? styles.ghostBarPillOn : ''}`}
              title={`Story-less claims — in the list below${g.mitre ? ' and the ATT&CK tab' : ''}. Click to ${g.expanded ? 'hide' : 'show'} them on the graph.`}
              onClick={() =>
                setExpandedGhostTypes((prev) => {
                  const next = new Set(prev);
                  if (next.has(g.type)) next.delete(g.type); else next.add(g.type);
                  return next;
                })
              }
            >
              <span className={styles.ghostBarDot} style={{ background: getNodeColor(g.type) }} />
              {g.count} {g.count === 1 ? getEntityLabel(g.type) : getEntityPluralLabel(g.type)}
              {g.mitre ? ' · MITRE' : ''} <span className="caret-glyph">{g.expanded ? '▾' : '▸'}</span>
            </button>
          ))}
          {hiddenNodes.size > 0 && (
            <button
              className={styles.ghostBarPill}
              title="Nodes hidden from the inspector — click to bring them all back"
              onClick={() => setHiddenNodes(new Set())}
            >
              {hiddenNodes.size} hidden · reset
            </button>
          )}
        </div>
        <div className={styles.stripRight}>
          {storyLayout && (
            <div className={styles.layoutToggle}>
              <button
                className={layoutMode === 'story' ? styles.layoutToggleOn : ''}
                onClick={() => setLayoutMode('story')}
                title="Group by story (operations map)"
              >
                Stories
              </button>
              <button
                className={layoutMode === 'type' ? styles.layoutToggleOn : ''}
                onClick={() => setLayoutMode('type')}
                title="Group by entity type (rings)"
              >
                Rings
              </button>
            </div>
          )}
          <button className={styles.toolbarButton} onClick={() => { const s = Math.min(4, scale * 1.2); const r = s / scale; setTranslate((p) => ({ x: width/2 - r*(width/2 - p.x), y: height/2 - r*(height/2 - p.y) })); setScale(s); }} title="Zoom in">+</button>
          <button className={styles.toolbarButton} onClick={() => { const s = Math.max(0.2, scale / 1.2); const r = s / scale; setTranslate((p) => ({ x: width/2 - r*(width/2 - p.x), y: height/2 - r*(height/2 - p.y) })); setScale(s); }} title="Zoom out">-</button>
          <button className={styles.toolbarButton} onClick={handleResetView} title="Fit to view">Fit</button>
          <button className={styles.toolbarButton} onClick={handleExport} title="Export as PNG">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
              <path d="M7.5 1.5a.5.5 0 0 1 1 0v7.79l2.15-2.14a.5.5 0 1 1 .7.7l-3 3a.5.5 0 0 1-.7 0l-3-3a.5.5 0 1 1 .7-.7L7.5 9.29V1.5zM2 11.5a.5.5 0 0 1 1 0v2a.5.5 0 0 0 .5.5h9a.5.5 0 0 0 .5-.5v-2a.5.5 0 0 1 1 0v2A1.5 1.5 0 0 1 12.5 15h-9A1.5 1.5 0 0 1 2 13.5v-2z"/>
            </svg>
          </button>
          <button
            className={`${styles.toolbarButton} ${isFullscreen ? styles.toolbarButtonActive : ''}`}
            onClick={() => setIsFullscreen(!isFullscreen)}
            title={isFullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen'}
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
              {isFullscreen
                ? <path d="M5.5 1a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1 0-1H5V1.5a.5.5 0 0 1 .5-.5zm5 0a.5.5 0 0 1 .5.5V4h2.5a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5v-3a.5.5 0 0 1 .5-.5zM1 10.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-1 0V11H1.5a.5.5 0 0 1-.5-.5zm9 0a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1H11v2.5a.5.5 0 0 1-1 0v-3z"/>
                : <path d="M1.5 1a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 1 0V2h2.5a.5.5 0 0 0 0-1h-3zm11 0a.5.5 0 0 0 0 1H15v2.5a.5.5 0 0 0 1 0v-3a.5.5 0 0 0-.5-.5h-3zM.5 11a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 0-1H1v-2.5a.5.5 0 0 0-1 0zm14 0a.5.5 0 0 0-1 0V14h-2.5a.5.5 0 0 0 0 1h3a.5.5 0 0 0 .5-.5v-3z"/>
              }
            </svg>
          </button>
          <button
            className={`${styles.toolbarButton} ${showSettings ? styles.toolbarButtonActive : ''}`}
            onClick={() => setShowSettings(!showSettings)}
            title="Settings"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
              <path d="M6.5 1a.5.5 0 0 0-.5.5v1.02a4.5 4.5 0 0 0-1.95 1.13l-.88-.51a.5.5 0 0 0-.68.18l-1 1.73a.5.5 0 0 0 .18.68l.88.51A4.5 4.5 0 0 0 2.5 8c0 .59.12 1.15.32 1.66l-.83.48a.5.5 0 0 0-.18.68l1 1.73a.5.5 0 0 0 .68.18l.83-.48c.5.49 1.12.87 1.82 1.09v1.16a.5.5 0 0 0 .5.5h2a.5.5 0 0 0 .5-.5v-1.16a4.5 4.5 0 0 0 1.82-1.09l.83.48a.5.5 0 0 0 .68-.18l1-1.73a.5.5 0 0 0-.18-.68l-.83-.48c.2-.51.32-1.07.32-1.66s-.12-1.15-.32-1.66l.83-.48a.5.5 0 0 0 .18-.68l-1-1.73a.5.5 0 0 0-.68-.18l-.83.48A4.5 4.5 0 0 0 9.14 2.52V1.5a.5.5 0 0 0-.5-.5h-2zM8 5.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5z"/>
            </svg>
          </button>
        </div>
      </div>

      {/* ── Inspector: what the selection is and what you can do with it ── */}
      {selected && (() => {
        if (selected.kind === 'node') {
          const node = nodeMap.get(selected.id) ?? nodes.find((n) => n.id === selected.id);
          if (!node) return null;
          const info = nodeInfo?.get(node.id);
          const isArticle = node.type === 'entry';
          const isSeed = node.id === seedId;
          return (
            <div className={styles.inspector}>
              <div className={styles.inspectorHead}>
                <span className={styles.legendDot} style={{ background: getNodeColor(node.type) }} />
                <span className={styles.inspectorTitle}>{node.label}</span>
                <button className={styles.inspectorClose} onClick={() => setSelected(null)}>&times;</button>
              </div>
              <div className={styles.inspectorMeta}>
                {isArticle ? 'Article' : getEntityLabel(node.type) || node.type.replace(/_/g, ' ')}
                {info?.trust ? ` · ${info.trust}` : ''}
              </div>
              {info?.phrase && <div className={styles.inspectorPhrase}>{info.phrase}</div>}
              {(info?.articles || info?.feeds) && (
                <div className={styles.inspectorMeta}>
                  {info.articles ? `${info.articles} art` : ''}
                  {info.feeds && info.feeds > 1 ? ` · ${info.feeds} feeds` : ''}
                </div>
              )}
              {(info?.kev || info?.covered !== undefined) && (
                <div className={styles.inspectorMeta}>
                  {info?.kev ? 'CISA KEV · ' : ''}
                  {info?.covered === true
                    ? `detection: covered ✓${info?.ruleCount ? ` · ${info.ruleCount} rule${info.ruleCount === 1 ? '' : 's'}` : ''}`
                    : info?.covered === false ? 'detection: no rule in library' : ''}
                </div>
              )}
              {info?.covered === true && (() => {
                const cr = coveringRules.get(node.id);
                if (cr === 'loading') return <div className={styles.inspectorMeta}>loading rules…</div>;
                if (!cr || cr.length === 0) return null;
                const more = (info.ruleCount ?? cr.length) - cr.length;
                return (
                  <div className={styles.inspectorRules}>
                    {cr.map((r) => (
                      <button key={r.id} className={styles.inspectorRuleBtn} onClick={() => onOpenRule?.(r.id)} title={r.title}>
                        <span className={styles.inspectorRuleTitle}>{r.title}</span>
                        <span className={styles.inspectorRuleType}>{r.rule_type}</span>
                      </button>
                    ))}
                    {more > 0 && <div className={styles.inspectorMeta}>+{more} more in the library</div>}
                  </div>
                );
              })()}
              {info?.description && <div className={styles.inspectorDesc}>{info.description}</div>}
              <div className={styles.inspectorActions}>
                {isArticle ? (
                  <button className={styles.inspectorBtn} onClick={() => onEntryClick?.(node.id.replace(/^entry-/, ''))}>
                    Open article →
                  </button>
                ) : (
                  !isSeed && (
                    <button className={styles.inspectorBtn} onClick={() => onNodeClick?.(node.id, node.type)}>
                      Open profile →
                    </button>
                  )
                )}
                {!storyActive && !isArticle && expandedNodes.has(node.id) && !isSeed && (
                  <button className={styles.inspectorBtn} onClick={() => collapseBranch(node.id)}>
                    Collapse branch
                  </button>
                )}
                {onToggleExpand && !isArticle && (
                  <button
                    className={styles.inspectorBtn}
                    onClick={() => onToggleExpand(node.id, node.type, !expansions?.has(node.id))}
                  >
                    {expansions?.has(node.id) ? 'Collapse connections' : 'Expand connections'}
                  </button>
                )}
                {!isSeed && (
                  <button
                    className={styles.inspectorBtn}
                    onClick={() => {
                      setHiddenNodes((prev) => new Set(prev).add(node.id));
                      setSelected(null);
                    }}
                  >
                    Hide from graph
                  </button>
                )}
              </div>
            </div>
          );
        }
        if (selected.kind === 'cluster') {
          const cluster = clusterById.get(selected.id);
          if (!cluster) return null;
          const members = cluster.nodeIds
            .map((id) => nodeMap.get(id) ?? nodes.find((n) => n.id === id))
            .filter(Boolean) as EntityNode[];
          return (
            <div className={styles.inspector}>
              <div className={styles.inspectorHead}>
                <span className={styles.inspectorTitle}>{cluster.heading}</span>
                <button className={styles.inspectorClose} onClick={() => setSelected(null)}>&times;</button>
              </div>
              <div className={styles.inspectorMeta}>
                Story · {cluster.articles} articles{cluster.corroborated ? ' · corroborated' : ''}
              </div>
              <div className={styles.inspectorActions}>
                {!cluster.external && (
                  <button className={styles.inspectorBtn} onClick={() => onClusterClick?.(cluster)}>
                    Filter list to this story
                  </button>
                )}
                {cluster.slug && onOpenThread && (
                  <button className={styles.inspectorBtn} onClick={() => onOpenThread(cluster.slug!)}>
                    Open story thread →
                  </button>
                )}
              </div>
              <div className={styles.inspectorList}>
                {members.map((m) => (
                  <button key={m.id} className={styles.inspectorRow} onClick={() => setSelected({ kind: 'node', id: m.id })}>
                    <span className={styles.legendDot} style={{ background: getNodeColor(m.type) }} />
                    {truncateLabel(m.label, 26)}
                  </button>
                ))}
              </div>
            </div>
          );
        }
        // edge
        const edge = visibleEdges[selected.idx];
        if (!edge) return null;
        const sourceNode = nodeMap.get(edge.source);
        const targetNode = nodeMap.get(edge.target);
        return (
          <div className={styles.inspector}>
            <div className={styles.inspectorHead}>
              <span className={styles.inspectorTitle}>
                {sourceNode ? truncateLabel(sourceNode.label, 14) : '?'} — {edge.label} —{' '}
                {targetNode ? truncateLabel(targetNode.label, 14) : '?'}
              </span>
              <button className={styles.inspectorClose} onClick={() => setSelected(null)}>&times;</button>
            </div>
            <div className={styles.inspectorMeta}>
              {edge.entries?.length ?? 0} linking article{(edge.entries?.length ?? 0) === 1 ? '' : 's'}
              {edge.confidence ? ` · ${edge.confidence}` : ''}
              {edge.provenance === 'analyst_confirmed' ? ' ✓' : edge.provenance === 'co_occurrence' ? ' · inferred' : ''}
            </div>
            <div className={styles.inspectorList}>
              {(edge.entries ?? []).map((entry) => (
                <button
                  key={entry.entry_id}
                  className={styles.inspectorRow}
                  onClick={() => onEntryClick?.(entry.entry_id)}
                  title={entry.title}
                >
                  {truncateLabel(entry.title || 'Untitled', 34)}
                </button>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Legend doubles as the type filter — click to hide/show a type. */}
      <div className={styles.legend}>
        {Array.from(entityTypes.keys()).map((type) => {
          const off = hiddenTypes.has(type);
          return (
            <button
              key={type}
              className={`${styles.legendItem} ${styles.legendItemBtn} ${off ? styles.legendItemOff : ''}`}
              onClick={() => toggleType(type)}
              title={off ? `Show ${getEntityLabel(type) || type}` : `Hide ${getEntityLabel(type) || type}`}
            >
              <span className={styles.legendDot} style={{ background: off ? 'var(--text-muted)' : getNodeColor(type) }} />
              <span className={styles.legendLabel}>
                {type === 'entry' ? 'Article' : (getEntityLabel(type) || type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()))}
              </span>
            </button>
          );
        })}
      </div>

      {/* Interaction hint */}
      <div className={styles.edgeHint}>
        {edgeDraft
          ? 'Release on a node to create relationship'
          : storyActive
            ? `Click to inspect · double-click to open · drag hulls to move${onEdgeCreate ? ' · Shift+drag to link' : ''}`
            : `Click to inspect & expand · double-click to open${onEdgeCreate ? ' · Shift+drag to link' : ''}`
        }
      </div>

      {/* Settings panel — only the knobs the active layout uses. */}
      {showSettings && (
        <div className={styles.settingsPanel}>
          <div className={styles.settingsPanelHeader}>
            <span>Graph Settings</span>
            <button className={styles.settingsPanelClose} onClick={() => setShowSettings(false)}>&times;</button>
          </div>

          {!storyActive && (
            <div className={styles.settingsSection}>
              <div className={styles.settingsSectionTitle}>
                Nodes per Type
                <span className={styles.settingsSliderValue}>{nodesPerType}</span>
              </div>
              <input type="range" className={styles.settingsSlider} min={1} max={20} value={nodesPerType} onChange={(e) => setNodesPerType(Number(e.target.value))} />
              <div className={styles.settingsSliderRange}><span>1</span><span>20</span></div>
            </div>
          )}

          <div className={styles.settingsSection}>
            <div className={styles.settingsSectionTitle}>
              {storyActive ? 'Cluster Spacing' : 'Node Spacing'}
              <span className={styles.settingsSliderValue}>{ringSpacing.toFixed(1)}x</span>
            </div>
            <input type="range" className={styles.settingsSlider} min={0.5} max={8.0} step={0.1} value={ringSpacing} onChange={(e) => setRingSpacing(Number(e.target.value))} />
            <div className={styles.settingsSliderRange}><span>Compact</span><span>Spread</span></div>
          </div>

          <div className={styles.settingsSection}>
            <div className={styles.settingsSectionTitle}>Display</div>
            {!storyActive && (
              <>
                <label className={styles.settingsCheckbox}><input type="checkbox" checked={showRingGuides} onChange={() => setShowRingGuides(!showRingGuides)} /><span className={styles.settingsOptionLabel}>Ring guides</span></label>
                <label className={styles.settingsCheckbox}><input type="checkbox" checked={showArcLabels} onChange={() => setShowArcLabels(!showArcLabels)} /><span className={styles.settingsOptionLabel}>Arc labels</span></label>
              </>
            )}
            <label className={styles.settingsCheckbox}><input type="checkbox" checked={showNodeLabels} onChange={() => setShowNodeLabels(!showNodeLabels)} /><span className={styles.settingsOptionLabel}>Node labels</span></label>
            <label className={styles.settingsCheckbox}><input type="checkbox" checked={showEdgeLabels} onChange={() => setShowEdgeLabels(!showEdgeLabels)} /><span className={styles.settingsOptionLabel}>Edge labels</span></label>
            {!storyActive && (
              <div className={styles.settingsButtons}>
                <button className={styles.settingsMiniButton} onClick={() => {
                  const all = new Map<string, string | null>([[nodes[0]?.id, null]]);
                  for (const n of nodes) { if (!all.has(n.id)) all.set(n.id, nodes[0]?.id ?? null); }
                  setExpandedNodes(all);
                }}>Expand All</button>
                <button className={styles.settingsMiniButton} onClick={() => setExpandedNodes(new Map(nodes[0] ? [[nodes[0].id, null]] : []))}>Collapse</button>
              </div>
            )}
          </div>

          <div className={styles.settingsStats}>
            {visibleNodeCount} nodes &middot; {visibleEdgeCount} edges
          </div>
        </div>
      )}
    </div>
  );
}
