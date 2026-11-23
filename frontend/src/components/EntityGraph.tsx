import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Background,
  BackgroundVariant,
  ConnectionLineType,
  ConnectionMode,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  getNodesBounds,
  getViewportForBounds,
  useNodesState,
  useReactFlow,
  type Connection,
  type Node,
  type NodeMouseHandler,
  type EdgeMouseHandler,
  type OnNodeDrag,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { toPng } from 'html-to-image';
import { getEntityLabel, getEntityPluralLabel } from '@/utils/entityTheme';
import {
  computeNetworkLayout,
  computeStoryLayout,
  nodeRadius,
  type GraphStoryCluster,
  type LayoutEdge,
  type LayoutNode,
  type Point,
} from './entityGraph/layout';
import {
  EntityNodeView,
  FloatingEdgeView,
  GraphViewContext,
  StoryNodeView,
  getNodeColor,
  truncateLabel,
  type EntityFlowEdge,
  type EntityFlowNode,
  type GraphView,
  type StoryFlowNode,
} from './entityGraph/graphView';
import styles from './EntityGraph.module.css';

// Re-export for consumers that import from here
export type EntityNode = LayoutNode;
export type EntityEdge = LayoutEdge;
export type { GraphStoryCluster };

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
  /** When provided, the graph offers a "story" layout (default) that groups
   * nodes by incident inside labeled boxes — same nodes, edges, and
   * interactions as the network layout. */
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
  | { kind: 'edge'; id: string }
  | null;

const nodeTypes = { entity: EntityNodeView, story: StoryNodeView };
const edgeTypes = { floating: FloatingEdgeView };
const STORY_PREFIX = 'story:';

/** "3 Articles" / "1 Malware" — graph-only `entry` nodes are articles. */
function typeCount(type: string, n: number): string {
  if (type === 'entry') return `${n} ${n === 1 ? 'Article' : 'Articles'}`;
  return `${n} ${n === 1 ? getEntityLabel(type) : getEntityPluralLabel(type)}`;
}

export function EntityGraph(props: EntityGraphProps) {
  return (
    <ReactFlowProvider>
      <EntityGraphInner {...props} />
    </ReactFlowProvider>
  );
}

function EntityGraphInner({
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
  const containerRef = useRef<HTMLDivElement>(null);
  const flow = useReactFlow();

  // Selection is the graph's core interaction: click selects (node, cluster,
  // or edge) and the inspector explains it; double-click navigates. Nothing
  // navigates on a single click.
  const [selected, setSelected] = useState<Selected>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Per-node hide (inspector action); the strip shows a reset pill.
  const [hiddenNodes, setHiddenNodes] = useState<Set<string>>(new Set());

  // --- Fullscreen ---
  const [isFullscreen, setIsFullscreen] = useState(false);
  useEffect(() => {
    if (!isFullscreen) return;
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') setIsFullscreen(false); };
    document.addEventListener('keydown', handler);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', handler);
      document.body.style.overflow = '';
    };
  }, [isFullscreen]);

  // --- Settings ---
  const [showSettings, setShowSettings] = useState(false);
  const [layoutMode, setLayoutMode] = useState<'story' | 'network'>('story');
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [showNodeLabels, setShowNodeLabels] = useState(true);
  const [showEdgeLabels, setShowEdgeLabels] = useState(false);
  const [nodesPerType, setNodesPerType] = useState(8);
  const [spacing, setSpacing] = useState(1.0);
  // Story-less claim types the user chose to show from their pill.
  const [expandedGhostTypes, setExpandedGhostTypes] = useState<Set<string>>(new Set());

  // Shift held = drawing a link (only when links can be created).
  const [linking, setLinking] = useState(false);
  useEffect(() => {
    if (!onEdgeCreate) return;
    const sync = (e: KeyboardEvent) => setLinking(e.shiftKey);
    const off = () => setLinking(false);
    window.addEventListener('keydown', sync);
    window.addEventListener('keyup', sync);
    window.addEventListener('blur', off);
    return () => {
      window.removeEventListener('keydown', sync);
      window.removeEventListener('keyup', sync);
      window.removeEventListener('blur', off);
    };
  }, [onEdgeCreate]);

  // Where each node ended up last layout (graph-space centers), so the next
  // layout starts from there, and positions the user dragged by hand.
  const previousRef = useRef<Map<string, Point>>(new Map());
  const draggedRef = useRef<Map<string, { x: number; y: number; parentId?: string }>>(new Map());

  // Reset when the seed entity changes — node ids recur across profiles (the
  // same country appears on many maps), so stale drags and pill expansions
  // from the previous profile must not carry over.
  const seedId = nodes[0]?.id;
  const prevSeedRef = useRef(seedId);
  useEffect(() => {
    if (seedId && seedId !== prevSeedRef.current) {
      prevSeedRef.current = seedId;
      setSelected(null);
      setHiddenNodes(new Set());
      setExpandedGhostTypes(new Set());
      previousRef.current = new Map();
      draggedRef.current = new Map();
    }
  }, [seedId]);

  // ── Merge on-demand expansions into the base graph ─────────────
  // Expanded nodes' claims and stories join the SAME node/edge/cluster sets
  // the layout consumes — no parallel rendering path, so expanding an
  // expansion node just works (any node is a real node).
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
  const nodeById = useMemo(() => new Map(allNodes.map((n) => [n.id, n])), [allNodes]);

  // Edge ids stay stable across layouts: endpoints + label, with a counter
  // only when the same pair carries the same label twice.
  const keyedEdges = useMemo(() => {
    const count = new Map<string, number>();
    return allEdges.map((edge) => {
      const base = `${edge.source}>${edge.target}:${edge.label}`;
      const n = count.get(base) ?? 0;
      count.set(base, n + 1);
      return { id: n ? `${base}#${n}` : base, edge };
    });
  }, [allEdges]);

  // Nodes from expansions are always shown in the network layout — the user
  // asked for them; the per-type cap is for the seed's own neighbors.
  const expansionIds = useMemo(() => {
    const s = new Set<string>();
    if (expansions) for (const [id, ex] of expansions) { s.add(id); for (const n of ex.nodes) s.add(n.id); }
    return s;
  }, [expansions]);

  // What each expansion brought in, keyed back to the node expanded, so the
  // story layout draws it beside that node.
  const { anchorOf, clusterAnchor } = useMemo(() => {
    const anchorOf = new Map<string, string>();
    const clusterAnchor = new Map<string, string>();
    if (expansions) {
      const base = new Set(nodes.map((n) => n.id));
      for (const [anchor, ex] of expansions) {
        for (const n of ex.nodes) if (!base.has(n.id) && !anchorOf.has(n.id)) anchorOf.set(n.id, anchor);
        for (const c of ex.clusters ?? []) clusterAnchor.set(c.id, anchor);
      }
    }
    return { anchorOf, clusterAnchor };
  }, [nodes, expansions]);

  // ── Layout ─────────────────────────────────────────────────────
  const storyLayout = useMemo(() => computeStoryLayout({
    nodes: allNodes,
    edges: allEdges,
    clusters: allClusters,
    seedId: seedId ?? '',
    hiddenTypes,
    hiddenNodes,
    expandedGhostTypes,
    anchorOf,
    clusterAnchor,
    spacing,
    labels: showNodeLabels,
    previous: previousRef.current,
  }), [allNodes, allEdges, allClusters, seedId, hiddenTypes, hiddenNodes, expandedGhostTypes, anchorOf, clusterAnchor, spacing, showNodeLabels]);

  const storyActive = layoutMode === 'story' && storyLayout !== null;

  const networkLayout = useMemo(() => storyActive ? null : computeNetworkLayout({
    nodes: allNodes,
    edges: allEdges,
    seedId: seedId ?? '',
    hiddenTypes,
    hiddenNodes,
    nodesPerType,
    capExempt: expansionIds,
    spacing,
    labels: showNodeLabels,
    previous: previousRef.current,
  }), [storyActive, allNodes, allEdges, seedId, hiddenTypes, hiddenNodes, nodesPerType, expansionIds, spacing, showNodeLabels]);

  const positions = storyActive ? storyLayout!.positions : networkLayout!.positions;

  const visibleIds = useMemo(() => new Set(positions.keys()), [positions]);
  const visibleEdges = useMemo(
    () => keyedEdges.filter(({ edge }) => visibleIds.has(edge.source) && visibleIds.has(edge.target)),
    [keyedEdges, visibleIds],
  );

  // Manual placements belong to a coordinate space: switching layouts drops them.
  const modeRef = useRef(storyActive);
  if (modeRef.current !== storyActive) {
    modeRef.current = storyActive;
    draggedRef.current = new Map();
  }

  // ── React Flow nodes ───────────────────────────────────────────
  const [flowNodes, setFlowNodes, onNodesChange] = useNodesState<Node>([]);

  useEffect(() => {
    previousRef.current = new Map(positions);
    if (storyActive) {
      for (const g of storyLayout!.groups) {
        previousRef.current.set(`${STORY_PREFIX}${g.cluster.id}`, { x: g.x + g.w / 2, y: g.y + g.h / 2 });
      }
    }

    const dragged = draggedRef.current;
    const out: Node[] = [];
    const groupAt = new Map<string, { x: number; y: number }>();
    if (storyActive) {
      for (const g of storyLayout!.groups) {
        const id = `${STORY_PREFIX}${g.cluster.id}`;
        groupAt.set(g.cluster.id, { x: g.x, y: g.y });
        const hand = dragged.get(id);
        out.push({
          id,
          type: 'story',
          position: hand ? { x: hand.x, y: hand.y } : { x: g.x, y: g.y },
          data: { cluster: g.cluster },
          style: { width: g.w, height: g.h },
        } satisfies StoryFlowNode);
      }
    }
    for (const [id, p] of positions) {
      const node = nodeById.get(id);
      if (!node) continue;
      const r = nodeRadius(node, id === seedId);
      const clusterId = storyActive ? storyLayout!.memberOf.get(id) : undefined;
      const parentId = clusterId ? `${STORY_PREFIX}${clusterId}` : undefined;
      const origin = clusterId ? groupAt.get(clusterId)! : { x: 0, y: 0 };
      const hand = dragged.get(id);
      out.push({
        id,
        type: 'entity',
        position: hand && hand.parentId === parentId
          ? { x: hand.x, y: hand.y }
          : { x: p.x - origin.x - r, y: p.y - origin.y - r },
        data: { node, r },
        ...(parentId ? { parentId, extent: 'parent' as const } : {}),
      } satisfies EntityFlowNode);
    }
    setFlowNodes(out);
  }, [positions, storyActive, storyLayout, nodeById, seedId, setFlowNodes]);

  const flowEdges = useMemo<EntityFlowEdge[]>(
    () => visibleEdges.map(({ id, edge }) => ({ id, source: edge.source, target: edge.target, type: 'floating', data: { edge } })),
    [visibleEdges],
  );

  // Fit when the set of visible things changes (not on drags or hover).
  const fitKey = `${storyActive}|${[...visibleIds].sort().join(',')}|${spacing}|${isFullscreen}`;
  useEffect(() => {
    const t = setTimeout(() => flow.fitView({ padding: 0.12, maxZoom: 1.25, duration: 250 }), 30);
    return () => clearTimeout(t);
  }, [fitKey, flow]);

  const onNodeDragStop: OnNodeDrag = useCallback((_e, node) => {
    draggedRef.current.set(node.id, { x: node.position.x, y: node.position.y, parentId: node.parentId });
  }, []);

  // ── Derived view state ─────────────────────────────────────────
  const hover = useMemo(() => {
    if (!hoveredNodeId) return null;
    const ns = new Set<string>([hoveredNodeId]);
    const es = new Set<string>();
    for (const { id, edge } of visibleEdges) {
      if (edge.source === hoveredNodeId || edge.target === hoveredNodeId) {
        es.add(id);
        ns.add(edge.source);
        ns.add(edge.target);
      }
    }
    return { nodes: ns, edges: es };
  }, [hoveredNodeId, visibleEdges]);

  // Search highlight: matching nodes stay lit, the rest recede. The tab's
  // search box drives this — no separate find UI.
  const hq = (highlightQuery ?? '').trim().toLowerCase();
  const searchMatches = useMemo(() => {
    if (!hq) return null;
    return new Set(allNodes.filter((n) => visibleIds.has(n.id) && n.label.toLowerCase().includes(hq)).map((n) => n.id));
  }, [hq, allNodes, visibleIds]);

  // The +/− badge: load a node's own connections, or fold them away again.
  const expandable = useCallback(
    (id: string) => !!onToggleExpand && id !== seedId && nodeById.get(id)?.type !== 'entry',
    [onToggleExpand, seedId, nodeById],
  );
  const isExpanded = useCallback((id: string) => !!expansions?.has(id), [expansions]);
  const toggleExpand = useCallback((id: string) => {
    const node = nodeById.get(id);
    if (node && onToggleExpand) onToggleExpand(id, node.type, !expansions?.has(id));
  }, [nodeById, onToggleExpand, expansions]);

  const view = useMemo<GraphView>(() => ({
    seedId,
    selectedNodeId: selected?.kind === 'node' ? selected.id : null,
    selectedClusterId: selected?.kind === 'cluster' ? selected.id : null,
    selectedEdgeId: selected?.kind === 'edge' ? selected.id : null,
    hover,
    hoveredNodeId,
    searchMatches,
    nodeInfo,
    showNodeLabels,
    showEdgeLabels,
    linking,
    expandable,
    isExpanded,
    toggleExpand,
  }), [seedId, selected, hover, hoveredNodeId, searchMatches, nodeInfo, showNodeLabels, showEdgeLabels, linking, expandable, isExpanded, toggleExpand]);

  // Detection rules covering the selected ttp/cve node — fetched lazily on
  // first selection, cached per node id for the life of the component.
  const [coveringRules, setCoveringRules] = useState<Map<string, CoveringRule[] | 'loading'>>(new Map());
  useEffect(() => {
    if (!onFetchCoveringRules || !selected || selected.kind !== 'node') return;
    const id = selected.id;
    if (!nodeInfo?.get(id)?.covered || coveringRules.has(id)) return;
    const node = nodeById.get(id);
    if (!node || (node.type !== 'ttp' && node.type !== 'cve')) return;
    setCoveringRules((prev) => new Map(prev).set(id, 'loading'));
    onFetchCoveringRules(node)
      .then((rules) => setCoveringRules((prev) => new Map(prev).set(id, rules)))
      .catch(() => setCoveringRules((prev) => new Map(prev).set(id, [])));
  }, [selected, onFetchCoveringRules, nodeInfo, nodeById, coveringRules]);

  // Entity type counts (from ALL nodes, not just visible)
  const entityTypes = useMemo(() => {
    const types = new Map<string, number>();
    for (const n of allNodes) types.set(n.type, (types.get(n.type) ?? 0) + 1);
    return types;
  }, [allNodes]);

  // Which node marks the legend needs to explain.
  const marks = useMemo(() => {
    let coverage = false;
    let kev = false;
    for (const id of visibleIds) {
      const ni = nodeInfo?.get(id);
      if (ni?.covered !== undefined) coverage = true;
      if (ni?.kev) kev = true;
    }
    return { coverage, kev };
  }, [visibleIds, nodeInfo]);

  // ── Interaction handlers ───────────────────────────────────────
  const handleNodeClick: NodeMouseHandler = useCallback((_e, n) => {
    if (n.id.startsWith(STORY_PREFIX)) {
      setSelected({ kind: 'cluster', id: n.id.slice(STORY_PREFIX.length) });
      return;
    }
    const node = nodeById.get(n.id);
    if (!node) return;
    // Click only selects. Loading a node's connections is the +/− badge (or
    // the inspector), so inspecting never grows the graph by accident.
    setSelected({ kind: 'node', id: node.id });
  }, [nodeById]);

  // Double-click opens the node's own page (profile / article).
  const handleNodeDoubleClick: NodeMouseHandler = useCallback((_e, n) => {
    const node = nodeById.get(n.id);
    if (!node) return;
    if (node.type === 'entry') onEntryClick?.(node.id.replace(/^entry-/, ''));
    else onNodeClick?.(node.id, node.type);
  }, [nodeById, onNodeClick, onEntryClick]);

  const handleEdgeClick: EdgeMouseHandler = useCallback((_e, edge) => {
    const data = (edge as EntityFlowEdge).data;
    if (!data?.edge.entries?.length) return;
    setSelected((prev) => (prev?.kind === 'edge' && prev.id === edge.id ? null : { kind: 'edge', id: edge.id }));
  }, []);

  const handleConnect = useCallback((c: Connection) => {
    if (!onEdgeCreate || !c.source || !c.target || c.source === c.target) return;
    onEdgeCreate(c.source, nodeById.get(c.source)?.type ?? '', c.target, nodeById.get(c.target)?.type ?? '');
  }, [onEdgeCreate, nodeById]);

  const onNodeMouseEnter: NodeMouseHandler = useCallback((_e, n) => {
    if (!n.id.startsWith(STORY_PREFIX)) setHoveredNodeId(n.id);
  }, []);
  const onNodeMouseLeave: NodeMouseHandler = useCallback(() => setHoveredNodeId(null), []);

  // --- Export the current graph as a PNG ---
  const handleExport = useCallback(() => {
    const viewport = containerRef.current?.querySelector<HTMLElement>('.react-flow__viewport');
    if (!viewport) return;
    const bounds = getNodesBounds(flow.getNodes());
    const w = Math.min(4000, Math.max(800, bounds.width + 160));
    const h = Math.min(4000, Math.max(600, bounds.height + 160));
    const vp = getViewportForBounds(bounds, w, h, 0.1, 2, 0.08);
    let bg = getComputedStyle(containerRef.current!).backgroundColor;
    if (!bg || bg === 'rgba(0, 0, 0, 0)') bg = getComputedStyle(document.body).backgroundColor || '#101318';
    toPng(viewport, {
      backgroundColor: bg,
      width: w,
      height: h,
      pixelRatio: 2,
      style: { width: `${w}px`, height: `${h}px`, transform: `translate(${vp.x}px, ${vp.y}px) scale(${vp.zoom})` },
    }).then((url) => {
      const a = document.createElement('a');
      a.href = url;
      a.download = `${nodes[0]?.label?.toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'graph'}-graph.png`;
      a.click();
    }).catch(() => { /* export is best-effort */ });
  }, [flow, nodes]);

  // --- Toggle type filter (the legend is the control) ---
  const toggleType = useCallback((type: string) => {
    setHiddenTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type); else next.add(type);
      return next;
    });
  }, []);

  // ── Empty state ────────────────────────────────────────────────
  if (nodes.length === 0) {
    return (
      <div ref={containerRef} className={styles.container} style={{ width: widthProp, height: heightProp }}>
        <div className={styles.emptyState}>No entities to display</div>
      </div>
    );
  }

  // ── Render ─────────────────────────────────────────────────────
  const containerClassName = [
    styles.container,
    isFullscreen ? styles.fullscreen : '',
    linking ? styles.linking : '',
  ].filter(Boolean).join(' ');
  const showMiniMap = (isFullscreen || heightProp >= 400) && !selected && !showSettings;

  return (
    <div
      ref={containerRef}
      className={containerClassName}
      style={isFullscreen ? undefined : { width: widthProp, height: heightProp }}
    >
      <GraphViewContext.Provider value={view}>
        <ReactFlow
          className={styles.flow}
          nodes={flowNodes}
          edges={flowEdges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodesChange={onNodesChange}
          onNodeDragStop={onNodeDragStop}
          onNodeClick={handleNodeClick}
          onNodeDoubleClick={handleNodeDoubleClick}
          onNodeMouseEnter={onNodeMouseEnter}
          onNodeMouseLeave={onNodeMouseLeave}
          onEdgeClick={handleEdgeClick}
          onPaneClick={() => setSelected(null)}
          onConnect={handleConnect}
          nodesConnectable={!!onEdgeCreate}
          connectionMode={ConnectionMode.Loose}
          connectionLineType={ConnectionLineType.Straight}
          connectionLineStyle={{ stroke: 'var(--accent)', strokeWidth: 2, strokeDasharray: '6 4' }}
          connectionRadius={40}
          elementsSelectable={false}
          deleteKeyCode={null}
          zoomOnDoubleClick={false}
          minZoom={0.08}
          maxZoom={3}
          attributionPosition="bottom-center"
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--border)" />
          {showMiniMap && (
            <MiniMap
              className={styles.minimap}
              pannable
              zoomable
              nodeColor={(n) => (n.type === 'story' ? 'transparent' : getNodeColor((n as EntityFlowNode).data.node.type))}
              nodeStrokeColor={(n) => (n.type === 'story' ? 'var(--accent-intel)' : 'transparent')}
              maskColor="color-mix(in srgb, var(--bg-primary) 70%, transparent)"
            />
          )}
        </ReactFlow>
      </GraphViewContext.Provider>

      {/* ── Top strip: pills left, tools right — the graph's one toolbar ── */}
      <div className={styles.topStrip}>
        <div className={styles.stripLeft}>
          {storyActive && storyLayout!.ghosts.length > 0 && <span className={styles.stripLabel}>Not in a story</span>}
          {storyActive && storyLayout!.ghosts.map((g) => (
            <button
              key={g.type}
              className={`${styles.ghostBarPill} ${g.expanded ? styles.ghostBarPillOn : ''}`}
              title={`Relationships not in any story. They are in the list below${g.mitre ? ' and the ATT&CK tab' : ''}. Click to ${g.expanded ? 'hide' : 'show'} them on the graph.`}
              onClick={() =>
                setExpandedGhostTypes((prev) => {
                  const next = new Set(prev);
                  if (next.has(g.type)) next.delete(g.type); else next.add(g.type);
                  return next;
                })
              }
            >
              <span className={styles.ghostBarDot} style={{ background: getNodeColor(g.type) }} />
              {typeCount(g.type, g.count)}
              {g.mitre ? ' · MITRE' : ''} <span className="caret-glyph">{g.expanded ? '▾' : '▸'}</span>
            </button>
          ))}
          {!storyActive && networkLayout && networkLayout.overflow.size > 0 && <span className={styles.stripLabel}>Not shown</span>}
          {!storyActive && networkLayout && [...networkLayout.overflow].map(([type, count]) => (
            <button
              key={type}
              className={styles.ghostBarPill}
              title={`${count} more ${getEntityPluralLabel(type) || type} not on the graph. Click to show more of each type.`}
              onClick={() => setNodesPerType((n) => Math.min(n + 8, 60))}
            >
              <span className={styles.ghostBarDot} style={{ background: getNodeColor(type) }} />
              +{typeCount(type, count)}
            </button>
          ))}
          {hiddenNodes.size > 0 && (
            <button
              className={styles.ghostBarPill}
              title="Nodes you hid. Click to show them all again."
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
                title="Group by story"
              >
                Stories
              </button>
              <button
                className={layoutMode === 'network' ? styles.layoutToggleOn : ''}
                onClick={() => setLayoutMode('network')}
                title="Every node and edge, arranged by its connections"
              >
                Network
              </button>
            </div>
          )}
          <button className={styles.toolbarButton} onClick={() => flow.zoomIn({ duration: 150 })} title="Zoom in">+</button>
          <button className={styles.toolbarButton} onClick={() => flow.zoomOut({ duration: 150 })} title="Zoom out">-</button>
          <button className={styles.toolbarButton} onClick={() => flow.fitView({ padding: 0.12, maxZoom: 1.25, duration: 250 })} title="Fit to view">Fit</button>
          <button
            className={styles.toolbarButton}
            onClick={() => {
              draggedRef.current = new Map();
              previousRef.current = new Map();
              // A new (equal) set makes both layouts recompute from scratch.
              setHiddenNodes((prev) => new Set(prev));
            }}
            title="Undo manual moves and lay the graph out again"
          >
            Re-layout
          </button>
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
          const node = nodeById.get(selected.id);
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
                  {info.articles ? `${info.articles} article${info.articles === 1 ? '' : 's'}` : ''}
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
              {(() => {
                const stories = allClusters.filter((c) => c.nodeIds.includes(node.id));
                if (stories.length === 0) return null;
                return (
                  <div className={styles.inspectorList}>
                    <div className={styles.inspectorMeta}>Stories</div>
                    {stories.map((c) => (
                      <button key={c.id} className={styles.inspectorRow} onClick={() => setSelected({ kind: 'cluster', id: c.id })} title={c.heading}>
                        {truncateLabel(c.heading, 34)} · {c.articles}
                      </button>
                    ))}
                  </div>
                );
              })()}
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
                {onToggleExpand && !isArticle && !isSeed && (
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
          const members = cluster.nodeIds.map((id) => nodeById.get(id)).filter(Boolean) as EntityNode[];
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
              {cluster.entries && cluster.entries.length > 0 && onEntryClick && (
                <div className={styles.inspectorList}>
                  <div className={styles.inspectorMeta}>Articles</div>
                  {cluster.entries.map((e) => (
                    <button key={e.entry_id} className={styles.inspectorRow} onClick={() => onEntryClick(e.entry_id)} title={e.title}>
                      {truncateLabel(e.title, 34)}
                    </button>
                  ))}
                </div>
              )}
              <div className={styles.inspectorList}>
                <div className={styles.inspectorMeta}>Entities</div>
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
        const edge = visibleEdges.find((e) => e.id === selected.id)?.edge;
        if (!edge) return null;
        const sourceNode = nodeById.get(edge.source);
        const targetNode = nodeById.get(edge.target);
        return (
          <div className={styles.inspector}>
            <div className={styles.inspectorHead}>
              <span className={styles.inspectorTitle}>
                {sourceNode ? truncateLabel(sourceNode.label, 14) : '?'} · {edge.label} ·{' '}
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
        {marks.coverage && (
          <>
            <span className={styles.legendItem} title="A detection rule in the library covers this technique or CVE">
              <svg width="8" height="8"><circle cx="4" cy="4" r="3" fill="var(--success)" /></svg>
              <span className={`${styles.legendLabel} ${styles.legendMark}`}>Has a rule</span>
            </span>
            <span className={styles.legendItem} title="No detection rule in the library covers this technique or CVE">
              <svg width="8" height="8"><circle cx="4" cy="4" r="3" fill="none" stroke="var(--danger)" strokeWidth="1.3" /></svg>
              <span className={`${styles.legendLabel} ${styles.legendMark}`}>No rule</span>
            </span>
          </>
        )}
        {marks.kev && (
          <span className={styles.legendItem} title="On the CISA Known Exploited Vulnerabilities list">
            <svg width="12" height="12"><circle cx="6" cy="6" r="5" fill="none" stroke="var(--danger)" strokeWidth="1.5" /></svg>
            <span className={`${styles.legendLabel} ${styles.legendMark}`}>KEV</span>
          </span>
        )}
      </div>

      {/* Interaction hint */}
      {!showMiniMap && (
        <div className={styles.edgeHint}>
          {linking
            ? 'Drag from a node to another node to create a relationship'
            : `Click to inspect · double-click to open${onToggleExpand ? ' · + loads connections' : ''} · drag to move${onEdgeCreate ? ' · Shift+drag to link' : ''}`}
        </div>
      )}

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
              <input type="range" className={styles.settingsSlider} min={1} max={60} value={nodesPerType} onChange={(e) => setNodesPerType(Number(e.target.value))} />
              <div className={styles.settingsSliderRange}><span>1</span><span>60</span></div>
            </div>
          )}

          <div className={styles.settingsSection}>
            <div className={styles.settingsSectionTitle}>
              Spacing
              <span className={styles.settingsSliderValue}>{spacing.toFixed(1)}x</span>
            </div>
            <input type="range" className={styles.settingsSlider} min={0.5} max={4.0} step={0.1} value={spacing} onChange={(e) => setSpacing(Number(e.target.value))} />
            <div className={styles.settingsSliderRange}><span>Compact</span><span>Spread</span></div>
          </div>

          <div className={styles.settingsSection}>
            <div className={styles.settingsSectionTitle}>Display</div>
            <label className={styles.settingsCheckbox}><input type="checkbox" checked={showNodeLabels} onChange={() => setShowNodeLabels(!showNodeLabels)} /><span className={styles.settingsOptionLabel}>Node labels</span></label>
            <label className={styles.settingsCheckbox}><input type="checkbox" checked={showEdgeLabels} onChange={() => setShowEdgeLabels(!showEdgeLabels)} /><span className={styles.settingsOptionLabel}>Edge labels</span></label>
          </div>

          <div className={styles.settingsStats}>
            {visibleIds.size} nodes &middot; {visibleEdges.length} edges
          </div>
        </div>
      )}
    </div>
  );
}
