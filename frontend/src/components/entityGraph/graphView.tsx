/**
 * React Flow node and edge components for the entity graph.
 *
 * Hover, selection, search and display toggles live in one context rather
 * than in each node's `data`, so hovering a node re-renders the nodes that
 * read the context instead of rebuilding the whole node array.
 */
import { createContext, memo, useContext } from 'react';
import {
  BaseEdge,
  EdgeLabelRenderer,
  Handle,
  Position,
  useInternalNode,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import { getEntityColor } from '@/utils/entityTheme';
import { LABEL_W, polygonPoints, type GraphStoryCluster, type LayoutEdge, type LayoutNode } from './layout';
import type { GraphNodeInfo } from '../EntityGraph';
import styles from '../EntityGraph.module.css';

// ── Shared view state ──────────────────────────────────────────────

export interface GraphView {
  seedId: string | undefined;
  selectedNodeId: string | null;
  selectedClusterId: string | null;
  selectedEdgeId: string | null;
  /** Hovered node plus its neighbors and the edges between them. */
  hover: { nodes: Set<string>; edges: Set<string> } | null;
  hoveredNodeId: string | null;
  searchMatches: Set<string> | null;
  nodeInfo?: Map<string, GraphNodeInfo>;
  showNodeLabels: boolean;
  showEdgeLabels: boolean;
  /** Shift is held and links can be drawn. */
  linking: boolean;
  /** Whether a node gets the +/− badge for loading its own connections. */
  expandable: (nodeId: string) => boolean;
  isExpanded: (nodeId: string) => boolean;
  toggleExpand: (nodeId: string) => void;
}

export const GraphViewContext = createContext<GraphView | null>(null);

function useGraphView(): GraphView {
  const v = useContext(GraphViewContext);
  if (!v) throw new Error('GraphViewContext missing');
  return v;
}

export function getNodeColor(type: string): string {
  if (type === 'entry') return '#6b7280';
  return getEntityColor(type);
}

export function truncateLabel(label: string, maxLen: number = 18): string {
  if (label.length <= maxLen) return label;
  return label.slice(0, maxLen - 1) + '…';
}

// ── Entity node ────────────────────────────────────────────────────

export type EntityFlowNode = Node<{ node: LayoutNode; r: number }, 'entity'>;

function shape(type: string, c: number, r: number, color: string, className: string) {
  const p = { className, fill: color };
  switch (type) {
    case 'malware':
      return <polygon {...p} points={polygonPoints(c, c, r, 6)} />;
    case 'ttp':
      return <rect {...p} x={c - r * 0.8} y={c - r * 0.8} width={r * 1.6} height={r * 1.6} rx={3} ry={3} />;
    case 'cve':
      return <polygon {...p} points={polygonPoints(c, c, r, 3)} />;
    case 'entry':
      return <rect {...p} className={`${className} ${styles.articleNode}`} x={c - r * 1.3} y={c - r * 0.8} width={r * 2.6} height={r * 1.6} rx={4} ry={4} />;
    case 'country':
      return (
        <g>
          <circle {...p} cx={c} cy={c} r={r} />
          <circle cx={c} cy={c} r={r + 3} fill="none" stroke={color} strokeWidth={1.5} opacity={0.4} />
        </g>
      );
    default: // threat_actor, tool, mitigation, etc.
      return <circle {...p} cx={c} cy={c} r={r} />;
  }
}

// Handles fill the node so a Shift+drag can start anywhere on it and drop
// anywhere on another node. Outside Shift they ignore the pointer, so a
// plain drag moves the node.
const handleStyle = (live: boolean): React.CSSProperties => ({
  inset: 0,
  width: '100%',
  height: '100%',
  transform: 'none',
  minWidth: 0,
  minHeight: 0,
  border: 0,
  borderRadius: '50%',
  background: 'transparent',
  opacity: 0,
  pointerEvents: live ? 'all' : 'none',
  cursor: live ? 'crosshair' : undefined,
});

export const EntityNodeView = memo(function EntityNodeView({ id, data }: NodeProps<EntityFlowNode>) {
  const view = useGraphView();
  const { node, r } = data;
  const c = r + 8; // room for the outer rings inside the svg box
  const color = getNodeColor(node.type);
  const isArticle = node.type === 'entry';
  const isSeed = id === view.seedId;
  const isHovered = view.hoveredNodeId === id;
  const isSelected = view.selectedNodeId === id;
  const dimmed = (view.hover && !view.hover.nodes.has(id)) || (view.searchMatches && !view.searchMatches.has(id));
  const info = view.nodeInfo?.get(id);
  const label = view.showNodeLabels && !dimmed;

  return (
    <div
      className={`${styles.node} ${dimmed ? styles.nodeDimmed : ''}`}
      style={{ width: r * 2, height: r * 2 }}
    >
      <svg
        className={styles.nodeSvg}
        width={c * 2}
        height={c * 2}
        style={{ left: r - c, top: r - c }}
      >
        {info?.kev && (
          <circle cx={c} cy={c} r={r + 4} fill="none" stroke="var(--danger)" strokeWidth={1.5} opacity={0.85}>
            <title>CISA KEV: known exploited</title>
          </circle>
        )}
        {isSeed && <circle cx={c} cy={c} r={r + 6} fill="none" stroke={color} strokeWidth={2} opacity={0.3} />}
        {isSelected && <circle cx={c} cy={c} r={r + 5} fill="none" stroke="var(--accent)" strokeWidth={2} opacity={0.85} />}
        {shape(
          node.type, c, isHovered ? r + 2 : r, color,
          `${styles.nodeShape} ${isHovered ? styles.nodeHovered : ''} ${isSeed ? styles.seedNode : ''}`,
        )}
        {view.expandable(id) && !dimmed && (isHovered || isSelected || view.isExpanded(id)) && (() => {
          const open = view.isExpanded(id);
          const bx = c + r * 0.8;
          const by = c + r * 0.8;
          return (
            <g
              className={`${styles.expandBadge} nodrag`}
              onClick={(e) => { e.stopPropagation(); view.toggleExpand(id); }}
              onDoubleClick={(e) => e.stopPropagation()}
            >
              <title>{open ? 'Hide the connections loaded from this node' : 'Load this node\'s own connections'}</title>
              <circle cx={bx} cy={by} r={6} />
              <path d={open ? `M ${bx - 3} ${by} H ${bx + 3}` : `M ${bx - 3} ${by} H ${bx + 3} M ${bx} ${by - 3} V ${by + 3}`} />
            </g>
          );
        })()}
        {info?.covered !== undefined && !dimmed && (
          <circle
            cx={c + r * 0.95}
            cy={c - r * 0.95}
            r={3.5}
            fill={info.covered ? 'var(--success)' : 'var(--bg-primary)'}
            stroke={info.covered ? 'var(--success)' : 'var(--danger)'}
            strokeWidth={1.3}
          >
            <title>{info.covered ? 'Detection rule exists' : 'No detection rule covers this'}</title>
          </circle>
        )}
      </svg>
      {label && (
        <div
          className={isArticle ? styles.articleLabel : styles.nodeLabel}
          style={{ top: r * 2 + 4, width: 'max-content', maxWidth: LABEL_W, fontWeight: isHovered || isSeed || isSelected ? 700 : undefined }}
          title={node.label}
        >
          {truncateLabel(node.label, 60)}
        </div>
      )}
      <Handle type="target" position={Position.Top} style={handleStyle(false)} isConnectable={view.linking} />
      <Handle type="source" position={Position.Top} style={handleStyle(view.linking)} isConnectable={view.linking} />
    </div>
  );
});

// ── Story box ──────────────────────────────────────────────────────

export type StoryFlowNode = Node<{ cluster: GraphStoryCluster }, 'story'>;

export const StoryNodeView = memo(function StoryNodeView({ data }: NodeProps<StoryFlowNode>) {
  const view = useGraphView();
  const { cluster } = data;
  const selected = view.selectedClusterId === cluster.id;
  const sub = [`${cluster.articles} articles`, cluster.corroborated ? 'corroborated' : null].filter(Boolean).join(' · ');
  return (
    <div
      className={`${styles.story} ${cluster.corroborated ? styles.storyCorroborated : ''} ${selected ? styles.storySelected : ''}`}
      title={`${cluster.heading}. Drag to move, click to inspect.`}
    >
      <div className={styles.storyTitle}>{cluster.heading}</div>
      <div className={styles.storySub}>{sub}</div>
      <Handle type="target" position={Position.Top} style={handleStyle(false)} isConnectable={false} />
      <Handle type="source" position={Position.Top} style={handleStyle(false)} isConnectable={false} />
    </div>
  );
});

// ── Floating edge ──────────────────────────────────────────────────

export type EntityFlowEdge = Edge<{ edge: LayoutEdge; spoke?: boolean; story?: boolean }, 'floating'>;

type Internal = NonNullable<ReturnType<typeof useInternalNode>>;

/** Where the line from (fx, fy) toward the node's center leaves the node:
 * its border for a story box, its shape (a circle) for everything else. */
function anchor(n: Internal, fx: number, fy: number, gap: number): { x: number; y: number; cx: number; cy: number } {
  const w = n.measured.width ?? 0;
  const h = n.measured.height ?? 0;
  const cx = n.internals.positionAbsolute.x + w / 2;
  const cy = n.internals.positionAbsolute.y + h / 2;
  const dx = fx - cx;
  const dy = fy - cy;
  const d = Math.hypot(dx, dy) || 1;
  if (n.type === 'story') {
    const t = Math.min(w / 2 / (Math.abs(dx) || 1e-9), h / 2 / (Math.abs(dy) || 1e-9));
    return { x: cx + dx * t + (dx / d) * gap, y: cy + dy * t + (dy / d) * gap, cx, cy };
  }
  const r = w / 2 + gap;
  return { x: cx + (dx / d) * r, y: cy + (dy / d) * r, cx, cy };
}

/** Straight line between node centers, trimmed to each node's shape so it
 * meets the shape edge instead of running under it. */
export const FloatingEdgeView = memo(function FloatingEdgeView({ id, source, target, data }: EdgeProps<EntityFlowEdge>) {
  const view = useGraphView();
  const s = useInternalNode(source);
  const t = useInternalNode(target);
  if (!s?.measured.width || !t?.measured.width || !data) return null;
  const edge = data.edge;
  if (data.spoke) {
    const focus = view.hover?.edges.has(id) || view.selectedNodeId === edge.source || view.selectedNodeId === edge.target;
    if (!focus) return null;
  }

  const sc = anchor(s, 0, 0, 0);
  const tc = anchor(t, 0, 0, 0);
  const { x: x1, y: y1 } = anchor(s, tc.cx, tc.cy, 2);
  const { x: x2, y: y2 } = anchor(t, sc.cx, sc.cy, 2);

  if (data.story) {
    const quiet = !!view.hover || !!view.searchMatches;
    return (
      <BaseEdge
        id={id}
        path={`M ${x1} ${y1} L ${x2} ${y2}`}
        interactionWidth={0}
        className={styles.storyEdge}
        style={{ strokeWidth: 1 + Math.min(3, Math.log2(1 + edge.weight)), opacity: quiet ? 0.08 : undefined }}
      />
    );
  }

  const searchDim = view.searchMatches && !view.searchMatches.has(edge.source) && !view.searchMatches.has(edge.target);
  const dimmed = (view.hover && !view.hover.edges.has(id)) || searchDim;
  const highlighted = view.hover?.edges.has(id);
  const selected = view.selectedEdgeId === id;
  // Width encodes relationship strength (0–1 composite) when present;
  // legacy weights fall back to the old scaling. Inferred (engine-only)
  // relationships render dashed; analyst-touched ones solid.
  const strength = edge.proximity_score;
  const w = strength != null
    ? Math.max(1, Math.min(4, 1 + strength * 3))
    : Math.max(1, Math.min(4, edge.weight <= 2 ? edge.weight * 2 : edge.weight));
  const inferred = !edge.provenance || edge.provenance === 'co_occurrence';
  // Signal-tier claims stay visible but quiet — same dimming the claims list
  // gives signal rows.
  const quiet = edge.confidence === 'possible' && !highlighted && !selected;
  const entryCount = edge.entries?.length ?? 0;

  return (
    <>
      <BaseEdge
        id={id}
        path={`M ${x1} ${y1} L ${x2} ${y2}`}
        interactionWidth={entryCount > 0 && !dimmed ? Math.max(14, w + 10) : 0}
        className={`${styles.edgeLine} ${selected ? styles.edgeSelected : ''} ${highlighted ? styles.edgeHighlighted : ''}`}
        style={{
          strokeWidth: highlighted ? Math.max(w, 2) : w,
          strokeDasharray: inferred ? '5 4' : undefined,
          opacity: dimmed ? 0.06 : quiet ? 0.2 : undefined,
        }}
      />
      {view.showEdgeLabels && edge.label && !dimmed && (
        <EdgeLabelRenderer>
          <div
            className={`${styles.edgeLabel} nodrag nopan`}
            style={{ transform: `translate(-50%, -50%) translate(${(x1 + x2) / 2}px, ${(y1 + y2) / 2}px)` }}
          >
            {truncateLabel(edge.label, 24)}
            {entryCount > 0 ? ` (${entryCount})` : ''}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});
