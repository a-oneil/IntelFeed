import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  addEdge,
  useNodesState,
  useEdgesState,
  type Connection,
  type Node,
  type Edge,
  type NodeTypes,
  MarkerType,
  Panel,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { TriggerNode } from "./nodes/TriggerNode";
import { ConditionNode } from "./nodes/ConditionNode";
import { ActionNode } from "./nodes/ActionNode";
import { BranchNode } from "./nodes/BranchNode";
import {
  useCreateAutomationRule,
  useUpdateAutomationRule,
} from "@/hooks/useAutomation";
import type { AutomationRule } from "@/api/types";
import { flowToRule, ruleToFlow } from "./flowSerializer";
import styles from "./FlowBuilder.module.css";

const nodeTypes: NodeTypes = {
  trigger: TriggerNode,
  condition: ConditionNode,
  action: ActionNode,
  branch: BranchNode,
};

const defaultEdgeOptions = {
  animated: true,
  style: { stroke: "var(--accent)", strokeWidth: 2 },
  markerEnd: { type: MarkerType.ArrowClosed, color: "var(--accent)" },
};

interface FlowBuilderProps {
  rule: AutomationRule | null;
  onClose: () => void;
}

let nodeIdCounter = 0;
function nextNodeId() {
  return `node_${++nodeIdCounter}`;
}

/** Ensure nodeIdCounter is above all existing node IDs to prevent collisions */
function syncNodeIdCounter(nodes: Node[]) {
  for (const n of nodes) {
    const match = n.id.match(/^node_(\d+)$/);
    if (match) {
      const num = parseInt(match[1], 10);
      if (num >= nodeIdCounter) nodeIdCounter = num;
    }
  }
}

/**
 * Stable callback dispatcher — nodes get a fixed `onUpdate`/`onDelete` that
 * dispatches through a ref, so React Flow never sees new node objects just
 * because the parent re-rendered.
 */
function useNodeCallbacks(
  setNodes: ReturnType<typeof useNodesState>[1],
  setEdges: ReturnType<typeof useEdgesState>[1]
) {
  const updateNode = useCallback(
    (nodeId: string, data: Record<string, unknown>) => {
      setNodes((nds) =>
        nds.map((n) =>
          n.id === nodeId ? { ...n, data: { ...n.data, ...data } } : n
        )
      );
    },
    [setNodes]
  );

  const deleteNode = useCallback(
    (nodeId: string) => {
      setNodes((nds) => nds.filter((n) => n.id !== nodeId));
      setEdges((eds) =>
        eds.filter((e) => e.source !== nodeId && e.target !== nodeId)
      );
    },
    [setNodes, setEdges]
  );

  return { updateNode, deleteNode };
}

export function FlowBuilder({ rule, onClose }: FlowBuilderProps) {
  const createRule = useCreateAutomationRule();
  const updateRule = useUpdateAutomationRule();
  const [error, setError] = useState("");
  const [name, setName] = useState(rule?.name ?? "");
  const [description, setDescription] = useState(rule?.description ?? "");
  const [labels, setLabels] = useState(rule?.labels?.join(", ") ?? "");

  const initial = useMemo(() => {
    if (rule) return ruleToFlow(rule);
    const triggerId = nextNodeId();
    return {
      nodes: [
        {
          id: triggerId,
          type: "trigger" as const,
          position: { x: 100, y: 200 },
          data: { triggerType: "on_new_entry", triggerConfig: {} },
        },
      ] as Node[],
      edges: [] as Edge[],
    };
  }, [rule]);

  // Sync module-level counter so new nodes don't collide with existing IDs
  syncNodeIdCounter(initial.nodes);

  const [nodes, setNodes, onNodesChange] = useNodesState(initial.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initial.edges);
  const reactFlowWrapper = useRef<HTMLDivElement>(null);

  const { updateNode, deleteNode } = useNodeCallbacks(setNodes, setEdges);

  // Store callbacks in a ref so we can give each node a stable function
  const callbacksRef = useRef({ updateNode, deleteNode });
  useEffect(() => {
    callbacksRef.current = { updateNode, deleteNode };
  }, [updateNode, deleteNode]);

  // Inject onUpdate/onDelete into node data only when nodes are created or
  // their core data changes — NOT on every position/selection change.
  // We key off a serialized snapshot of each node's data (excluding callbacks).
  const prevDataSnapshotRef = useRef<string>("");

  const nodesWithCallbacks = useMemo(() => {
    // Action nodes need the rule's execution mode (set on the trigger) to show
    // accurate variable hints — derive it here and inject into every node.
    const triggerNode = nodes.find((n) => n.type === "trigger");
    const executionMode =
      ((triggerNode?.data?.triggerConfig as Record<string, unknown> | undefined)
        ?.execution_mode as string) ?? "per_entry";
    return nodes.map((n) => ({
      ...n,
      data: {
        ...n.data,
        executionMode,
        onDelete: () => callbacksRef.current.deleteNode(n.id),
        onUpdate: (data: Record<string, unknown>) =>
          callbacksRef.current.updateNode(n.id, data),
      },
    }));
    // Only depend on nodes — the callbacks are accessed via ref (always stable)
  }, [nodes]);

  // Track whether data actually changed to avoid infinite update loops
  const dataSnapshot = nodes
    .map((n) => `${n.id}:${n.type}:${JSON.stringify(n.data)}`)
    .join("|");

  // Keep prevDataSnapshotRef in sync
  useEffect(() => {
    prevDataSnapshotRef.current = dataSnapshot;
  }, [dataSnapshot]);

  const onConnect = useCallback(
    (params: Connection) => {
      setEdges((eds) => addEdge({ ...params, ...defaultEdgeOptions }, eds));
    },
    [setEdges]
  );

  const addConditionNode = useCallback(() => {
    const id = nextNodeId();
    setNodes((nds) => {
      const count = nds.filter((n) => n.type === "condition").length;
      const newNode: Node = {
        id,
        type: "condition",
        position: { x: 400, y: 100 + count * 200 },
        data: {
          conditionType: "feed_matches",
          config: {},
          operator: "AND",
        },
      };
      return [...nds, newNode];
    });
  }, [setNodes]);

  const addActionNode = useCallback(() => {
    const id = nextNodeId();
    setNodes((nds) => {
      const count = nds.filter((n) => n.type === "action").length;
      const newNode: Node = {
        id,
        type: "action",
        position: { x: 700, y: 100 + count * 200 },
        data: {
          actionType: "add_tags",
          config: {},
        },
      };
      return [...nds, newNode];
    });
  }, [setNodes]);

  const addBranchNode = useCallback(() => {
    const id = nextNodeId();
    setNodes((nds) => {
      const count = nds.filter((n) => n.type === "branch").length;
      const newNode: Node = {
        id,
        type: "branch",
        position: { x: 550, y: 100 + count * 250 },
        data: {
          conditionType: "has_tag",
          conditionConfig: {},
        },
      };
      return [...nds, newNode];
    });
  }, [setNodes]);

  const handleSave = async () => {
    setError("");
    if (!name.trim()) {
      setError("Name is required");
      return;
    }

    const triggerNodes = nodes.filter((n) => n.type === "trigger");
    if (triggerNodes.length === 0) {
      setError("A trigger node is required");
      return;
    }

    const actionNodes = nodes.filter((n) => n.type === "action" || n.type === "branch");
    if (actionNodes.length === 0) {
      setError("At least one action or branch node is required");
      return;
    }

    const ruleData = {
      ...flowToRule(nodes, edges, name.trim(), description.trim()),
      labels: labels
        .split(",")
        .map((l) => l.trim().toLowerCase())
        .filter(Boolean),
    };

    try {
      if (rule) {
        await updateRule.mutateAsync({ ruleId: rule.id, data: ruleData });
      } else {
        await createRule.mutateAsync(ruleData as Parameters<typeof createRule.mutateAsync>[0]);
      }
      onClose();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to save rule";
      setError(msg);
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <button onClick={onClose} className={styles.backBtn}>
          &larr; Back
        </button>
        <div className={styles.nameGroup}>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Rule name"
            className={styles.nameInput}
          />
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description (optional)"
            className={styles.descInput}
          />
          <input
            type="text"
            value={labels}
            onChange={(e) => setLabels(e.target.value)}
            placeholder="Labels (comma-separated)"
            className={styles.descInput}
          />
        </div>
        <button
          onClick={handleSave}
          className={styles.saveBtn}
          disabled={createRule.isPending || updateRule.isPending}
        >
          {createRule.isPending || updateRule.isPending ? "Saving..." : "Save"}
        </button>
      </div>

      {error && <div className={styles.error}>{error}</div>}

      <div className={styles.flowWrapper} ref={reactFlowWrapper}>
        <ReactFlow
          nodes={nodesWithCallbacks}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          defaultEdgeOptions={defaultEdgeOptions}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          deleteKeyCode={["Backspace", "Delete"]}
          colorMode="dark"
        >
          <Background gap={20} color="var(--border)" />
          <Controls
            showInteractive={false}
            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border)" }}
          />
          <Panel position="top-left" className={styles.addPanel}>
            <button onClick={addConditionNode} className={styles.addNodeBtn}>
              + Condition
            </button>
            <button onClick={addBranchNode} className={styles.addNodeBtn}>
              + Branch
            </button>
            <button onClick={addActionNode} className={styles.addNodeBtn}>
              + Action
            </button>
          </Panel>
          <Panel position="top-right" className={styles.legend}>
            <span className={styles.legendItem}>
              <span className={`${styles.legendDot} ${styles.triggerDot}`} />
              Trigger
            </span>
            <span className={styles.legendItem}>
              <span className={`${styles.legendDot} ${styles.conditionDot}`} />
              Condition
            </span>
            <span className={styles.legendItem}>
              <span className={`${styles.legendDot} ${styles.branchDot}`} />
              Branch
            </span>
            <span className={styles.legendItem}>
              <span className={`${styles.legendDot} ${styles.actionDot}`} />
              Action
            </span>
          </Panel>
        </ReactFlow>
      </div>
    </div>
  );
}
