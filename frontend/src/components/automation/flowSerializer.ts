import type { Node, Edge } from "@xyflow/react";
import type { AutomationRule } from "@/api/types";

/**
 * Convert a flow graph (nodes + edges) into the automation rule JSON
 * structure expected by the backend API.
 */
export function flowToRule(
  nodes: Node[],
  edges: Edge[],
  name: string,
  description: string
) {
  const triggerNode = nodes.find((n) => n.type === "trigger");
  const conditionNodes = nodes.filter((n) => n.type === "condition");
  const actionNodes = nodes.filter((n) => n.type === "action");
  const branchNodes = nodes.filter((n) => n.type === "branch");

  // Determine which condition/action/branch nodes are connected to the trigger
  // via edges (directly or through conditions)
  const connectedConditionIds = new Set<string>();
  const connectedActionIds = new Set<string>();
  const connectedBranchIds = new Set<string>();

  // Walk edges from trigger outward
  if (triggerNode) {
    const queue = [triggerNode.id];
    const visited = new Set<string>();
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);
      for (const edge of edges) {
        if (edge.source === current) {
          const targetNode = nodes.find((n) => n.id === edge.target);
          if (targetNode?.type === "condition") {
            connectedConditionIds.add(edge.target);
            queue.push(edge.target);
          } else if (targetNode?.type === "action") {
            connectedActionIds.add(edge.target);
            queue.push(edge.target);
          } else if (targetNode?.type === "branch") {
            connectedBranchIds.add(edge.target);
            queue.push(edge.target);
          }
        }
      }
    }
  }

  // Also include conditions that connect to actions/branches
  for (const edge of edges) {
    if (connectedConditionIds.has(edge.source)) {
      const targetNode = nodes.find((n) => n.id === edge.target);
      if (targetNode?.type === "action") {
        connectedActionIds.add(edge.target);
      } else if (targetNode?.type === "branch") {
        connectedBranchIds.add(edge.target);
      }
    }
  }

  // Follow action-to-action and action-to-branch chains
  let changed = true;
  while (changed) {
    changed = false;
    for (const edge of edges) {
      const sourceConnected =
        connectedActionIds.has(edge.source) ||
        connectedBranchIds.has(edge.source);
      if (sourceConnected) {
        const targetNode = nodes.find((n) => n.id === edge.target);
        if (
          targetNode?.type === "action" &&
          !connectedActionIds.has(edge.target)
        ) {
          connectedActionIds.add(edge.target);
          changed = true;
        }
        if (
          targetNode?.type === "branch" &&
          !connectedBranchIds.has(edge.target)
        ) {
          connectedBranchIds.add(edge.target);
          changed = true;
        }
      }
    }
  }

  // Build trigger
  const triggerType =
    (triggerNode?.data?.triggerType as string) ?? "on_new_entry";
  const triggerConfig =
    (triggerNode?.data?.triggerConfig as Record<string, unknown>) ?? {};

  // Build conditions from connected condition nodes
  const conditions: Record<string, unknown> =
    connectedConditionIds.size > 0
      ? {
          operator: "AND",
          conditions: Array.from(connectedConditionIds)
            .map((id) => conditionNodes.find((n) => n.id === id))
            .filter(Boolean)
            .map((n) => ({
              type: n!.data.conditionType as string,
              config: n!.data.config as Record<string, unknown>,
            })),
        }
      : {};

  // Collect all "executable" node IDs (actions + branches) for topological sort
  const executableIds = new Set([
    ...connectedActionIds,
    ...connectedBranchIds,
  ]);

  // Build action-to-action edge map for topological sort
  const execEdgeMap = new Map<string, string[]>();
  for (const edge of edges) {
    if (executableIds.has(edge.source) && executableIds.has(edge.target)) {
      // Skip branch->action edges that use "then"/"else" handles — those
      // are sub-chain connections, not sequential flow
      if (
        connectedBranchIds.has(edge.source) &&
        (edge.sourceHandle === "then" || edge.sourceHandle === "else")
      ) {
        continue;
      }
      const targets = execEdgeMap.get(edge.source) ?? [];
      targets.push(edge.target);
      execEdgeMap.set(edge.source, targets);
    }
  }

  const hasIncomingExecEdge = new Set<string>();
  for (const targets of execEdgeMap.values()) {
    for (const t of targets) hasIncomingExecEdge.add(t);
  }
  // Nodes that are targets of branch "then"/"else" edges also have incoming
  for (const edge of edges) {
    if (
      connectedBranchIds.has(edge.source) &&
      (edge.sourceHandle === "then" || edge.sourceHandle === "else")
    ) {
      hasIncomingExecEdge.add(edge.target);
    }
  }

  // Topological sort
  const sortedExecIds: string[] = [];
  const visited = new Set<string>();
  function visit(id: string) {
    if (visited.has(id)) return;
    visited.add(id);
    sortedExecIds.push(id);
    for (const next of execEdgeMap.get(id) ?? []) {
      visit(next);
    }
  }

  // Start from roots
  const allExec = [...actionNodes, ...branchNodes].filter((n) =>
    executableIds.has(n.id)
  );
  const roots = allExec
    .filter((n) => !hasIncomingExecEdge.has(n.id))
    .sort((a, b) => a.position.y - b.position.y);

  for (const root of roots) visit(root.id);
  for (const id of executableIds) visit(id);

  // Helper: collect the sub-chain of action nodes connected from a branch's
  // "then" or "else" handle
  function collectBranchSubChain(
    branchId: string,
    handle: "then" | "else"
  ): Array<Record<string, unknown>> {
    const subActions: Array<Record<string, unknown>> = [];
    // Find direct targets from this handle
    const directTargets = edges
      .filter(
        (e) =>
          e.source === branchId &&
          e.sourceHandle === handle &&
          executableIds.has(e.target)
      )
      .map((e) => e.target);

    // Walk each target and its sequential chain
    for (const targetId of directTargets) {
      const chain = collectChainFrom(targetId);
      subActions.push(...chain);
    }
    return subActions;
  }

  // Collect a sequential chain starting from a node
  function collectChainFrom(
    startId: string
  ): Array<Record<string, unknown>> {
    const result: Array<Record<string, unknown>> = [];
    let currentId: string | null = startId;
    const chainVisited = new Set<string>();

    while (currentId && !chainVisited.has(currentId)) {
      chainVisited.add(currentId);
      const node = nodes.find((n) => n.id === currentId);
      if (!node) break;

      if (node.type === "action") {
        result.push({
          type: node.data.actionType as string,
          config: node.data.config as Record<string, unknown>,
        });
      } else if (node.type === "branch") {
        result.push(serializeBranchNode(node));
      }

      // Follow sequential edges (not branch handle edges)
      const nextEdge = edges.find(
        (e) =>
          e.source === currentId &&
          !e.sourceHandle &&
          executableIds.has(e.target)
      );
      currentId = nextEdge?.target ?? null;
    }
    return result;
  }

  function serializeBranchNode(
    node: Node
  ): Record<string, unknown> {
    const condType =
      (node.data.conditionType as string) ?? "has_tag";
    const condConfig =
      (node.data.conditionConfig as Record<string, unknown>) ?? {};

    return {
      type: "branch",
      config: {
        condition: { type: condType, config: condConfig },
        then_actions: collectBranchSubChain(node.id, "then"),
        else_actions: collectBranchSubChain(node.id, "else"),
      },
    };
  }

  // Build the final actions list from the sorted executable IDs,
  // skipping nodes that are part of a branch sub-chain
  const branchSubChainIds = new Set<string>();
  for (const bId of connectedBranchIds) {
    for (const handle of ["then", "else"] as const) {
      const targets = edges
        .filter(
          (e) =>
            e.source === bId &&
            e.sourceHandle === handle &&
            executableIds.has(e.target)
        )
        .map((e) => e.target);
      for (const t of targets) {
        // Walk the chain
        let cur: string | null = t;
        const cv = new Set<string>();
        while (cur && !cv.has(cur)) {
          cv.add(cur);
          branchSubChainIds.add(cur);
          const nextEdge = edges.find(
            (e) =>
              e.source === cur &&
              !e.sourceHandle &&
              executableIds.has(e.target)
          );
          cur = nextEdge?.target ?? null;
        }
      }
    }
  }

  const orderedActions = sortedExecIds
    .filter((id) => !branchSubChainIds.has(id))
    .map((id) => {
      const node = nodes.find((n) => n.id === id);
      if (!node) return null;
      if (node.type === "branch") {
        return serializeBranchNode(node);
      }
      return {
        type: node.data.actionType as string,
        config: node.data.config as Record<string, unknown>,
      };
    })
    .filter(Boolean) as Array<Record<string, unknown>>;

  // Fall back to all action nodes if none are connected
  const actions =
    orderedActions.length > 0
      ? orderedActions
      : actionNodes.map((n) => ({
          type: n.data.actionType as string,
          config: n.data.config as Record<string, unknown>,
        }));

  return {
    name,
    description: description || undefined,
    trigger_type: triggerType,
    trigger_config: triggerConfig,
    conditions,
    actions,
  };
}

/**
 * Convert an existing AutomationRule into a set of flow nodes and edges
 * for rendering in React Flow.
 */
export function ruleToFlow(rule: AutomationRule): {
  nodes: Node[];
  edges: Edge[];
} {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  let idCounter = 0;
  const nextId = () => `node_${++idCounter}`;

  // 1. Create trigger node
  const triggerId = nextId();
  nodes.push({
    id: triggerId,
    type: "trigger",
    position: { x: 50, y: 200 },
    data: {
      triggerType: rule.trigger_type,
      triggerConfig: rule.trigger_config ?? {},
    },
  });

  // 2. Create condition nodes
  const conditionsList =
    (
      rule.conditions as {
        conditions?: Array<{ type: string; config: Record<string, unknown> }>;
      }
    )?.conditions ?? [];

  let lastSourceId = triggerId;

  conditionsList.forEach((cond, i) => {
    const condId = nextId();
    nodes.push({
      id: condId,
      type: "condition",
      position: { x: 350, y: 80 + i * 180 },
      data: {
        conditionType: cond.type,
        config: cond.config ?? {},
      },
    });
    edges.push({
      id: `e_${triggerId}_${condId}`,
      source: triggerId,
      target: condId,
    });
    lastSourceId = condId;
  });

  if (conditionsList.length === 0) {
    lastSourceId = triggerId;
  }

  // 3. Create action + branch nodes
  const actionsList = rule.actions ?? [];

  // Helper to create nodes for an action list, returns the ID of the last node created
  function createActionChain(
    actions: Array<Record<string, unknown>>,
    startX: number,
    startY: number,
    connectFromId: string,
    connectFromHandle?: string
  ): string {
    let prevId = connectFromId;
    actions.forEach((act, i) => {
      const actData = act as {
        type: string;
        config: Record<string, unknown>;
      };

      if (actData.type === "branch") {
        // Create a branch node
        const branchId = nextId();
        const branchConfig = (actData.config ?? {}) as {
          condition?: { type: string; config: Record<string, unknown> };
          then_actions?: Array<Record<string, unknown>>;
          else_actions?: Array<Record<string, unknown>>;
        };

        nodes.push({
          id: branchId,
          type: "branch",
          position: { x: startX + i * 300, y: startY },
          data: {
            conditionType: branchConfig.condition?.type ?? "has_tag",
            conditionConfig: branchConfig.condition?.config ?? {},
          },
        });

        const edgeProps: Record<string, unknown> = {
          id: `e_${prevId}_${branchId}${connectFromHandle ? `_${connectFromHandle}` : ""}`,
          source: prevId,
          target: branchId,
        };
        if (connectFromHandle && i === 0) {
          edgeProps.sourceHandle = connectFromHandle;
        }
        edges.push(edgeProps as Edge);

        // Create then sub-chain
        const thenActions = branchConfig.then_actions ?? [];
        if (thenActions.length > 0) {
          createActionChain(
            thenActions,
            startX + (i + 1) * 300,
            startY - 120,
            branchId,
            "then"
          );
        }

        // Create else sub-chain
        const elseActions = branchConfig.else_actions ?? [];
        if (elseActions.length > 0) {
          createActionChain(
            elseActions,
            startX + (i + 1) * 300,
            startY + 120,
            branchId,
            "else"
          );
        }

        prevId = branchId;
        // Reset connectFromHandle for subsequent nodes in the same chain
        connectFromHandle = undefined;
      } else {
        // Regular action node
        const actId = nextId();
        nodes.push({
          id: actId,
          type: "action",
          position: { x: startX + i * 300, y: startY },
          data: {
            actionType: actData.type,
            config: actData.config ?? {},
          },
        });

        const edgeProps: Record<string, unknown> = {
          id: `e_${prevId}_${actId}${connectFromHandle ? `_${connectFromHandle}` : ""}`,
          source: prevId,
          target: actId,
        };
        if (connectFromHandle && i === 0) {
          edgeProps.sourceHandle = connectFromHandle;
        }
        edges.push(edgeProps as Edge);

        prevId = actId;
        connectFromHandle = undefined;
      }
    });
    return prevId;
  }

  const firstActionSourceId =
    conditionsList.length > 0 ? lastSourceId : triggerId;
  createActionChain(actionsList, 650, 200, firstActionSourceId);

  return { nodes, edges };
}
