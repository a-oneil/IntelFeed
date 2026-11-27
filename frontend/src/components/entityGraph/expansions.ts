/**
 * Which on-demand expansions survive a collapse.
 *
 * An expansion is keyed by the node that was expanded. It stays only while that node is reachable from the base graph: a base node, or a node brought in by another surviving expansion. Expansions that only keep each other alive (Y and Z both expanded from X, each listing the other) go when X is collapsed.
 */
export function pruneExpansions<T extends { nodes: Array<{ id: string }> }>(
  expansions: Map<string, T>,
  baseIds: Set<string>,
): Map<string, T> {
  const reachable = new Set(baseIds);
  const kept = new Set<string>();
  let grew = true;
  while (grew) {
    grew = false;
    for (const [anchor, ex] of expansions) {
      if (kept.has(anchor) || !reachable.has(anchor)) continue;
      kept.add(anchor);
      for (const n of ex.nodes) reachable.add(n.id);
      grew = true;
    }
  }
  return new Map([...expansions].filter(([anchor]) => kept.has(anchor)));
}
