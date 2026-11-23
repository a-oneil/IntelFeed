import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { EntityGraph, type EntityEdge, type EntityNode, type GraphStoryCluster } from "../EntityGraph";

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", ResizeObserverStub);
class DOMMatrixReadOnlyStub {
  m22 = 1;
}
vi.stubGlobal("DOMMatrixReadOnly", DOMMatrixReadOnlyStub);

const nodes: EntityNode[] = [
  { id: "threat_actor-1", type: "threat_actor", label: "APT29", size: 10 },
  { id: "malware-1", type: "malware", label: "WINELOADER", size: 3 },
];
const edges: EntityEdge[] = [{ source: "threat_actor-1", target: "malware-1", weight: 1, label: "uses" }];
const clusters: GraphStoryCluster[] = [
  { id: "s1", heading: "Wine lure", corroborated: true, articles: 3, nodeIds: ["malware-1"] },
];
const expansion = {
  nodes: [{ id: "tool-9", type: "tool", label: "Rclone", size: 1 }],
  edges: [{ source: "malware-1", target: "tool-9", weight: 1, label: "uses" }],
  clusters: [],
};

describe("EntityGraph expansions", () => {
  it.each([
    ["story layout", clusters],
    ["network layout", undefined],
  ])("collapsing removes the expanded nodes (%s)", async (_name, storyClusters) => {
    const props = { nodes, edges, storyClusters, onToggleExpand: vi.fn(), width: 800, height: 500 };
    const { rerender } = render(<EntityGraph {...props} expansions={new Map([["malware-1", expansion]])} />);
    expect(await screen.findByText("Rclone")).toBeInTheDocument();

    rerender(<EntityGraph {...props} expansions={new Map()} />);
    await waitFor(() => expect(screen.queryByText("Rclone")).not.toBeInTheDocument());
  });
});
