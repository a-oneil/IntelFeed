import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { EntityGraph, type CoveringRule, type GraphNodeInfo } from "../EntityGraph";

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", ResizeObserverStub);

const nodes = [
  { id: "malware-seed", type: "malware", label: "SocGholish", size: 10, data: {} },
  {
    id: "ttp-abc",
    type: "ttp",
    label: "T1047",
    size: 10,
    data: { technique_id: "T1047" },
  },
];
const edges = [
  {
    source: "malware-seed",
    target: "ttp-abc",
    weight: 1,
    label: "uses",
    confidence: "confirmed",
    provenance: "external_feed",
  },
];

describe("EntityGraph covering rules in the inspector", () => {
  it("selecting a covered ttp node fetches and lists its rules, click-through opens the rule", async () => {
    const rules: CoveringRule[] = [
      { id: "r1", title: "Service Started Via Wmic.EXE", rule_type: "sigma" },
      { id: "r2", title: "Mofcomp Activity", rule_type: "elastic_ql" },
    ];
    const onFetchCoveringRules = vi.fn().mockResolvedValue(rules);
    const onOpenRule = vi.fn();
    const nodeInfo = new Map<string, GraphNodeInfo>([
      ["ttp-abc", { covered: true, ruleCount: 39 }],
    ]);

    render(
      <EntityGraph
        nodes={nodes}
        edges={edges}
        nodeInfo={nodeInfo}
        onFetchCoveringRules={onFetchCoveringRules}
        onOpenRule={onOpenRule}
        width={800}
        height={500}
      />,
    );

    // Select the TTP node (mousedown+mouseup without movement = click-select).
    const label = screen.getByText("T1047");
    const nodeGroup = label.closest("g")!;
    fireEvent.mouseDown(nodeGroup.querySelector("circle, path, rect, polygon")!);
    fireEvent.mouseUp(nodeGroup.querySelector("circle, path, rect, polygon")!);

    // Inspector shows the coverage line with the library count.
    await waitFor(() => expect(screen.getByText(/covered ✓ · 39 rules/)).toBeInTheDocument());
    expect(onFetchCoveringRules).toHaveBeenCalledTimes(1);
    expect(onFetchCoveringRules.mock.calls[0][0].id).toBe("ttp-abc");

    // The fetched rules render as clickable rows.
    await waitFor(() => expect(screen.getByText("Service Started Via Wmic.EXE")).toBeInTheDocument());
    expect(screen.getByText("Mofcomp Activity")).toBeInTheDocument();
    expect(screen.getByText("sigma")).toBeInTheDocument();
    expect(screen.getByText(/\+37 more in the library/)).toBeInTheDocument();

    fireEvent.click(screen.getByText("Service Started Via Wmic.EXE"));
    expect(onOpenRule).toHaveBeenCalledWith("r1");
  });

  it("an uncovered node shows the gap line and never fetches", async () => {
    const onFetchCoveringRules = vi.fn();
    const nodeInfo = new Map<string, GraphNodeInfo>([["ttp-abc", { covered: false }]]);

    render(
      <EntityGraph
        nodes={nodes}
        edges={edges}
        nodeInfo={nodeInfo}
        onFetchCoveringRules={onFetchCoveringRules}
        width={800}
        height={500}
      />,
    );

    const label = screen.getByText("T1047");
    const nodeGroup = label.closest("g")!;
    fireEvent.mouseDown(nodeGroup.querySelector("circle, path, rect, polygon")!);
    fireEvent.mouseUp(nodeGroup.querySelector("circle, path, rect, polygon")!);

    await waitFor(() => expect(screen.getByText(/no rule in library/)).toBeInTheDocument());
    expect(onFetchCoveringRules).not.toHaveBeenCalled();
  });
});
