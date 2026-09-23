import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type { RuleValidationResult } from "@/api/types";
import { RuleStatusLine } from "../ruleBench/RuleStatusLine";

const OK: RuleValidationResult = { valid: true, errors: [], suggestions: [] };
const BROKEN: RuleValidationResult = {
  valid: false,
  errors: [{ line: 3, column: null, severity: "error", message: "unknown key" }],
  suggestions: [],
};

function renderLine(props: Partial<Parameters<typeof RuleStatusLine>[0]> = {}) {
  const onToggleIssues = vi.fn();
  render(
    <RuleStatusLine
      validation={OK}
      ruleTypeLabel="KQL"
      telemetry={{ required: 4, collected: 4 }}
      nearDupeCount={1}
      freshIntelCount={2}
      issuesOpen={false}
      onToggleIssues={onToggleIssues}
      {...props}
    />
  );
  return { onToggleIssues };
}

describe("RuleStatusLine", () => {
  it("reports all four facts on one line", () => {
    renderLine();
    expect(screen.getByText("KQL").parentElement).toHaveTextContent("parses");
    expect(screen.getByText("4 collected")).toBeInTheDocument();
    expect(screen.getByText("1 near-duplicate")).toBeInTheDocument();
    expect(screen.getByText("2 new articles since last save")).toBeInTheDocument();
  });

  it("reports syntax errors without offering anything that blocks", () => {
    const { onToggleIssues } = renderLine({ validation: BROKEN });
    expect(screen.getByText("1 error")).toBeInTheDocument();
    // The only control on the line reveals the detail; there is no save gate here.
    const buttons = screen.getAllByRole("button");
    expect(buttons).toHaveLength(1);
    fireEvent.click(buttons[0]);
    expect(onToggleIssues).toHaveBeenCalled();
  });

  it("does not offer the issues toggle when the rule is clean", () => {
    renderLine();
    expect(screen.getByRole("button")).toBeDisabled();
  });

  it("drops the counts it has nothing to say about", () => {
    renderLine({ validation: null, telemetry: null, nearDupeCount: 0, freshIntelCount: 0 });
    expect(screen.getByText("KQL").parentElement).toHaveTextContent("not checked");
    expect(screen.queryByText(/collected/)).not.toBeInTheDocument();
    expect(screen.queryByText(/near-duplicate/)).not.toBeInTheDocument();
    expect(screen.queryByText(/since last save/)).not.toBeInTheDocument();
  });
});
