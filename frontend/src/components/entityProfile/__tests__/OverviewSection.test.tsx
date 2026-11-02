import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { OverviewSection } from "../OverviewSection";

/**
 * One Overview row: closed, it is a single line that still answers the usual
 * question through its digest; open, the section's components render under it.
 */
describe("OverviewSection", () => {
  it("closed: shows name, count and digest, and renders no body", () => {
    render(
      <OverviewSection id="context" title="Context" count="3 sources" digest="NVD · EPSS · all fresh" open={false} onToggle={() => {}}>
        <p>the body</p>
      </OverviewSection>,
    );
    const toggle = screen.getByRole("button", { name: /Context/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveAttribute("aria-controls", "overview-context-body");
    expect(toggle).toHaveTextContent("3 sources");
    expect(toggle).toHaveTextContent("NVD · EPSS · all fresh");
    expect(screen.queryByText("the body")).toBeNull();
  });

  it("open: renders the body under the row, labelled by the row's name", () => {
    render(
      <OverviewSection id="activity" title="Activity" open onToggle={() => {}}>
        <p>the body</p>
      </OverviewSection>,
    );
    expect(screen.getByRole("button", { name: /Activity/ })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("the body")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Activity" })).toBeInTheDocument();
  });

  it("omits the count and digest spans when there is nothing to say", () => {
    const { container } = render(
      <OverviewSection id="reading" title="Stories & reading" count={undefined} digest={null} open={false} onToggle={() => {}}>
        <p />
      </OverviewSection>,
    );
    // The row is just caret + name: no stray separators or empty mono spans.
    expect(container.querySelector("button")?.textContent?.trim()).toBe("Stories & reading");
  });

  it("clicking the row calls onToggle", async () => {
    const onToggle = vi.fn();
    render(
      <OverviewSection id="workspace" title="Workspace" open={false} onToggle={onToggle}>
        <p />
      </OverviewSection>,
    );
    await userEvent.click(screen.getByRole("button", { name: /Workspace/ }));
    expect(onToggle).toHaveBeenCalledTimes(1);
  });
});
