import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ReliabilityBadge } from "../ReliabilityBadge";

describe("ReliabilityBadge", () => {
  it("renders the rating letter with an admiralty tooltip", () => {
    render(<ReliabilityBadge rating="A" />);
    const badge = screen.getByText("A");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveAttribute("data-tooltip", "A — Reliable source");
  });

  it.each(["A", "B", "C", "D", "E", "F"])("renders rating %s", (rating) => {
    render(<ReliabilityBadge rating={rating} />);
    expect(screen.getByText(rating)).toBeInTheDocument();
  });

  it("renders nothing when unrated", () => {
    const { container } = render(<ReliabilityBadge rating={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for unknown ratings", () => {
    const { container } = render(<ReliabilityBadge rating="Z" />);
    expect(container).toBeEmptyDOMElement();
  });
});
