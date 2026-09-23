import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { SafeHTML } from "@/components/SafeHTML";

describe("SafeHTML", () => {
  it("renders safe HTML content", () => {
    render(<SafeHTML html="<p>Hello, world!</p>" />);
    expect(screen.getByText("Hello, world!")).toBeInTheDocument();
  });

  it("strips script tags", () => {
    const { container } = render(
      <SafeHTML html='<p>Safe text</p><script>alert("xss")</script>' />
    );
    expect(screen.getByText("Safe text")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    expect(container.innerHTML).not.toContain("alert");
  });

  it("strips iframe tags", () => {
    const { container } = render(
      <SafeHTML html='<p>Content</p><iframe src="https://evil.com"></iframe>' />
    );
    expect(screen.getByText("Content")).toBeInTheDocument();
    expect(container.querySelector("iframe")).toBeNull();
  });

  it("strips style tags", () => {
    const { container } = render(
      <SafeHTML html="<p>Styled</p><style>body { display: none; }</style>" />
    );
    expect(screen.getByText("Styled")).toBeInTheDocument();
    expect(container.querySelector("style")).toBeNull();
  });

  it("applies className prop to wrapper div", () => {
    const { container } = render(
      <SafeHTML html="<p>Test</p>" className="custom-class" />
    );
    const wrapper = container.firstElementChild as HTMLElement;
    expect(wrapper).toHaveClass("custom-class");
  });

  it("preserves anchor links", () => {
    const { container } = render(
      <SafeHTML html='<a href="https://example.com">Click here</a>' />
    );
    const link = container.querySelector("a");
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "https://example.com");
    expect(screen.getByText("Click here")).toBeInTheDocument();
  });
});
