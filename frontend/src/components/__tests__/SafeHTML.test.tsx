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

  it("strips image maps and areas that can navigate without an anchor", () => {
    const { container } = render(
      <SafeHTML html='<img usemap="#links"><map name="links"><area href="https://evil.example/"></map>' />
    );
    expect(container.querySelector("map")).toBeNull();
    expect(container.querySelector("area")).toBeNull();
  });

  it("strips forms and controls that can submit outside the link guard", () => {
    const { container } = render(
      <SafeHTML html='<form action="https://evil.example/"><input name="q"><select><option>Go</option></select><textarea>text</textarea><button>Submit</button></form>' />
    );
    for (const tag of ["form", "input", "select", "option", "textarea", "button"]) {
      expect(container.querySelector(tag), tag).toBeNull();
    }
  });
});
