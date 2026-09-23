import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

// EntityLinkedMarkdown scans text for entities via the API — stub it out.
vi.mock("@/hooks/useEntityScan", () => ({
  useEntityScan: () => ({ data: [] }),
}));

import { NoteBody } from "../NoteBody";

function renderBody(props: Parameters<typeof NoteBody>[0]) {
  return render(
    <MemoryRouter>
      <NoteBody {...props} />
    </MemoryRouter>,
  );
}

describe("NoteBody", () => {
  it("renders markdown content as formatted HTML (not raw source)", () => {
    const { container } = renderBody({
      content: "# FortiBleed\n\n**Critical** finding\n\n---\n\n- one\n- two",
    });
    // Heading, bold and list render as real elements — the raw markers are gone.
    expect(container.querySelector("h1")?.textContent).toContain("FortiBleed");
    expect(container.querySelector("strong")?.textContent).toBe("Critical");
    expect(container.querySelector("hr")).toBeInTheDocument();
    expect(container.querySelectorAll("li").length).toBe(2);
    expect(screen.queryByText(/^#\s/)).not.toBeInTheDocument();
  });

  it("auto-detects markdown when no format is given", () => {
    const { container } = renderBody({ content: "## Detections\n\nmap to T1566" });
    expect(container.querySelector("h2")?.textContent).toContain("Detections");
  });

  it("renders HTML content via the html renderer", () => {
    const { container } = renderBody({
      content: "<h2>Findings</h2><p>Key takeaways</p>",
      format: "html",
    });
    expect(container.querySelector("h2")?.textContent).toBe("Findings");
    expect(screen.getByText("Key takeaways")).toBeInTheDocument();
  });

  it("auto-detects HTML content", () => {
    const { container } = renderBody({ content: "<p>Some <strong>observations</strong></p>" });
    expect(container.querySelector("strong")?.textContent).toBe("observations");
  });

  it("renders markdown that was wrapped in <p> tags by the AI copilot", () => {
    // Each markdown block wrapped in <p>…</p>, markdown syntax intact inside.
    const { container } = renderBody({
      content: "<p># FortiBleed</p><p>**TLP:CLEAR**</p><p>---</p><p>## Section</p>",
    });
    expect(container.querySelector("h1")?.textContent).toContain("FortiBleed");
    expect(container.querySelector("strong")?.textContent).toBe("TLP:CLEAR");
    expect(container.querySelector("hr")).toBeInTheDocument();
    expect(container.querySelector("h2")?.textContent).toContain("Section");
    // The raw markers must be gone from the output.
    expect(container.textContent).not.toContain("# FortiBleed");
    expect(container.textContent).not.toContain("**TLP");
  });

  it("renders the copilot 'hybrid' note: <p>-wrapped markdown mixed with real inline HTML", () => {
    // The block structure is markdown-in-<p>, but the copilot emitted a few
    // genuine inline tags (<code>, <a>). Previously the <a>/<code> tripped the
    // HTML detector and the whole note rendered as raw markdown.
    const { container } = renderBody({
      content:
        "<p># FortiBleed</p>" +
        "<p>Spray <code>forticheck</code> across targets.</p>" +
        '<p>Reported by <a href="https://securitydiscovery.com">SecurityDiscovery.com</a>.</p>' +
        "<p>**Critical**</p>" +
        "<p>| Metric | Figure |</p><p>| --- | --- |</p><p>| Devices | 75000 |</p>",
    });
    // Block markdown now renders...
    expect(container.querySelector("h1")?.textContent).toContain("FortiBleed");
    expect(container.querySelector("strong")?.textContent).toBe("Critical");
    // ...and the real inline tags survive as formatted output.
    expect(container.querySelector("code")?.textContent).toBe("forticheck");
    const link = container.querySelector('a[href="https://securitydiscovery.com"]');
    expect(link?.textContent).toContain("SecurityDiscovery.com");
    // Raw markdown markers are gone.
    expect(container.textContent).not.toContain("# FortiBleed");
    expect(container.textContent).not.toContain("**Critical**");
  });
});
