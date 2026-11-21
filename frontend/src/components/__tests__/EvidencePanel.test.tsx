import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const get = vi.fn();
vi.mock("@/api/client", () => ({ default: { get: (...args: unknown[]) => get(...args) } }));

import { RelationshipEvidencePanel, RowEvidencePanel } from "../engine/EvidencePanel";

function renderIt(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

const edge = {
  relationship_id: "e1",
  adjudication_verdict: null,
  article_count: 3,
  articles: [
    {
      entry_id: "a1",
      title: "Warlock deploys Cobalt Strike",
      feed_title: "Vendor blog",
      published_at: null,
      analysis_verb: null,
      analysis_sentence: null,
      passages: ["The Warlock operators relied on Cobalt Strike."],
      source_only: null,
      target_only: null,
    },
  ],
  reviews: [
    {
      reviewer: "sweep",
      verdict: "keep",
      confidence: "high",
      reason: "stated",
      quote: "relied on Cobalt Strike",
      suggested_verb: null,
      flipped: false,
      counted: false,
      entry_id: null,
      entry_title: null,
      created_at: "2026-11-21T10:00:00Z",
    },
  ],
};

describe("EvidencePanel", () => {
  it("shows an edge's articles with both ends marked, and its reviews", async () => {
    get.mockResolvedValue({ data: edge });
    renderIt(<RelationshipEvidencePanel id="e1" names={["Warlock", "Cobalt Strike"]} />);
    const link = await screen.findByRole("link", { name: "Warlock deploys Cobalt Strike" });
    expect(link.getAttribute("href")).toBe("/?entry=a1");
    expect(screen.getByText("Articles (3, 1 shown)")).toBeTruthy();
    const marks = [...document.querySelectorAll("mark")].map((m) => m.textContent);
    expect(marks).toContain("Warlock");
    expect(marks).toContain("Cobalt Strike");
    expect(screen.getByText("Kept")).toBeTruthy();
    expect(screen.getByText(/Edge sweep · high/)).toBeTruthy();
    expect(get).toHaveBeenCalledWith("/entity-relationships/e1/evidence");
  });

  it("shows a proposal's quote, facts and article", async () => {
    get.mockResolvedValue({
      data: {
        id: "entity_maintenance:l1",
        reason: "only a passing mention",
        confidence: "medium",
        quote: "Everest hit a hospital",
        article: {
          entry_id: "a2",
          title: "Hospital attack",
          feed_title: "News",
          published_at: null,
          paragraphs: ["Everest hit a hospital."],
          highlight: ["Everest"],
        },
        facts: [{ label: "Matched as", value: "Everest" }],
        relationship: null,
        history: [],
      },
    });
    renderIt(<RowEvidencePanel id="entity_maintenance:l1" />);
    expect(await screen.findByText("only a passing mention")).toBeTruthy();
    expect(screen.getByText("Why it was proposed (medium confidence)")).toBeTruthy();
    expect(screen.getByText("Matched as")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Hospital attack" })).toBeTruthy();
    expect(get).toHaveBeenCalledWith("/admin/hygiene/feed/entity_maintenance/l1/evidence");
  });
});
