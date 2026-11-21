import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const get = vi.fn();
vi.mock("@/api/client", () => ({ default: { get: (...args: unknown[]) => get(...args) } }));

import { RelationshipEvidencePanel, RowEvidencePanel } from "../engine/EvidencePanel";

function renderIt(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>{node}</QueryClientProvider>
    </MemoryRouter>,
  );
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

const proposal = {
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
  profiles: [],
  relationship: null,
  history: [],
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

  it("shows a proposal's article, quote and facts, not the reason the row already says", async () => {
    get.mockResolvedValue({ data: proposal });
    renderIt(<RowEvidencePanel id="entity_maintenance:l1" />);
    expect(await screen.findByRole("link", { name: "Hospital attack" })).toBeTruthy();
    expect(screen.getByText("Matched as")).toBeTruthy();
    expect(screen.getByText(/The AI quoted/)).toBeTruthy();
    expect(screen.queryByText("only a passing mention")).toBeNull();
    expect(screen.queryByText(/Why it was proposed/)).toBeNull();
    expect(screen.queryByText(/medium confidence/)).toBeNull();
    expect(get).toHaveBeenCalledWith("/admin/hygiene/feed/entity_maintenance/l1/evidence");
  });

  it("shows a merge proposal's two profiles side by side", async () => {
    get.mockResolvedValue({
      data: {
        ...proposal,
        article: null,
        quote: null,
        facts: [],
        profiles: [
          {
            entity_type: "threat_actor",
            entity_id: "t1",
            name: "UAC-0051",
            aliases: [],
            article_count: 0,
            created_via: "ai_extraction",
            first_seen: "2026-11-19",
            description: null,
            subtype: null,
          },
          {
            entity_type: "threat_actor",
            entity_id: "t2",
            name: "UNC1151",
            aliases: ["Ghostwriter", "TA445"],
            article_count: 72,
            created_via: null,
            first_seen: null,
            description: "Belarus-aligned group.",
            subtype: "nation-state",
          },
        ],
      },
    });
    renderIt(<RowEvidencePanel id="entity_maintenance:l1" />);
    expect(await screen.findByText("Both profiles")).toBeTruthy();
    expect(screen.getByRole("link", { name: "UAC-0051" }).getAttribute("href")).toBe("/workbench/threat_actor/t1");
    expect(screen.getByRole("link", { name: "UNC1151" }).getAttribute("href")).toBe("/workbench/threat_actor/t2");
    expect(screen.getByText("aliases: none")).toBeTruthy();
    expect(screen.getByText("aliases: Ghostwriter, TA445")).toBeTruthy();
    expect(screen.getByText("created by the analysis · first seen 2026-11-19")).toBeTruthy();
    expect(screen.getByText("catalogue entry")).toBeTruthy();
    expect(screen.getByText(/72 articles · nation-state/)).toBeTruthy();
    expect(screen.queryByText(/no article or recorded evidence/)).toBeNull();
  });
});
