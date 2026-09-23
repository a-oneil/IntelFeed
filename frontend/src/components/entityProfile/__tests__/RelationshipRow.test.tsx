/**
 * RelationshipRow — evidence structure rendering: the shape phrase on the
 * evidence line, the chip economy (reported = unmarked default), and the
 * story-grouped evidence panel.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { EntitySearchResult } from "@/api/types";
import type { RelRow } from "@/utils/relationshipBrowser";
import { RelationshipRow } from "../RelationshipRow";

const baseItem: Partial<EntitySearchResult> = {
  id: "m1",
  name: "OWAReaper",
  relationship_id: "r1",
  relationship_type: "uses",
  relationship_direction: "outbound",
  proximity_entries: [
    { entry_id: "e1", title: "Russian hackers exploit OWA zero-day", score: 0.91, published_at: "2026-07-30" },
    { entry_id: "e2", title: "Kremlin-linked crew keeps mailbox access", score: 0.84, published_at: "2026-07-29" },
    { entry_id: "e3", title: "Weekly threat roundup", score: 0.2, published_at: "2026-08-03" },
  ],
  strength: {
    score: 0.6,
    tier: "moderate",
    closeness: 0.8,
    articles: 3,
    sources: 3,
    first_seen: "2026-07-29",
    last_seen: "2026-08-03",
    trend: [0, 0, 3],
  },
};

const row = (over: Partial<EntitySearchResult>): RelRow => ({
  type: "malware",
  item: { ...baseItem, ...over } as EntitySearchResult,
  label: "OWAReaper",
  meta: "backdoor",
});

const renderRow = (over: Partial<EntitySearchResult>) =>
  render(<RelationshipRow row={row(over)} viewedLabel="Void Blizzard" onOpen={vi.fn()} />);

describe("chip economy", () => {
  it("renders no chip for reported (probable) rows — the unmarked default", () => {
    renderRow({ relationship_confidence: "probable" });
    expect(screen.queryByText(/reported/i)).toBeNull();
  });

  it("keeps the corroborated chip with provenance", () => {
    renderRow({
      relationship_confidence: "confirmed",
      relationship_source: "external_feed",
    });
    expect(screen.getByText(/corroborated · MITRE/i)).toBeTruthy();
  });

  it("keeps the signal chip", () => {
    renderRow({ relationship_confidence: "possible" });
    expect(screen.getByText("signal")).toBeTruthy();
  });
});

describe("evidence structure", () => {
  const structure = {
    shape: "single_story" as const,
    stories: [
      {
        entries: 2,
        entry_ids: ["e1", "e2"],
        first: "2026-07-29",
        last: "2026-07-30",
        slug: "owa-zero-day",
        title: "Russian OWA zero-day espionage",
      },
    ],
    loose: 1,
    sampled: 3,
  };

  it("shows the shape phrase with a bold lead on the reading line", () => {
    renderRow({ relationship_confidence: "probable", evidence_structure: structure });
    expect(
      screen.getByText(
        (_, el) =>
          el?.tagName === "BUTTON" && el.textContent === "one story — “Russian OWA zero-day espionage”",
      ),
    ).toBeTruthy();
    expect(screen.getByText("one story").tagName).toBe("B");
  });

  it("groups the expanded evidence panel by story with a loose tail", () => {
    renderRow({ relationship_confidence: "probable", evidence_structure: structure });
    fireEvent.click(screen.getAllByTitle("Show contributing articles")[0]);
    expect(screen.getByText("Russian OWA zero-day espionage")).toBeTruthy();
    expect(screen.getByText("Outside these stories")).toBeTruthy();
    expect(screen.getByText("Weekly threat roundup")).toBeTruthy();
  });

  it("renders the flat evidence list when no structure is available", () => {
    renderRow({ relationship_confidence: "probable" });
    fireEvent.click(screen.getByTitle("Show contributing articles"));
    expect(screen.getByText("Russian hackers exploit OWA zero-day")).toBeTruthy();
    expect(screen.queryByText("Outside these stories")).toBeNull();
  });
});
