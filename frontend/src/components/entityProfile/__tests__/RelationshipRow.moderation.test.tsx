import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import type { EntitySearchResult } from "@/api/types";
import type { RelRow } from "@/utils/relationshipBrowser";
import { RelationshipRow } from "../RelationshipRow";

const strength = {
  score: 0.75,
  tier: "strong" as const,
  closeness: 0.9,
  articles: 12,
  sources: 5,
  first_seen: "2026-01-01",
  last_seen: "2026-06-30",
  trend: [0, 0, 0, 1, 2, 3, 0, 0, 1, 2, 1, 2],
};

function makeRow(): RelRow {
  return {
    type: "threat_actor",
    label: "APT28",
    meta: "Russia",
    item: {
      id: "a1",
      proximity_score: 0.75,
      strength,
      relationship_id: "r1",
      relationship_type: "targets",
      relationship_direction: "inbound",
      relationship_source: "co_occurrence",
      relationship_confidence: "probable",
      co_occurrence_count: 12,
      proximity_entries: [
        { entry_id: "e1", title: "APT28 hits ministries", score: 0.9, published_at: "2026-06-30" },
      ],
    } as EntitySearchResult,
  };
}

describe("RelationshipRow", () => {
  it("renders evidence facts with no chip on reported rows — the unmarked default", () => {
    // probable → reported is the unmarked default (chip economy: a chip on
    // most rows carries no information); strength tier words never render.
    render(<RelationshipRow row={makeRow()} viewedLabel="Germany" onOpen={vi.fn()} />);
    expect(screen.queryByText("reported")).not.toBeInTheDocument();
    expect(screen.queryByText("strong")).not.toBeInTheDocument();
    expect(screen.getByText(/12 art\b/)).toBeInTheDocument();
  });

  it("shows machine-earned corroboration with provenance", () => {
    const row = makeRow();
    row.item.relationship_confidence = "confirmed";
    row.item.relationship_source = "external_feed";
    row.item.relationship_description = "MITRE ATT&CK";
    render(<RelationshipRow row={row} viewedLabel="Germany" onOpen={vi.fn()} />);
    expect(screen.getByText(/corroborated · MITRE/)).toBeInTheDocument();
    // Corroborated rows are settled — no pin/reject moderation buttons.
    expect(screen.queryByTitle("Pin — mark corroborated by you")).not.toBeInTheDocument();
  });

  it("labels AI-adjudicated corroboration with evidence count", () => {
    const row = makeRow();
    row.item.relationship_confidence = "confirmed";
    row.item.relationship_source = "auto_extracted";
    row.item.relationship_adjudication = "corroborated";
    row.item.relationship_evidence_count = 9;
    render(<RelationshipRow row={row} viewedLabel="Germany" onOpen={vi.fn()} />);
    expect(screen.getByText(/corroborated · AI ×9/)).toBeInTheDocument();
  });

  it("expands evidence and opens contributing articles", () => {
    const onOpenArticle = vi.fn();
    render(
      <RelationshipRow row={makeRow()} viewedLabel="Germany" onOpen={vi.fn()} onOpenArticle={onOpenArticle} />,
    );
    fireEvent.click(screen.getByText(/12 art\b/));
    fireEvent.click(screen.getByText("APT28 hits ministries"));
    expect(onOpenArticle).toHaveBeenCalledWith("e1");
  });

  it("fires pin and reject with the relationship id", () => {
    const onConfirm = vi.fn();
    const onReject = vi.fn();
    render(
      <RelationshipRow
        row={makeRow()}
        viewedLabel="Germany"
        onOpen={vi.fn()}
        onConfirm={onConfirm}
        onReject={onReject}
      />,
    );
    fireEvent.click(screen.getByTitle("Pin — mark corroborated by you"));
    expect(onConfirm).toHaveBeenCalledWith("r1");
    fireEvent.click(screen.getByTitle("Reject — hide and never re-infer"));
    expect(onReject).toHaveBeenCalledWith("r1");
  });

  it("navigates on row click", () => {
    const onOpen = vi.fn();
    render(<RelationshipRow row={makeRow()} viewedLabel="Germany" onOpen={onOpen} />);
    fireEvent.click(screen.getByText("APT28"));
    expect(onOpen).toHaveBeenCalledWith("threat_actor", "a1", "APT28");
  });
});
