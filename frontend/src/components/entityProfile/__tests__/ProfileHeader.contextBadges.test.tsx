import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { EntitySearchResult } from "@/api/types";
import type { EntityContext } from "@/hooks/useEntityContext";
import { contextBadgeSpecs, getEntityProfileConfig } from "../entityProfileConfig";
import { ProfileHeader } from "../ProfileHeader";

const context: EntityContext = {
  sources: [],
  unavailable: [],
  badges: [
    { source_type: "greynoise", key: "noise_class", label: "noise · benign", tone: "success" },
    { source_type: "cisa_adp", key: "ssvc", label: "SSVC exploitation: active", tone: "danger" },
  ],
  can_enrich: true,
};

vi.mock("@/hooks/useEntityContext", async (orig) => ({
  ...(await orig<typeof import("@/hooks/useEntityContext")>()),
  useEntityContext: () => ({ data: context }),
}));
// The action row pulls in half the app's hooks; it isn't what's under test.
vi.mock("../EntityActionsMenu", () => ({ EntityActionsMenu: () => null }));
vi.mock("../WatchToggleButton", () => ({ WatchToggleButton: () => null }));

describe("ProfileHeader context badges", () => {
  it("appends manifest badges after the hand-written ones", () => {
    const entity = { id: "o1", value: "71.6.135.131", kind: "ipv4" } as unknown as EntitySearchResult;
    render(
      <MemoryRouter>
        <ProfileHeader
          entityType="observable"
          entityId="o1"
          entity={entity}
          config={getEntityProfileConfig("observable")}
          entries={[]}
          relatedCountries={[]}
          onUpdateField={vi.fn()}
          onOpenEntity={vi.fn()}
          onNavigateAway={vi.fn()}
        />
      </MemoryRouter>,
    );
    const kind = screen.getByText("ipv4");
    const noise = screen.getByText("noise · benign");
    expect(screen.getByText("SSVC exploitation: active")).toBeInTheDocument();
    // Hand-written first, manifest badges after.
    expect(kind.compareDocumentPosition(noise) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("keeps benign tones neutral and red/amber for things that need attention", () => {
    expect(
      contextBadgeSpecs([
        { source_type: "a", key: "k", label: "benign", tone: "success" },
        { source_type: "a", key: "k", label: "info", tone: "info" },
        { source_type: "a", key: "k", label: "eol", tone: "warning" },
        { source_type: "a", key: "k", label: "active", tone: "danger" },
      ]).map((b) => b.tone),
    ).toEqual(["neutral", "neutral", "medium", "danger"]);
  });

  it("gives a badge that mirrors a column that column's provenance marker", () => {
    const [mirrored, plain] = contextBadgeSpecs([
      { source_type: "greynoise", key: "classification", label: "noise · benign", tone: "success", field: "reputation.gn_classification" },
      { source_type: "vulncheck", key: "in_kev", label: "VulnCheck KEV", tone: "critical" },
    ]);
    expect(mirrored.provenanceKey).toBe("reputation.gn_classification");
    expect(plain.provenanceKey).toBeUndefined();
  });
});
