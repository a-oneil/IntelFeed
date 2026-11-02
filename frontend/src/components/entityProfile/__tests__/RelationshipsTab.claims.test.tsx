import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { PivotResponse } from "@/api/types";
import type { RelationClaims } from "@/hooks/useRelationships";
import { RelationshipsTab } from "../tabs/RelationshipsTab";

const claims: { data: RelationClaims | undefined; enabled: boolean[] } = { data: undefined, enabled: [] };
const noop = () => ({ mutate: vi.fn(), isPending: false });

vi.mock("@/hooks/useRelationships", () => ({
  useRelationClaims: (_t: string, _id: string, enabled = true) => {
    claims.enabled.push(enabled);
    return { data: enabled ? claims.data : undefined };
  },
  useCreateRelationship: () => noop(),
  useConfirmRelationship: () => noop(),
  useRejectRelationship: () => noop(),
}));
vi.mock("@/hooks/useCorrelation", () => ({
  usePivot: () => ({ data: undefined }),
  useEntityGraph: () => ({ data: undefined }),
  useUnlinkRelatedEntity: () => noop(),
}));
// The graph canvas isn't what's under test.
vi.mock("@/components/EntityGraph", () => ({ EntityGraph: () => null }));
vi.mock("@/utils/openEntry", () => ({ useOpenThread: () => vi.fn() }));

const auth = { visitor: false };
vi.mock("@/stores/authStore", () => ({ useIsVisitor: () => auth.visitor }));

const tool = (id: string, name: string) => ({
  id,
  name,
  relationship_id: `rel-${id}`,
  relationship_type: "uses",
  relationship_confidence: "probable",
  relationship_source: "enrichment",
});

const related = {
  tools: [tool("t1", "AdFind"), tool("t2", "7-Zip"), tool("t3", "Cobalt Strike")],
} as unknown as PivotResponse["related"];

function renderTab() {
  return render(
    <MemoryRouter>
      <RelationshipsTab
        entityType="threat_actor"
        entityId="a1"
        entityLabel="APT29"
        related={related}
        onOpenEntity={vi.fn()}
        onOpenArticle={vi.fn()}
        onOpenEntry={vi.fn()}
      />
    </MemoryRouter>,
  );
}

const visibleNames = () =>
  ["AdFind", "7-Zip", "Cobalt Strike"].filter((n) => screen.queryByText(n) !== null);

describe("RelationshipsTab enrichment claims", () => {
  beforeEach(() => {
    auth.visitor = false;
    claims.enabled = [];
    claims.data = {
      entity_type: "threat_actor",
      entity_id: "a1",
      sources: [
        { source_type: "etda", label: "ETDA", linked: 2 },
        { source_type: "malpedia", label: "Malpedia", linked: 1 },
      ],
      by_target: { "tool-t1": ["etda"], "tool-t2": ["etda", "malpedia"] },
      held: [
        {
          source_type: "etda",
          source_label: "ETDA",
          relation: "uses",
          target_name: "ATI-Agent",
          target_type: "tool",
          held_reason: "unknown",
          evidence: null,
        },
      ],
      held_count: 1,
    };
  });

  it("tags each claimed row with its sources", () => {
    renderTab();
    const adfind = screen.getByText("AdFind").closest("button")!;
    expect(within(adfind).getByText("ETDA")).toBeInTheDocument();
    const zip = screen.getByText("7-Zip").closest("button")!;
    expect(within(zip).getByText("ETDA · Malpedia")).toBeInTheDocument();
    const cs = screen.getByText("Cobalt Strike").closest("button")!;
    expect(within(cs).queryByText(/ETDA|Malpedia/)).not.toBeInTheDocument();
  });

  it("narrows to one source with a via chip, and back", () => {
    renderTab();
    expect(visibleNames()).toEqual(["AdFind", "7-Zip", "Cobalt Strike"]);
    const via = screen.getByRole("button", { name: "via Malpedia 1" });
    fireEvent.click(via);
    expect(via).toHaveAttribute("aria-pressed", "true");
    expect(visibleNames()).toEqual(["7-Zip"]);
    fireEvent.click(via);
    expect(visibleNames()).toEqual(["AdFind", "7-Zip", "Cobalt Strike"]);
  });

  it("lists held targets behind an unresolved count", () => {
    renderTab();
    const toggle = screen.getByRole("button", { name: "unresolved · 1" });
    expect(screen.queryByText("ATI-Agent")).not.toBeInTheDocument();
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("ATI-Agent")).toBeInTheDocument();
    expect(screen.getByText(/via ETDA · no entity has this name yet/)).toBeInTheDocument();
  });

  it("doesn't ask for claims as a visitor", () => {
    auth.visitor = true;
    renderTab();
    expect(claims.enabled.every((e) => e === false)).toBe(true);
    expect(screen.queryByRole("button", { name: /^via / })).not.toBeInTheDocument();
    expect(screen.queryByText(/unresolved/)).not.toBeInTheDocument();
  });
});
