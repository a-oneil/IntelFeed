import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { PivotResponse } from "@/api/types";
import type { RelationClaims } from "@/hooks/useRelationships";
import type { RelationshipEvidence } from "@/hooks/useHygiene";
import { RelationshipsTab } from "../tabs/RelationshipsTab";

const claims: { data: RelationClaims | undefined; enabled: boolean[] } = { data: undefined, enabled: [] };
const update = vi.fn();
const noop = () => ({ mutate: vi.fn(), isPending: false });

vi.mock("@/hooks/useRelationships", () => ({
  useRelationClaims: (_t: string, _id: string, enabled = true) => {
    claims.enabled.push(enabled);
    return { data: enabled ? claims.data : undefined };
  },
  useCreateRelationship: () => noop(),
  useConfirmRelationship: () => noop(),
  useRejectRelationship: () => noop(),
  useUpdateRelationship: () => ({ mutate: update, isPending: false }),
}));
vi.mock("@/hooks/useCorrelation", () => ({
  usePivot: () => ({ data: undefined }),
  useEntityGraph: () => ({ data: undefined }),
}));

const evidence: { data: RelationshipEvidence | undefined; asked: Array<string | null> } = { data: undefined, asked: [] };
vi.mock("@/hooks/useHygiene", () => ({
  useRelationshipEvidence: (id: string | null) => {
    evidence.asked.push(id);
    return { data: id ? evidence.data : undefined, isLoading: false };
  },
}));
// The graph canvas isn't what's under test.
vi.mock("@/components/EntityGraph", () => ({ EntityGraph: () => null }));
vi.mock("@/utils/openEntry", () => ({ useOpenThread: () => vi.fn() }));

const auth = { visitor: false };
vi.mock("@/stores/authStore", () => ({ useIsVisitor: () => auth.visitor }));
const screenSize = { mobile: false };
vi.mock("@/hooks/useMediaQuery", () => ({ useIsMobile: () => screenSize.mobile }));

/** A stored relationship id (a UUID; catalog rows carry synthetic ones). */
const relId = (key: string) => `00000000-0000-4000-8000-${key.padStart(12, "0")}`;

const tool = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  id,
  name,
  relationship_id: relId(id.replace(/\D/g, "")),
  relationship_type: "uses",
  relationship_confidence: "probable",
  relationship_source: "enrichment",
  relationship_direction: "outbound",
  ...extra,
});

const related = {
  tools: [
    tool("t1", "AdFind", { relationship_description: "Seen on the group's ETDA card" }),
    tool("t2", "7-Zip"),
    tool("t3", "Cobalt Strike"),
  ],
  malwares: [
    {
      id: "m1",
      name: "WINELOADER",
      relationship_id: relId("901"),
      relationship_type: "uses",
      relationship_confidence: "possible",
      relationship_source: "co_occurrence",
      relationship_direction: "outbound",
    },
  ],
} as unknown as PivotResponse["related"];

function renderTab(rel: PivotResponse["related"] = related) {
  return render(
    <MemoryRouter>
      <RelationshipsTab
        entityType="threat_actor"
        entityId="a1"
        entityLabel="APT29"
        related={rel}
        onOpenEntity={vi.fn()}
        onOpenArticle={vi.fn()}
        onOpenEntry={vi.fn()}
      />
    </MemoryRouter>,
  );
}

/** The list's rows (the panel has buttons too). */
const rows = () => [...document.querySelectorAll<HTMLButtonElement>("button[aria-pressed]")];
const rowNames = () => rows().map((b) => b.querySelector("span span:last-child")?.textContent);
const row = (name: string) => rows().find((b) => b.textContent?.includes(name))!;

describe("RelationshipsTab", () => {
  beforeEach(() => {
    auth.visitor = false;
    screenSize.mobile = false;
    claims.enabled = [];
    evidence.asked = [];
    evidence.data = undefined;
    update.mockClear();
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

  it("names each row's source in plain words", () => {
    renderTab();
    expect(within(row("AdFind")).getByText("ETDA")).toBeInTheDocument();
    expect(within(row("7-Zip")).getByText("ETDA + Malpedia")).toBeInTheDocument();
    expect(within(row("Cobalt Strike")).getByText("Enrichment feed")).toBeInTheDocument();
    expect(within(row("WINELOADER")).getByText("Articles, not reviewed")).toBeInTheDocument();
  });

  it("narrows to one source with the Source filter, and back", () => {
    renderTab();
    const select = screen.getByRole("combobox", { name: "Source" });
    fireEvent.change(select, { target: { value: "feed:Malpedia" } });
    expect(rowNames()).toEqual(["7-Zip"]);
    fireEvent.change(select, { target: { value: "" } });
    expect(rowNames()).toHaveLength(4);
  });

  it("lists names no entity matches under Not matched yet", () => {
    renderTab();
    const toggle = screen.getByRole("button", { name: /Not matched yet · 1/ });
    expect(screen.queryByText("ATI-Agent")).not.toBeInTheDocument();
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("ATI-Agent")).toBeInTheDocument();
    expect(screen.getByText("ETDA lists these, but no IntelFeed entity has the name.")).toBeInTheDocument();
  });

  it("explains the selected relationship: the source's words and the articles that state it", () => {
    evidence.data = {
      relationship_id: relId("1"),
      adjudication_verdict: "kept",
      article_count: 1,
      articles: [
        {
          entry_id: "e1",
          title: "APT29 tooling report",
          feed_title: "Some Feed",
          published_at: null,
          analysis_verb: "uses",
          analysis_sentence: "APT29 ran AdFind to map the domain.",
          passages: [],
          source_only: null,
          target_only: null,
        },
      ],
      reviews: [
        {
          reviewer: "sweep",
          verdict: "keep",
          confidence: "high",
          reason: "The article says so.",
          quote: null,
          suggested_verb: null,
          flipped: false,
          counted: true,
          entry_id: "e1",
          entry_title: "APT29 tooling report",
          created_at: "2026-11-01T00:00:00Z",
        },
      ],
    };
    renderTab();
    fireEvent.click(row("AdFind"));
    expect(row("AdFind")).toHaveAttribute("aria-pressed", "true");
    const panel = screen.getByRole("region", { name: "Why this relationship is listed" });
    expect(within(panel).getByText("APT29 uses AdFind")).toBeInTheDocument();
    expect(within(panel).getByText("“Seen on the group's ETDA card”")).toBeInTheDocument();
    expect(within(panel).getByText("Articles that state it · 1")).toBeInTheDocument();
    expect(within(panel).getByText("APT29 ran AdFind to map the domain.")).toBeInTheDocument();
    expect(within(panel).getByText("AI reviewer kept it")).toBeInTheDocument();
    expect(evidence.asked).toContain(relId("1"));
  });

  it("changes a relationship's type to one the pair allows", () => {
    renderTab();
    fireEvent.click(row("WINELOADER"));
    const panel = screen.getByRole("region", { name: "Why this relationship is listed" });
    const pick = within(panel).getByRole("combobox");
    expect([...pick.querySelectorAll("option")].map((o) => o.value)).toEqual(["uses", "delivers", "related_to"]);
    fireEvent.change(pick, { target: { value: "delivers" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Change" }));
    expect(update).toHaveBeenCalledWith({ id: relId("901"), relationship_type: "delivers" });
  });

  it("gives a visitor no claims, no review evidence and no editing", () => {
    auth.visitor = true;
    renderTab();
    expect(claims.enabled.every((e) => e === false)).toBe(true);
    expect(evidence.asked.every((id) => id === null)).toBe(true);
    expect(screen.queryByText(/Not matched yet/)).not.toBeInTheDocument();
    const panel = screen.getByRole("region", { name: "Why this relationship is listed" });
    expect(within(panel).queryByRole("combobox")).not.toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();
  });

  it("on a phone, opens the evidence under the tapped row and closes it on a second tap", () => {
    screenSize.mobile = true;
    renderTab();
    // Nothing opens until a row is tapped.
    expect(screen.queryByRole("region", { name: "Why this relationship is listed" })).not.toBeInTheDocument();
    fireEvent.click(row("AdFind"));
    const panel = screen.getByRole("region", { name: "Why this relationship is listed" });
    expect(within(panel).getByText("APT29 uses AdFind")).toBeInTheDocument();
    // It sits right after the row, not beside the list.
    expect(row("AdFind").nextElementSibling?.contains(panel)).toBe(true);
    expect(row("AdFind")).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(row("AdFind"));
    expect(screen.queryByRole("region", { name: "Why this relationship is listed" })).not.toBeInTheDocument();
  });

  it("opens the co-mentions when there are no relationships, and keeps them closed when there are", () => {
    const coMentioned = { malwares: [{ id: "m9", name: "LockBit", co_occurrence_count: 4 }] } as unknown as PivotResponse["related"];
    const { unmount } = renderTab(coMentioned);
    const toggle = screen.getByRole("button", { name: /Mentioned in the same articles · 1/ });
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("LockBit")).toBeInTheDocument();
    fireEvent.click(toggle);
    expect(screen.queryByText("LockBit")).not.toBeInTheDocument();
    unmount();

    renderTab({ ...related, ...coMentioned } as PivotResponse["related"]);
    expect(screen.getByRole("button", { name: /Mentioned in the same articles · 1/ })).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText("LockBit")).not.toBeInTheDocument();
  });

  it("asks for no evidence and offers no editing on a catalog row with a synthetic id", () => {
    const catalog = {
      mitigations: [
        {
          id: "mi1",
          name: "Network Intrusion Prevention",
          relationship_id: "catalog-ttp-mitigation-mi1",
          relationship_type: "mitigated_by",
          relationship_confidence: "confirmed",
          relationship_source: "external_feed",
          relationship_direction: "outbound",
        },
      ],
    } as unknown as PivotResponse["related"];
    renderTab(catalog);
    fireEvent.click(row("Network Intrusion Prevention"));
    expect(evidence.asked.every((id) => id === null)).toBe(true);
    const panel = screen.getByRole("region", { name: "Why this relationship is listed" });
    expect(within(panel).queryByRole("combobox")).not.toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();
  });
});

