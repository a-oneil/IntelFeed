import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import ThreatBoard from "../ThreatBoard";
import type { ThreatBoardItem } from "@/hooks/useThreatBoard";

/** The quiet briefing row: story first, one caption line, no chip band; the
    detail lives in the drawer. The story is the brief when cached, the lead
    headline otherwise — never a template sentence over three integers. */

function makeItem(overrides: Partial<ThreatBoardItem> = {}): ThreatBoardItem {
  return {
    entity_type: "threat_actor",
    entity_key: "a1",
    label: "ShinyHunters",
    facets: ["threat_actor"],
    attention: 21,
    stories: 21,
    echoes_folded: 0,
    beats: 0,
    new_techniques: 0,
    on_record: 100,
    prior_rules: 1,
    prior_rules_strong: 0,
    prior_rule_repos: { "nuclei-templates": 1 },
    last_seen: "2026-09-02T10:00:00+00:00",
    state: "open",
    is_generic: false,
    score: 21,
    action: "diff",
    articles: 12,
    headline: {
      entry_id: "e1",
      title: "McKesson confirms cyber incident after ShinyHunters claims patient-data theft",
      url: "https://example.com/a",
      source: "bleepingcomputer.com",
      published_at: "2026-08-31T10:00:00+00:00",
    },
    sources: ["bleepingcomputer.com", "securityweek.com"],
    writable_observables: 1,
    brief: null,
    brief_sources: [],
    product: null,
    in_stack: false,
    is_kev: false,
    cvss_score: null,
    epss_score: null,
    exploit_status: null,
    posture: null,
    profile_id: null,
    on_surface: true,
    thread_slug: null,
    thread_title: null,
    is_story: false,
    merged_from: [],
    ...overrides,
  };
}

const items: ThreatBoardItem[] = [
  makeItem(),
  makeItem({
    entity_key: "a2",
    label: "APT29",
    attention: 6,
    stories: 6,
    new_techniques: 6,
    on_record: 126,
    prior_rules: 35,
    prior_rules_strong: 14,
    action: "extend",
    articles: 10,
    writable_observables: 0,
    brief: "Session-cookie theft and MFA modification documented in the diplomatic-sector chain.",
    brief_sources: ["e2", "e3"],
    headline: null,
  }),
];

let precedent: { slug: string; title: string; status: string; entry_count: number; similarity: number }[] = [];

vi.mock("sonner", () => ({ toast: { success: vi.fn(), info: vi.fn(), error: vi.fn() } }));

const setStateMutate = vi.fn();
vi.mock("@/hooks/useThreatBoard", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/hooks/useThreatBoard")>();
  return {
    ...actual,
    useThreatBoard: () => ({ data: { window: "14d", items, total: items.length }, isLoading: false }),
    useSetThreatState: () => ({ mutate: setStateMutate, isPending: false }),
    usePrecedent: () => ({ data: precedent }),
    // The drawer's full-width rule inventory — loading state is enough here.
    useBoardRules: () => ({ data: undefined, isLoading: true }),
  };
});

const workspaceSpy = vi.fn();
vi.mock("@/hooks/useCoverageWorkspace", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/hooks/useCoverageWorkspace")>();
  return {
    ...actual,
    useCoverageWorkspace: (...args: unknown[]) => {
      workspaceSpy(...args);
      return { data: undefined, isLoading: true };
    },
  };
});

function renderBoard(facet = "all") {
  return render(
    <MemoryRouter>
      <ThreatBoard facet={facet} />
    </MemoryRouter>
  );
}

describe("ThreatBoard briefing rows", () => {
  it("renders the AI brief as the story when cached, the headline otherwise", () => {
    renderBoard();
    // Headline fallback, rendered as a quoted lede — not a template sentence.
    expect(
      screen.getByText(/McKesson confirms cyber incident after ShinyHunters/)
    ).toBeInTheDocument();
    // Cached brief wins for APT29.
    expect(
      screen.getByText(/Session-cookie theft and MFA modification documented/)
    ).toBeInTheDocument();
    // The retired template phrasing never appears.
    expect(screen.queryByText(/no new tradecraft/)).not.toBeInTheDocument();
  });

  it("keeps the evidence to one quiet caption line — rule-ready indicators included", () => {
    renderBoard();
    expect(screen.getByText("12 articles · 1 rule-ready indicator · 1 rule loosely matches")).toBeInTheDocument();
    expect(screen.getByText("10 articles · 14 rules name it · +21 weak")).toBeInTheDocument();
  });

  it("derives the action label from the counts", () => {
    renderBoard();
    expect(screen.getByRole("button", { name: "Check 1 weak match →" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Extend 14 rules →" })).toBeInTheDocument();
  });

  it("expands a row into the workspace-backed drawer on click", () => {
    renderBoard();
    fireEvent.click(screen.getByText(/Session-cookie theft and MFA modification/));
    // The drawer lazy-fetches the workspace for exactly this row and window.
    expect(workspaceSpy).toHaveBeenCalledWith("threat_actor", "a2", "14d", true);
    expect(screen.getByText("Assembling…")).toBeInTheDocument();
  });

  it("marks a threat handled with the view's window", () => {
    renderBoard();
    fireEvent.click(screen.getByRole("button", { name: "Mark handled: ShinyHunters" }));
    expect(setStateMutate).toHaveBeenCalledWith(
      expect.objectContaining({ entityType: "threat_actor", entityKey: "a1", state: "handled", window: "14d" }),
      expect.anything()
    );
  });

  it("filters rows by facet", () => {
    renderBoard("malware");
    expect(screen.queryByText("ShinyHunters")).not.toBeInTheDocument();
    expect(screen.getByText(/No threats above the attention threshold/)).toBeInTheDocument();
  });
});


/** Story threads on the board: what the counts mean once one story can be told
    apart from eleven re-reports of it, and the row that only a thread can
    carry. */
describe("ThreatBoard with story threads", () => {
  const storyRow = makeItem({
    entity_type: "story",
    entity_key: "fortiweb-preauth-rce",
    label: "FortiWeb pre-auth RCE, exploited pre-patch",
    facets: ["story"],
    is_story: true,
    stories: 1,
    attention: 5,
    articles: 5,
    echoes_folded: 2,
    beats: 3,
    on_record: 1,
    prior_rules: 0,
    prior_rules_strong: 0,
    prior_rule_repos: {},
    writable_observables: 2,
    action: "collect",
    thread_slug: "fortiweb-preauth-rce",
    thread_title: "FortiWeb pre-auth RCE, exploited pre-patch",
    headline: {
      entry_id: "e9",
      title: "Fortinet confirms FortiWeb attacks after two weeks of honeypot hits",
      url: "https://example.com/fw",
      source: "bleepingcomputer.com",
      published_at: "2026-09-02T10:00:00+00:00",
      is_origin: true,
      outlets: 5,
    },
  });

  const foldedRow = makeItem({
    entity_key: "a3",
    label: "Storm-1811",
    stories: 1,
    attention: 7,
    articles: 6,
    echoes_folded: 5,
    facets: ["threat_actor", "malware"],
    merged_from: [{ entity_type: "malware", entity_key: "m9", label: "BlackSuit" }],
    thread_slug: "quick-assist-blacksuit",
  });

  function renderRows(rows: ThreatBoardItem[], facet = "all") {
    items.splice(0, items.length, ...rows);
    return render(
      <MemoryRouter>
        <ThreatBoard facet={facet} />
      </MemoryRouter>
    );
  }

  it("counts stories and outlets once a thread folds the coverage", () => {
    renderRows([foldedRow]);
    expect(screen.getByText("1 story")).toBeInTheDocument();
    expect(screen.getByText("7 outlets")).toBeInTheDocument();
    expect(screen.queryByText(/attn 7/)).not.toBeInTheDocument();
    expect(
      screen.getByText("1 story · 6 articles · 5 duplicates hidden · 1 rule-ready indicator · 1 rule loosely matches")
    ).toBeInTheDocument();
  });

  it("keeps the outlet count as the story count when nothing is threaded", () => {
    renderRows([makeItem({ stories: 21, attention: 21, articles: 12 })]);
    expect(screen.getByText("21 outlets")).toBeInTheDocument();
    expect(screen.queryByText(/stories/)).not.toBeInTheDocument();
  });

  it("puts the absorbed row on the same identity line", () => {
    renderRows([foldedRow]);
    expect(screen.getByText("Storm-1811")).toBeInTheDocument();
    expect(screen.getByText("· BlackSuit")).toBeInTheDocument();
    expect(screen.getByText("same story")).toBeInTheDocument();
  });

  it("says when the lead article is the one that broke the story", () => {
    renderRows([storyRow]);
    expect(screen.getByText(/first of 5 outlets/)).toBeInTheDocument();
  });

  it("never reports a rule gap on a row that has no entity", () => {
    renderRows([storyRow]);
    expect(
      screen.getByText("1 story · 5 articles · 2 duplicates hidden · 2 rule-ready indicators · 3 beats, still developing")
    ).toBeInTheDocument();
    expect(screen.queryByText(/nothing matches/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Read the story →" })).toBeInTheDocument();
  });

  it("opens a story row's own drawer instead of fetching a workspace", () => {
    precedent = [
      { slug: "cisco-asa-wave", title: "Akira via Cisco ASA", status: "dormant", entry_count: 9, similarity: 0.83 },
    ];
    workspaceSpy.mockClear();
    renderRows([storyRow]);
    fireEvent.click(screen.getByText(/Fortinet confirms FortiWeb attacks/));
    expect(workspaceSpy).not.toHaveBeenCalledWith("story", "fortiweb-preauth-rce", "14d", true);
    expect(screen.getByText("Coverage · 3 beats, 5 outlets")).toBeInTheDocument();
    // The precedent line is the one thing keyword search could never answer.
    expect(screen.getByText("Akira via Cisco ASA")).toBeInTheDocument();
    expect(screen.getByText(/83% match/)).toBeInTheDocument();
    precedent = [];
  });
});
