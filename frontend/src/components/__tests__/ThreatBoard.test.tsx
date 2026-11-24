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
const draftMutate = vi.fn();
const downloadSpy = vi.fn();
const packageSpy = vi.fn();
// The hunt pack the drawer shows: none until a test sets one. The profile's
// all-reporting pack stays none, so the drawer offers no profile link.
const NO_PACK = {
  status: "none" as const,
  language: "kql" as const,
  language_name: "KQL (Microsoft Sentinel / Defender XDR)",
  pack: null,
  started_at: null,
  error: null,
};
let huntPack: import("@/hooks/useHuntPacks").HuntPackResponse = NO_PACK;
vi.mock("@/hooks/useHuntPacks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/hooks/useHuntPacks")>();
  return {
    ...actual,
    useHuntPack: (_type: string, _key: string, scope: string) => ({
      data: scope === "all" ? NO_PACK : huntPack,
      isLoading: false,
    }),
    useDraftHuntPack: () => ({ mutate: draftMutate, isPending: false }),
    downloadHuntFile: (...args: unknown[]) => {
      downloadSpy(...args);
      return Promise.resolve();
    },
    downloadHuntPackage: (...args: unknown[]) => {
      packageSpy(...args);
      return Promise.resolve();
    },
  };
});
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
// Undefined keeps the drawer in its loading state; a test that needs the
// drawer's body sets a (minimal) workspace.
let workspace: Record<string, unknown> | undefined;
vi.mock("@/hooks/useCoverageWorkspace", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/hooks/useCoverageWorkspace")>();
  return {
    ...actual,
    useCoverageWorkspace: (...args: unknown[]) => {
      workspaceSpy(...args);
      return { data: workspace, isLoading: workspace === undefined };
    },
  };
});

const EMPTY_WORKSPACE = {
  entity_type: "threat_actor",
  entity_key: "a2",
  label: "APT29",
  window: "14d",
  articles: [],
  behaviours: [],
  article_total: 0,
  article_contributed_total: 0,
  missing_categories: [],
};

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

  it("derives the action label from the counts", () => {
    renderBoard();
    expect(screen.getByRole("button", { name: "Review 1 rule →" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Extend 14 rules →" })).toBeInTheDocument();
  });

  it("expands a row into the workspace-backed drawer on click", () => {
    renderBoard();
    fireEvent.click(screen.getByText(/Session-cookie theft and MFA modification/));
    // The drawer lazy-fetches the workspace for exactly this row and window.
    expect(workspaceSpy).toHaveBeenCalledWith("threat_actor", "a2", "14d", true);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("marks a threat handled from the row menu, with the view's window", () => {
    renderBoard();
    fireEvent.click(screen.getByRole("button", { name: "More actions: ShinyHunters" }));
    fireEvent.click(screen.getByRole("menuitem", { name: /Mark handled/ }));
    expect(setStateMutate).toHaveBeenCalledWith(
      expect.objectContaining({ entityType: "threat_actor", entityKey: "a1", state: "handled", window: "14d" }),
      expect.anything()
    );
  });

  it("dismisses a threat as muted from the row menu", () => {
    renderBoard();
    fireEvent.click(screen.getByRole("button", { name: "More actions: ShinyHunters" }));
    fireEvent.click(screen.getByRole("menuitem", { name: /Dismiss/ }));
    expect(setStateMutate).toHaveBeenCalledWith(
      expect.objectContaining({ entityType: "threat_actor", entityKey: "a1", state: "muted" }),
      expect.anything()
    );
  });

  it("offers Open, Tracked, Handled and Muted views", () => {
    renderBoard();
    for (const label of ["Open", "Tracked", "Handled", "Muted"]) {
      expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
    }
  });

  it("filters rows by facet", () => {
    renderBoard("malware");
    expect(screen.queryByText("ShinyHunters")).not.toBeInTheDocument();
    expect(screen.getByText(/No threats with enough coverage/)).toBeInTheDocument();
  });
});


/** The hunt pack at the drawer's foot: drafted on request, copied to the SIEM,
    downloaded one ATHF file per hunt or as the whole package. Nothing here
    tracks a hunt. */
describe("ThreatBoard hunt pack", () => {
  function openDrawer() {
    renderBoard();
    fireEvent.click(screen.getByText(/Session-cookie theft and MFA modification/));
  }

  it("offers to draft a pack when none exists, and asks the server for this row and window", () => {
    workspace = EMPTY_WORKSPACE;
    huntPack = NO_PACK;
    openDrawer();
    fireEvent.click(screen.getByRole("button", { name: "Draft hunts" }));
    expect(draftMutate).toHaveBeenCalledWith(
      { entityType: "threat_actor", entityKey: "a2", scope: "14d", more: false },
      expect.anything()
    );
    expect(screen.queryByRole("button", { name: /ATHF hunt file/ })).not.toBeInTheDocument();
  });

  it("renders each hypothesis with its query, telemetry check, a per-hunt ATHF file and the package", () => {
    workspace = EMPTY_WORKSPACE;
    huntPack = {
      status: "ready",
      language: "kql",
      language_name: "KQL (Microsoft Sentinel / Defender XDR)",
      started_at: null,
      error: null,
      pack: {
        entity_type: "threat_actor",
        entity_key: "a2",
        label: "APT29",
        window: "14d",
        language: "kql",
        language_name: "KQL (Microsoft Sentinel / Defender XDR)",
        generated_at: "2026-11-17T10:00:00+00:00",
        model: "stub",
        entry_ids: ["e2"],
        hypotheses: [
          {
            id: "H1",
            title: "Help-desk reset then MFA enrollment",
            hypothesis: "Adversaries use help-desk resets to register their own MFA method on employee accounts.",
            tactic: "credential-access",
            techniques: ["T1621"],
            platform: "Identity Provider",
            data_sources: ["auth.mfa", "vpn.session"],
            telemetry: [
              { source: "auth.mfa", have: true },
              { source: "vpn.session", have: false },
            ],
            runnable: false,
            query: "AuditLogs | where TimeGenerated > ago(7d) | take 100",
            query_notes: "Join resets to registrations within one hour.",
            false_positives: "New-hire onboarding.",
          },
        ],
      },
    };
    openDrawer();
    // One line per hunt; the first is open, showing its query.
    expect(screen.getByText("Help-desk reset then MFA enrollment")).toBeInTheDocument();
    expect(screen.getByText("AuditLogs | where TimeGenerated > ago(7d) | take 100")).toBeInTheDocument();
    expect(screen.getByText("needs vpn.session")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Draft more" }));
    expect(draftMutate).toHaveBeenLastCalledWith(
      { entityType: "threat_actor", entityKey: "a2", scope: "14d", more: true },
      expect.anything()
    );
    expect(screen.getByRole("button", { name: "Copy KQL for H1" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Download H1 as an ATHF hunt file" }));
    expect(downloadSpy).toHaveBeenCalledWith("threat_actor", "a2", "14d", "H1");
    fireEvent.click(screen.getByRole("button", { name: "Download hunt package" }));
    expect(packageSpy).toHaveBeenCalledWith("threat_actor", "a2", "APT29");
    // The pack is a starting point: no verdicts, findings or tickets anywhere.
    expect(screen.queryByText(/verdict|finding|ticket/i)).not.toBeInTheDocument();
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
  });

  it("keeps the outlet count as the story count when nothing is threaded", () => {
    renderRows([makeItem({ stories: 21, attention: 21, articles: 12 })]);
    expect(screen.getByText("21 outlets")).toBeInTheDocument();
    expect(screen.queryByText(/stories/)).not.toBeInTheDocument();
  });

  it("names a claimed CVE on the row instead of dropping it", () => {
    renderRows([
      makeItem({
        merged_from: [{ entity_type: "cve", entity_key: "CVE-2026-1234", label: "CVE-2026-1234", is_kev: true }],
      }),
    ]);
    expect(screen.getByText(/exploits CVE-2026-1234 · KEV/)).toBeInTheDocument();
    // A carried CVE is a chip, not a second name on the identity line.
    expect(screen.queryByText("· CVE-2026-1234")).not.toBeInTheDocument();
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
      screen.getByText("3 updates, still developing")
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
    expect(screen.getByText("Coverage · 3 updates, 5 outlets")).toBeInTheDocument();
    // The precedent line is the one thing keyword search could never answer.
    expect(screen.getByText("Akira via Cisco ASA")).toBeInTheDocument();
    expect(screen.getByText(/83% similar/)).toBeInTheDocument();
    precedent = [];
  });
});
