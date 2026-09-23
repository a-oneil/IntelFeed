import { render, screen, fireEvent, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";
import { CoverageWorkspace } from "../CoverageWorkspace";
import { useUIStore } from "@/stores/uiStore";
import type { CoverageWorkspace as WorkspaceData, PriorRulesResponse } from "@/hooks/useCoverageWorkspace";

const workspace: WorkspaceData = {
  entity_type: "threat_actor",
  entity_key: "actor-1",
  label: "APT29",
  window: "14d",
  articles: [
    {
      entry_id: "e1",
      title: "Diplomatic-sector intrusion set",
      url: "https://unit42.example.com/a",
      source: "unit42.example.com",
      published_at: "2026-08-30T10:00:00+00:00",
      word_count: 2340,
      technique_count: 9,
      new_technique_count: 3,
      contributed: true,
    },
    {
      entry_id: "e2",
      title: "Advisory roundup",
      url: null,
      source: "aggregator.example.com",
      published_at: "2026-08-28T10:00:00+00:00",
      word_count: 300,
      technique_count: 0,
      new_technique_count: 0,
      contributed: false,
    },
  ],
  article_total: 2,
  article_contributed_total: 1,
  behaviours: [
    {
      technique_id: "T1078.004",
      technique_name: "Cloud Accounts",
      tactic: "defense-evasion",
      entry_count: 1,
      first_seen: "2026-08-29T10:00:00+00:00",
      is_new: true,
      quotes: [
        {
          entry_id: "e1",
          entry_title: "Diplomatic-sector intrusion set",
          text: "authentication used the device-code flow",
          paragraph_indices: [4],
          observable_type: null,
          observable_value: null,
        },
      ],
      channels: [{ source: "m365:unified", tier: "source" }],
      tier: "source",
      missing_channels: [],
      missing_categories: [],
      below_line: false,
      prior_rules: 47,
      prior_rules_strong: 47,
    },
    {
      technique_id: "T1574.002",
      technique_name: "DLL Side-Loading",
      tactic: "persistence",
      entry_count: 1,
      first_seen: "2026-08-27T10:00:00+00:00",
      is_new: false,
      quotes: [],
      channels: [{ source: "WinEventLog:Sysmon", tier: null }],
      tier: null,
      missing_channels: ["WinEventLog:Sysmon"],
      missing_categories: ["windows_events"],
      below_line: true,
      prior_rules: 3,
      prior_rules_strong: 1,
    },
  ],
  missing_categories: ["windows_events"],
  below_line_count: 1,
  threat_prior_rules: 0,
  threat_prior_rules_strong: 0,
  cve: null,
};

const rules: PriorRulesResponse = {
  technique_id: "T1078.004",
  items: [
    {
      rule_id: "r1",
      title: "Device Code Authentication Flow",
      rule_type: "kql",
      repo: "Azure-Sentinel",
      license: "MIT",
      is_draft: false,
      scope: "technique",
      via: "tag",
      confidence: "high",
      matched_on: "T1078.004",
      tier: "source",
      required: ["SigninLogs"],
      missing: [],
      maintained_at: "2026-09-01T00:00:00+00:00",
    },
    {
      rule_id: "r2",
      title: "APT29 CozyDuke Loader",
      rule_type: "yara",
      repo: "signature-base",
      license: "CC-BY-4.0",
      is_draft: false,
      scope: "threat",
      via: "text",
      confidence: "low",
      matched_on: "APT29",
      tier: null,
      required: ["file"],
      missing: ["file"],
      maintained_at: null,
    },
  ],
  total: 2,
  total_candidates: 2,
  strong: 1,
  weak: 1,
  technique_scope: 1,
  threat_scope: 1,
};

const saveMutate = vi.fn();

vi.mock("sonner", () => ({ toast: { success: vi.fn(), info: vi.fn(), error: vi.fn() } }));

vi.mock("@/hooks/useCoverageWorkspace", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/hooks/useCoverageWorkspace")>();
  return {
    ...actual,
    useCoverageWorkspace: () => ({ data: workspace, isLoading: false }),
    useBehaviourRules: () => ({ data: rules, isLoading: false }),
    useSavedSets: () => ({ data: { items: [], total: 0 } }),
    useSaveCoverageSet: () => ({ mutate: saveMutate, isPending: false }),
    useDeleteCoverageSet: () => ({ mutate: vi.fn(), isPending: false }),
  };
});

function renderWorkspace() {
  // The workspace navigates (draft-new and extend open the bench), so it
  // needs a router around it.
  return render(
    <MemoryRouter>
      <CoverageWorkspace entityType="threat_actor" entityKey="actor-1" label="APT29" onNavigateRule={vi.fn()} />
    </MemoryRouter>,
  );
}

/** Opens the one above-the-line behaviour and returns its drawer contents. */
function openBehaviour(techniqueId = "T1078.004") {
  fireEvent.click(screen.getByRole("button", { expanded: false, name: new RegExp(techniqueId) }));
}

describe("CoverageWorkspace", () => {
  it("answers the coverage question in a sentence before showing any input to it", () => {
    renderWorkspace();
    // 2 behaviours, 1 of which has no log source.
    expect(screen.getByText(/of APT29’s/)).toHaveTextContent(
      /1 of APT29’s 2 behaviours in this window could fire against your telemetry/,
    );
    expect(screen.getByText(/of APT29’s/)).toHaveTextContent(/1 cannot — you collect no windows events source/);
  });

  it("promotes 'nothing names this threat' out of a tooltip and into the verdict", () => {
    renderWorkspace();
    // 47 + 3 candidate rules across the two behaviours, none scoped to the threat.
    expect(screen.getByText(/of APT29’s/)).toHaveTextContent(/Of the 50 library rules.*none were written for APT29/);
  });

  it("keeps the unsourced behaviour out of the ladder and calls it a collection job", () => {
    renderWorkspace();
    // The ladder holds only the behaviour a rule could fire for.
    const ladderRows = screen.getAllByRole("button", { expanded: false });
    expect(ladderRows.map((r) => r.textContent).join(" ")).not.toContain("T1574.002");

    const note = screen.getByText(/could not fire here/);
    expect(note.textContent).toContain("collection job, not a detection gap");
  });

  it("states the verdict on the closed row, before anything is opened", () => {
    renderWorkspace();
    expect(screen.getByRole("button", { expanded: false, name: /T1078\.004/ })).toHaveTextContent("Adopt 3");
  });

  it("opens a row onto its own evidence and candidates", () => {
    renderWorkspace();
    expect(screen.queryByText(/device-code flow/)).not.toBeInTheDocument();
    openBehaviour();
    expect(screen.getByText(/device-code flow/)).toBeInTheDocument();
    expect(screen.getByText("Device Code Authentication Flow")).toBeInTheDocument();
  });

  it("marks a low-confidence candidate as a weak match and says it cannot fire", () => {
    renderWorkspace();
    openBehaviour();
    expect(screen.getByText("weak match")).toBeInTheDocument();
    expect(screen.getByText(/no matching source — cannot fire here/)).toBeInTheDocument();
  });

  it("counts the articles that carried a technique against the full window", () => {
    renderWorkspace();
    expect(screen.getByText(/1 of 2 articles in this window carried a technique/)).toBeInTheDocument();
  });

  it("adopting a rule carries its repo and licence into the set tray", () => {
    renderWorkspace();
    openBehaviour();
    fireEvent.click(screen.getAllByRole("button", { name: "Adopt" })[0]);
    const tray = screen.getByText("Set").parentElement as HTMLElement;
    expect(within(tray).getByText("adopt")).toBeInTheDocument();
    expect(within(tray).getByText(/kql · Azure-Sentinel · MIT/)).toBeInTheDocument();
  });

  it("saves the assembled set", () => {
    renderWorkspace();
    openBehaviour();
    fireEvent.click(screen.getAllByRole("button", { name: "Adopt" })[0]);
    fireEvent.click(screen.getByRole("button", { name: "Save set" }));
    expect(saveMutate).toHaveBeenCalledWith(
      expect.objectContaining({
        window: "14d",
        items: [expect.objectContaining({ op: "adopt", rule_id: "r1", technique_id: "T1078.004" })],
      }),
      expect.anything(),
    );
  });

  it("sends the set into the reporting system, rules and gaps included", () => {
    renderWorkspace();
    openBehaviour();
    fireEvent.click(screen.getAllByRole("button", { name: "Adopt" })[0]);
    fireEvent.click(screen.getAllByRole("button", { name: "Skip" })[1]);
    fireEvent.click(screen.getByRole("button", { name: "Send to report" }));

    const payload = useUIStore.getState().sendToReportState?.payload;
    // The adopted rule rides as report evidence; the skip rides as prose.
    expect(payload?.entityIds?.detection_rules).toEqual(["r1"]);
    expect(payload?.entityIds?.actors).toEqual(["actor-1"]);
    expect(payload?.note).toContain("APT29 CozyDuke Loader");
    expect(payload?.note).toContain("Known gaps");
    // Only the article that carried a technique is evidence.
    expect(payload?.entryIds).toEqual(["e1"]);
  });

  it("no longer offers the exports that bypassed the reporting system", () => {
    renderWorkspace();
    expect(screen.queryByRole("button", { name: "Report .md" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy payload" })).not.toBeInTheDocument();
    // The one genuine take-away stays: rule files, not a report.
    expect(screen.getByRole("button", { name: "Bundle .zip" })).toBeInTheDocument();
  });

  it("offers an all-time window alongside the bounded ones", () => {
    renderWorkspace();
    expect(screen.getByRole("button", { name: "All" })).toBeInTheDocument();
  });
});
