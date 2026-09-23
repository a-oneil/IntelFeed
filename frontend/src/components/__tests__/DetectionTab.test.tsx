import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { EntitySearchResult, PivotResponse } from "@/api/types";
import { DetectionTab } from "../entityProfile/tabs/DetectionTab";

const mutateMock = vi.fn();

vi.mock("@/hooks/useIntelligence", () => ({
  useGenerateEntityRules: () => ({ mutate: mutateMock, isPending: false }),
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), info: vi.fn(), error: vi.fn() },
}));

// The workspace is four network reads of its own. These tests are about which
// face the tab picks and about the no-workspace fallback, so the workspace
// stands in as a marker — see CoverageWorkspace.test.tsx for its own coverage.
vi.mock("@/components/coverageWorkspace", () => ({
  CoverageWorkspace: ({ label }: { label: string }) => <div>workspace:{label}</div>,
}));

function makeEntity(overrides: Partial<EntitySearchResult> = {}): EntitySearchResult {
  return { id: "actor-1", type: "threat_actor", name: "APT29", ...overrides } as EntitySearchResult;
}

function makeRelated(overrides: Partial<PivotResponse["related"]> = {}): PivotResponse["related"] {
  return {
    ttps: [],
    cves: [],
    threat_actors: [],
    malwares: [],
    countrys: [],
    detection_rules: [],
    ...overrides,
  } as PivotResponse["related"];
}

function renderTab(props: Partial<Parameters<typeof DetectionTab>[0]> = {}) {
  return render(
    <MemoryRouter>
      <DetectionTab
        entityType="threat_actor"
        entityId="actor-1"
        entity={makeEntity()}
        related={makeRelated()}
        onNavigateRule={vi.fn()}
        {...props}
      />
    </MemoryRouter>,
  );
}

describe("DetectionTab", () => {
  beforeEach(() => mutateMock.mockReset());

  it("gives a threat the coverage workspace, with no segmented views to choose between", () => {
    renderTab();
    expect(screen.getByText("workspace:APT29")).toBeInTheDocument();
    // The Build|Coverage pair is gone: one question, one answer.
    expect(screen.queryByRole("button", { name: /^Coverage/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Build/ })).not.toBeInTheDocument();
  });

  it("gives a CVE the same workspace, keyed on its CVE id", () => {
    renderTab({
      entityType: "cve",
      entityId: "cve-1",
      entity: makeEntity({ id: "cve-1", type: "cve", name: undefined, cve_id: "CVE-2024-1111" }),
    });
    expect(screen.getByText("workspace:CVE-2024-1111")).toBeInTheDocument();
  });

  it("falls back to a rule list for an entity with no extracted behaviours", () => {
    renderTab({
      entityType: "cwe",
      entityId: "cwe-1",
      entity: makeEntity({ id: "cwe-1", type: "cwe", name: "CWE-79" }),
    });
    expect(screen.queryByText(/^workspace:/)).not.toBeInTheDocument();
    expect(screen.getByText("No detection rules cover this entity yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Search library" })).toHaveAttribute(
      "href",
      "/workbench/explore?section=rules&rules_q=CWE-79",
    );
  });

  it("lists the covering rules on the fallback face", () => {
    renderTab({
      entityType: "cwe",
      entityId: "cwe-1",
      entity: makeEntity({ id: "cwe-1", type: "cwe", name: "CWE-79" }),
      related: makeRelated({
        detection_rules: [
          { id: "r1", title: "Reflected XSS in query string", rule_type: "sigma", severity: "high", created_at: "2026-01-01" },
        ],
      }),
    });
    expect(screen.getByText("Reflected XSS in query string")).toBeInTheDocument();
  });

  it("does not offer generation for a type the endpoint cannot extract", () => {
    renderTab({
      entityType: "cwe",
      entityId: "cwe-1",
      entity: makeEntity({ id: "cwe-1", type: "cwe", name: "CWE-79" }),
    });
    expect(screen.queryByRole("button", { name: "Generate rule" })).not.toBeInTheDocument();
    // The way into the library is still offered.
    expect(screen.getByRole("link", { name: "Search library" })).toBeInTheDocument();
  });
});
