import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { EntitySearchResult } from "@/api/types";
import type { EntityContext } from "@/hooks/useEntityContext";
import type { CVEAffectedEntityRow } from "@/hooks/useAffectedCves";
import { contextBadgeSpecs, getEntityProfileConfig, noPatchBadge, supportBadge } from "../entityProfileConfig";
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
const affected: { rows: CVEAffectedEntityRow[] | undefined } = { rows: undefined };
vi.mock("@/hooks/useAffectedCves", () => ({
  useCveAffectedRows: (id: string | undefined) => ({ data: id ? affected.rows : undefined }),
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
      { source_type: "greynoise", key: "noise_class", label: "noise · benign", tone: "success", field: "noise_class" },
      { source_type: "vulncheck", key: "in_kev", label: "VulnCheck KEV", tone: "critical" },
    ]);
    expect(mirrored.provenanceKey).toBe("noise_class");
    expect(plain.provenanceKey).toBeUndefined();
  });
});

const affectedRow = (name: string, status: string | null): CVEAffectedEntityRow => ({
  cpe_vendor: "microsoft",
  cpe_product: name.toLowerCase().replace(/ /g, "_"),
  vendor_id: "v1",
  vendor_name: "Microsoft",
  product_id: `p-${name}`,
  product_name: name,
  version_start: null,
  version_end: null,
  product_support_status: status,
  product_next_eol: null,
});

describe("lifecycle badges", () => {
  it("marks a CVE that affects an end-of-life product as getting no patch", () => {
    affected.rows = [affectedRow("Windows Server 2012", "eol"), affectedRow("Windows Server 2022", "maintained")];
    const entity = { id: "c1", cve_id: "CVE-2024-0001", severity: "high" } as unknown as EntitySearchResult;
    render(
      <MemoryRouter>
        <ProfileHeader
          entityType="cve"
          entityId="c1"
          entity={entity}
          config={getEntityProfileConfig("cve")}
          entries={[]}
          relatedCountries={[]}
          onUpdateField={vi.fn()}
          onOpenEntity={vi.fn()}
          onNavigateAway={vi.fn()}
        />
      </MemoryRouter>,
    );
    const badge = screen.getByText("no patch coming");
    expect(badge.closest("[title]")?.getAttribute("title") ?? "").toMatch(/Windows Server 2012/);
  });

  it("badges an end-of-life release of a product that is still maintained", () => {
    const row = { ...affectedRow("PAN-OS", "maintained"), eol_releases: ["10.1"] };
    expect(noPatchBadge([row])).toMatchObject({
      label: "no patch coming",
      title: expect.stringMatching(/PAN-OS 10\.1, past end of life/),
    });
  });

  it("gives no no-patch badge when nothing affected is end of life", () => {
    expect(noPatchBadge([affectedRow("Windows Server 2022", "maintained")])).toBeNull();
    expect(noPatchBadge(undefined)).toBeNull();
  });

  it("badges a product's support lifecycle, quiet while it is maintained", () => {
    const today = new Date("2026-10-29T00:00:00Z");
    expect(supportBadge({ support_status: "eol" }, today)).toMatchObject({ label: "EOL", tone: "danger" });
    expect(supportBadge({ support_status: "security_only", next_eol: "2031-10-14" }, today)).toMatchObject({
      label: "security fixes only · until 2031-10-14",
      tone: "medium",
    });
    expect(supportBadge({ support_status: "maintained", next_eol: "2026-12-01" }, today)).toMatchObject({
      label: "EOL 2026-12-01",
    });
    expect(supportBadge({ support_status: "maintained", next_eol: "2029-11-13" }, today)).toBeNull();
    expect(supportBadge({ support_status: null }, today)).toBeNull();
    const product = getEntityProfileConfig("product").signalBadges({
      id: "p1",
      type: "product",
      support_status: "eol",
    } as EntitySearchResult);
    expect(product.map((b) => b.label)).toContain("EOL");
  });
});
