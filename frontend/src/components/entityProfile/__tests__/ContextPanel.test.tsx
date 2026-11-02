import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { EntityContext } from "@/hooks/useEntityContext";
import type { EntityProvenance, FieldClaim } from "@/hooks/useEntityProvenance";
import { ContextPanel } from "../ContextPanel";

const ctx: { data: EntityContext | undefined } = { data: undefined };
vi.mock("@/hooks/useEntityContext", async (orig) => ({
  ...(await orig<typeof import("@/hooks/useEntityContext")>()),
  useEntityContext: () => ({ data: ctx.data }),
}));

const prov: { data: EntityProvenance | undefined } = { data: undefined };
vi.mock("@/hooks/useEntityProvenance", () => ({
  useEntityProvenance: (type: string | undefined) => ({ data: type ? prov.data : undefined }),
}));

const mutate = vi.fn();
vi.mock("@/hooks/useEnrichment", () => ({
  useEnrichEntity: () => ({ mutate, isPending: false }),
}));

const auth = { visitor: false, admin: true };
vi.mock("@/stores/authStore", () => ({
  useIsVisitor: () => auth.visitor,
  useIsAdmin: () => auth.admin,
}));

// Shows what the panel hands the formatter, so a test can see the zone it chose.
vi.mock("@/utils/formatDate", () => ({ formatDateTime: (input: string) => `at ${input}` }));

const HOUR = 3_600_000;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

/** Spec §B sample, one source per display type. */
function sample(over: Partial<EntityContext> = {}): EntityContext {
  return {
    sources: [
      {
        source_type: "cymru",
        label: "Team Cymru",
        license: null,
        observed_at: ago(2 * HOUR),
        stale: false,
        items: [
          { key: "asn", label: "ASN", display: "fact", value: "10439 · CARINET" },
          { key: "ports", label: "Ports", display: "chips", value: ["22", "500"] },
          { key: "noise", label: "Noise", display: "badge", value: "benign" },
        ],
      },
      {
        source_type: "etda",
        label: "ETDA Threat Group Cards",
        license: { name: "CC BY-NC-SA", attribution: "ThaiCERT" },
        observed_at: ago(3 * 24 * HOUR),
        stale: true,
        items: [
          { key: "operations", label: "Operations", display: "timeline", value: [{ date: "2013-02", text: "MiniDuke PDF exploit" }] },
          { key: "card", label: "Card", display: "link", value: { url: "https://apt.etda.or.th/cgi-bin/card.cgi?g=APT29" } },
        ],
      },
      {
        source_type: "endoflife",
        label: "endoflife.date",
        license: null,
        observed_at: ago(10 * 60_000),
        stale: false,
        items: [
          {
            key: "releases",
            label: "Releases",
            display: "table",
            value: { columns: ["Release", "Released"], rows: [["2025", "2024-11-01"]] },
          },
        ],
      },
    ],
    unavailable: [],
    badges: [],
    can_enrich: true,
    ...over,
  };
}

function renderPanel(entityType = "observable", entityId = "o1") {
  const qc = new QueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ContextPanel entityType={entityType} entityId={entityId} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ContextPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auth.visitor = false;
    auth.admin = true;
    ctx.data = sample();
    prov.data = undefined;
  });

  it("is a titled section, not a card", () => {
    renderPanel();
    expect(screen.getByRole("region", { name: "Context" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Context" })).toBeInTheDocument();
  });

  it("opens the first source and closes the rest to a digest of their facts", async () => {
    const user = userEvent.setup();
    renderPanel();
    expect(screen.getByRole("button", { name: /^Team Cymru/ })).toHaveAttribute("aria-expanded", "true");
    const etda = screen.getByRole("button", { name: /^ETDA Threat Group Cards/ });
    expect(etda).toHaveAttribute("aria-expanded", "false");
    expect(etda).toHaveTextContent("Operations 1 · Card");
    expect(screen.getByRole("button", { name: /^endoflife\.date/ })).toHaveTextContent("Releases 1 row");
    expect(screen.queryByText("MiniDuke PDF exploit")).not.toBeInTheDocument();

    await user.click(etda);
    expect(etda).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("MiniDuke PDF exploit")).toBeInTheDocument();
    await user.click(etda);
    expect(screen.queryByText("MiniDuke PDF exploit")).not.toBeInTheDocument();
  });

  it("renders each display type", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole("button", { name: /^ETDA Threat Group Cards/ }));
    await user.click(screen.getByRole("button", { name: /^endoflife\.date/ }));
    // fact
    expect(screen.getByText("ASN")).toBeInTheDocument();
    expect(screen.getByText("10439 · CARINET")).toBeInTheDocument();
    // chips
    expect(screen.getByText("22")).toBeInTheDocument();
    expect(screen.getByText("500")).toBeInTheDocument();
    // timeline
    expect(screen.getByText("2013-02")).toBeInTheDocument();
    expect(screen.getByText("MiniDuke PDF exploit")).toBeInTheDocument();
    // table
    expect(screen.getByRole("columnheader", { name: "Release" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "2024-11-01" })).toBeInTheDocument();
    // link
    const link = screen.getByRole("link", { name: /apt\.etda\.or\.th/ });
    expect(link).toHaveAttribute("href", "https://apt.etda.or.th/cgi-bin/card.cgi?g=APT29");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link.getAttribute("rel")).toContain("noopener");
  });

  it("keeps badge items out of the panel", () => {
    renderPanel();
    expect(screen.queryByText("Noise")).not.toBeInTheDocument();
    expect(screen.queryByText("benign")).not.toBeInTheDocument();
  });

  it("says when each source last answered and whether that is fresh or stale, with the license line", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole("button", { name: /^ETDA Threat Group Cards/ }));
    const cymru = screen.getByRole("region", { name: "Team Cymru" });
    expect(within(cymru).getByText("2h · fresh")).toBeInTheDocument();
    expect(within(cymru).getByText("2h · fresh")).toHaveAttribute("title", expect.stringMatching(/^Last looked up /));
    expect(within(cymru).queryByText(/stale/)).not.toBeInTheDocument();

    const etda = screen.getByRole("region", { name: "ETDA Threat Group Cards" });
    expect(within(etda).getByText(/stale/)).toBeInTheDocument();
    expect(within(etda).getByText("CC BY-NC-SA · ThaiCERT")).toBeInTheDocument();
  });

  it("renders a quiet row per unavailable source, linking admins to its key in the console", () => {
    ctx.data = sample({ unavailable: [{ source_type: "abusech", label: "abuse.ch", needs: "api_key" }] });
    renderPanel();
    expect(screen.getByText("abuse.ch · needs key")).toBeInTheDocument();
    expect(screen.getByText("3 sources · 1 needs key")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Add key" })).toHaveAttribute(
      "href",
      "/settings?section=enrichment&key_for=abusech",
    );
  });

  it("counts a source that has data once, not again as needing a key", () => {
    ctx.data = sample({ unavailable: [{ source_type: "cymru", label: "Team Cymru", needs: "api_key" }] });
    renderPanel();
    expect(screen.getByText("3 sources")).toBeInTheDocument();
    expect(screen.queryByText("Team Cymru · needs key")).not.toBeInTheDocument();
  });

  it("drops the console link for non-admins", () => {
    auth.admin = false;
    ctx.data = sample({ unavailable: [{ source_type: "abusech", label: "abuse.ch", needs: "api_key" }] });
    renderPanel();
    expect(screen.getByText("abuse.ch · needs key")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Add key" })).not.toBeInTheDocument();
  });

  const facts = (items: Array<[string, string]>): EntityContext => ({
    sources: [
      {
        source_type: "cisa_kev",
        label: "CISA KEV",
        license: null,
        observed_at: null,
        stale: false,
        items: items.map(([label, value]) => ({ key: label, label, display: "fact" as const, value })),
      },
    ],
    unavailable: [],
    badges: [],
    can_enrich: false,
  });

  it("formats timestamps as UTC unless they name a zone, and leaves dates alone", () => {
    ctx.data = facts([
      ["Added", "2024-04-12"],
      ["Assessed", "2024-04-17T04:00:13.543064Z"],
      ["Offset", "2024-04-17T04:00:13+02:00"],
      ["Published", "2024-04-12T08:15:06.230"],
      ["First seen", "2024-04-12 08:15:06 UTC"],
    ]);
    renderPanel();
    expect(screen.getByText("2024-04-12")).toBeInTheDocument();
    expect(screen.getByText("at 2024-04-17T04:00:13.543064Z")).toBeInTheDocument();
    expect(screen.getByText("at 2024-04-17T04:00:13+02:00")).toBeInTheDocument();
    expect(screen.getByText("at 2024-04-12T08:15:06.230Z")).toBeInTheDocument();
    expect(screen.getByText("at 2024-04-12T08:15:06Z")).toBeInTheDocument();
  });

  describe("long text", () => {
    const long = "Apply mitigations per vendor instructions. ".repeat(8).trim();
    afterEach(() => vi.restoreAllMocks());

    it("puts it on its own line, inside the dd with its toggle, when it runs past four lines", async () => {
      vi.spyOn(Element.prototype, "scrollHeight", "get").mockReturnValue(200);
      vi.spyOn(Element.prototype, "clientHeight", "get").mockReturnValue(80);
      ctx.data = facts([["Required action", long]]);
      const user = userEvent.setup();
      renderPanel();

      const text = screen.getByText(long);
      const more = screen.getByRole("button", { name: "Show more of Required action" });
      expect(more).toHaveTextContent("more");
      expect(more).toHaveAttribute("aria-expanded", "false");
      expect(more).toHaveAttribute("aria-controls", text.id);
      expect(more.parentElement?.tagName).toBe("DD");
      expect(text.parentElement).toBe(more.parentElement);

      await user.click(more);
      const less = screen.getByRole("button", { name: "Show less of Required action" });
      expect(less).toHaveAttribute("aria-expanded", "true");
    });

    it("has no toggle when it fits", () => {
      // jsdom lays nothing out: scrollHeight equals clientHeight.
      ctx.data = facts([["Required action", long]]);
      renderPanel();
      expect(screen.getByText(long)).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /Show (more|less)/ })).not.toBeInTheDocument();
    });
  });

  it("renders nothing when no source applies", () => {
    ctx.data = sample({ sources: [], unavailable: [] });
    const { container } = renderPanel();
    expect(container).toBeEmptyDOMElement();
  });

  it("offers Enrich now when sources apply but nothing is stored yet, and shows queued sources", async () => {
    ctx.data = sample({
      sources: [
        { source_type: "shodan", label: "Shodan InternetDB", license: null, observed_at: null, stale: false, items: [] },
        { source_type: "greynoise", label: "GreyNoise", license: null, observed_at: null, stale: false, items: [] },
      ],
    });
    mutate.mockImplementation((_vars, opts) => opts?.onSuccess?.({ queued: ["greynoise"] }));
    const user = userEvent.setup();
    renderPanel();

    expect(screen.getByText("No context yet")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Enrich now" }));
    expect(mutate).toHaveBeenCalledWith(
      // Named, so auto-mode sources run too, not just manual-mode ones.
      { entityType: "observable", entityId: "o1", sourceTypes: ["shodan", "greynoise"], refresh: false },
      expect.anything(),
    );
    expect(screen.getByRole("status")).toHaveTextContent("queued: GreyNoise");
  });

  it("keeps a failed lookup in the panel with a retry", async () => {
    mutate.mockImplementation((_vars, opts) =>
      opts?.onSuccess?.({ queued: [], results: [{ source_type: "cymru", status: "error", error: "timed out" }] }),
    );
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(screen.getByText("Team Cymru · lookup failed: timed out")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(mutate).toHaveBeenLastCalledWith(
      { entityType: "observable", entityId: "o1", sourceTypes: ["cymru"], refresh: true },
      expect.anything(),
    );
  });

  it("refreshes every source from the header, or one source from its block, past the cache", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(mutate).toHaveBeenLastCalledWith(
      { entityType: "observable", entityId: "o1", sourceTypes: ["cymru", "etda", "endoflife"], refresh: true },
      expect.anything(),
    );
    await user.click(screen.getByRole("button", { name: "Refresh Team Cymru" }));
    expect(mutate).toHaveBeenLastCalledWith(
      { entityType: "observable", entityId: "o1", sourceTypes: ["cymru"], refresh: true },
      expect.anything(),
    );
  });

  // Rows still open and close for everyone; only the enrichment buttons go.
  const enrichButtons = () => screen.queryAllByRole("button", { name: /^(Refresh|Enrich now)/ });

  it("is read-only for visitors", () => {
    auth.visitor = true;
    auth.admin = false;
    renderPanel();
    expect(screen.getByText("10439 · CARINET")).toBeInTheDocument();
    expect(enrichButtons()).toHaveLength(0);
  });

  it("hides enrichment buttons when the server says this viewer can't enrich", () => {
    ctx.data = sample({ can_enrich: false });
    renderPanel();
    expect(enrichButtons()).toHaveLength(0);
  });

  it("renders nothing for a visitor when no source has data yet", () => {
    auth.visitor = true;
    ctx.data = sample({
      sources: [{ source_type: "shodan", label: "Shodan InternetDB", license: null, observed_at: null, stale: false, items: [] }],
    });
    const { container } = renderPanel();
    expect(container).toBeEmptyDOMElement();
  });

  describe("CVSS by source", () => {
    const claim = (over: Partial<FieldClaim>): FieldClaim => ({
      id: Math.random().toString(36),
      value: "10.0",
      source_kind: "enrichment",
      source_label: "Enrichment",
      source_ref: "nvd",
      quote: null,
      confidence: null,
      analyst: null,
      entry: null,
      first_asserted_at: "2026-10-01T00:00:00Z",
      last_asserted_at: "2026-10-01T00:00:00Z",
      agrees: true,
      ...over,
    });
    const cveContext = (): EntityContext => ({
      sources: [
        {
          source_type: "nvd",
          label: "NVD 2.0",
          license: null,
          observed_at: ago(HOUR),
          stale: false,
          items: [{ key: "cvss_vector", label: "CVSS vector", display: "fact", value: "AV:N/AC:L/PR:N/UI:N/S:C" }],
        },
        {
          source_type: "cvelist",
          label: "cvelistV5 + CISA-ADP",
          license: null,
          observed_at: ago(HOUR),
          stale: false,
          items: [{ key: "cvss_vector", label: "CVSS vector", display: "fact", value: "CVSS:3.1/AV:N/AC:L" }],
        },
      ],
      unavailable: [],
      badges: [],
      can_enrich: false,
    });
    const provenance = (claims: FieldClaim[]): EntityProvenance => ({
      entity_type: "cve",
      entity_id: "c1",
      fields: { cvss_score: { current_value: "10.0", claims } },
      unsourced_fields: [],
      tracked_fields: ["cvss_score"],
    });

    it("lists every source's score and vector and marks the one shown", () => {
      ctx.data = cveContext();
      prov.data = provenance([
        claim({ source_ref: "nvd", value: "10.0", agrees: true }),
        claim({ source_ref: "cvelist", value: "9.8", agrees: false }),
        // Replaced by the same source's newer answer: drops out.
        claim({ source_ref: "cvelist", value: "7.5", agrees: false, last_asserted_at: "2025-01-01T00:00:00Z" }),
      ]);
      renderPanel("cve", "c1");
      const block = screen.getByRole("region", { name: "CVSS by source" });
      const rows = within(block).getAllByRole("term").map((dt) => [dt.textContent, dt.nextElementSibling?.textContent]);
      expect(rows).toEqual([
        ["NVD 2.0", "10.0 · AV:N/AC:L/PR:N/UI:N/S:Cshown"],
        ["cvelistV5 + CISA-ADP", "9.8 · CVSS:3.1/AV:N/AC:Lclaim"],
      ]);
    });

    it("closes to one line of scores like the source rows", async () => {
      ctx.data = cveContext();
      prov.data = provenance([
        claim({ source_ref: "nvd", value: "10.0", agrees: true }),
        claim({ source_ref: "cvelist", value: "9.8", agrees: false }),
      ]);
      renderPanel("cve", "c1");
      const toggle = screen.getByRole("button", { name: /^CVSS by source/ });
      expect(toggle).toHaveAttribute("aria-expanded", "true");
      await userEvent.setup().click(toggle);
      expect(toggle).toHaveAttribute("aria-expanded", "false");
      expect(toggle).toHaveTextContent("NVD 2.0 10.0 · cvelistV5 + CISA-ADP 9.8");
      expect(within(screen.getByRole("region", { name: "CVSS by source" })).queryByRole("term")).not.toBeInTheDocument();
    });

    it("names a CNA and an ADP score from one source apart", () => {
      ctx.data = cveContext();
      prov.data = provenance([
        claim({ source_ref: "cvelist:cna", value: "9.8", agrees: true }),
        claim({ source_ref: "cvelist:adp", value: "9.1", agrees: false }),
      ]);
      renderPanel("cve", "c1");
      const block = screen.getByRole("region", { name: "CVSS by source" });
      expect(within(block).getByText("cvelistV5 + CISA-ADP · CNA")).toBeInTheDocument();
      expect(within(block).getByText("cvelistV5 + CISA-ADP · ADP")).toBeInTheDocument();
    });

    it("is absent on other types and when no source scored the CVE", () => {
      prov.data = provenance([claim({})]);
      renderPanel();
      expect(screen.queryByRole("region", { name: "CVSS by source" })).not.toBeInTheDocument();
    });
  });
});
