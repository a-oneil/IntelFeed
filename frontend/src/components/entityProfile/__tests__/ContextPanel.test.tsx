import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { EntityContext } from "@/hooks/useEntityContext";
import { ContextPanel } from "../ContextPanel";

const ctx: { data: EntityContext | undefined } = { data: undefined };
vi.mock("@/hooks/useEntityContext", async (orig) => ({
  ...(await orig<typeof import("@/hooks/useEntityContext")>()),
  useEntityContext: () => ({ data: ctx.data }),
}));

const mutate = vi.fn();
vi.mock("@/hooks/useEnrichment", () => ({
  useEnrichEntity: () => ({ mutate, isPending: false }),
}));

const auth = { visitor: false, admin: true };
vi.mock("@/stores/authStore", () => ({
  useIsVisitor: () => auth.visitor,
  useIsAdmin: () => auth.admin,
  // Date formatting reads the signed-in user's date-format preference.
  useAuthStore: { getState: () => ({ user: null }) },
}));

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

function renderPanel() {
  const qc = new QueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ContextPanel entityType="observable" entityId="o1" />
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
  });

  it("renders each display type", () => {
    renderPanel();
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

  it("shows the age, a stale marker and the license line", () => {
    renderPanel();
    const cymru = screen.getByRole("region", { name: "Team Cymru" });
    expect(within(cymru).getByText("2h")).toBeInTheDocument();
    expect(within(cymru).queryByText(/stale/)).not.toBeInTheDocument();

    const etda = screen.getByRole("region", { name: "ETDA Threat Group Cards" });
    expect(within(etda).getByText(/stale/)).toBeInTheDocument();
    expect(within(etda).getByText("CC BY-NC-SA · ThaiCERT")).toBeInTheDocument();
  });

  it("renders a quiet row per unavailable source, linking admins to the console", () => {
    ctx.data = sample({ unavailable: [{ source_type: "abusech", label: "abuse.ch", needs: "api_key" }] });
    renderPanel();
    expect(screen.getByText("abuse.ch · needs API key")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Enrichment" })).toHaveAttribute("href", "/settings?section=enrichment");
  });

  it("drops the console link for non-admins", () => {
    auth.admin = false;
    ctx.data = sample({ unavailable: [{ source_type: "abusech", label: "abuse.ch", needs: "api_key" }] });
    renderPanel();
    expect(screen.getByText("abuse.ch · needs API key")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Open Enrichment" })).not.toBeInTheDocument();
  });

  it("puts long text on its own line, clamps very long text, and formats timestamps", async () => {
    const long = "Apply mitigations per vendor instructions. ".repeat(8).trim();
    ctx.data = {
      sources: [
        {
          source_type: "cisa_kev",
          label: "CISA KEV",
          license: null,
          observed_at: null,
          stale: false,
          items: [
            { key: "added", label: "Added", display: "fact", value: "2024-04-12" },
            { key: "required_action", label: "Required action", display: "fact", value: long },
            { key: "assessed", label: "SSVC assessed", display: "fact", value: "2024-04-17T04:00:13.543064Z" },
          ],
        },
      ],
      unavailable: [],
      badges: [],
      can_enrich: false,
    };
    const user = userEvent.setup();
    renderPanel();
    expect(screen.getByText("2024-04-12")).toBeInTheDocument();
    expect(screen.queryByText("2024-04-17T04:00:13.543064Z")).not.toBeInTheDocument();
    const more = screen.getByRole("button", { name: "more" });
    expect(more).toHaveAttribute("aria-expanded", "false");
    await user.click(more);
    expect(screen.getByRole("button", { name: "less" })).toHaveAttribute("aria-expanded", "true");
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
      { entityType: "observable", entityId: "o1", sourceTypes: undefined, refresh: false },
      expect.anything(),
    );
    expect(screen.getByRole("status")).toHaveTextContent("queued: GreyNoise");
  });

  it("refreshes every source from the header, or one source from its block, past the cache", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(mutate).toHaveBeenLastCalledWith(
      { entityType: "observable", entityId: "o1", sourceTypes: undefined, refresh: true },
      expect.anything(),
    );
    await user.click(screen.getByRole("button", { name: "Refresh Team Cymru" }));
    expect(mutate).toHaveBeenLastCalledWith(
      { entityType: "observable", entityId: "o1", sourceTypes: ["cymru"], refresh: true },
      expect.anything(),
    );
  });

  it("is read-only for visitors", () => {
    auth.visitor = true;
    auth.admin = false;
    renderPanel();
    expect(screen.getByText("10439 · CARINET")).toBeInTheDocument();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("hides buttons when the server says this viewer can't enrich", () => {
    ctx.data = sample({ can_enrich: false });
    renderPanel();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("renders nothing for a visitor when no source has data yet", () => {
    auth.visitor = true;
    ctx.data = sample({
      sources: [{ source_type: "shodan", label: "Shodan InternetDB", license: null, observed_at: null, stale: false, items: [] }],
    });
    const { container } = renderPanel();
    expect(container).toBeEmptyDOMElement();
  });
});
