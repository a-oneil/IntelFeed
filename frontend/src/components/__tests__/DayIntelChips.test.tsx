import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, it, expect, vi } from "vitest";

import { DayIntelChips, type DayFocus } from "../DayIntelChips";
import type { DayIntelResult } from "@/hooks/useDayIntel";

// Keep the real dayWindowIso; only stub the query hook so we control the payload.
const useDayIntelMock = vi.fn();
vi.mock("@/hooks/useDayIntel", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/hooks/useDayIntel")>();
  return { ...actual, useDayIntel: () => useDayIntelMock() };
});

const isMobileMock = vi.fn(() => false);
vi.mock("@/hooks/useMediaQuery", () => ({ useIsMobile: () => isMobileMock() }));

function makeData(over: Partial<DayIntelResult> = {}): DayIntelResult {
  return {
    threat_actor: null,
    malware: null,
    cve: null,
    ttp: null,
    sector: null,
    product: null,
    country: null,
    signals: { actively_exploited: 0, new: null },
    ...over,
  };
}

const DAY = "2026-07-08";

function renderChips(
  data: DayIntelResult | undefined,
  extra: { focus?: DayFocus | null; onFocus?: (f: DayFocus | null) => void } = {},
) {
  useDayIntelMock.mockReturnValue({ data });
  return render(
    <MemoryRouter>
      <DayIntelChips dayKey={DAY} filters={{}} {...extra} />
    </MemoryRouter>,
  );
}

describe("DayIntelChips", () => {
  afterEach(() => {
    isMobileMock.mockReturnValue(false);
  });

  it("renders nothing before data loads", () => {
    const { container } = renderChips(undefined);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when the day has no entities or signals", () => {
    const { container } = renderChips(makeData());
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the actively-exploited signal only when non-zero", () => {
    renderChips(makeData({ signals: { actively_exploited: 2, new: null } }));
    expect(screen.getByText(/2 actively exploited/)).toBeInTheDocument();
  });

  it("labels the CVE chip as KEV and shows CVSS when exploited", () => {
    renderChips(
      makeData({
        cve: { id: "c1", name: "CVE-2026-2222", count: 1, cvss_score: 9.8, severity: "critical", kev: true },
      }),
    );
    expect(screen.getByText("cve · kev")).toBeInTheDocument();
    expect(screen.getByText("9.8")).toBeInTheDocument();
  });

  it("caps the bar at 5 chips, dropping lowest-priority fills", () => {
    const { container } = renderChips(
      makeData({
        threat_actor: { id: "a", name: "APT-Test", count: 5 },
        malware: { id: "m", name: "LockBit", count: 4 },
        product: { id: "p", name: "Ivanti", count: 3 },
        country: { id: "co", name: "Ukraine", count: 3 },
        ttp: { id: "t", technique_id: "T1566", name: "Phishing", count: 6 },
        sector: { slug: "healthcare", name: "Healthcare", count: 7 },
        cve: { id: "c", name: "CVE-2026-1", count: 8, cvss_score: null, severity: null, kev: false },
        signals: { actively_exploited: 1, new: { type: "threat_actor", id: "a", name: "APT-Test", total: 1 } },
      }),
    );
    // 5 chips total: signal, new, ttp, sector, cve — actor/malware/product/country dropped.
    // `[data-chip]` skips the leading "?" legend button, which is not an intel chip.
    expect(container.querySelectorAll("[data-chip]").length).toBe(5);
    expect(screen.getByText(/actively exploited/)).toBeInTheDocument();
    expect(screen.getByText("new actor")).toBeInTheDocument();
    expect(screen.getByText("ttp")).toBeInTheDocument();
    expect(screen.getByText("sector")).toBeInTheDocument();
    expect(screen.queryByText("product")).not.toBeInTheDocument();
    expect(screen.queryByText("country")).not.toBeInTheDocument();
  });

  it("keeps the mobile lane at the full chip count", () => {
    isMobileMock.mockReturnValue(true);
    const { container } = renderChips(
      makeData({
        threat_actor: { id: "a", name: "APT-Test", count: 5 },
        malware: { id: "m", name: "LockBit", count: 4 },
        ttp: { id: "t", technique_id: "T1566", name: "Phishing", count: 6 },
        sector: { slug: "healthcare", name: "Healthcare", count: 7 },
        cve: { id: "c", name: "CVE-2026-1", count: 8, cvss_score: null, severity: null, kev: false },
        signals: { actively_exploited: 1, new: { type: "threat_actor", id: "a", name: "APT-Test", total: 1 } },
      }),
    );
    // The strip scrolls sideways rather than wrapping, so a narrow divider
    // carries the same five chips as a wide one — signal, new, ttp, sector, cve.
    expect(container.querySelectorAll("[data-chip]").length).toBe(5);
    expect(screen.getByText("ttp")).toBeInTheDocument();
    expect(screen.getByText("cve")).toBeInTheDocument();
    // The lower-priority fills still drop off past the cap.
    expect(screen.queryByText("product")).not.toBeInTheDocument();
    expect(screen.queryByText("country")).not.toBeInTheDocument();
  });

  it("surfaces lower-priority chips on a quiet day", () => {
    renderChips(
      makeData({
        threat_actor: { id: "a", name: "Lazarus", count: 2 },
        cve: { id: "c", name: "CVE-2026-3", count: 1, cvss_score: 7.5, severity: "high", kev: false },
      }),
    );
    expect(screen.getByText("actor")).toBeInTheDocument();
    expect(screen.getByText("Lazarus")).toBeInTheDocument();
  });

  it("explains only the chips actually on screen", async () => {
    renderChips(
      makeData({
        threat_actor: { id: "a", name: "Lazarus", count: 2 },
        signals: { actively_exploited: 3, new: null },
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: "What are these chips?" }));
    const legend = screen.getByRole("dialog", { name: "About these chips" });
    expect(legend).toHaveTextContent("Vulnerabilities named on this day");
    expect(legend).toHaveTextContent("The threat actor named in the most");
    // No CVE chip on this day, so no CVE line in the legend.
    expect(legend).not.toHaveTextContent("headline vulnerability");
  });

  it("filters the list rather than navigating when a chip is clicked", async () => {
    const onFocus = vi.fn();
    renderChips(
      makeData({
        threat_actor: { id: "a1", name: "Lazarus", count: 2 },
        sector: { slug: "healthcare", name: "Healthcare", count: 3 },
        signals: { actively_exploited: 4, new: null },
      }),
      { onFocus },
    );

    await userEvent.click(screen.getByText(/4 actively exploited/));
    expect(onFocus).toHaveBeenLastCalledWith(
      expect.objectContaining({ dayKey: DAY, chip: "signal", filter: { exploited_cves: true } }),
    );

    await userEvent.click(screen.getByText("Healthcare"));
    expect(onFocus).toHaveBeenLastCalledWith(
      expect.objectContaining({ chip: "sector", filter: { sector: "healthcare" } }),
    );

    // The entity chips carry the canonical slug the /entries filter speaks.
    await userEvent.click(screen.getByText("Lazarus"));
    expect(onFocus).toHaveBeenLastCalledWith(
      expect.objectContaining({
        chip: "threat_actor",
        filter: { entity_type: "threat_actor", entity_id: "a1" },
      }),
    );
  });

  it("clears the focus when the engaged chip is clicked again", async () => {
    const onFocus = vi.fn();
    renderChips(makeData({ signals: { actively_exploited: 4, new: null } }), {
      onFocus,
      focus: { dayKey: DAY, chip: "signal", label: "x", filter: { exploited_cves: true } },
    });
    const chip = screen.getByRole("button", { pressed: true });
    await userEvent.click(chip);
    expect(onFocus).toHaveBeenCalledWith(null);
  });

  it("lights only the chip on the day the focus was set from", () => {
    renderChips(makeData({ signals: { actively_exploited: 4, new: null } }), {
      onFocus: vi.fn(),
      focus: { dayKey: "2026-07-07", chip: "signal", label: "x", filter: { exploited_cves: true } },
    });
    expect(screen.queryByRole("button", { pressed: true })).not.toBeInTheDocument();
  });

  it("renders chips as plain labels when the list can't be filtered", () => {
    const { container } = renderChips(
      makeData({ signals: { actively_exploited: 4, new: null } }),
    );
    // Only the "?" legend button remains interactive.
    expect(container.querySelector("button[data-chip]")).toBeNull();
  });

  it("closes the legend on a second click", async () => {
    renderChips(makeData({ signals: { actively_exploited: 1, new: null } }));
    const btn = screen.getByRole("button", { name: "What are these chips?" });
    await userEvent.click(btn);
    expect(screen.getByRole("dialog", { name: "About these chips" })).toBeInTheDocument();
    await userEvent.click(btn);
    expect(screen.queryByRole("dialog", { name: "About these chips" })).not.toBeInTheDocument();
  });
});
