import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { SectorProfile } from "@/api/types";
import { VictimologyTab } from "../tabs/VictimologyTab";

const profile: SectorProfile = {
  sector: {
    id: "sec-1",
    slug: "healthcare",
    name: "Healthcare",
    aliases: ["hospitals"],
    description: "Hospitals and health systems.",
    first_seen_at: "2026-07-24T00:00:00Z",
    last_seen_at: "2026-09-29T00:00:00Z",
    article_count: 774,
  },
  window_days: 90,
  reported_actors: [{ id: "a1", name: "ShinyHunters", article_count: 63 }],
  reported_malware: [],
  asserted_actors: [{ id: "a2", name: "Qilin", article_count: 47, source: "rollup" }],
  asserted_malware: [],
  campaigns: [{ id: "c1", name: "Hospital wave", status: "active", start_date: null }],
  victims: {
    total: 2698,
    in_window: 252,
    monthly: [{ month: "2026-08-01", count: 80 }, { month: "2026-09-01", count: 90 }],
    top_groups: [{ group: "thegentlemen", victims: 27 }],
    recent: [
      {
        id: "d1",
        victim_id: "v1",
        victim_name: "Mercy General",
        group: "qilin",
        country: "United States",
        country_code: "US",
        posted_at: "2026-09-29T00:00:00Z",
      },
    ],
  },
  countries: [{ id: "us", name: "United States", iso_code: "US", article_count: 214, victim_count: 93 }],
  intel_profiles: [],
  recent_entries: [{ id: "e1", title: "Hospital ransomware wave", published_at: "2026-09-29T00:00:00Z", confidence: "high" }],
  articles_monthly: [],
};

const useSectorProfile = vi.fn(() => ({ data: profile, isLoading: false }));
vi.mock("@/hooks/useSectorProfile", () => ({ useSectorProfile: (...args: unknown[]) => useSectorProfile(...args) }));

describe("VictimologyTab", () => {
  it("splits reported from asserted targeting and lists victims, groups and countries", () => {
    const onOpenEntity = vi.fn();
    const onOpenArticle = vi.fn();
    render(
      <MemoryRouter>
        <VictimologyTab entityId="sec-1" entityLabel="Healthcare" onOpenEntity={onOpenEntity} onOpenArticle={onOpenArticle} />
      </MemoryRouter>,
    );

    expect(screen.getByText("ShinyHunters")).toBeInTheDocument();
    expect(screen.getByText("Qilin")).toBeInTheDocument();
    expect(screen.getByText(/rolled up from articles/)).toBeInTheDocument();
    expect(screen.getByText("2698 leak-site victims all time")).toBeInTheDocument();
    expect(screen.getByText("thegentlemen")).toBeInTheDocument();
    expect(screen.getByText("Mercy General")).toBeInTheDocument();

    fireEvent.click(screen.getByText("United States"));
    expect(onOpenEntity).toHaveBeenCalledWith("country", "us", "United States");

    fireEvent.click(screen.getByText("Hospital ransomware wave"));
    expect(onOpenArticle).toHaveBeenCalledWith("e1");
  });

  it("re-queries the profile when the window changes", () => {
    render(
      <MemoryRouter>
        <VictimologyTab entityId="sec-1" onOpenEntity={vi.fn()} onOpenArticle={vi.fn()} />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByText("30d"));
    expect(useSectorProfile).toHaveBeenLastCalledWith("sec-1", 30);
  });
});
