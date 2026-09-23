import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";

import { EntryIntelBadges } from "../EntryIntelBadges";
import type { EntryIntelCounts } from "@/hooks/useEntryIntelBadges";

const baseCounts: EntryIntelCounts = {
  ttps: 2,
  cves: 0,
  rules: 0,
  notes: 0,
  ai_results: 0,
  total: 2,
  has_detection_gap: true,
  high_value: false,
};

describe("EntryIntelBadges detection opportunity tiers", () => {
  it("shows the actionable opportunity badge when no rule exists", () => {
    render(
      <EntryIntelBadges counts={{ ...baseCounts, detection_opportunity: "actionable_gap" }} />
    );
    expect(screen.getByText("detection opportunity")).toBeInTheDocument();
    expect(screen.getByText("detection opportunity").getAttribute("title")).toMatch(/No detection rule exists/);
  });

  it("shows the telemetry gap badge when library rules are blocked", () => {
    render(
      <EntryIntelBadges counts={{ ...baseCounts, detection_opportunity: "telemetry_gap" }} />
    );
    expect(screen.getByText("telemetry gap")).toBeInTheDocument();
    expect(screen.queryByText("detection opportunity")).not.toBeInTheDocument();
    expect(screen.getByText("telemetry gap").getAttribute("title")).toMatch(/telemetry inventory/);
  });

  it("shows no opportunity badge when techniques are covered", () => {
    render(
      <EntryIntelBadges
        counts={{ ...baseCounts, has_detection_gap: true, detection_opportunity: null }}
      />
    );
    expect(screen.queryByText("detection opportunity")).not.toBeInTheDocument();
    expect(screen.queryByText("telemetry gap")).not.toBeInTheDocument();
  });

  it("falls back to the legacy binary flag when tier is absent", () => {
    render(<EntryIntelBadges counts={baseCounts} />);
    expect(screen.getByText("detection opportunity")).toBeInTheDocument();
  });

  it("keeps the KEV elevation over tier display", () => {
    render(
      <EntryIntelBadges
        counts={{
          ...baseCounts,
          detection_opportunity: "actionable_gap",
          has_high_risk_cve: true,
          has_kev_cve: true,
        }}
      />
    );
    expect(screen.getByText("KEV opportunity")).toBeInTheDocument();
  });
});

describe("EntryIntelBadges personal-state markers", () => {
  it("renders starred and bookmarked markers from props", () => {
    render(<EntryIntelBadges counts={baseCounts} starred bookmarked />);
    expect(screen.getByLabelText("Starred")).toBeInTheDocument();
    expect(screen.getByLabelText("Bookmarked")).toBeInTheDocument();
  });

  it("renders a note marker from the note count instead of a 'Notes' count chip", () => {
    render(<EntryIntelBadges counts={{ ...baseCounts, notes: 2 }} />);
    expect(screen.getByLabelText("2 analyst notes")).toBeInTheDocument();
    // The note is a personal marker now, not an evidence chip
    expect(screen.queryByText("Notes")).not.toBeInTheDocument();
  });

  it("renders on personal state alone even with no intel", () => {
    const empty: EntryIntelCounts = {
      ttps: 0, cves: 0, rules: 0, notes: 0, ai_results: 0, total: 0,
      has_detection_gap: false, high_value: false,
    };
    const { container } = render(<EntryIntelBadges counts={empty} bookmarked />);
    expect(screen.getByLabelText("Bookmarked")).toBeInTheDocument();
    expect(container.firstChild).not.toBeNull();
  });
});

describe("EntryIntelBadges named subject", () => {
  it("names the primary threat actor with a +N overflow", () => {
    render(
      <EntryIntelBadges
        counts={{ ...baseCounts, actors: ["The Gentlemen", "Scattered Spider"], actor_count: 2 }}
      />
    );
    expect(screen.getByText("The Gentlemen")).toBeInTheDocument();
    expect(screen.getByText("+1")).toBeInTheDocument();
  });

  it("falls back to malware when there is no actor", () => {
    render(
      <EntryIntelBadges
        counts={{ ...baseCounts, malware: ["VECT"], malware_count: 1 }}
      />
    );
    expect(screen.getByText("VECT")).toBeInTheDocument();
  });

  it("prefers the actor over malware as the subject", () => {
    render(
      <EntryIntelBadges
        counts={{ ...baseCounts, actors: ["APT29"], actor_count: 1, malware: ["Cobalt Strike"], malware_count: 1 }}
      />
    );
    expect(screen.getByText("APT29")).toBeInTheDocument();
    // malware still counts toward the overflow
    expect(screen.getByText("+1")).toBeInTheDocument();
    expect(screen.queryByText("Cobalt Strike")).not.toBeInTheDocument();
  });
});

describe("EntryIntelBadges CVE severity", () => {
  it("annotates the CVE chip with the worst severity", () => {
    render(<EntryIntelBadges counts={{ ...baseCounts, cves: 6, cve_max_severity: "critical" }} />);
    expect(screen.getByTitle(/worst severity critical/)).toBeInTheDocument();
  });
});
