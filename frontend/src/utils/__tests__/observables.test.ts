import { describe, expect, it } from "vitest";
import { networkLabel, registeredLabel, reputationLabel } from "../observables";

describe("observable enrichment labels", () => {
  it("summarises reputation and the network columns in one line", () => {
    expect(
      reputationLabel({
        reputation: { gn_riot: true, vt_ratio: "3/92", ports: "22, 443" },
        noise_class: "benign",
        asn: 10439,
        geo_country: "US",
        popularity_rank: 4200,
      }),
    ).toBe("RIOT · GN benign · VT 3/92 · AS10439 · US · Tranco #4200 · ports 22, 443");
    // "Not seen scanning" isn't a class worth a cell; nothing enriched is empty.
    expect(reputationLabel({ noise_class: "not_seen" })).toBe("");
  });

  it("names the network", () => {
    expect(networkLabel({ asn: 10439, asn_org: "CARINET - CariNet, Inc., US", geo_country: "US" })).toBe(
      "AS10439 · CARINET - CariNet, Inc., US · US",
    );
    expect(networkLabel({ asn: 15169 })).toBe("AS15169");
  });

  it("shows a registration date with its age", () => {
    const now = new Date("2026-10-28T12:00:00Z");
    expect(registeredLabel("1996-10-29T05:00:00Z", now)).toBe("Oct 29, 1996 — 29 years ago");
    expect(registeredLabel("2026-10-25T00:00:00Z", now)).toBe("Oct 25, 2026 — 3 days ago");
    expect(registeredLabel("2026-10-28T06:00:00Z", now)).toBe("Oct 28, 2026 — today");
  });
});
