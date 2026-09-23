import { describe, it, expect } from "vitest";
import { ENTITY_PROFILE_CONFIG, getEntityProfileConfig, entityProfilePath } from "../entityProfileConfig";
import type { EntitySearchResult } from "@/api/types";

const campaign = (over: Partial<EntitySearchResult> = {}): EntitySearchResult => ({
  id: "c1",
  type: "campaign",
  name: "shinyhunters Activity",
  status: "active",
  tlp_marking: "TLP:GREEN",
  ...over,
});

describe("campaign profile config", () => {
  it("renders through the shared shell at the campaign route", () => {
    expect(getEntityProfileConfig("campaign")).toBe(ENTITY_PROFILE_CONFIG.campaign);
    expect(entityProfilePath("campaign", "c1")).toBe("/workbench/campaign/c1");
  });

  it("carries the same four tabs as an actor — the other five folded into shell surfaces", () => {
    expect(ENTITY_PROFILE_CONFIG.campaign.tabs).toEqual(["overview", "relationships", "detection"]);
  });

  it("puts status and TLP in the header, with status editable in place", () => {
    const badges = ENTITY_PROFILE_CONFIG.campaign.signalBadges(campaign());
    const status = badges.find((b) => b.title === "Status");
    expect(status?.label).toBe("active");
    expect(status?.editKey).toBe("status");
    expect(badges.map((b) => b.label)).toContain("TLP:GREEN");
  });

  it("reads a closed campaign as neutral rather than live", () => {
    const [open] = ENTITY_PROFILE_CONFIG.campaign.signalBadges(campaign());
    const [closed] = ENTITY_PROFILE_CONFIG.campaign.signalBadges(campaign({ status: "closed" }));
    expect(open.tone).toBe("success");
    expect(closed.tone).toBe("neutral");
  });

  it("shows tags as badges, capped so they can't crowd out the identity", () => {
    const badges = ENTITY_PROFILE_CONFIG.campaign.signalBadges(
      campaign({ tags: ["a", "b", "c", "d", "e", "f"] }),
    );
    expect(badges.filter((b) => b.title === "Tag")).toHaveLength(4);
  });

  it("offers no alias editor or external lookups — a campaign is an internal object", () => {
    expect(ENTITY_PROFILE_CONFIG.campaign.hasAliases).toBe(false);
    expect(ENTITY_PROFILE_CONFIG.campaign.externalLinks?.(campaign())).toEqual([]);
    expect(ENTITY_PROFILE_CONFIG.campaign.hasDescription).toBe(true);
    expect(ENTITY_PROFILE_CONFIG.campaign.nameEditable).toBe(true);
  });
});
