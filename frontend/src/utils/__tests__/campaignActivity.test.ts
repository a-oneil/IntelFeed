import { describe, it, expect } from "vitest";
import { daysQuiet, isCampaignQuiet, QUIET_AFTER_DAYS } from "../campaignActivity";

const NOW = new Date("2026-09-15T00:00:00Z").getTime();
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString();

describe("daysQuiet", () => {
  it("counts days since the newest article", () => {
    expect(daysQuiet(daysAgo(74), NOW)).toBe(74);
  });

  it("is null for a campaign holding nothing", () => {
    expect(daysQuiet(null, NOW)).toBeNull();
    expect(daysQuiet(undefined, NOW)).toBeNull();
  });

  it("is null rather than NaN for an unparseable date", () => {
    expect(daysQuiet("not a date", NOW)).toBeNull();
  });
});

describe("isCampaignQuiet", () => {
  it("flags an active campaign past the threshold", () => {
    expect(isCampaignQuiet("active", daysAgo(QUIET_AFTER_DAYS + 1), NOW)).toBe(true);
    expect(isCampaignQuiet("monitoring", daysAgo(150), NOW)).toBe(true);
  });

  it("leaves a campaign still receiving coverage alone", () => {
    expect(isCampaignQuiet("active", daysAgo(5), NOW)).toBe(false);
  });

  it("does not nag about campaigns that are already closed", () => {
    expect(isCampaignQuiet("closed", daysAgo(400), NOW)).toBe(false);
    expect(isCampaignQuiet("historical", daysAgo(400), NOW)).toBe(false);
  });

  it("says nothing about a campaign with no articles at all", () => {
    expect(isCampaignQuiet("active", null, NOW)).toBe(false);
  });
});
