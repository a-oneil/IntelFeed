import { describe, expect, it } from "vitest";
import { describeHealthWarning, describePauseReason } from "../feedHealth";

describe("describePauseReason", () => {
  it("says what paused the feed and for how long", () => {
    expect(
      describePauseReason({
        reason: "http_4xx",
        last_error: "HTTP 403",
        status: 403,
        failures: 35,
        error_since: "2026-09-20T00:00:00Z",
        days: 30,
        client: "httpx",
        paused_at: "2026-10-21T00:00:00Z",
      })
    ).toBe("Paused automatically after HTTP 403 for 30 days (35 failed fetches)");
  });
});

describe("describeHealthWarning", () => {
  it("names where a redirected feed lands", () => {
    expect(
      describeHealthWarning({
        kind: "redirected_no_items",
        since: "2026-04-16T00:00:00Z",
        days: 190,
        redirected_to: "https://cloud.google.com/security/mandiant-services",
        content_type: "text/html",
      })
    ).toBe(
      "Reachable but empty: redirects to cloud.google.com/security/mandiant-services, which has no articles"
    );
  });

  it("counts the days of an empty feed", () => {
    expect(
      describeHealthWarning({
        kind: "no_items",
        since: "2026-10-20T00:00:00Z",
        days: 5,
        redirected_to: null,
        content_type: "application/rss+xml",
      })
    ).toBe("Reachable but empty: no articles in the feed for 5 days");
  });
});
