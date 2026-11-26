import assert from "node:assert/strict";
import { test } from "node:test";

import { MAX_PICKS, preferredSource, rememberPick, sitePrefix } from "../src/lib/telemetry.js";

test("sitePrefix is host plus two path segments", () => {
  assert.equal(sitePrefix("https://Docs.aws.amazon.com/guardduty/latest/ug/x.html"), "docs.aws.amazon.com/guardduty/latest");
  assert.equal(sitePrefix("https://example.com/"), "example.com");
  assert.equal(sitePrefix("nope"), "");
});

test("the user's own pick beats the server's suggestion", () => {
  const url = "https://docs.aws.amazon.com/guardduty/latest/ug/a.html";
  const suggestions = [{ name: "AWS CloudTrail" }];
  assert.equal(preferredSource({}, url, suggestions), "AWS CloudTrail");
  const picks = rememberPick({}, url, "AWS GuardDuty");
  assert.equal(preferredSource(picks, "https://docs.aws.amazon.com/guardduty/latest/ug/b.html", suggestions), "AWS GuardDuty");
  assert.equal(preferredSource(picks, "https://other.example/", []), "");
});

test("rememberPick keeps the newest MAX_PICKS", () => {
  let picks = {};
  for (let i = 0; i < MAX_PICKS + 5; i++) picks = rememberPick(picks, `https://s${i}.example/`, `n${i}`);
  assert.equal(Object.keys(picks).length, MAX_PICKS);
  assert.equal(picks["s0.example"], undefined);
  assert.equal(picks[`s${MAX_PICKS + 4}.example`], `n${MAX_PICKS + 4}`);
});
