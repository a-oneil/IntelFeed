import assert from "node:assert/strict";
import { test } from "node:test";

import { notificationText, summarize, threadSize } from "../src/lib/findings.js";

test("summarize names what was found, in plain counts", () => {
  const r = {
    actors: [{}, {}],
    malware: [{}],
    tools: [],
    cves: [{}, {}, {}],
    ttps: [{}],
    rule_count: 1,
    observable_count: 0,
  };
  assert.equal(summarize(r), "2 actors, 1 malware family, 3 CVEs, 1 technique, 1 detection rule");
  assert.equal(summarize({}), "");
});

test("the notification says when nothing was found or something failed", () => {
  assert.equal(notificationText({ state: "done" }), "Nothing was found in it.");
  assert.equal(notificationText({ state: "done", cves: [{}] }), "Found 1 CVE.");
  assert.match(notificationText({ state: "errored", cves: [{}] }), /error\. Found so far: 1 CVE/);
});

test("threadSize", () => {
  assert.equal(threadSize({ title: "Akira hits SonicWall", entry_count: 7, source_count: 1 }), "7 articles from 1 site");
  assert.equal(threadSize(null), "");
});
