import assert from "node:assert/strict";
import { test } from "node:test";

import { entityOption, initialKind, linkNoteMarkdown } from "../src/lib/notes.js";

test("the note links the page, quotes the selection, then adds the user's text", () => {
  const md = linkNoteMarkdown({
    url: "https://docs.aws.amazon.com/guardduty/x",
    pageTitle: "GuardDuty [finding] types",
    quote: "line one\nline two",
    content: "  Covers S3 only.  ",
  });
  assert.equal(md, "[GuardDuty finding types](https://docs.aws.amazon.com/guardduty/x)\n\n> line one\n> line two\n\nCovers S3 only.");
  assert.equal(linkNoteMarkdown({ url: "https://a.test/" }), "[https://a.test/](https://a.test/)");
});

test("search results become pickable entities; types that can't take a note are dropped", () => {
  assert.deepEqual(entityOption({ type: "threat_actor", id: "1", name: "Scattered Spider" }), {
    type: "threat_actor",
    id: "1",
    name: "Scattered Spider",
  });
  assert.equal(entityOption({ type: "cve", id: "2", cve_id: "CVE-2025-31324" }).name, "CVE-2025-31324");
  assert.equal(
    entityOption({ type: "ttp", id: "3", technique_id: "T1078", technique_name: "Valid Accounts" }).name,
    "T1078 Valid Accounts",
  );
  assert.equal(entityOption({ type: "detection_rule", id: "4", title: "x" }), null);
});

test("the Note tab opens on a suggested source, else the last kind used", () => {
  assert.equal(initialKind({ preferredSource: "AWS GuardDuty", lastKind: "entity" }), "telemetry");
  assert.equal(initialKind({ preferredSource: "", lastKind: "entity" }), "entity");
  assert.equal(initialKind({ preferredSource: "", lastKind: undefined }), "note");
});
