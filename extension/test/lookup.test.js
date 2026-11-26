import assert from "node:assert/strict";
import { test } from "node:test";

import { lookupUrl, refang } from "../src/lib/lookup.js";

test("refang undoes the common defangs", () => {
  assert.equal(refang("hxxps://evil[.]example[.]com/x"), "https://evil.example.com/x");
  assert.equal(refang("192.168(.)1[.]10"), "192.168.1.10");
  assert.equal(refang("bad[at]example{dot}org"), "bad@example.org");
  assert.equal(refang("hxxp[:]//a[.]b"), "http://a.b");
  assert.equal(refang("  CVE-2024-3400 "), "CVE-2024-3400");
});

test("lookup opens a search on the server", () => {
  assert.equal(lookupUrl("https://intel.example.com", "evil[.]com"), "https://intel.example.com/search?q=evil.com");
  assert.equal(lookupUrl("https://intel.example.com", "  "), null);
});
