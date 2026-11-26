import assert from "node:assert/strict";
import { test } from "node:test";

await import("../src/content/matcher.js");
const { buildPattern, findMatches } = globalThis.IntelFeedMatcher;

test("longest form wins and only whole words match", () => {
  const p = buildPattern(["APT29", "APT29 Cozy Bear", "Akira", "x"]);
  const text = "APT29 Cozy Bear and APT29, not APT290 or SAkira; Akira's site";
  assert.deepEqual(
    findMatches(text, p).map((m) => m.form),
    ["APT29 Cozy Bear", "APT29", "Akira"],
  );
});

test("regex characters in names are literal", () => {
  const p = buildPattern(["C++Bot", "Ransom.Win32"]);
  assert.deepEqual(
    findMatches("seen C++Bot and Ransom.Win32 but not RansomXWin32", p).map((m) => m.form),
    ["C++Bot", "Ransom.Win32"],
  );
});

test("non-latin letters are word characters", () => {
  const p = buildPattern(["Lazarus"]);
  assert.equal(findMatches("éLazarus", p).length, 0);
  assert.equal(findMatches("(Lazarus)", p).length, 1);
});

test("nothing to match", () => {
  assert.equal(buildPattern([]), null);
  assert.deepEqual(findMatches("text", null), []);
});

test("CVE and ATT&CK pages are recognized from their address", () => {
  const { contextFromUrl } = globalThis.IntelFeedMatcher;
  assert.deepEqual(contextFromUrl("https://nvd.nist.gov/vuln/detail/CVE-2024-3400"), { kind: "cve", id: "CVE-2024-3400" });
  assert.deepEqual(contextFromUrl("https://www.cve.org/CVERecord?id=cve-2024-40766"), { kind: "cve", id: "CVE-2024-40766" });
  assert.deepEqual(contextFromUrl("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298"), {
    kind: "cve",
    id: "CVE-2025-21298",
  });
  assert.equal(contextFromUrl("https://example.com/cve-2024-1111-and-cve-2024-2222"), null);
  assert.deepEqual(contextFromUrl("https://attack.mitre.org/techniques/T1566/001/"), { kind: "ttp", id: "T1566.001" });
  assert.deepEqual(contextFromUrl("https://attack.mitre.org/techniques/T1059/"), { kind: "ttp", id: "T1059" });
  assert.equal(contextFromUrl("https://attack.mitre.org/groups/G0016/"), null);
  assert.equal(contextFromUrl("https://example.com/blog"), null);
});
