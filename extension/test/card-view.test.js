import assert from "node:assert/strict";
import { test } from "node:test";

import { cardView } from "../src/lib/card-view.js";

test("a CVE gets the app's badges, facts and reference links", () => {
  const v = cardView(
    "cve",
    {
      cve_id: "CVE-2026-132165",
      is_kev: true,
      severity: "CRITICAL",
      cvss_score: 9.8,
      epss_score: 0.0421,
      github_poc_count: 3,
      metasploit_module: "exploit/multi/http/x",
      exploit_status: "kev",
      first_seen_at: "2026-11-18T00:00:00Z",
      description: "Drupal Core contains a not failing securely vulnerability.",
    },
    "CVE-2026-132165",
  );
  assert.deepEqual(v.badges.map((b) => b.text), ["KEV", "CRITICAL"]);
  assert.equal(v.badges[0].solid, true);
  assert.deepEqual(
    v.facts.map((f) => `${f.label}=${f.value}`),
    ["CVSS=9.8", "EPSS=4.2%", "PoC=3 GitHub · Metasploit", "Exploit=kev"],
  );
  assert.equal(v.facts.find((f) => f.label === "Exploit").tone, "bad");
  assert.equal(v.seenFirst, true);
  assert.equal(v.descMax, 120);
  assert.deepEqual(v.links.map((l) => l.label), ["CVE.org", "NVD", "CVEDetails", "MITRE"]);
  assert.equal(v.links[1].url, "https://nvd.nist.gov/vuln/detail/CVE-2026-132165");
});

test("an actor gets its facts, other names, MITRE and Wikipedia links, and its picture", () => {
  const v = cardView(
    "threat_actor",
    {
      motivation: "financial",
      country: "US",
      targeted_sectors: ["retail", "insurance", "telecom", "hospitality"],
      mitre_id: "G1015",
      wikipedia_url: "https://en.wikipedia.org/wiki/Scattered_Spider",
      wikipedia_image_url: "https://upload.wikimedia.org/x.png",
      aliases: ["UNC3944", "scattered spider", "Octo Tempest"],
    },
    "Scattered Spider",
  );
  assert.deepEqual(v.facts.map((f) => f.label), ["Motivation", "Origin", "Targets"]);
  assert.equal(v.facts[2].value, "retail, insurance, telecom");
  assert.deepEqual(v.aliases, ["UNC3944", "Octo Tempest"]);
  assert.deepEqual(v.links.map((l) => l.label), ["MITRE ATT&CK", "Wikipedia"]);
  assert.equal(v.image, "https://upload.wikimedia.org/x.png");
  assert.equal(v.seenFirst, false);
});

test("a tool lists its detection artifacts; an indicator gets reputation links", () => {
  const tool = cardView("tool", { tool_type: "rmm", detection_artifacts: { file_names: ["a.exe", "b.exe"], empty: null } }, "AnyDesk");
  assert.deepEqual(tool.artifacts, [{ label: "file names", value: "a.exe, b.exe" }]);
  const ip = cardView("observable", { kind: "ipv4", value: "203.0.113.7", current_confidence: 0.8 }, "203.0.113.7");
  assert.deepEqual(ip.links.map((l) => l.label), ["VirusTotal", "Shodan", "GreyNoise", "AbuseIPDB"]);
  assert.equal(ip.facts.find((f) => f.label === "Confidence").value, "80%");
});

test("a technique shows its ID and tactic and no links, like the app", () => {
  const v = cardView("ttp", { technique_id: "T1566.004", tactic: "initial-access", mitre_url: "https://x" }, "T1566.004");
  assert.deepEqual(v.facts.map((f) => f.label), ["Technique", "Tactic"]);
  assert.deepEqual(v.links, []);
});

test("only https links reach the card", () => {
  const v = cardView(
    "vendor",
    { website: "javascript:alert(1)", wikipedia_url: "http://en.wikipedia.org/wiki/Acme" },
    "Acme",
  );
  assert.deepEqual(v.links, []);
  const ok = cardView("vendor", { website: "https://acme.example" }, "Acme");
  assert.deepEqual(ok.links.map((l) => l.url), ["https://acme.example"]);
});
