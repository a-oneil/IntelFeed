import { describe, it, expect } from "vitest";
import { parseRuleOutline } from "../ruleBench/ruleOutline";

const SIGMA = `title: Device Code Authentication Flow
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        AuthenticationProtocol: deviceCode
        ResultType: 0
    filter:
        AppDisplayName: Approved App
    condition: selection and not filter
falsepositives:
    - Legitimate device onboarding
level: high`;

const KQL = `// Device code authentication against a first-party client
SigninLogs
| where AuthenticationProtocol == "deviceCode" and ResultType == "0"
| project UserPrincipalName, IPAddress, AppDisplayName`;

const YARA = `rule Suspicious_Loader
{
    meta:
        author = "analyst"
    strings:
        $a = "loader"
        $b = { 4d 5a }
    condition:
        all of them
}`;

describe("parseRuleOutline", () => {
  it("lists sigma top-level keys and nests only the detection blocks", () => {
    const nodes = parseRuleOutline(SIGMA, "sigma");
    expect(nodes.filter((n) => n.depth === 0).map((n) => n.label)).toEqual([
      "title", "logsource", "detection", "falsepositives", "level",
    ]);
    // logsource children stay out; selection/filter/condition come in under detection.
    expect(nodes.filter((n) => n.depth === 1).map((n) => n.label)).toEqual([
      "selection", "filter", "condition",
    ]);
  });

  it("counts the fields inside a selection block", () => {
    const nodes = parseRuleOutline(SIGMA, "sigma");
    expect(nodes.find((n) => n.label === "selection")?.count).toBe(2);
    expect(nodes.find((n) => n.label === "filter")?.count).toBe(1);
    // A leaf key has nothing to count and must not render a 0 badge.
    expect(nodes.find((n) => n.label === "condition")?.count).toBeUndefined();
  });

  it("points each node at the line the editor should scroll to", () => {
    const nodes = parseRuleOutline(SIGMA, "sigma");
    expect(nodes.find((n) => n.label === "detection")?.line).toBe(5);
    expect(nodes.find((n) => n.label === "level")?.line).toBe(14);
  });

  it("splits a KQL query on its pipes and skips the comment", () => {
    const nodes = parseRuleOutline(KQL, "kql");
    expect(nodes.map((n) => n.label)).toEqual(["SigninLogs", "where AuthenticationProtocol", "project UserPrincipalName"]);
    expect(nodes[0].depth).toBe(0);
    expect(nodes[1].count).toBe(2); // two comparisons
    expect(nodes[2].count).toBe(3); // three projected fields
  });

  it("reads YARA sections under their rule", () => {
    const nodes = parseRuleOutline(YARA, "yara");
    expect(nodes.map((n) => n.label)).toEqual(["Suspicious_Loader", "meta", "strings", "condition"]);
    expect(nodes.find((n) => n.label === "strings")?.count).toBe(2);
  });

  it("returns nothing rather than a wrong outline for unparseable content", () => {
    expect(parseRuleOutline("", "sigma")).toEqual([]);
    expect(parseRuleOutline("just some prose about a threat", "unknown_format")).toEqual([]);
  });
});
