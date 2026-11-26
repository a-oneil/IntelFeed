import assert from "node:assert/strict";
import { test } from "node:test";

import { detectRuleType } from "../src/lib/rule-format.js";

test("common rule languages are recognized", () => {
  const cases = {
    yara: 'rule Akira_Loader {\n  strings:\n    $a = "akira"\n  condition:\n    $a\n}',
    sigma: "title: Suspicious\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image|endswith: '\\\\rclone.exe'\n  condition: sel",
    kql: 'DeviceProcessEvents\n| where FileName =~ "rclone.exe"\n| project Timestamp, DeviceName',
    splunk_spl: 'index=windows sourcetype=sysmon EventCode=1 Image="*\\\\rclone.exe"\n| stats count by host',
    elastic_ql: 'process where process.name == "rclone.exe" and process.args : "copy"',
    snort_suricata: 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Akira C2"; sid:1000001;)',
    nuclei: "id: cve-2024-3400\ninfo:\n  name: PAN-OS\n  severity: critical\nhttp:\n  - method: GET",
    crowdstrike_ql: '#event_simpleName=ProcessRollup2 FileName="rclone.exe"',
  };
  for (const [type, text] of Object.entries(cases)) assert.equal(detectRuleType(text), type, type);
});

test("plain prose is not guessed", () => {
  assert.equal(detectRuleType("The actor used rclone to copy files to Mega."), null);
  assert.equal(detectRuleType(""), null);
});
