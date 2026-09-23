"""Tests for BE-4: Rule validation engine."""

from app.intelligence.rule_validation import (
    validate_crowdstrike_ql,
    validate_elastic_ql,
    validate_kql,
    validate_rule,
    validate_sigma,
    validate_snort_suricata,
    validate_splunk_spl,
    validate_yara,
)


class TestSigmaValidation:
    def test_valid_sigma_rule(self):
        rule = """
title: Test Rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
level: high
"""
        result = validate_sigma(rule)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_invalid_yaml(self):
        result = validate_sigma("title: [invalid yaml")
        assert result.valid is False
        assert any("YAML" in e.message or "yaml" in e.message.lower() for e in result.errors)

    def test_missing_required_fields(self):
        rule = """
title: Test Rule
"""
        result = validate_sigma(rule)
        assert result.valid is False
        assert any("status" in e.message for e in result.errors)
        assert any("logsource" in e.message for e in result.errors)
        assert any("detection" in e.message for e in result.errors)

    def test_missing_condition(self):
        rule = """
title: Test Rule
status: test
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: test
"""
        result = validate_sigma(rule)
        assert result.valid is False
        assert any("condition" in e.message for e in result.errors)

    def test_logsource_missing_category(self):
        rule = """
title: Test Rule
status: test
logsource:
    custom_field: something
detection:
    selection:
        CommandLine: test
    condition: selection
"""
        result = validate_sigma(rule)
        assert result.valid is False
        assert any("category" in e.message or "product" in e.message for e in result.errors)

    def test_suggestions_for_missing_optional_fields(self):
        rule = """
title: Test Rule
status: test
logsource:
    category: process_creation
detection:
    selection:
        CommandLine: test
    condition: selection
"""
        result = validate_sigma(rule)
        assert result.valid is True
        assert len(result.suggestions) > 0
        assert any("falsepositives" in s for s in result.suggestions)


class TestSplunkSPLValidation:
    def test_valid_spl(self):
        result = validate_splunk_spl('index=main sourcetype="WinEventLog" | stats count by src_ip')
        assert result.valid is True

    def test_empty_spl(self):
        result = validate_splunk_spl("")
        assert result.valid is False

    def test_unbalanced_parens(self):
        result = validate_splunk_spl('index=main (sourcetype="test"')
        assert result.valid is False
        assert any("Unmatched" in e.message for e in result.errors)

    def test_unbalanced_quotes(self):
        result = validate_splunk_spl('index=main sourcetype="test')
        assert result.valid is False

    def test_missing_index_suggestion(self):
        result = validate_splunk_spl('sourcetype="WinEventLog" | stats count')
        assert any("index" in s.lower() for s in result.suggestions)


class TestKQLValidation:
    def test_valid_kql(self):
        result = validate_kql("SecurityEvent | where EventID == 4625 | summarize count() by Account")
        assert result.valid is True

    def test_empty_kql(self):
        result = validate_kql("")
        assert result.valid is False


class TestElasticQLValidation:
    def test_valid_eql(self):
        result = validate_elastic_ql('process where process.name == "cmd.exe"')
        assert result.valid is True

    def test_empty_eql(self):
        result = validate_elastic_ql("")
        assert result.valid is False


class TestCrowdStrikeQLValidation:
    def test_valid_cs_ql(self):
        result = validate_crowdstrike_ql('event_simpleName=ProcessRollup2 AND FileName="mimikatz.exe"')
        assert result.valid is True

    def test_empty_cs_ql(self):
        result = validate_crowdstrike_ql("")
        assert result.valid is False


class TestSnortSuricataValidation:
    def test_valid_snort_rule(self):
        rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test Rule"; content:"malware"; sid:1000001; rev:1;)'
        result = validate_snort_suricata(rule)
        assert result.valid is True

    def test_missing_sid(self):
        rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test Rule"; content:"malware";)'
        result = validate_snort_suricata(rule)
        assert result.valid is False
        assert any("sid" in e.message for e in result.errors)

    def test_invalid_action(self):
        rule = 'invalid tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test Rule"; sid:1; rev:1;)'
        result = validate_snort_suricata(rule)
        assert result.valid is False
        assert any("action" in e.message.lower() for e in result.errors)

    def test_invalid_direction(self):
        rule = 'alert tcp $HOME_NET any >> $EXTERNAL_NET 443 (msg:"Test Rule"; sid:1; rev:1;)'
        result = validate_snort_suricata(rule)
        assert result.valid is False
        assert any("direction" in e.message.lower() for e in result.errors)


class TestYARAValidation:
    def test_valid_yara_rule(self):
        rule = """
rule test_rule
{
    meta:
        author = "test"
    strings:
        $a = "malware"
    condition:
        $a
}
"""
        result = validate_yara(rule)
        assert result.valid is True

    def test_missing_condition(self):
        rule = """
rule test_rule
{
    strings:
        $a = "malware"
}
"""
        result = validate_yara(rule)
        assert result.valid is False
        assert any("condition" in e.message for e in result.errors)

    def test_unbalanced_braces(self):
        rule = """
rule test_rule
{
    condition:
        true
"""
        result = validate_yara(rule)
        assert result.valid is False

    def test_missing_rule_keyword(self):
        result = validate_yara("just some text")
        assert result.valid is False

    def test_empty_yara(self):
        result = validate_yara("")
        assert result.valid is False


class TestValidateRuleRouter:
    def test_unknown_rule_type(self):
        result = validate_rule("unknown_type", "some content")
        assert result.valid is False

    def test_routes_to_sigma(self):
        rule = """
title: Test
status: test
logsource:
    category: process_creation
detection:
    sel:
        CommandLine: test
    condition: sel
"""
        result = validate_rule("sigma", rule)
        assert result.valid is True

    def test_routes_to_yara(self):
        rule = """
rule test { condition: true }
"""
        result = validate_rule("yara", rule)
        assert result.valid is True
