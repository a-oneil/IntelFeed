"""Tests for DE-9: YARA template scaffolding."""

from app.intelligence.yara_rules import (
    SCAFFOLDING_TEMPLATES,
    generate_document_template,
    generate_elf_template,
    generate_memory_template,
    generate_pe_template,
    generate_yara_rules,
)


class TestYARAFromIOCs:
    def test_md5_hash(self):
        rules = generate_yara_rules([{"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}])
        assert len(rules) == 1
        assert "hash.md5" in rules[0]["rule_content"]
        assert rules[0]["template_type"] == "hash"

    def test_sha1_hash(self):
        rules = generate_yara_rules([{"type": "sha1", "value": "a" * 40}])
        assert "hash.sha1" in rules[0]["rule_content"]

    def test_sha256_hash(self):
        rules = generate_yara_rules([{"type": "sha256", "value": "b" * 64}])
        assert "hash.sha256" in rules[0]["rule_content"]

    def test_domain_generates_string_match(self):
        rules = generate_yara_rules([{"type": "domain", "value": "evil.example.com"}])
        assert len(rules) == 1
        assert "evil.example.com" in rules[0]["rule_content"]
        assert "ascii wide nocase" in rules[0]["rule_content"]

    def test_url_generates_string_match(self):
        rules = generate_yara_rules([{"type": "url", "value": "http://bad.com/payload.exe"}])
        assert len(rules) == 1
        assert "http://bad.com/payload.exe" in rules[0]["rule_content"]

    def test_ip_generates_string_match(self):
        rules = generate_yara_rules([{"type": "ip", "value": "10.0.0.1"}])
        assert len(rules) == 1
        assert "10.0.0.1" in rules[0]["rule_content"]

    def test_string_type(self):
        rules = generate_yara_rules([{"type": "string", "value": "CreateRemoteThread"}])
        assert len(rules) == 1
        assert "CreateRemoteThread" in rules[0]["rule_content"]

    def test_custom_prefix_and_author(self):
        rules = generate_yara_rules(
            [{"type": "domain", "value": "test.com"}],
            rule_name_prefix="custom",
            author="TestAuthor",
        )
        assert "custom_" in rules[0]["rule_content"]
        assert "TestAuthor" in rules[0]["rule_content"]

    def test_empty_value_skipped(self):
        rules = generate_yara_rules([{"type": "ip", "value": ""}])
        assert len(rules) == 0

    def test_unknown_type_skipped(self):
        rules = generate_yara_rules([{"type": "something_weird", "value": "test"}])
        assert len(rules) == 0

    def test_multiple_iocs(self):
        iocs = [
            {"type": "md5", "value": "a" * 32},
            {"type": "domain", "value": "evil.com"},
            {"type": "ip", "value": "1.2.3.4"},
        ]
        rules = generate_yara_rules(iocs)
        assert len(rules) == 3


class TestYARAScaffoldingTemplates:
    def test_pe_template(self):
        content = generate_pe_template("test_pe")
        assert 'import "pe"' in content
        assert "pe.is_pe" in content
        assert "rule test_pe" in content

    def test_elf_template(self):
        content = generate_elf_template("test_elf")
        assert 'import "elf"' in content
        assert "elf.type" in content
        assert "rule test_elf" in content

    def test_document_template(self):
        content = generate_document_template("test_doc")
        assert "D0 CF 11 E0" in content
        assert "AutoOpen" in content
        assert "powershell" in content

    def test_memory_template(self):
        content = generate_memory_template("test_mem")
        assert "scan_context" in content
        assert "rule test_mem" in content

    def test_all_templates_registered(self):
        assert "pe_file" in SCAFFOLDING_TEMPLATES
        assert "elf_file" in SCAFFOLDING_TEMPLATES
        assert "document" in SCAFFOLDING_TEMPLATES
        assert "memory" in SCAFFOLDING_TEMPLATES

    def test_custom_author(self):
        content = generate_pe_template("test", author="CustomAuthor")
        assert "CustomAuthor" in content
