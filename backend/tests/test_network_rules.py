"""Tests for DE-8: Snort/Suricata template scaffolding."""

from app.intelligence.network_rules import generate_snort_suricata_rules


class TestIPRules:
    def test_ip_generates_bidirectional(self):
        rules = generate_snort_suricata_rules([{"type": "ip", "value": "10.0.0.1"}])
        assert len(rules) == 2
        titles = [r["title"] for r in rules]
        assert any("Outbound" in t for t in titles)
        assert any("Inbound" in t for t in titles)

    def test_ip_contains_sid(self):
        rules = generate_snort_suricata_rules([{"type": "ip", "value": "192.168.1.1"}])
        for r in rules:
            assert "sid:" in r["rule_content"]
            assert "rev:1" in r["rule_content"]

    def test_ip_aliases(self):
        for alias in ["ipv4", "ipv6", "ip_address"]:
            rules = generate_snort_suricata_rules([{"type": alias, "value": "1.2.3.4"}])
            assert len(rules) == 2

    def test_ip_uses_prefix(self):
        rules = generate_snort_suricata_rules([{"type": "ip", "value": "8.8.8.8"}], rule_prefix="CUSTOM")
        assert all("CUSTOM" in r["rule_content"] for r in rules)


class TestDomainRules:
    def test_domain_generates_dns_and_tls(self):
        rules = generate_snort_suricata_rules([{"type": "domain", "value": "evil.com"}])
        assert len(rules) == 2
        types = {r["title"].split(" ")[0] for r in rules}
        assert "DNS" in types
        assert "TLS" in types

    def test_domain_contains_content_match(self):
        rules = generate_snort_suricata_rules([{"type": "domain", "value": "bad.example.org"}])
        for r in rules:
            assert "bad.example.org" in r["rule_content"]

    def test_domain_aliases(self):
        for alias in ["hostname", "fqdn"]:
            rules = generate_snort_suricata_rules([{"type": alias, "value": "test.com"}])
            assert len(rules) == 2


class TestURLRules:
    def test_url_generates_http_rule(self):
        rules = generate_snort_suricata_rules([{"type": "url", "value": "http://evil.com/payload.exe"}])
        assert len(rules) == 1
        assert "http.host" in rules[0]["rule_content"]
        assert "http.uri" in rules[0]["rule_content"]

    def test_url_without_scheme(self):
        rules = generate_snort_suricata_rules([{"type": "url", "value": "evil.com/malware"}])
        assert len(rules) == 1
        assert "evil.com" in rules[0]["rule_content"]

    def test_url_alias(self):
        rules = generate_snort_suricata_rules([{"type": "uri", "value": "http://test.com/path"}])
        assert len(rules) == 1


class TestHashRules:
    def test_md5_generates_stub(self):
        rules = generate_snort_suricata_rules([{"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"}])
        assert len(rules) == 1
        assert "MD5" in rules[0]["rule_content"]
        assert rules[0]["rule_content"].startswith("#")

    def test_sha1_detection(self):
        rules = generate_snort_suricata_rules([{"type": "sha1", "value": "a" * 40}])
        assert "SHA1" in rules[0]["rule_content"]

    def test_sha256_detection(self):
        rules = generate_snort_suricata_rules([{"type": "sha256", "value": "b" * 64}])
        assert "SHA256" in rules[0]["rule_content"]


class TestMixedIOCs:
    def test_multiple_ioc_types(self):
        iocs = [
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "domain", "value": "evil.com"},
            {"type": "url", "value": "http://bad.com/payload"},
            {"type": "md5", "value": "a" * 32},
        ]
        rules = generate_snort_suricata_rules(iocs)
        # 2 IP + 2 domain + 1 URL + 1 hash = 6
        assert len(rules) == 6

    def test_empty_values_skipped(self):
        rules = generate_snort_suricata_rules([{"type": "ip", "value": ""}])
        assert len(rules) == 0

    def test_unknown_type_skipped(self):
        rules = generate_snort_suricata_rules([{"type": "unknown", "value": "test"}])
        assert len(rules) == 0

    def test_empty_list(self):
        rules = generate_snort_suricata_rules([])
        assert len(rules) == 0
