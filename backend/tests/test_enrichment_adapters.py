"""Tests for enrichment adapter base and registry."""

import pytest

from app.enrichment.base import EnrichmentData
from app.enrichment.registry import ADAPTER_REGISTRY, DEFAULT_SOURCES, get_adapter


class TestEnrichmentBase:
    def test_enrichment_data_defaults(self):
        data = EnrichmentData(raw_response={"key": "value"}, parsed_data={"result": True})
        assert data.ttl_hours == 24

    def test_enrichment_data_custom_ttl(self):
        data = EnrichmentData(raw_response={}, parsed_data={}, ttl_hours=168)
        assert data.ttl_hours == 168


class TestAdapterRegistry:
    def test_registry_has_all_adapters(self):
        assert len(ADAPTER_REGISTRY) == 13

    def test_registry_contains_expected_sources(self):
        expected = {
            "epss",
            "nvd",
            "cisa_kev",
            "mitre_attack",
            "vulncheck",
            "osv",
            "malpedia",
            "github_poc",
            "cvedetails",
            "wikipedia",
            # Observable (IOC ledger) reputation adapters, restored from v1.
            "virustotal",
            "greynoise",
            "shodan",
        }
        assert set(ADAPTER_REGISTRY.keys()) == expected

    def test_get_adapter_returns_correct_type(self):
        adapter = get_adapter("nvd")
        assert adapter.source_type == "nvd"
        assert adapter.display_name == "NVD API 2.0"

    def test_get_adapter_unknown_type(self):
        with pytest.raises(ValueError, match="Unknown enrichment source"):
            get_adapter("nonexistent_source")

    def test_get_adapter_with_api_key(self):
        adapter = get_adapter("nvd", api_key="test-key")
        assert adapter.api_key == "test-key"

    def test_get_adapter_with_config(self):
        adapter = get_adapter("epss", config={"ttl_hours": 48})
        assert adapter.config["ttl_hours"] == 48

    def test_default_sources_defined(self):
        assert len(DEFAULT_SOURCES) == 13
        source_types = {s["source_type"] for s in DEFAULT_SOURCES}
        assert source_types == set(ADAPTER_REGISTRY.keys())

    def test_all_adapters_have_required_attributes(self):
        for source_type, adapter_cls in ADAPTER_REGISTRY.items():
            adapter = adapter_cls()
            assert hasattr(adapter, "source_type")
            assert hasattr(adapter, "display_name")
            assert hasattr(adapter, "supported_entity_types")
            assert isinstance(adapter.supported_entity_types, list)
            assert len(adapter.supported_entity_types) > 0


class TestEPSSAdapter:
    def test_supports_cve(self):
        adapter = get_adapter("epss")
        assert adapter.supports_entity("cve")
        assert not adapter.supports_entity("ioc_ipv4")


class TestNVDAdapter:
    def test_supports_cve(self):
        adapter = get_adapter("nvd")
        assert adapter.supports_entity("cve")
        assert not adapter.supports_entity("threat_actor")


class TestCISAKEVAdapter:
    def test_supports_cve(self):
        adapter = get_adapter("cisa_kev")
        assert adapter.supports_entity("cve")


class TestMITREAttackAdapter:
    def test_supports_multiple_types(self):
        adapter = get_adapter("mitre_attack")
        assert adapter.supports_entity("ttp")
        assert adapter.supports_entity("threat_actor")
        assert adapter.supports_entity("malware")
        assert not adapter.supports_entity("cve")


class TestVulnCheckAdapter:
    def test_supports_cve(self):
        adapter = get_adapter("vulncheck")
        assert adapter.supports_entity("cve")
        assert not adapter.supports_entity("ioc_ipv4")
        assert adapter.default_trigger_mode == "scheduled"


class TestOSVAdapter:
    def test_supports_cve(self):
        adapter = get_adapter("osv")
        assert adapter.supports_entity("cve")
        assert not adapter.supports_entity("ioc_ipv4")
        assert adapter.requires_api_key is False


class TestMalpediaAdapter:
    def test_supports_malware_and_actor(self):
        adapter = get_adapter("malpedia")
        assert adapter.supports_entity("malware")
        assert adapter.supports_entity("threat_actor")
        assert not adapter.supports_entity("cve")
        assert adapter.default_trigger_mode == "scheduled"


class TestGitHubPoCAdapter:
    def test_supports_cve(self):
        adapter = get_adapter("github_poc")
        assert adapter.supports_entity("cve")
        assert not adapter.supports_entity("ioc_ipv4")
        assert adapter.requires_api_key is False
        assert adapter.default_trigger_mode == "scheduled"


class TestWikipediaAdapter:
    def test_supports_intelligence_entity_types(self):
        adapter = get_adapter("wikipedia")
        assert adapter.supports_entity("threat_actor")
        assert adapter.supports_entity("malware")
        assert adapter.supports_entity("country")
        assert adapter.supports_entity("vendor")
        assert adapter.supports_entity("product")
        assert adapter.supports_entity("ttp")
        assert adapter.supports_entity("mitigation")
        assert adapter.supports_entity("cve")

    def test_does_not_support_ioc_types(self):
        adapter = get_adapter("wikipedia")
        assert not adapter.supports_entity("ioc_ipv4")
        assert not adapter.supports_entity("ioc_domain")
        assert not adapter.supports_entity("ioc_sha256")

    def test_requires_no_api_key(self):
        adapter = get_adapter("wikipedia")
        assert adapter.requires_api_key is False

    def test_default_trigger_mode_is_auto(self):
        adapter = get_adapter("wikipedia")
        assert adapter.default_trigger_mode == "auto"


class TestWikipediaHelper:
    def test_get_search_queries_threat_actor(self):
        from app.enrichment.wikipedia_helper import get_search_queries

        queries = get_search_queries("Lazarus Group", "threat_actor")
        assert queries[0] == "Lazarus Group"
        assert "Lazarus Group hacker group" in queries
        assert "Lazarus Group APT" in queries

    def test_get_search_queries_malware(self):
        from app.enrichment.wikipedia_helper import get_search_queries

        queries = get_search_queries("WannaCry", "malware")
        assert queries[0] == "WannaCry"
        assert "WannaCry malware" in queries

    def test_get_search_queries_vendor_with_override(self):
        from app.enrichment.wikipedia_helper import get_search_queries

        queries = get_search_queries("Apple", "vendor")
        assert queries[0] == "Apple Inc."

    def test_get_search_queries_country(self):
        from app.enrichment.wikipedia_helper import get_search_queries

        queries = get_search_queries("United States", "country")
        assert queries == ["United States"]

    def test_format_wiki_content_filters_sections(self):
        from app.enrichment.wikipedia_helper import format_wiki_content

        raw = "Introduction paragraph.\n== History ==\nHistory text.\n== References ==\nRef text."
        result = format_wiki_content(raw, "https://en.wikipedia.org/wiki/Test")
        assert "History text" in result
        assert "Ref text" not in result

    def test_format_wiki_content_converts_headers(self):
        from app.enrichment.wikipedia_helper import format_wiki_content

        raw = "Intro.\n== Section One ==\nText.\n=== Sub Section ===\nMore text."
        result = format_wiki_content(raw, "https://en.wikipedia.org/wiki/Test")
        assert "## Section One" in result
        assert "### Sub Section" in result

    def test_format_wiki_content_truncates(self):
        from app.enrichment.wikipedia_helper import format_wiki_content

        raw = "A" * 15000
        result = format_wiki_content(raw, "https://en.wikipedia.org/wiki/Test", max_chars=100)
        assert "[Read more on Wikipedia]" in result

    def test_extract_first_paragraph_skips_headers(self):
        from app.enrichment.wikipedia_helper import extract_first_paragraph

        content = "## Section Header\n\nThis is the first real paragraph with enough text."
        result = extract_first_paragraph(content)
        assert result == "This is the first real paragraph with enough text."

    def test_extract_first_paragraph_skips_short(self):
        from app.enrichment.wikipedia_helper import extract_first_paragraph

        content = "Short.\n\nThis is a longer paragraph that should be returned."
        result = extract_first_paragraph(content)
        assert result == "This is a longer paragraph that should be returned."

    def test_extract_first_paragraph_skips_attribution(self):
        from app.enrichment.wikipedia_helper import extract_first_paragraph

        content = "*Source: [Wikipedia](https://example.com)*\n\nActual content paragraph here."
        result = extract_first_paragraph(content)
        assert result == "Actual content paragraph here."


class TestWikipediaTitleGuardrail:
    def test_exact_match(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert title_matches_entity("Iran", "Iran")

    def test_case_insensitive(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert title_matches_entity("EMOTET", "Emotet")

    def test_parenthetical_qualifier_ignored(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert title_matches_entity("Iran (country)", "Iran")
        assert title_matches_entity("Sandworm (hacker group)", "Sandworm")

    def test_alias_match(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert title_matches_entity("Cozy Bear", "APT29", aliases=["Cozy Bear", "The Dukes"])

    def test_extra_titles_match_override_target(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert title_matches_entity("Elastic NV", "Elastic", extra_titles=["Elastic NV"])

    def test_redirect_extension_on_word_boundary(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert title_matches_entity("WannaCry ransomware attack", "WannaCry")

    def test_rejects_wrong_article(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert not title_matches_entity("International Standard Book Number", "Iran")
        assert not title_matches_entity("ISBN", "Iran")

    def test_rejects_partial_token_overlap(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert not title_matches_entity("Iranian Revolution", "Iran")

    def test_rejects_empty_title(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert not title_matches_entity("", "Iran")
        assert not title_matches_entity("()", "Iran")

    def test_punctuation_and_whitespace_normalized(self):
        from app.enrichment.wikipedia_helper import title_matches_entity

        assert title_matches_entity("F5, Inc.", "F5 Inc")
        assert title_matches_entity("Check_Point", "check point")


class _FakeAsyncPage:
    def __init__(self, title: str, exists: bool = True):
        self.title = title
        self._exists = exists

    async def exists(self):
        return self._exists

    @property
    def summary(self):
        async def _get():
            return f"{self.title} is a thing with a summary long enough to matter."

        return _get()

    @property
    def sections(self):
        async def _get():
            return []

        return _get()

    @property
    def fullurl(self):
        async def _get():
            return f"https://en.wikipedia.org/wiki/{self.title.replace(' ', '_')}"

        return _get()


class TestFetchWikipediaGuardrail:
    def _install_fake_wiki(self, monkeypatch, resolver):
        import sys as _sys
        import types

        class FakeAsyncWikipedia:
            def __init__(self, **kwargs):
                pass

            def page(self, query):
                return resolver(query)

        fake_module = types.SimpleNamespace(AsyncWikipedia=FakeAsyncWikipedia)
        monkeypatch.setitem(_sys.modules, "wikipediaapi", fake_module)

        async def _no_image(title, thumb_size=300, transport=None):
            return None

        monkeypatch.setattr("app.enrichment.wikipedia_helper._fetch_page_image_async", _no_image)

    async def test_rejects_mismatched_resolution(self, monkeypatch):
        from app.enrichment.wikipedia_helper import fetch_wikipedia

        # Every query resolves to the ISBN article (the historic auto-suggest bug)
        self._install_fake_wiki(monkeypatch, lambda q: _FakeAsyncPage("International Standard Book Number"))
        result = await fetch_wikipedia("Iran", "country")
        assert result is None

    async def test_accepts_matching_resolution(self, monkeypatch):
        from app.enrichment.wikipedia_helper import fetch_wikipedia

        self._install_fake_wiki(monkeypatch, lambda q: _FakeAsyncPage("Iran"))
        result = await fetch_wikipedia("Iran", "country")
        assert result is not None
        assert result["title"] == "Iran"
        assert result["url"] == "https://en.wikipedia.org/wiki/Iran"

    async def test_accepts_alias_resolution(self, monkeypatch):
        from app.enrichment.wikipedia_helper import fetch_wikipedia

        self._install_fake_wiki(monkeypatch, lambda q: _FakeAsyncPage("Cozy Bear"))
        result = await fetch_wikipedia("APT29", "threat_actor", aliases=["Cozy Bear"])
        assert result is not None
        assert result["title"] == "Cozy Bear"

    async def test_cve_exact_id_redirect_is_trusted(self, monkeypatch):
        from app.enrichment.wikipedia_helper import fetch_wikipedia

        # CVE-id pages exist only as redirects to the vuln's common name
        self._install_fake_wiki(monkeypatch, lambda q: _FakeAsyncPage("Log4Shell"))
        result = await fetch_wikipedia("CVE-2021-44228", "cve")
        assert result is not None
        assert result["title"] == "Log4Shell"

    async def test_by_title_bypasses_guardrail(self, monkeypatch):
        from app.enrichment.wikipedia_helper import fetch_wikipedia_by_title

        self._install_fake_wiki(monkeypatch, lambda q: _FakeAsyncPage(q))
        result = await fetch_wikipedia_by_title("Iran")
        assert result is not None
        assert result["title"] == "Iran"


class TestEntityTypeCoverage:
    """Verify entity type coverage across all adapters."""

    def test_cve_has_sufficient_coverage(self):
        cve_adapters = [name for name, cls in ADAPTER_REGISTRY.items() if "cve" in cls.supported_entity_types]
        assert len(cve_adapters) >= 6

    def test_malware_has_coverage(self):
        malware_adapters = [name for name, cls in ADAPTER_REGISTRY.items() if "malware" in cls.supported_entity_types]
        assert len(malware_adapters) >= 2

    def test_threat_actor_has_coverage(self):
        actor_adapters = [
            name for name, cls in ADAPTER_REGISTRY.items() if "threat_actor" in cls.supported_entity_types
        ]
        assert len(actor_adapters) >= 2
