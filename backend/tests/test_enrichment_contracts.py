"""Adapter contract tests: each keyless adapter against a real recorded response.

The fixtures in ``tests/fixtures/enrichment/`` are trimmed live responses, so a
test here fails when an adapter's parsing drifts from what the source really
returns. Each fixture file maps a name to ``{url, status, body}``. The adapter
gets a real SourceGateway whose inner transport is a mock server: it answers a
request with the recording whose URL matches it (path and query), else with
the file's ``not_found`` recording, else a bare 404.

Adapters that need a key (VirusTotal, VulnCheck, CVEDetails) have no recording.
"""

import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app.enrichment.gateway import SourceGateway
from app.enrichment.registry import get_adapter

FIXTURES = Path(__file__).parent / "fixtures" / "enrichment"


def _recordings(source: str) -> dict:
    return json.loads((FIXTURES / f"{source}.json").read_text())


def _key(url: str) -> tuple:
    parts = urlsplit(url)
    query = {k: tuple(sorted(v)) for k, v in parse_qs(parts.query).items()}
    return parts.netloc, parts.path, tuple(sorted(query.items()))


def _wire(source: str, api_key: str | None = None):
    """The adapter for ``source``, its gateway serving every request from the
    recordings. Returns ``(adapter, requests)`` — the requests it sent, in order."""
    recordings = _recordings(source)
    by_url = {_key(r["url"]): r for r in recordings.values()}
    fallback = recordings.get("not_found")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        rec = by_url.get(_key(str(request.url))) or fallback
        if rec is None:
            return httpx.Response(404, json={})
        return httpx.Response(rec["status"], json=rec["body"])

    gateway = SourceGateway(
        source,
        rate_limit_config={"requests_per_period": 1000, "period_seconds": 60},
        api_key=api_key,
        inner=httpx.MockTransport(handler),
    )
    return get_adapter(source, api_key=api_key, gateway=gateway), seen


# The endpoint each adapter's enrich() calls first. check_health() must call
# the same shape, so a health check can't pass while enrichment is broken (OSV
# once probed a POST that answered 400 to every request).
ENDPOINTS = {
    "osv": r"^https://api\.osv\.dev/v1/vulns/[^/]+$",
    "greynoise": r"^https://api\.greynoise\.io/v3/community/[\d.]+$",
    "epss": r"^https://api\.first\.org/data/v1/epss\?cve=CVE-[\d-]+$",
    "shodan": r"^https://internetdb\.shodan\.io/[\d.]+$",
    "nvd": r"^https://services\.nvd\.nist\.gov/rest/json/cves/2\.0\?cveId=CVE-[\d-]+$",
    "cisa_kev": r"^https://www\.cisa\.gov/sites/default/files/feeds/known_exploited_vulnerabilities\.json$",
    "mitre_attack": r"^https://raw\.githubusercontent\.com/mitre-attack/attack-stix-data/.+/enterprise-attack\.json$",
    "malpedia": r"^https://malpedia\.caad\.fkie\.fraunhofer\.de/api/(get/family/[^/]+|list/families)$",
    "github_poc": r"^https://api\.github\.com/search/repositories\?q=",
    "wikipedia": r"^https://en\.wikipedia\.org/w/api\.php\?.*action=query",
    "cvelist": r"^https://raw\.githubusercontent\.com/CVEProject/cvelistV5/main/cves/\d{4}/\d+xxx/CVE-[\d-]+\.json$",
}

# One enrich() call per adapter, for the endpoint-shape check.
ENRICH_CALLS = {
    "osv": ("cve", "CVE-2021-44228"),
    "greynoise": ("observable", "71.6.135.131"),
    "epss": ("cve", "CVE-2021-44228"),
    "shodan": ("observable", "8.8.8.8"),
    "nvd": ("cve", "CVE-2021-44228"),
    "cisa_kev": ("cve", "CVE-2021-44228"),
    "mitre_attack": ("ttp", "T1059.001"),
    "malpedia": ("malware", "WannaCry"),
    "github_poc": ("cve", "CVE-2021-44228"),
    "wikipedia": ("threat_actor", "Lazarus Group"),
    "cvelist": ("cve", "CVE-2024-3400"),
}


@pytest.mark.parametrize("source", sorted(ENDPOINTS))
async def test_check_health_uses_the_enrich_endpoint(source):
    pattern = re.compile(ENDPOINTS[source])

    adapter, seen = _wire(source)
    await adapter.enrich(*ENRICH_CALLS[source])
    assert seen and pattern.match(str(seen[0].url)), f"enrich() called {seen[0].url if seen else 'nothing'}"

    adapter, seen = _wire(source)
    await adapter.check_health()
    assert seen, "check_health() made no request"
    assert all(pattern.match(str(r.url)) for r in seen), f"check_health() called {[str(r.url) for r in seen]}"


# ── OSV ──────────────────────────────────────────────────────────────


async def test_osv_parses_a_vuln_record():
    adapter, seen = _wire("osv")
    data = await adapter.enrich("cve", "CVE-2021-44228")

    assert seen[0].method == "GET"
    parsed = data.parsed_data
    assert parsed["found"] is True
    assert parsed["osv_id"] == "CVE-2021-44228"
    assert parsed["aliases"] == ["GHSA-jfh8-c2jp-5v3q"]
    assert parsed["severity"] == ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"]
    assert parsed["published"] == "2021-12-10T10:15:09.143Z"
    assert parsed["modified"].startswith("2026-")
    assert parsed["details"].startswith("Apache Log4j2 2.0-beta9 through 2.15.0")
    # NVD-sourced OSV records carry GIT ranges only: no package, but the repo
    # and the introduced/fixed commits.
    (affected,) = parsed["affected"]
    assert affected["ecosystem"] is None and affected["package_name"] is None
    (git_range,) = affected["ranges"]
    assert git_range["type"] == "GIT"
    assert git_range["repo"] == "https://github.com/apache/logging-log4j2"
    assert "0" in git_range["introduced"]
    assert "ad361d2e517e765f69db464d9407ac2dd80bc93e" in git_range["fixed"]
    assert len(parsed["references"]) == 3 and parsed["references"][0]["url"].startswith("https://")


async def test_osv_parses_package_ranges():
    from app.enrichment.adapters.osv import _affected

    entry = {
        "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}],
    }
    assert _affected(entry) == {
        "ecosystem": "Maven",
        "package_name": "org.apache.logging.log4j:log4j-core",
        "ranges": [{"type": "ECOSYSTEM", "repo": None, "introduced": ["2.13.0"], "fixed": ["2.15.0"]}],
    }


async def test_osv_not_found():
    adapter, _ = _wire("osv")
    data = await adapter.enrich("cve", "CVE-1999-99999")
    assert data.parsed_data == {"found": False}


async def test_osv_health_is_healthy():
    adapter, _ = _wire("osv")
    assert await adapter.check_health() is True


# ── GreyNoise ────────────────────────────────────────────────────────


async def test_greynoise_works_without_a_key():
    adapter, seen = _wire("greynoise")
    assert adapter.requires_api_key is False
    data = await adapter.enrich("observable", "71.6.135.131")

    assert "key" not in seen[0].headers
    assert data.parsed_data == {
        "found": True,
        "noise_class": "benign",
        "noise": True,
        "riot": False,
        "name": "Shodan.io",
        "last_seen": "2026-10-28",
        "link": "https://viz.greynoise.io/ip/71.6.135.131",
    }


async def test_greynoise_sends_a_configured_key():
    adapter, seen = _wire("greynoise", api_key="gn-test-key")
    await adapter.enrich("observable", "71.6.135.131")
    assert seen[0].headers["key"] == "gn-test-key"


async def test_greynoise_not_observed():
    adapter, _ = _wire("greynoise")
    data = await adapter.enrich("observable", "1.1.1.1")
    assert data.parsed_data["found"] is False
    assert data.parsed_data["noise_class"] == "not_seen"
    assert data.parsed_data["noise"] is False
    assert data.parsed_data["riot"] is False


async def test_greynoise_default_source_needs_no_key():
    from app.enrichment.adapters.greynoise import GreyNoiseAdapter
    from app.enrichment.registry import DEFAULT_SOURCES

    assert GreyNoiseAdapter.requires == ()
    row = next(s for s in DEFAULT_SOURCES if s["source_type"] == "greynoise")
    assert row["default_trigger_mode"] == "manual"


# ── The other keyless adapters ───────────────────────────────────────


async def test_epss():
    adapter, _ = _wire("epss")
    data = await adapter.enrich("cve", "CVE-2021-44228")
    assert data.parsed_data == {"cve": "CVE-2021-44228", "epss": 0.99999, "percentile": 1.0, "date": "2026-10-27"}
    data = await adapter.enrich("cve", "CVE-1999-99999")
    assert data.parsed_data == {"found": False}


async def test_shodan():
    adapter, _ = _wire("shodan")
    data = await adapter.enrich("observable", "8.8.8.8")
    assert data.parsed_data == {
        "found": True,
        "ports": "53, 443",
        "hostnames": "dns.google, direct.suntory.co.jp",
        "tags": None,
        "vulns": None,
        "cpes": None,
    }
    data = await adapter.enrich("observable", "10.1.2.3")
    assert data.parsed_data == {"found": False}


async def test_nvd():
    adapter, _ = _wire("nvd")
    data = await adapter.enrich("cve", "CVE-2021-44228")
    parsed = data.parsed_data
    assert parsed["cve_id"] == "CVE-2021-44228"
    assert parsed["cvss_score"] == 10.0
    assert parsed["cvss_severity"] == "CRITICAL"
    assert parsed["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert parsed["description"].startswith("Apache Log4j2")
    assert parsed["weaknesses"] and all(w.startswith("CWE-") for w in parsed["weaknesses"])
    assert len(parsed["references"]) == 3
    data = await adapter.enrich("cve", "CVE-1999-99999")
    assert data.parsed_data == {"found": False}


async def test_cisa_kev():
    adapter, _ = _wire("cisa_kev")
    data = await adapter.enrich("cve", "CVE-2021-44228")
    parsed = data.parsed_data
    assert parsed["in_kev"] is True
    assert parsed["vendor"] == "Apache"
    assert parsed["product"] == "Log4j2"
    assert parsed["date_added"] == "2021-12-10"
    assert parsed["known_ransomware_use"] == "Known"
    data = await adapter.enrich("cve", "CVE-1999-99999")
    assert data.parsed_data == {"in_kev": False}


async def test_mitre_attack():
    adapter, _ = _wire("mitre_attack")
    technique = (await adapter.enrich("ttp", "T1059.001")).parsed_data
    assert technique["name"] == "PowerShell"
    assert technique["is_subtechnique"] is True
    assert technique["url"] == "https://attack.mitre.org/techniques/T1059/001"

    group = (await adapter.enrich("threat_actor", "Lazarus Group")).parsed_data
    assert group["mitre_id"] == "G0032"

    software = (await adapter.enrich("malware", "WannaCry")).parsed_data
    assert software["type"] == "malware"

    mitigation = (await adapter.enrich("mitigation", "M1042")).parsed_data
    assert {"technique_id": "T1059.001", "technique_name": "PowerShell"} in mitigation["mitigated_ttps"]

    assert (await adapter.enrich("ttp", "T9999")).parsed_data == {"found": False}


async def test_malpedia():
    adapter, _ = _wire("malpedia")
    # "WannaCry" has no family of that id: the adapter falls back to the
    # family list and finds win.wannacryptor.
    family = (await adapter.enrich("malware", "WannaCry")).parsed_data
    assert family["found"] is True
    assert family["family_name"] == "WannaCryptor"
    assert family["attribution"] == ["Lazarus Group"]
    assert family["urls"] and all(u.startswith("http") for u in family["urls"])

    actor = (await adapter.enrich("threat_actor", "Lazarus Group")).parsed_data
    assert actor["actor_name"] == "Lazarus Group"
    assert len(actor["families"]) == 5 and all("." in f for f in actor["families"])
    assert actor["country"] == "KP"

    assert (await adapter.enrich("malware", "Nonexistent")).parsed_data == {"found": False}


async def test_github_poc():
    adapter, _ = _wire("github_poc")
    parsed = (await adapter.enrich("cve", "CVE-2021-44228")).parsed_data
    assert parsed["has_public_poc"] is True
    assert parsed["poc_count"] == 15
    assert parsed["exploit_maturity"] == "weaponized"
    assert parsed["poc_repos"][0]["name"] == "CVE-2021-44228-PoC-log4j-bypass-words"

    parsed = (await adapter.enrich("cve", "CVE-1999-99999")).parsed_data
    assert parsed["has_public_poc"] is False and parsed["poc_count"] == 0


async def test_wikipedia():
    adapter, seen = _wire("wikipedia")
    parsed = (await adapter.enrich("threat_actor", "Lazarus Group")).parsed_data
    assert parsed["found"] is True
    assert parsed["title"] == "Lazarus Group"
    assert parsed["wikipedia_url"] == "https://en.wikipedia.org/wiki/Lazarus_Group"
    assert parsed["first_paragraph"].startswith("The Lazarus Group (also known as the Guardians of Peace")
    assert parsed["wikipedia_image_url"] is None
    # One page lookup is three MediaWiki calls: info, extracts, pageimages.
    props = [parse_qs(urlsplit(str(r.url)).query)["prop"][0] for r in seen]
    assert props == ["info", "extracts", "pageimages"]
