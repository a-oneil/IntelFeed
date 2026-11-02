"""Tests for CVE extraction and NVD enrichment."""

import httpx
import pytest

from app.enrichment.adapters.nvd import NVDAdapter
from app.enrichment.gateway import BreakerOpen, RateLimited, SourceGateway
from app.intelligence.cve import (
    _severity_from_score,
    calculate_cve_priority,
    compute_risk_tier,
    enrich_from_nvd,
    extract_cve_ids,
)
from app.workers.enrichment_tasks import iter_epss_csv

# --- Severity classification tests ---


def test_severity_critical():
    assert _severity_from_score(9.8) == "CRITICAL"


def test_severity_high():
    assert _severity_from_score(7.5) == "HIGH"


def test_severity_medium():
    assert _severity_from_score(5.0) == "MEDIUM"


def test_severity_low():
    assert _severity_from_score(2.0) == "LOW"


def test_severity_none():
    assert _severity_from_score(None) == "UNKNOWN"


def test_severity_boundary_9():
    assert _severity_from_score(9.0) == "CRITICAL"


def test_severity_boundary_7():
    assert _severity_from_score(7.0) == "HIGH"


def test_severity_boundary_4():
    assert _severity_from_score(4.0) == "MEDIUM"


# --- CVE ID extraction tests ---


def test_extract_cve_ids_basic():
    text = "This vulnerability CVE-2024-21762 is critical. Also see CVE-2024-3400 for details."
    result = extract_cve_ids(text)
    assert len(result) == 2
    assert set(result) == {"CVE-2024-21762", "CVE-2024-3400"}


def test_extract_cve_ids_dedup():
    text = "CVE-2024-21762 was discovered. CVE-2024-21762 is being exploited in the wild."
    result = extract_cve_ids(text)
    assert len(result) == 1
    assert result[0] == "CVE-2024-21762"


def test_extract_cve_ids_empty():
    assert extract_cve_ids("") == []
    assert extract_cve_ids(None) == []
    assert extract_cve_ids("No CVEs mentioned in this text at all.") == []


# --- NVD enrichment tests ---


def _make_nvd_response(cve_id: str = "CVE-2024-21762") -> dict:
    """Build a realistic NVD API 2.0 response."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "descriptions": [{"lang": "en", "value": "A critical vulnerability in FortiOS."}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:fortinet:fortios:7.4.0:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "7.0.0",
                                            "versionEndIncluding": "7.4.2",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762", "source": "nvd"}],
                }
            }
        ]
    }


def _nvd_gateway(handler) -> SourceGateway:
    """The NVD source's gateway with ``handler`` standing in for NVD."""
    return SourceGateway(
        "nvd",
        rate_limit_config={"requests_per_period": 50, "period_seconds": 30},
        throttle_statuses=NVDAdapter.throttle_statuses,
        inner=httpx.MockTransport(handler),
    )


async def test_enrich_from_nvd_success():
    seen: list[httpx.Request] = []

    def nvd(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_make_nvd_response())

    result = await enrich_from_nvd("CVE-2024-21762", _nvd_gateway(nvd), "nvd-key")

    assert seen[0].url.params["cveId"] == "CVE-2024-21762"
    assert seen[0].headers["apiKey"] == "nvd-key"
    assert result is not None
    assert result["cvss_score"] == 9.8
    assert result["severity"] == "CRITICAL"
    assert result["description"] == "A critical vulnerability in FortiOS."
    assert len(result["affected_products"]) == 1
    assert result["affected_products"][0]["vendor"] == "fortinet"
    assert result["affected_products"][0]["product"] == "fortios"
    assert len(result["references"]) == 1
    assert result["references"][0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-21762"


async def test_enrich_from_nvd_not_found():
    result = await enrich_from_nvd("CVE-9999-99999", _nvd_gateway(lambda r: httpx.Response(404)))
    assert result is None


async def test_enrich_from_nvd_403_opens_the_breaker():
    """NVD throttles with 403 as well as 429: the gateway backs off for the
    whole source instead of enrich_from_nvd retrying in a loop."""
    seen: list[httpx.Request] = []

    def nvd(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(403)

    gateway = _nvd_gateway(nvd)
    with pytest.raises(RateLimited):
        await enrich_from_nvd("CVE-2024-21762", gateway)
    with pytest.raises(BreakerOpen):
        await enrich_from_nvd("CVE-2024-21763", gateway)
    assert len(seen) == 1


async def test_enrich_from_nvd_timeout():
    def nvd(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Connection timed out")

    assert await enrich_from_nvd("CVE-2024-21762", _nvd_gateway(nvd)) is None


# --- Risk tier derivation tests ---


def test_risk_tier_kev_is_critical():
    assert compute_risk_tier(is_kev=True, epss_score=0.01, cvss_score=3.0, epss_threshold=0.1) == "critical"


def test_risk_tier_kev_beats_everything():
    # KEV wins even with no other signals
    assert compute_risk_tier(is_kev=True, epss_threshold=0.1) == "critical"


def test_risk_tier_high_epss():
    assert compute_risk_tier(epss_score=0.1, epss_threshold=0.1) == "high"
    assert compute_risk_tier(epss_score=0.95, epss_threshold=0.1) == "high"


def test_risk_tier_epss_below_threshold_not_high():
    assert compute_risk_tier(epss_score=0.09, epss_threshold=0.1) == "low"


def test_risk_tier_configurable_threshold():
    # Raising the threshold demotes a 0.2 EPSS score out of "high"
    assert compute_risk_tier(epss_score=0.2, epss_threshold=0.1) == "high"
    assert compute_risk_tier(epss_score=0.2, epss_threshold=0.5) == "low"


def test_risk_tier_metasploit_is_high():
    assert compute_risk_tier(metasploit_module="exploit/multi/http/thing", epss_threshold=0.1) == "high"


def test_risk_tier_github_poc_is_medium():
    assert compute_risk_tier(github_poc_count=3, epss_threshold=0.1) == "medium"


def test_risk_tier_critical_cvss_is_medium():
    assert compute_risk_tier(cvss_score=9.8, epss_threshold=0.1) == "medium"


def test_risk_tier_high_severity_is_medium():
    assert compute_risk_tier(severity="HIGH", cvss_score=7.5, epss_threshold=0.1) == "medium"


def test_risk_tier_default_low():
    assert compute_risk_tier(epss_threshold=0.1) == "low"
    assert compute_risk_tier(severity="MEDIUM", cvss_score=5.0, epss_threshold=0.1) == "low"


def test_risk_tier_none_values():
    assert (
        compute_risk_tier(
            is_kev=False,
            epss_score=None,
            metasploit_module=None,
            github_poc_count=None,
            cvss_score=None,
            severity=None,
            epss_threshold=0.1,
        )
        == "low"
    )


def test_calculate_cve_priority_is_kev_flag():
    # The first-class is_kev flag forces CRITICAL even when exploit_status is unset
    assert calculate_cve_priority(5.0, 0.01, None, is_kev=True) == "CRITICAL"
    assert calculate_cve_priority(5.0, 0.01, None, is_kev=False) == "LOW"


# --- EPSS CSV parsing tests ---


def test_iter_epss_csv_basic():
    text = (
        "#model_version:v2023.03.01,score_date:2026-07-04\n"
        "cve,epss,percentile\n"
        "CVE-2024-21762,0.96432,0.99871\n"
        "CVE-2019-0001,0.00042,0.05123\n"
    )
    assert list(iter_epss_csv(text)) == [
        ("CVE-2024-21762", 0.96432, 0.99871),
        ("CVE-2019-0001", 0.00042, 0.05123),
    ]


def test_iter_epss_csv_skips_malformed_rows():
    text = "cve,epss,percentile\nCVE-2024-1111,not-a-number,0.5\nNOT-A-CVE,0.5,0.5\nCVE-2024-2222,0.25,0.75\n"
    assert list(iter_epss_csv(text)) == [("CVE-2024-2222", 0.25, 0.75)]


def test_iter_epss_csv_empty():
    assert list(iter_epss_csv("")) == []
    assert list(iter_epss_csv("#comment only\n")) == []
