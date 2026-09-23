"""NVD/CVE adapter — polls the NVD API 2.0 for new/updated CVEs."""

import hashlib
import logging
from datetime import UTC, datetime, timedelta

import httpx

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDAdapter(ExtendedAdapter):
    """Fetches CVEs from the NVD API 2.0 with incremental polling."""

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        api_key = config.get("api_key")
        keywords = config.get("keywords", [])
        min_cvss = config.get("min_cvss", 0.0)

        headers = {"User-Agent": "IntelFeed/1.0"}
        if api_key:
            headers["apiKey"] = api_key

        params: dict = {"resultsPerPage": 50}

        # Incremental polling via lastModStartDate/lastModEndDate
        if since:
            params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")
        else:
            # First poll: get CVEs from the last 7 days
            start = datetime.now(UTC) - timedelta(days=7)
            params["lastModStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")

        if keywords:
            params["keywordSearch"] = " ".join(keywords)
            params["keywordExactMatch"] = ""

        meta = ParsedFeedMeta(
            title="NVD CVE Database",
            description="NIST National Vulnerability Database",
            site_url="https://nvd.nist.gov/",
        )

        async with httpx.AsyncClient(timeout=60.0, headers=headers) as client:
            response = await client.get(NVD_API_BASE, params=params)
            if response.status_code != 200:
                logger.warning(f"NVD API returned {response.status_code}")
                return meta, []

            data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        entries = []

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Get CVSS score
            cvss_score = _extract_cvss_score(cve)
            if cvss_score is not None and cvss_score < min_cvss:
                continue

            # Get description
            descriptions = cve.get("descriptions", [])
            desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

            published = None
            pub_str = cve.get("published")
            if pub_str:
                try:
                    published = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            severity = _score_to_severity(cvss_score) if cvss_score else None

            entry = ParsedEntry(
                guid=hashlib.sha256(cve_id.encode()).hexdigest()[:32],
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                title=f"{cve_id}: {desc_en[:120]}..." if len(desc_en) > 120 else f"{cve_id}: {desc_en}",
                content_html=desc_en,
                published_at=published,
                metadata={
                    "source": "nvd",
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "references": [r.get("url") for r in cve.get("references", [])],
                },
            )
            entries.append(entry)

        return meta, entries

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        keywords = config.get("keywords", [])
        return ParsedFeedMeta(
            title="NVD CVE Database",
            description=f"CVEs matching: {', '.join(keywords)}" if keywords else "All CVEs",
            site_url="https://nvd.nist.gov/",
        )


def _extract_cvss_score(cve: dict) -> float | None:
    """Extract the highest CVSS score from a CVE record."""
    metrics = cve.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0, then v2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                return float(score)

    return None


def _score_to_severity(score: float) -> str:
    """Convert CVSS score to severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"
