"""NVD API 2.0 adapter — free (optional API key for higher rate limits).

Provides CVE details, CVSS scores, references, and affected products.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Context, Display, Egress, Job, License, Quota


class NVDAdapter(EnrichmentAdapter):
    source_type = "nvd"
    display_name = "NVD API 2.0"
    applies_to = {"cve": None}
    # NVD allows 50 requests per rolling 30 s with an API key and 5 without
    # (nvd.nist.gov/developers/start-here). The jobs pace themselves to the
    # keyless window when there is no key (nvd_request_pace).
    quota = Quota(50, 30, daily_budget=5000, ceiling_per_period=50)
    egress = Egress.LOW
    key_setting = "nvd_api_key"
    license = License(
        "NVD terms of use", attribution="This product uses the NVD API but is not endorsed or certified by the NVD."
    )
    default_trigger_mode = "auto"
    # NVD answers 403 as well as 429 when a client exceeds its rolling window.
    throttle_statuses = (403, 429, 503)
    jobs = (
        Job(
            "cve-nvd-refresh",
            "app.workers.enrichment_tasks.run_cve_nvd_refresh",
            {"type": "crontab", "minute": "0", "hour": "12"},
            "Re-check NVD for CVSS score changes on existing CVEs",
        ),
        Job(
            "cve-nvd-backfill",
            "app.workers.enrichment_tasks.run_cve_nvd_backfill",
            {"type": "crontab", "minute": "30", "hour": "1"},
            "Backfill NVD data (CVSS, description, affected products, references) for CVEs missing it",
        ),
        Job(
            "reenrich-cve-nvd",
            "app.workers.maintenance.reenrich_cve_nvd",
            {"type": "crontab", "minute": "5", "hour": "3"},
            "Re-fetch NVD data for CVEs missing it (bulk-imported or awaiting NVD analysis)",
            settings_keys=("cve_reenrich_batch_size",),
        ),
    )
    outputs = (
        Context("cvss_vector", "CVSS vector", Display.FACT),
        Context("published", "Published", Display.FACT),
        Context("last_modified", "Last modified", Display.FACT),
        Context("weaknesses", "Weaknesses", Display.CHIPS),
        Context("references", "References", Display.LINK),
    )

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        async with self.http(timeout=15) as client:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": entity_value},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return EnrichmentData(
                raw_response=data,
                parsed_data={"found": False},
                ttl_hours=168,  # 1 week for NVD data
            )

        cve_item = vulnerabilities[0].get("cve", {})
        metrics = cve_item.get("metrics", {})

        # Extract CVSS v3.1 or v3.0 score
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        cvss_v30 = metrics.get("cvssMetricV30", [{}])
        cvss_data = (cvss_v31[0] if cvss_v31 else cvss_v30[0] if cvss_v30 else {}).get("cvssData", {})

        descriptions = cve_item.get("descriptions", [])
        en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

        references = [
            {"url": ref.get("url"), "source": ref.get("source"), "tags": ref.get("tags", [])}
            for ref in cve_item.get("references", [])
        ]

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "cve_id": cve_item.get("id"),
                "description": en_desc,
                "cvss_score": cvss_data.get("baseScore"),
                "cvss_severity": cvss_data.get("baseSeverity"),
                "cvss_vector": cvss_data.get("vectorString"),
                "published": cve_item.get("published"),
                "last_modified": cve_item.get("lastModified"),
                "references": references[:20],
                "weaknesses": [
                    w.get("description", [{}])[0].get("value")
                    for w in cve_item.get("weaknesses", [])
                    if w.get("description")
                ],
            },
            ttl_hours=168,
        )

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": "CVE-2021-44228"},
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
