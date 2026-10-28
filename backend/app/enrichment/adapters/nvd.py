"""NVD API 2.0 adapter — free (optional API key for higher rate limits).

Provides CVE details, CVSS scores, references, and affected products.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData


class NVDAdapter(EnrichmentAdapter):
    source_type = "nvd"
    display_name = "NVD API 2.0"
    supported_entity_types = ["cve"]
    requires_api_key = False
    default_trigger_mode = "auto"
    # NVD answers 403 as well as 429 when a client exceeds its rolling window.
    throttle_statuses = (403, 429, 503)

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
