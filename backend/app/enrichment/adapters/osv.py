"""OSV (Open Source Vulnerabilities) adapter — free, no API key.

Provides open source vulnerability data for CVEs with package/ecosystem impact details.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData


class OSVAdapter(EnrichmentAdapter):
    source_type = "osv"
    display_name = "OSV"
    supported_entity_types = ["cve"]
    requires_api_key = False
    default_trigger_mode = "auto"

    _api_base = "https://api.osv.dev/v1/"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        # Query OSV by CVE alias
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{self._api_base}query",
                json={"query": entity_value},
            )

            if resp.status_code == 404:
                return EnrichmentData(
                    raw_response={"status": "not_found"},
                    parsed_data={"found": False},
                    ttl_hours=24,
                )

            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulns", [])
        if not vulns:
            return EnrichmentData(
                raw_response=data,
                parsed_data={"found": False},
                ttl_hours=24,
            )

        # Return data from the first matching vulnerability
        vuln = vulns[0]
        affected = vuln.get("affected", [])

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "osv_id": vuln.get("id"),
                "aliases": vuln.get("aliases", []),
                "summary": vuln.get("summary"),
                "details": (vuln.get("details") or "")[:1000],
                "severity": vuln.get("severity", []),
                "affected": [
                    {
                        "package_name": a.get("package", {}).get("name"),
                        "ecosystem": a.get("package", {}).get("ecosystem"),
                        "versions": a.get("versions", [])[:10],
                    }
                    for a in affected[:10]
                ],
                "references": [{"type": r.get("type"), "url": r.get("url")} for r in vuln.get("references", [])[:10]],
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
                "total_vulns": len(vulns),
            },
            ttl_hours=24,
        )

    async def check_health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    f"{self._api_base}query",
                    json={"query": "CVE-2021-44228"},
                )
                return resp.status_code == 200
        except Exception:
            return False
