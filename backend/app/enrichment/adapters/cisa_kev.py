"""CISA Known Exploited Vulnerabilities (KEV) adapter — free, no API key.

Checks if a CVE is in the CISA KEV catalog.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData


class CISAKEVAdapter(EnrichmentAdapter):
    source_type = "cisa_kev"
    display_name = "CISA KEV"
    supported_entity_types = ["cve"]
    requires_api_key = False
    default_trigger_mode = "scheduled"

    _kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(self._kev_url)
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        match = next((v for v in vulnerabilities if v.get("cveID") == entity_value), None)

        if not match:
            return EnrichmentData(
                raw_response={"total": len(vulnerabilities), "found": False},
                parsed_data={"in_kev": False},
                ttl_hours=24,
            )

        return EnrichmentData(
            raw_response=match,
            parsed_data={
                "in_kev": True,
                "vendor": match.get("vendorProject"),
                "product": match.get("product"),
                "vulnerability_name": match.get("vulnerabilityName"),
                "date_added": match.get("dateAdded"),
                "short_description": match.get("shortDescription"),
                "required_action": match.get("requiredAction"),
                "due_date": match.get("dueDate"),
                "known_ransomware_use": match.get("knownRansomwareCampaignUse"),
            },
            ttl_hours=24,
        )

    async def check_health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.head(self._kev_url)
                return resp.status_code == 200
        except Exception:
            return False
