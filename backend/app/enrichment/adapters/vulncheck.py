"""VulnCheck KEV adapter — free with Bearer token (1,000 requests/minute).

Checks if a CVE is in VulnCheck's KEV database with exploit references.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData


class VulnCheckAdapter(EnrichmentAdapter):
    source_type = "vulncheck"
    display_name = "VulnCheck KEV"
    supported_entity_types = ["cve"]
    requires_api_key = True
    default_trigger_mode = "scheduled"

    _api_base = "https://api.vulncheck.com/v3/"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        if not self.api_key:
            return EnrichmentData(
                raw_response={"error": "API key required"},
                parsed_data={"found": False, "error": "API key required"},
                ttl_hours=1,
            )

        headers = {"Authorization": f"Bearer {self.api_key}"}

        async with self.http(timeout=10) as client:
            resp = await client.get(
                f"{self._api_base}index/vulncheck-kev",
                headers=headers,
                params={"cve": entity_value},
            )
            resp.raise_for_status()
            data = resp.json()

        entries = data.get("data", [])
        if not entries:
            return EnrichmentData(
                raw_response=data,
                parsed_data={"found": False, "in_kev": False},
                ttl_hours=24,
            )

        entry = entries[0]
        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "cve_id": entry.get("cve_id", entity_value),
                "in_kev": True,
                "date_added": entry.get("date_added"),
                "due_date": entry.get("due_date"),
                "known_ransomware_campaign_use": entry.get("known_ransomware_campaign_use"),
                "exploit_references": entry.get("exploit_references", [])[:10],
                "xdb_references": entry.get("xdb", [])[:10],
            },
            ttl_hours=24,
        )

    async def check_health(self) -> bool:
        if not self.api_key:
            return False
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with self.http(timeout=5) as client:
                resp = await client.get(
                    f"{self._api_base}index/vulncheck-kev",
                    headers=headers,
                    params={"cve": "CVE-2021-44228"},
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
