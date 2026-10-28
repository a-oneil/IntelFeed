"""FIRST EPSS adapter — free, no API key required.

Provides exploitation probability scores for CVEs.
"""

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData


class EPSSAdapter(EnrichmentAdapter):
    source_type = "epss"
    display_name = "FIRST EPSS"
    supported_entity_types = ["cve"]
    requires_api_key = False
    default_trigger_mode = "scheduled"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        """Enrich a single CVE with EPSS score."""
        async with self.http(timeout=10) as client:
            resp = await client.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": entity_value},
            )
            resp.raise_for_status()
            data = resp.json()

        epss_data = data.get("data", [])
        if not epss_data:
            return EnrichmentData(
                raw_response=data,
                parsed_data={"found": False},
                ttl_hours=24,
            )

        entry = epss_data[0]
        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "cve": entry.get("cve"),
                "epss": float(entry.get("epss", 0)),
                "percentile": float(entry.get("percentile", 0)),
                "date": entry.get("date"),
            },
            ttl_hours=24,
        )

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.get(
                    "https://api.first.org/data/v1/epss",
                    params={"cve": "CVE-2021-44228"},
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
