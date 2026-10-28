"""Shodan InternetDB adapter — free, no API key required.

Port/service/CVE/tag data for IPv4 addresses. Restored from the IOC-v1 era
(removed in 22ae889) for the observables ledger; non-IP kinds report
unsupported rather than erroring.
"""

import re

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class ShodanAdapter(EnrichmentAdapter):
    source_type = "shodan"
    display_name = "Shodan InternetDB"
    supported_entity_types = ["observable"]
    requires_api_key = False
    default_trigger_mode = "auto"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        if not _IPV4_RE.match(entity_value):
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "Shodan InternetDB covers IPv4 only"},
                ttl_hours=168,
            )
        async with self.http(timeout=10) as client:
            resp = await client.get(f"https://internetdb.shodan.io/{entity_value}")
            if resp.status_code == 404:
                return EnrichmentData(raw_response={"status": "not_found"}, parsed_data={"found": False}, ttl_hours=24)
            resp.raise_for_status()
            data = resp.json()

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "ports": ", ".join(str(p) for p in data.get("ports", [])[:16]) or None,
                "hostnames": ", ".join(data.get("hostnames", [])[:6]) or None,
                "tags": ", ".join(data.get("tags", [])[:8]) or None,
                "vulns": ", ".join(data.get("vulns", [])[:10]) or None,
                "cpes": ", ".join(data.get("cpes", [])[:6]) or None,
            },
            ttl_hours=24,
        )

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=5) as client:
                resp = await client.get("https://internetdb.shodan.io/8.8.8.8")
                return resp.status_code in (200, 404)
        except httpx.HTTPError:
            return False
