"""GreyNoise Community adapter — free with API key (50 requests/week).

Classifies IPv4 addresses as benign, malicious, or unknown based on internet
scanning behavior. Restored from the IOC-v1 era (removed in 22ae889) for the
observables ledger; non-IP kinds report unsupported rather than erroring.
"""

import re

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class GreyNoiseAdapter(EnrichmentAdapter):
    source_type = "greynoise"
    display_name = "GreyNoise Community"
    supported_entity_types = ["observable"]
    requires_api_key = True
    default_trigger_mode = "manual"

    _api_base = "https://api.greynoise.io/v3/community/"

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        if not _IPV4_RE.match(entity_value):
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "GreyNoise covers IPv4 only"},
                ttl_hours=168,
            )
        headers = {"key": self.api_key} if self.api_key else {}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{self._api_base}{entity_value}", headers=headers)
            if resp.status_code == 404:
                # Not seen scanning the internet — for a suspected C2 that is
                # itself signal (targeted infrastructure, not mass noise).
                return EnrichmentData(
                    raw_response={"status": "not_found"},
                    parsed_data={"found": False, "note": "not seen mass-scanning — targeted, not noise"},
                    ttl_hours=168,
                )
            resp.raise_for_status()
            data = resp.json()

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "classification": data.get("classification", "unknown"),
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "name": data.get("name"),
                "last_seen": data.get("last_seen"),
                "link": data.get("link"),
            },
            ttl_hours=168,
        )

    async def check_health(self) -> bool:
        try:
            headers = {"key": self.api_key} if self.api_key else {}
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self._api_base}8.8.8.8", headers=headers)
                return resp.status_code in (200, 404)
        except Exception:
            return False
