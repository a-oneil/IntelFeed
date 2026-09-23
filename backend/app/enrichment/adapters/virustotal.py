"""VirusTotal v3 adapter — free with API key (4 req/min, 500/day).

Restored from the IOC-v1 era (removed in 22ae889) for the observables ledger:
entity_type is "observable" and the kind is inferred from the value's shape
(hash / IP / domain), since the enrich() contract carries only two strings.
Values arrive refanged/canonical from the ledger.
"""

import re

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData

_HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.IGNORECASE)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class VirusTotalAdapter(EnrichmentAdapter):
    source_type = "virustotal"
    display_name = "VirusTotal v3"
    supported_entity_types = ["observable"]
    requires_api_key = True
    default_trigger_mode = "manual"

    _api_base = "https://www.virustotal.com/api/v3/"

    def _endpoint_for(self, value: str) -> str | None:
        if _HASH_RE.match(value):
            return f"{self._api_base}files/{value}"
        if _IPV4_RE.match(value):
            return f"{self._api_base}ip_addresses/{value}"
        if "://" in value or "/" in value or "@" in value:
            return None  # URLs need VT's id transform; emails/paths have no VT object
        if "." in value:
            return f"{self._api_base}domains/{value}"
        return None

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        if not self.api_key:
            return EnrichmentData(
                raw_response={"error": "API key required"},
                parsed_data={"found": False, "error": "API key required"},
                ttl_hours=1,
            )
        endpoint = self._endpoint_for(entity_value)
        if endpoint is None:
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "VirusTotal covers hashes, IPs and domains"},
                ttl_hours=168,
            )

        headers = {"x-apikey": self.api_key}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(endpoint, headers=headers)
            if resp.status_code == 404:
                return EnrichmentData(raw_response={"status": "not_found"}, parsed_data={"found": False}, ttl_hours=72)
            resp.raise_for_status()
            data = resp.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        total = sum(stats.values()) if stats else 0
        malicious = stats.get("malicious", 0)
        parsed: dict = {
            "found": True,
            "detection_ratio": f"{malicious}/{total}" if total else None,
            "malicious_votes": malicious,
            "reputation": attrs.get("reputation"),
            "tags": ", ".join(attrs.get("tags", [])[:8]) or None,
        }
        if "files/" in endpoint:
            parsed.update(
                {
                    "meaningful_name": attrs.get("meaningful_name"),
                    "type_description": attrs.get("type_description"),
                    "size": attrs.get("size"),
                    "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
                }
            )
        elif "ip_addresses/" in endpoint:
            parsed.update(
                {
                    "country": attrs.get("country"),
                    "as_owner": attrs.get("as_owner"),
                    "asn": attrs.get("asn"),
                    "network": attrs.get("network"),
                }
            )
        else:
            parsed.update(
                {
                    "registrar": attrs.get("registrar"),
                    "creation_date": attrs.get("creation_date"),
                }
            )
        return EnrichmentData(
            raw_response=data, parsed_data={k: v for k, v in parsed.items() if v is not None}, ttl_hours=72
        )

    async def check_health(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self._api_base}ip_addresses/8.8.8.8", headers={"x-apikey": self.api_key})
                return resp.status_code == 200
        except Exception:
            return False
