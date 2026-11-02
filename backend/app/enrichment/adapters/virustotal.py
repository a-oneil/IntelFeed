"""VirusTotal v3 adapter — free with API key (4 req/min, 500/day).

Restored from the IOC-v1 era (removed in 22ae889) for the observables ledger:
entity_type is "observable" and the kind is inferred from the value's shape
(hash / IP / domain), since the enrich() contract carries only two strings.
Values arrive refanged/canonical from the ledger.
"""

import re

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, Key, License, Policy, Quota

_HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.IGNORECASE)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

#: parsed_data key → key in Observable.reputation.
_REPUTATION = {
    "detection_ratio": "vt_ratio",
    "malicious_votes": "vt_malicious",
    "threat_label": "vt_threat_label",
    "tags": "vt_tags",
}


class VirusTotalAdapter(EnrichmentAdapter):
    source_type = "virustotal"
    display_name = "VirusTotal v3"
    about = "Antivirus verdicts for a file, URL, domain or IP."
    applies_to = {"observable": ("ipv4", "domain", "md5", "sha1", "sha256")}
    requires = (Key(),)
    # The public API allows 4 lookups a minute and 500 a day
    # (docs.virustotal.com, "Public vs Premium API"). Premium keys are sized
    # per contract, so there is no ceiling.
    quota = Quota(4, 60, daily_budget=500)
    egress = Egress.SHARES_IOC
    # The public API may not be used in commercial products or services.
    license = License("VirusTotal public API terms", attribution="VirusTotal", commercial_ok=False)
    # Context only: the network columns (asn, asn_org, geo_country) are Team
    # Cymru's, so a manual VirusTotal lookup never overwrites them. The
    # reputation summary keeps VT's verdict for the ledger's list rows.
    outputs = (
        *(Column(key, f"observable.reputation.{rep}", Policy.NEWER_WINS) for key, rep in _REPUTATION.items()),
        Context("detection_ratio", "Detections", Display.FACT),
        Context("threat_label", "Threat label", Display.FACT),
        Context("tags", "Tags", Display.CHIPS),
        Context("meaningful_name", "File name", Display.FACT),
        Context("type_description", "File type", Display.FACT),
        Context("asn", "ASN", Display.FACT),
        Context("as_owner", "AS owner", Display.FACT),
        Context("country", "Country", Display.FACT),
        Context("network", "Network", Display.FACT),
        Context("registrar", "Registrar", Display.FACT),
    )

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
        async with self.http(timeout=15) as client:
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
            async with self.http(timeout=5) as client:
                resp = await client.get(f"{self._api_base}ip_addresses/8.8.8.8", headers={"x-apikey": self.api_key})
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
