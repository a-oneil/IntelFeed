"""Shodan InternetDB adapter — free, no API key required.

Port/service/CVE/tag data for IPv4 addresses. Restored from the IOC-v1 era
(removed in 22ae889) for the observables ledger; non-IP kinds report
unsupported rather than erroring.
"""

import re

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, License, Policy, Quota

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

#: parsed_data key → key in Observable.reputation.
_REPUTATION = {"ports": "ports", "hostnames": "hostnames", "tags": "shodan_tags", "vulns": "vulns"}


class ShodanAdapter(EnrichmentAdapter):
    source_type = "shodan"
    display_name = "Shodan InternetDB"
    applies_to = {"observable": ("ipv4",)}
    quota = Quota(30, 60, daily_budget=1000)
    egress = Egress.SHARES_IOC
    license = License("InternetDB, free for non-commercial use", attribution="Shodan", commercial_ok=False)
    # Keyless and cheap: run automatically for freshly judged IPs. (Existing
    # installs keep their row's trigger_mode — flip it under Settings →
    # Engine → Enrichment.)
    default_trigger_mode = "auto"
    outputs = (
        *(Column(key, f"observable.reputation.{rep}", Policy.NEWER_WINS) for key, rep in _REPUTATION.items()),
        # A vpn / proxy / tor tag names dual-use infrastructure.
        Column("tags", "observable.infra_tag", Policy.RANK, rank=1, filter="infra_tag"),
        Context("ports", "Open ports", Display.CHIPS),
        Context("hostnames", "Hostnames", Display.CHIPS),
        Context("tags", "Tags", Display.CHIPS),
        Context("cpes", "Software", Display.CHIPS),
        Context("vulns", "Vulnerabilities", Display.CHIPS),
    )

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
