"""Shodan InternetDB adapter — free, no API key required.

Port/service/CVE/tag data for IPv4 addresses. Restored from the IOC-v1 era
(removed in 22ae889) for the observables ledger; non-IP kinds report
unsupported rather than erroring.
"""

import re

import httpx

from app import entity_types
from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, License, Policy, Quota, Relation

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

#: parsed_data key → key in Observable.reputation.
_REPUTATION = {"ports": "ports", "hostnames": "hostnames", "tags": "shodan_tags", "vulns": "vulns"}


class ShodanAdapter(EnrichmentAdapter):
    source_type = "shodan"
    display_name = "Shodan InternetDB"
    about = "What Shodan's scanners saw on an IP: open ports, software, and tags like vpn or scanner."
    applies_to = {"observable": ("ipv4",)}
    # On its own it only looks up IPs the ledger still holds active; a person
    # can ask about any of them.
    scope = {"status": ("active",)}
    quota = Quota(30, 60, daily_budget=1000)
    # Sends the IP to Shodan. It still runs on its own: the ledger's IPs come
    # from published reporting, and InternetDB only answers from Shodan's own
    # scans. An admin can set it to manual under Settings → Engine → Enrichment.
    egress = Egress.SHARES_IOC
    license = License("InternetDB, free for non-commercial use", attribution="Shodan", commercial_ok=False)
    default_enabled = True
    default_trigger_mode = "auto"
    outputs = (
        *(Column(key, f"observable.reputation.{rep}", Policy.NEWER_WINS) for key, rep in _REPUTATION.items()),
        # A vpn / proxy / tor / scanner tag names dual-use infrastructure. An
        # IP InternetDB no longer knows loses the tag it gave.
        Column("tags", "observable.infra_tag", Policy.RANK, rank=1, filter="infra_tag", clears=True),
        Context("ports", "Open ports", Display.CHIPS),
        Context("hostnames", "Hostnames", Display.CHIPS),
        Context("tags", "Tags", Display.CHIPS),
        Context("cpes", "Software", Display.CHIPS),
        Context("vulns", "Vulnerabilities", Display.CHIPS),
        # The CVEs Shodan matched to the host's software banners: "observable
        # exposes cve". A CVE IntelFeed doesn't track is dropped, not held —
        # an IP lists dozens and tracking one is the analyst's call.
        Relation("cve_ids", "exposes", (entity_types.CVE,), hold=False),
    )

    @staticmethod
    async def apply_record(db, entity_type: str, entity_id, data: EnrichmentData, cache: dict) -> None:
        """A newly scanner-tagged IP is flagged for review (``app/enrichment/review.py``).
        Runs before the field map, so ``reputation`` still holds the earlier tags."""
        from app.enrichment.review import flag_for_review, shodan_says_scanner

        if entity_type == "observable":
            now = shodan_says_scanner((data.parsed_data or {}).get("tags"))
            await flag_for_review(
                db, entity_id, now, lambda obs: shodan_says_scanner((obs.reputation or {}).get("shodan_tags"))
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
                "cve_ids": [v for v in data.get("vulns") or [] if isinstance(v, str)][:50],
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
