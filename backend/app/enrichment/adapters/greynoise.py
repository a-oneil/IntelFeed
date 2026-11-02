"""GreyNoise Community adapter — free, no API key required.

Classifies IPv4 addresses as benign, malicious, or unknown based on internet
scanning behavior. The Community endpoint answers without a key; a key, when
configured, is sent for its higher allowance. Restored from the IOC-v1 era
(removed in 22ae889) for the observables ledger; non-IP kinds report
unsupported rather than erroring.
"""

import re

import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, License, Policy, Quota

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

#: parsed_data key → key in Observable.reputation.
_REPUTATION = {"noise": "gn_noise", "riot": "gn_riot", "name": "gn_name"}


class GreyNoiseAdapter(EnrichmentAdapter):
    source_type = "greynoise"
    display_name = "GreyNoise Community"
    about = "Whether an IP is mass-scanning the internet, and whether it's a known business service."
    applies_to = {"observable": ("ipv4",)}
    # Sends the IP off the box: on its own it only looks up IPs the ledger
    # still holds active. A person can ask about any of them.
    scope = {"status": ("active",)}
    # GreyNoise publishes no per-minute figure for the Community API; it
    # answers 429 when a caller goes over, and the breaker backs off.
    quota = Quota(10, 3600, daily_budget=100)
    # Sends the IP to GreyNoise; it runs on its own anyway, as Shodan does.
    egress = Egress.SHARES_IOC
    default_enabled = True
    default_trigger_mode = "auto"
    optional_key = True
    license = License("GreyNoise Community terms", attribution="GreyNoise", commercial_ok=False)
    outputs = (
        *(Column(key, f"observable.reputation.{rep}", Policy.NEWER_WINS) for key, rep in _REPUTATION.items()),
        # Only GreyNoise's own classes are stored. An IP it hasn't seen
        # scanning empties the column: an earlier class no longer stands.
        Column("noise_class", "observable.noise_class", Policy.NEWER_WINS, clears=True),
        # RIOT: a known benign business service. Shodan's tags rank first.
        # An IP that leaves RIOT, or that GreyNoise no longer knows, loses it.
        Column("riot", "observable.infra_tag", Policy.RANK, rank=2, filter="benign_service", clears=True),
        Context(
            "noise_class",
            "noise",
            Display.BADGE,
            tones={"malicious": "danger", "benign": "success", "unknown": "neutral"},
        ),
        Context("riot", "Business service (RIOT)", Display.FACT),
        Context("name", "Actor", Display.FACT),
        Context("last_seen", "Last seen scanning", Display.FACT),
        Context("note", "Scanning", Display.FACT),
        Context("link", "GreyNoise", Display.LINK),
    )

    _api_base = "https://api.greynoise.io/v3/community/"

    @staticmethod
    async def apply_record(db, entity_type: str, entity_id, data: EnrichmentData, cache: dict) -> None:
        """An IP newly classed benign noise is flagged for review
        (``app/enrichment/review.py``). Runs before the field map, so
        ``noise_class`` still holds the earlier answer."""
        from app.enrichment.review import flag_for_review, greynoise_says_benign_noise

        if entity_type == "observable":
            now = greynoise_says_benign_noise(data.parsed_data or {})
            await flag_for_review(db, entity_id, now, lambda obs: obs.noise_class == "benign")

    def _headers(self) -> dict:
        return {"key": self.api_key} if self.api_key else {}

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        if not _IPV4_RE.match(entity_value):
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "GreyNoise covers IPv4 only"},
                ttl_hours=168,
            )
        async with self.http(timeout=10) as client:
            resp = await client.get(f"{self._api_base}{entity_value}", headers=self._headers())
            if resp.status_code == 404:
                # Not seen scanning the internet (the body still says
                # noise:false / riot:false) — for a suspected C2 that is itself
                # signal: targeted infrastructure, not mass noise. GreyNoise
                # gives no class for it, so none is stored.
                data = resp.json()
                return EnrichmentData(
                    raw_response=data,
                    parsed_data={
                        "found": False,
                        "noise": data.get("noise", False),
                        "riot": data.get("riot", False),
                        "note": "not seen mass-scanning — targeted, not noise",
                    },
                    ttl_hours=168,
                )
            resp.raise_for_status()
            data = resp.json()

        return EnrichmentData(
            raw_response=data,
            parsed_data={
                "found": True,
                "noise_class": data.get("classification") or "unknown",
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
            async with self.http(timeout=5) as client:
                resp = await client.get(f"{self._api_base}8.8.8.8", headers=self._headers())
                return resp.status_code in (200, 404)
        except httpx.HTTPError:
            return False
