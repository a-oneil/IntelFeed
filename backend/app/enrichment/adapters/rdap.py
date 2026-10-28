"""RDAP domain registration — free, no key.

Looks up the registrable domain (the ICANN public suffix plus one label, so
``login.evil.co.uk`` asks about ``evil.co.uk``) at ``rdap.org``, which
redirects to the registry's own RDAP server. Subdomains share one answer: it
is cached in Redis per registrable domain for ``CACHE_TTL``, so a second
subdomain costs no request. rdap.org allows 10 requests in 10 seconds per
client (https://about.rdap.org/); registries throttle on their own, so the
source keeps to one request a second, and a lookup takes two (the redirect).
"""

import json
from datetime import timedelta

import httpx
from publicsuffixlist import PublicSuffixList
from redis.exceptions import RedisError

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, License, Policy, Quota
from app.services.redis_client import get_redis

RDAP_URL = "https://rdap.org/domain/"

#: Redis key prefix of the per-registrable-domain cache.
CACHE_PREFIX = "enrichment:rdap:"
CACHE_TTL = timedelta(days=7)

_EVENTS = {"registration": "registered", "expiration": "expires", "last changed": "updated"}

_psl: PublicSuffixList | None = None


def registrable_domain(domain: str) -> str | None:
    """The domain a registry holds a record for; None for a bare suffix.
    ICANN suffixes only: ``evil.github.io`` is registered as ``github.io``."""
    global _psl
    if _psl is None:
        _psl = PublicSuffixList(only_icann=True)
    return _psl.privatesuffix(domain.strip().lower().rstrip("."))


def _vcard_name(entity: dict) -> str | None:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list)):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) > 3 and item[0] == "fn" and isinstance(item[3], str):
            return item[3].strip() or None
    return None


def parse_rdap(domain: str, data: dict) -> dict:
    """A registry's RDAP domain object as parsed_data."""
    parsed: dict = {"found": True, "domain": domain}
    for event in data.get("events") or []:
        key = _EVENTS.get(event.get("eventAction"))
        if key and event.get("eventDate"):
            parsed[key] = event["eventDate"]
    registrar = next(
        (_vcard_name(e) for e in data.get("entities") or [] if "registrar" in (e.get("roles") or [])),
        None,
    )
    if registrar:
        parsed["registrar"] = registrar
    if status := [s for s in data.get("status") or [] if isinstance(s, str)]:
        parsed["status"] = status
    if nameservers := [n["ldhName"].lower() for n in data.get("nameservers") or [] if n.get("ldhName")]:
        parsed["nameservers"] = nameservers
    return parsed


class RDAPAdapter(EnrichmentAdapter):
    source_type = "rdap"
    display_name = "RDAP"
    applies_to = {"observable": ("domain",)}
    scope = {"status": ("active",)}
    quota = Quota(1, 1, daily_budget=2000, ceiling_per_period=1)
    egress = Egress.LOW
    # Registration data is published by each registry under its own terms of
    # service; rdap.org is a free redirector (https://about.rdap.org/).
    license = License("Registry RDAP terms of service", attribution="rdap.org and the domain's registry")
    default_trigger_mode = "auto"
    outputs = (
        Column("registered", "observable.registered_at", Policy.NEWER_WINS, filter="timestamp"),
        Context("domain", "Registered domain", Display.FACT),
        Context("registrar", "Registrar", Display.FACT),
        Context("expires", "Expires", Display.FACT),
        Context("updated", "Last changed", Display.FACT),
        Context("status", "Status", Display.CHIPS),
        Context("nameservers", "Nameservers", Display.CHIPS),
    )

    async def _cached(self, domain: str) -> dict | None:
        try:
            cached = await (await get_redis()).get(CACHE_PREFIX + domain)
        except (RedisError, OSError):
            return None
        return json.loads(cached) if cached else None

    async def _cache(self, domain: str, parsed: dict) -> None:
        try:
            await (await get_redis()).set(CACHE_PREFIX + domain, json.dumps(parsed), ex=CACHE_TTL)
        except (RedisError, OSError):
            pass

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        domain = registrable_domain(entity_value) if "/" not in entity_value and "@" not in entity_value else None
        if domain is None:
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "RDAP looks up registrable domains only"},
                ttl_hours=168,
            )
        if (parsed := await self._cached(domain)) is not None:
            return EnrichmentData(raw_response={"cached": domain}, parsed_data=parsed, ttl_hours=168)

        async with self.http(timeout=15, follow_redirects=True) as client:
            resp = await client.get(RDAP_URL + domain, headers={"Accept": "application/rdap+json"})
            if resp.status_code == 404:
                # Not registered, or a TLD with no RDAP service.
                data = {"status": "not_found"}
                parsed = {"found": False, "domain": domain}
            else:
                resp.raise_for_status()
                data = resp.json()
                parsed = parse_rdap(domain, data)
        await self._cache(domain, parsed)
        return EnrichmentData(raw_response=data, parsed_data=parsed, ttl_hours=168)

    async def check_health(self) -> bool:
        try:
            async with self.http(timeout=10, follow_redirects=True) as client:
                resp = await client.get(RDAP_URL + "example.com", headers={"Accept": "application/rdap+json"})
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
