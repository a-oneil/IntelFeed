"""Team Cymru IP-to-ASN mapping — free, no key, over DNS.

Two TXT lookups per IP: ``{reversed ip}.origin.asn.cymru.com`` (IPv6:
``origin6`` with the address in nibbles) answers
``"10439 | 71.6.128.0/17 | US | arin | 2006-02-01"`` (origin AS, announced
prefix, country, registry, allocation date), then ``AS10439.asn.cymru.com``
answers ``"10439 | US | arin | 1997-08-05 | CARINET - CariNet, Inc., US"``
for the AS name. Team Cymru asks that individual lookups use DNS rather than
WHOIS (https://www.team-cymru.com/ip-asn-mapping). The bulk WHOIS interface
suits batches of thousands; this source looks up one new IP at a time.

DNS isn't HTTP, so each query takes a permit from the source's gateway by
hand: the rate limit, daily budget, breaker and pause switch all apply.
"""

import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, License, Policy, Quota

#: Seconds one query may take, retries included.
DNS_TIMEOUT = 5.0

#: What the gateway is told when the resolver answered: the source is up.
_ANSWERED = httpx.Response(200)


def origin_name(ip: str) -> str | None:
    """The origin zone name for an IP, or None when the value isn't one."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    reversed_ip = address.reverse_pointer.rsplit(".", 2)[0]
    zone = "origin6" if address.version == 6 else "origin"
    return f"{reversed_ip}.{zone}.asn.cymru.com"


def _fields(txt: str) -> list[str]:
    return [f.strip() for f in txt.split("|")]


def parse_origin(records: list[str]) -> dict | None:
    """The most specific announcement among the origin answers. An IP
    announced by several ASes lists them space-separated; the first is kept."""
    best = None
    for txt in records:
        fields = _fields(txt)
        asns = fields[0].split()
        if len(fields) < 5 or not asns or not asns[0].isdigit():
            continue
        prefix = fields[1]
        bits = prefix.partition("/")[2]
        length = int(bits) if bits.isdigit() else -1
        if best is None or length > best[0]:
            best = (
                length,
                {
                    "asn": int(asns[0]),
                    "prefix": prefix or None,
                    "country": fields[2] or None,
                    "registry": fields[3].upper() or None,
                    "allocated": fields[4] or None,
                },
            )
    return best[1] if best else None


def parse_as_name(records: list[str]) -> str | None:
    for txt in records:
        fields = _fields(txt)
        if len(fields) >= 5 and fields[4]:
            return fields[4]
    return None


class CymruAdapter(EnrichmentAdapter):
    source_type = "cymru"
    display_name = "Team Cymru"
    applies_to = {"observable": ("ipv4", "ipv6")}
    scope = {"status": ("active",)}
    # Two queries per IP. Team Cymru publishes no figure for DNS, only the ask
    # to use DNS (or bulk) at volume; 60 a minute is ~30 IPs.
    quota = Quota(60, 60, daily_budget=4000)
    egress = Egress.LOW
    # "Does this service cost anything? Free, forever." (team-cymru.com/ip-asn-mapping)
    license = License("Team Cymru IP-to-ASN mapping, free service", attribution="Team Cymru")
    default_trigger_mode = "auto"
    outputs = (
        Column("asn", "observable.asn", Policy.NEWER_WINS),
        Column("asn_org", "observable.asn_org", Policy.NEWER_WINS),
        Column("country", "observable.geo_country", Policy.NEWER_WINS, filter="country_code"),
        Context("prefix", "Announced prefix", Display.FACT),
        Context("registry", "Registry", Display.FACT),
        Context("allocated", "Allocated", Display.FACT),
    )

    #: The DNS resolver; built from the host's resolver config on first use.
    resolver: dns.asyncresolver.Resolver | None = None

    async def _txt(self, name: str) -> list[str]:
        """TXT answers for ``name`` under a gateway permit; [] when the name
        doesn't exist (an unannounced IP)."""
        if self.gateway is None:
            raise RuntimeError(f"{self.source_type} adapter has no SourceGateway")
        await self.gateway.acquire()
        try:
            if self.resolver is None:
                self.resolver = dns.asyncresolver.Resolver()
            answer = await self.resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            await self.gateway.record(_ANSWERED)
            return []
        except dns.exception.DNSException:
            await self.gateway.record(None)
            raise
        await self.gateway.record(_ANSWERED)
        return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        name = origin_name(entity_value)
        if name is None:
            return EnrichmentData(
                raw_response={"status": "unsupported_kind"},
                parsed_data={"found": False, "note": "Team Cymru maps IP addresses only"},
                ttl_hours=168,
            )
        origin_txt = await self._txt(name)
        origin = parse_origin(origin_txt)
        if origin is None:
            return EnrichmentData(
                raw_response={"origin": origin_txt},
                parsed_data={"found": False, "note": "not announced in BGP"},
                ttl_hours=24,
            )
        as_txt = await self._txt(f"AS{origin['asn']}.asn.cymru.com")
        parsed = {"found": True, **origin, "asn_org": parse_as_name(as_txt)}
        return EnrichmentData(
            raw_response={"origin": origin_txt, "as": as_txt},
            parsed_data={k: v for k, v in parsed.items() if v is not None},
            ttl_hours=168,
        )

    async def check_health(self) -> bool:
        try:
            return bool(await self._txt(origin_name("8.8.8.8")))
        except dns.exception.DNSException:
            return False
