"""Team Cymru IP-to-ASN mapping — free, no key, over DNS.

Two TXT lookups per IP: ``{reversed ip}.origin.asn.cymru.com`` (IPv6:
``origin6`` with the address in nibbles) answers
``"10439 | 71.6.128.0/17 | US | arin | 2006-02-01"`` (origin AS, announced
prefix, country, registry, allocation date), then ``AS10439.asn.cymru.com``
answers ``"10439 | US | arin | 1997-08-05 | CARINET - CariNet, Inc., US"``
for the AS name. Team Cymru asks that individual lookups use DNS and batches
use bulk WHOIS (https://www.team-cymru.com/ip-asn-mapping), so a person's
lookup and a new IP go over DNS, and the ``cymru-bulk-sync`` job maps every
active IP that is due over one WHOIS connection (``bulk_lookup``):
``begin`` / ``verbose`` / one IP a line / ``end`` to whois.cymru.com:43, which
answers ``10439 | 71.6.135.131 | 71.6.128.0/17 | US | arin | 2006-02-01 |
CARINET - CariNet, Inc., US`` per IP.

Neither is HTTP, so each DNS query and each bulk connection takes a permit
from the source's gateway by hand: the rate limit, daily budget, breaker,
pause switch and concurrency cap all apply.
"""

import asyncio
import ipaddress
from contextlib import suppress

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota

#: Seconds one query may take, retries included.
DNS_TIMEOUT = 5.0
BULK_HOST = "whois.cymru.com"
BULK_PORT = 43
#: Seconds one bulk connection may take, the whole answer read.
BULK_TIMEOUT = 300.0

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


async def _connect(host: str, port: int):
    """A TCP connection: (reader, writer)."""
    return await asyncio.open_connection(host, port)


def bulk_query(ips: list[str]) -> bytes:
    return ("begin\nverbose\n" + "".join(f"{ip}\n" for ip in ips) + "end\n").encode()


def parse_bulk(text: str) -> dict[str, dict]:
    """IP → parsed_data, as ``enrich()`` gives it, from a verbose bulk answer.
    The banner and error lines are skipped; an unannounced IP (``NA``) is
    ``found: False``."""
    answers = {}
    for line in text.splitlines():
        fields = _fields(line)
        if len(fields) < 7:
            continue
        asn, ip, prefix, country, registry, allocated, name = fields[:7]
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        if not asn.isdigit():
            answers[ip] = {"found": False, "note": "not announced in BGP"}
            continue
        parsed = {
            "found": True,
            "asn": int(asn),
            "prefix": prefix if prefix not in ("", "NA") else None,
            "country": country if country not in ("", "NA") else None,
            "registry": registry.upper() if registry not in ("", "NA") else None,
            "allocated": allocated or None,
            "asn_org": name if name not in ("", "NA") else None,
        }
        answers[ip] = {k: v for k, v in parsed.items() if v is not None}
    return answers


class CymruAdapter(EnrichmentAdapter):
    source_type = "cymru"
    display_name = "Team Cymru"
    about = "Maps an IP to the network (AS) that announces it and the country it's allocated to."
    applies_to = {"observable": ("ipv4", "ipv6")}
    scope = {"status": ("active",)}
    # Two queries per IP, or one per bulk connection. Team Cymru publishes no
    # figure for DNS, only the ask to use DNS (or bulk) at volume; 60 a minute
    # is ~30 IPs.
    quota = Quota(60, 60, daily_budget=4000)
    egress = Egress.LOW
    # "Does this service cost anything? Free, forever." (team-cymru.com/ip-asn-mapping)
    license = License("Team Cymru IP-to-ASN mapping, free service", attribution="Team Cymru")
    default_enabled = True
    default_trigger_mode = "auto"
    jobs = (
        Job(
            "cymru-bulk-sync",
            "app.workers.enrichment_tasks.run_cymru_bulk_sync",
            {"type": "crontab", "minute": "25", "hour": "*/6"},
            "Map the ledger's active IPs to their AS over one Team Cymru bulk WHOIS connection",
        ),
    )
    outputs = (
        Column("asn", "observable.asn", Policy.NEWER_WINS, filter="asn"),
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
        # permit() holds an in-flight slot for the query, so DNS lookups count
        # toward the source's concurrency cap like its HTTP ones would.
        async with self.gateway.permit(DNS_TIMEOUT + 5) as permit:
            try:
                if self.resolver is None:
                    self.resolver = dns.asyncresolver.Resolver()
                answer = await self.resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                await self.gateway.record(_ANSWERED, permit=permit, release=False)
                return []
            except dns.exception.DNSException:
                await self.gateway.record(None, permit=permit, release=False)
                raise
            await self.gateway.record(_ANSWERED, permit=permit, release=False)
        return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]

    async def bulk_lookup(self, ips: list[str]) -> dict[str, dict]:
        """IP → parsed_data for ``ips`` over one bulk WHOIS connection, under
        one gateway permit. An IP the answer leaves out is left out."""
        if self.gateway is None:
            raise RuntimeError(f"{self.source_type} adapter has no SourceGateway")
        if not ips:
            return {}
        async with self.gateway.permit(BULK_TIMEOUT + 5) as permit:
            try:
                async with asyncio.timeout(BULK_TIMEOUT):
                    reader, writer = await _connect(BULK_HOST, BULK_PORT)
                    try:
                        writer.write(bulk_query(ips))
                        await writer.drain()
                        answer = await reader.read()
                    finally:
                        writer.close()
                        with suppress(OSError):
                            await writer.wait_closed()
            except (OSError, TimeoutError):
                await self.gateway.record(None, permit=permit, release=False)
                raise
            await self.gateway.record(_ANSWERED, permit=permit, release=False)
        return parse_bulk(answer.decode("utf-8", "replace"))

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
