"""Network context for observables: Team Cymru (IP → ASN over DNS), RDAP
(domain registration), Tranco (domain popularity) and GreyNoise's class.

Recorded answers live in ``tests/fixtures/enrichment/``: ``cymru.json`` maps a
query name to its TXT answers (dig, 2026-10-28; a name it lacks is NXDOMAIN),
``rdap.json`` holds rdap.org's redirect and the registry's record, and
``tranco_sample.csv`` is rows of the 2026-10-27 list as served (CRLF),
``cymru_bulk.txt`` a verbose bulk WHOIS answer (2026-10-30). DNS goes
to a fake resolver, HTTP to ``httpx.MockTransport``, both behind real gateways
(Redis; conftest gives each test its own key prefix).
"""

import importlib.util
import json
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import httpx
import pytest
from sqlalchemy import select, text, update

import app.workers.enrichment_tasks as tasks
from app.enrichment import console, pipeline
from app.enrichment import gateway as gw
from app.enrichment import queue as q
from app.enrichment.adapters import rdap
from app.enrichment.adapters.cymru import CymruAdapter, bulk_query, origin_name, parse_bulk
from app.enrichment.entity_updater import apply_enrichment_results_to_entity
from app.enrichment.gateway import Paused, SourceGateway
from app.enrichment.registry import get_adapter, source_gateway
from app.models.enrichment import EnrichmentJob, EnrichmentResult, EnrichmentSource, EntityContext
from app.models.observable import Observable
from app.services.redis_client import get_redis_bytes
from app.workers.db import SOURCE_DISABLED

FIXTURES = Path(__file__).parent / "fixtures" / "enrichment"
CYMRU = json.loads((FIXTURES / "cymru.json").read_text())
RDAP = json.loads((FIXTURES / "rdap.json").read_text())
TRANCO_CSV = (FIXTURES / "tranco_sample.csv").read_bytes()
CYMRU_BULK = (FIXTURES / "cymru_bulk.txt").read_bytes()


class _Resolver:
    """Answers TXT queries from the recordings; NXDOMAIN for anything else."""

    def __init__(self):
        self.asked: list[str] = []

    async def resolve(self, name, rdtype, lifetime=None):
        assert rdtype == "TXT"
        self.asked.append(name)
        if name not in CYMRU:
            raise dns.resolver.NXDOMAIN
        return [SimpleNamespace(strings=(txt.encode(),)) for txt in CYMRU[name]]


def _gateway(source: str, inner=None) -> SourceGateway:
    return SourceGateway(source, rate_limit_config={"requests_per_period": 100, "period_seconds": 60}, inner=inner)


def _cymru() -> tuple[CymruAdapter, _Resolver]:
    adapter = get_adapter("cymru", gateway=_gateway("cymru"))
    adapter.resolver = _Resolver()
    return adapter, adapter.resolver


@pytest.fixture(autouse=True)
async def _only_our_sources(db_session):
    """Sources other tests left enabled would queue rows of their own."""
    await db_session.execute(update(EnrichmentSource).values(is_enabled=False))
    await db_session.flush()


async def _source(db, source_type: str, **fields) -> EnrichmentSource:
    row = (
        await db.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == source_type))
    ).scalar_one_or_none()
    if row is None:
        row = EnrichmentSource(source_type=source_type, display_name=source_type)
        db.add(row)
    row.is_enabled = True
    row.trigger_mode = "auto"
    row.config = {}
    row.daily_budget = None
    row.min_confidence_threshold = "low"
    row.rate_limit_config = {"requests_per_period": 100, "period_seconds": 60}
    for k, v in fields.items():
        setattr(row, k, v)
    await db.flush()
    return row


async def _obs(db, value: str, kind: str = "ipv4", **fields) -> Observable:
    obs = Observable(kind=kind, value=value, base_confidence=0.8, current_confidence=0.8, **fields)
    db.add(obs)
    await db.flush()
    return obs


async def _context(db, entity_id) -> dict:
    rows = (await db.execute(select(EntityContext).where(EntityContext.entity_id == entity_id))).scalars()
    return {(r.source_type, r.key): r.value for r in rows}


# ── Team Cymru ───────────────────────────────────────────────────────


async def test_cymru_maps_an_ip_to_its_origin_and_as_name():
    adapter, resolver = _cymru()
    data = await adapter.enrich("observable", "71.6.135.131")

    assert resolver.asked == ["131.135.6.71.origin.asn.cymru.com", "AS10439.asn.cymru.com"]
    assert data.parsed_data == {
        "found": True,
        "asn": 10439,
        "prefix": "71.6.128.0/17",
        "country": "US",
        "registry": "ARIN",
        "allocated": "2006-02-01",
        "asn_org": "CARINET - CariNet, Inc., US",
    }


async def test_cymru_asks_ipv6_in_nibble_format():
    adapter, resolver = _cymru()
    data = await adapter.enrich("observable", "2001:4860:4860::8888")

    assert resolver.asked[0] == (
        "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"
    )
    assert (data.parsed_data["asn"], data.parsed_data["prefix"]) == (15169, "2001:4860::/32")
    assert data.parsed_data["asn_org"] == "GOOGLE - Google LLC, US"


async def test_cymru_unannounced_and_non_ip_values():
    adapter, resolver = _cymru()
    data = await adapter.enrich("observable", "240.0.0.1")
    assert data.parsed_data == {"found": False, "note": "not announced in BGP"}
    assert len(resolver.asked) == 1  # no AS-name query without an AS

    data = await adapter.enrich("observable", "evil.example")
    assert data.parsed_data["found"] is False
    assert origin_name("evil.example") is None
    assert len(resolver.asked) == 1


async def test_cymru_takes_a_gateway_permit_for_every_query():
    adapter, resolver = _cymru()
    await adapter.enrich("observable", "71.6.135.131")
    assert await SourceGateway("cymru").used_today() == 2
    assert await adapter.check_health() is True
    assert await SourceGateway("cymru").used_today() == 3

    await (await get_redis_bytes()).set(gw.paused_key(), b"1")
    with pytest.raises(Paused):
        await adapter.enrich("observable", "8.8.8.8")
    assert len(resolver.asked) == 3  # the pause stopped it before the resolver


async def test_a_cymru_lookup_writes_columns_and_context(db_session, monkeypatch):
    await _source(db_session, "cymru")
    monkeypatch.setattr(CymruAdapter, "resolver", _Resolver())
    obs = await _obs(db_session, "71.6.135.131")

    results = await pipeline.enrich_entity(
        "observable", obs.id, obs.value, db_session, trigger="manual", source_types=["cymru"]
    )
    assert [r["status"] for r in results] == ["success"]
    assert await apply_enrichment_results_to_entity(db_session, "observable", obs.id, results)

    assert (obs.asn, obs.asn_org, obs.geo_country) == (10439, "CARINET - CariNet, Inc., US", "US")
    assert obs.reputation is None  # network facts have their own columns
    assert await _context(db_session, obs.id) == {
        ("cymru", "prefix"): "71.6.128.0/17",
        ("cymru", "registry"): "ARIN",
        ("cymru", "allocated"): "2006-02-01",
    }


def test_cymru_bulk_answers_read_like_dns_ones():
    answers = parse_bulk(CYMRU_BULK.decode())
    assert set(answers) == {"71.6.135.131", "8.8.8.8", "240.0.0.1", "2001:4860:4860::8888"}
    # The same values a DNS lookup of the IP gives.
    assert answers["71.6.135.131"] == {
        "found": True,
        "asn": 10439,
        "prefix": "71.6.128.0/17",
        "country": "US",
        "registry": "ARIN",
        "allocated": "2006-02-01",
        "asn_org": "CARINET - CariNet, Inc., US",
    }
    assert answers["240.0.0.1"] == {"found": False, "note": "not announced in BGP"}
    assert answers["2001:4860:4860::8888"]["prefix"] == "2001:4860::/32"
    assert bulk_query(["8.8.8.8", "1.1.1.1"]) == b"begin\nverbose\n8.8.8.8\n1.1.1.1\nend\n"


class _Whois:
    """whois.cymru.com:43: records what was sent, answers the recording."""

    def __init__(self):
        self.sent = b""
        self.connections = 0

    async def open_connection(self, host, port):
        assert (host, port) == ("whois.cymru.com", 43)
        self.connections += 1
        server = self

        class Writer:
            def write(self, data):
                server.sent += data

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

        reader = SimpleNamespace(read=_answer)
        return reader, Writer()


async def _answer():
    return CYMRU_BULK


@pytest.fixture
def whois(monkeypatch, db_session):
    server = _Whois()

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.setattr("app.enrichment.adapters.cymru._connect", server.open_connection)
    monkeypatch.setattr(tasks, "_get_worker_session", session)
    return server


async def test_cymru_bulk_sync_maps_due_active_ips_over_one_connection(db_session, whois):
    await _source(db_session, "cymru")
    carinet = await _obs(db_session, "71.6.135.131")
    v6 = await _obs(db_session, "2001:4860:4860:0::8888", kind="ipv6")  # written longhand
    dark = await _obs(db_session, "240.0.0.1")
    aged = await _obs(db_session, "8.8.4.4", status="aging")
    fresh = await _obs(db_session, "8.8.8.8")
    domain = await _obs(db_session, "cymru-bulk.example", kind="domain")
    db_session.add(
        EnrichmentResult(
            entity_type="observable",
            entity_id=fresh.id,
            source_type="cymru",
            raw_response={},
            parsed_data={"found": True, "asn": 15169},
            status="success",
            enriched_at=datetime.now(UTC),
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        )
    )
    await db_session.flush()

    stats = await tasks._run_cymru_bulk_sync()

    assert whois.connections == 1
    sent = set(whois.sent.decode().splitlines())
    assert {"begin", "verbose", "end", "71.6.135.131", "240.0.0.1", "2001:4860:4860::8888"} == sent
    assert stats == {"due": 3, "fetched": 4, "changed": 3, "written": 2, "unannounced": 1}
    for row in (carinet, v6, dark, aged, domain):
        await db_session.refresh(row)
    assert (carinet.asn, carinet.asn_org, carinet.geo_country) == (10439, "CARINET - CariNet, Inc., US", "US")
    assert v6.asn == 15169
    assert dark.asn is None and aged.asn is None
    assert await _context(db_session, carinet.id) == {
        ("cymru", "prefix"): "71.6.128.0/17",
        ("cymru", "registry"): "ARIN",
        ("cymru", "allocated"): "2006-02-01",
    }
    # One permit for the whole connection.
    assert await SourceGateway("cymru").used_today() == 1

    # Answered: nothing is due on the next run.
    whois.sent = b""
    assert (await tasks._run_cymru_bulk_sync())["due"] == 0
    assert whois.connections == 1


async def test_cymru_bulk_sync_skips_while_disabled_or_paused(db_session, whois, pause_enrichment):
    await _source(db_session, "cymru", is_enabled=False)
    await _obs(db_session, "71.6.135.131")
    assert await tasks._run_cymru_bulk_sync() == SOURCE_DISABLED

    await _source(db_session, "cymru")
    await pause_enrichment()
    stats = await tasks._run_cymru_bulk_sync()
    assert stats["stopped"] == "paused"
    assert whois.connections == 0


async def test_a_32_bit_asn_is_written(db_session):
    # observables.asn is bigint: AS numbers past int4 (4,200,000,000 is a
    # private-use 32-bit ASN) are stored like any other.
    obs = await _obs(db_session, "203.0.113.9")
    parsed = {"found": True, "asn": 4_200_000_000, "asn_org": "Private use", "country": "US"}
    results = [{"source_type": "cymru", "status": "success", "parsed_data": parsed}]
    assert await apply_enrichment_results_to_entity(db_session, "observable", obs.id, results)
    await db_session.flush()
    assert (obs.asn, obs.asn_org, obs.geo_country) == (4_200_000_000, "Private use", "US")


async def test_a_disabled_source_is_neither_queued_nor_looked_up(db_session, monkeypatch):
    await _source(db_session, "cymru", is_enabled=False)
    resolver = _Resolver()
    monkeypatch.setattr(CymruAdapter, "resolver", resolver)
    obs = await _obs(db_session, "71.6.135.131")

    assert await q.enqueue(db_session, "observable", obs.id, obs.value) == []
    assert await pipeline.enrich_entity("observable", obs.id, obs.value, db_session, trigger="manual") == []
    assert resolver.asked == []


# ── RDAP ─────────────────────────────────────────────────────────────


@pytest.fixture
def rdap_server(monkeypatch):
    """rdap.org redirecting to Verisign, from the recordings; a private cache."""
    monkeypatch.setattr(rdap, "CACHE_PREFIX", f"intelfeed:test:{uuid.uuid4().hex}:rdap:")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        url = str(request.url)
        if url == RDAP["redirect"]["url"]:
            return httpx.Response(302, headers={"Location": RDAP["redirect"]["location"]})
        if url == RDAP["domain"]["url"]:
            return httpx.Response(200, json=RDAP["domain"]["body"])
        return httpx.Response(404, json=RDAP["not_found"]["body"])

    return httpx.MockTransport(handler), seen


def test_registrable_domain_uses_icann_suffixes():
    assert rdap.registrable_domain("login.mail.carinet.com") == "carinet.com"
    assert rdap.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    # A private suffix is registered as the platform's own domain.
    assert rdap.registrable_domain("evil.github.io") == "github.io"
    assert rdap.registrable_domain("co.uk") is None


async def test_rdap_follows_the_redirect_and_parses_the_record(rdap_server):
    transport, seen = rdap_server
    adapter = get_adapter("rdap", gateway=_gateway("rdap", transport))
    data = await adapter.enrich("observable", "mail.carinet.com")

    assert [str(r.url) for r in seen] == [RDAP["redirect"]["url"], RDAP["domain"]["url"]]
    assert seen[0].headers["Accept"] == "application/rdap+json"
    assert data.parsed_data == {
        "found": True,
        "domain": "carinet.com",
        "registered": "1996-10-29T05:00:00Z",
        "expires": "2027-10-28T04:00:00Z",
        "updated": "2026-10-13T08:09:17Z",
        "registrar": "Network Solutions, LLC",
        "status": ["client transfer prohibited"],
        "nameservers": ["ns1.sandalsbeta.com", "ns2.sandalsbeta.com"],
    }
    # Both hops took a permit.
    assert await SourceGateway("rdap").used_today() == 2


async def test_rdap_caches_per_registrable_domain(rdap_server):
    transport, seen = rdap_server
    adapter = get_adapter("rdap", gateway=_gateway("rdap", transport))
    first = await adapter.enrich("observable", "mail.carinet.com")
    second = await adapter.enrich("observable", "www.carinet.com")

    assert len(seen) == 2  # the second subdomain cost nothing
    assert second.parsed_data == first.parsed_data
    assert second.raw_response == {"cached": "carinet.com"}


async def test_rdap_without_a_record(rdap_server):
    transport, _ = rdap_server
    adapter = get_adapter("rdap", gateway=_gateway("rdap", transport))
    data = await adapter.enrich("observable", "example.ru")
    assert data.parsed_data == {"found": False, "domain": "example.ru"}

    data = await adapter.enrich("observable", "203.0.113.5/26")
    assert data.parsed_data["found"] is False


async def test_an_rdap_result_writes_the_registration_date(db_session, rdap_server, monkeypatch):
    transport, _ = rdap_server
    row = await _source(db_session, "rdap")
    obs = await _obs(db_session, "mail.carinet.com", kind="domain")

    def wired(source, api_key):
        g = source_gateway(source, api_key)
        g._inner = transport
        return get_adapter(source.source_type, gateway=g)

    monkeypatch.setattr(pipeline, "adapter_for_source", wired)
    results = await pipeline.enrich_entity(
        "observable", obs.id, obs.value, db_session, trigger="manual", source_types=[row.source_type]
    )
    await apply_enrichment_results_to_entity(db_session, "observable", obs.id, results)

    assert obs.registered_at == datetime(1996, 10, 29, 5, tzinfo=UTC)
    context = await _context(db_session, obs.id)
    assert context[("rdap", "registrar")] == "Network Solutions, LLC"
    assert context[("rdap", "expires")] == "2027-10-28T04:00:00Z"
    assert context[("rdap", "nameservers")] == ["ns1.sandalsbeta.com", "ns2.sandalsbeta.com"]
    assert context[("rdap", "domain")] == "carinet.com"


async def test_rdap_looks_up_a_victim_by_its_domain(rdap_server):
    transport, seen = rdap_server
    adapter = get_adapter("rdap", gateway=_gateway("rdap", transport))
    assert adapter.supports_entity("ransomware_victim")

    data = await adapter.enrich("ransomware_victim", "www.carinet.com")
    assert data.parsed_data["registrar"] == "Network Solutions, LLC"

    # A victim known only by name (or a URL) has nothing to look up.
    seen.clear()
    for value in ("Carinet Holdings Ltd.", "https://carinet.com/about", ""):
        data = await adapter.enrich("ransomware_victim", value)
        assert data.parsed_data == {"found": False, "note": "the victim has no domain to look up"}
    assert seen == []


# ── Scope: only active observables are looked up on their own ────────


def test_ip_sources_look_up_active_ips_only_and_run_on_their_own():
    from app.enrichment.registry import SOURCE_REGISTRY

    for source_type in ("shodan", "greynoise", "cymru"):
        cls = SOURCE_REGISTRY[source_type]
        assert cls.scope == {"status": ("active",)}, source_type
        assert (cls.default_enabled, cls.default_trigger_mode) == (True, "auto"), source_type


async def test_aged_ips_are_not_sent_to_shodan_on_its_own(db_session):
    await _source(db_session, "shodan")  # an admin set it to auto
    aged = await _obs(db_session, "198.51.100.21", status="aging")
    active = await _obs(db_session, "198.51.100.22")

    assert await q.enqueue(db_session, "observable", aged.id, aged.value) == []
    assert await q.enqueue(db_session, "observable", active.id, active.value) == ["shodan"]
    assert await q.enqueue(db_session, "observable", aged.id, aged.value, lane="manual", source_types=["shodan"]) == [
        "shodan"
    ]


async def test_new_observables_queue_the_sources_that_take_their_kind(db_session):
    from app.intelligence import observables as obs_mod

    await _source(db_session, "cymru")
    await _source(db_session, "rdap")
    await _source(db_session, "shodan")

    v6 = await obs_mod.get_or_create_observable(db_session, "ipv6", "2001:db8::77", via="ai_extraction")
    domain = await obs_mod.get_or_create_observable(db_session, "domain", "evil-netctx.example", via="manual")
    jobs = (await db_session.execute(select(EnrichmentJob.entity_id, EnrichmentJob.source_type))).all()
    assert set(jobs) == {(v6.id, "cymru"), (domain.id, "rdap")}


async def test_aged_observables_are_not_queued_except_by_a_person(db_session):
    await _source(db_session, "cymru")
    aged = await _obs(db_session, "198.51.100.9", status="aging")

    assert await q.enqueue(db_session, "observable", aged.id, aged.value) == []
    assert await q.enqueue(db_session, "observable", aged.id, aged.value, lane="backfill") == []
    assert await q.enqueue(db_session, "observable", aged.id, aged.value, lane="manual", source_types=["cymru"]) == [
        "cymru"
    ]


async def test_backfill_and_fill_rate_count_only_active_observables(db_session):
    await _source(db_session, "cymru")
    await db_session.execute(text("UPDATE observables SET status = 'expired' WHERE kind IN ('ipv4', 'ipv6')"))
    active = await _obs(db_session, "198.51.100.10")
    await _obs(db_session, "198.51.100.11", status="aging")
    await _obs(db_session, "198.51.100.12", status="expired")
    await _obs(db_session, "198.51.100.13", asn=64500)

    assert await console.backfill(db_session, "cymru", None, None) == 1
    (job,) = (await db_session.execute(select(EnrichmentJob))).scalars()
    assert (job.entity_id, job.lane) == (active.id, "backfill")

    rates = await console.fill_rates(db_session, CymruAdapter)
    assert rates["observable.asn"] == 50.0  # of the two active rows, one has an ASN


# ── Tranco ───────────────────────────────────────────────────────────


LATEST = {"list_id": "GQ3LK", "download": "https://tranco-list.eu/download/GQ3LK/1000000"}


@pytest.fixture
def tranco_upstream(monkeypatch, db_session):
    """Every gateway sends to a fake Tranco serving the sample CSV in 7-byte
    pieces; the job's sessions are the test's session."""
    seen: list[httpx.Request] = []

    async def pieces():
        for i in range(0, len(TRANCO_CSV), 7):
            yield TRANCO_CSV[i : i + 7]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if str(request.url) == tasks.TRANCO_LATEST_URL:
            return httpx.Response(200, json=LATEST)
        if str(request.url) == LATEST["download"]:
            return httpx.Response(200, content=pieces())
        return httpx.Response(404)

    def transport(self):
        return gw._GatewayTransport(self, httpx.MockTransport(handler))

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.setattr(SourceGateway, "transport", transport)
    monkeypatch.setattr(tasks, "_get_worker_session", session)
    return seen


async def test_tranco_ranks_only_our_domains_and_flags_the_top_10k(db_session, tranco_upstream, monkeypatch):
    await _source(db_session, "tranco")
    google = await _obs(db_session, "google.com", kind="domain")
    reviewed = await _obs(db_session, "mencretmesum.store", kind="domain", popularity_rank=9999)
    popular_enough = await _obs(db_session, "physionet.org", kind="domain")
    denied = await _obs(db_session, "pinayflix.uk", kind="domain", is_denied=True)
    gone = await _obs(db_session, "fell-out-netctx.example", kind="domain", popularity_rank=77)
    db_session.add(
        EntityContext(
            entity_type="observable",
            entity_id=gone.id,
            source_type="tranco",
            key="rank",
            value=77,
            observed_at=datetime(2026, 10, 1, tzinfo=UTC),
            expires_at=datetime(2026, 10, 3, tzinfo=UTC),
        )
    )
    ip = await _obs(db_session, "203.0.113.1")
    await db_session.flush()

    # Matched a few rows at a time: the list is never held whole.
    monkeypatch.setattr(tasks, "_TRANCO_CHUNK", 4)
    batches: list[int] = []
    match = tasks._tranco_match

    async def counting_match(db, batch):
        batches.append(len(batch))
        return await match(db, batch)

    monkeypatch.setattr(tasks, "_tranco_match", counting_match)

    stats = await tasks._run_tranco_sync()

    assert batches == [4, 4, 4]
    assert stats == {
        "listed": 12,
        "fetched": 12,
        "matched": 4,
        "ranked": 3,  # the reviewed row's rank didn't move
        "dropped": 1,
        "flagged": 1,
        "victims": 0,
        "changed": 5,  # every answer is new to enrichment_results
        "written": 4,  # the reviewed row's column already held 9999
        "list_id": "GQ3LK",
    }
    for row in (google, reviewed, popular_enough, denied, gone, ip):
        await db_session.refresh(row)
    assert (google.popularity_rank, google.needs_review) == (1, True)
    # Already in the top 10k when an analyst cleared it: not flagged again.
    assert (reviewed.popularity_rank, reviewed.needs_review) == (9999, False)
    assert (popular_enough.popularity_rank, popular_enough.needs_review) == (50000, False)
    assert (denied.popularity_rank, denied.needs_review, denied.is_denied) == (10000, False, True)
    assert gone.popularity_rank is None
    assert ip.popularity_rank is None
    assert await _context(db_session, google.id) == {("tranco", "rank"): 1}
    assert await _context(db_session, gone.id) == {}
    # Both requests went through the gateway.
    assert [str(r.url) for r in tranco_upstream] == [tasks.TRANCO_LATEST_URL, LATEST["download"]]
    assert await SourceGateway("tranco").used_today() == 2


async def test_tranco_skips_while_disabled_or_paused(db_session, tranco_upstream, pause_enrichment):
    await _source(db_session, "tranco", is_enabled=False)
    assert await tasks._run_tranco_sync() == SOURCE_DISABLED

    await _source(db_session, "tranco")
    await pause_enrichment()
    stats = await tasks._run_tranco_sync()
    assert stats["stopped"] == "paused"
    assert tranco_upstream == []


def test_tranco_lines():
    assert tasks.parse_tranco_line("1,google.com\r\n") == (1, "google.com")
    assert tasks.parse_tranco_line("rank,domain") is None
    assert tasks.parse_tranco_line("") is None


# ── GreyNoise ────────────────────────────────────────────────────────


async def test_greynoise_writes_its_class_to_a_column(db_session):
    obs = await _obs(db_session, "71.6.135.131")
    seen = {"source_type": "greynoise", "status": "success"}
    await apply_enrichment_results_to_entity(
        db_session, "observable", obs.id, [{**seen, "parsed_data": {"found": True, "noise_class": "malicious"}}]
    )
    assert obs.noise_class == "malicious"
    assert "gn_classification" not in (obs.reputation or {})

    # Not seen scanning: GreyNoise gives no class, and the earlier one no longer stands.
    await apply_enrichment_results_to_entity(
        db_session, "observable", obs.id, [{**seen, "parsed_data": {"found": False, "noise": False, "riot": False}}]
    )
    assert obs.noise_class is None


# ── Migration ────────────────────────────────────────────────────────


def _migration():
    path = Path(__file__).parents[1] / "alembic" / "versions" / "f7n2e3t4c5x6_observable_network_context.py"
    spec = importlib.util.spec_from_file_location("network_context_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_migration_moves_reputation_keys_into_columns(db_session):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    migration = _migration()

    def run(step):
        def apply(sync_conn):
            with Operations.context(MigrationContext.configure(sync_conn)):
                step()

        return apply

    conn = await db_session.connection()
    # Start from the schema before it (the test schema is built from the models).
    await conn.run_sync(run(migration.downgrade))
    oid = uuid.uuid4()
    reputation = {"asn": 10439, "as_owner": "CARINET", "country": "us", "gn_classification": "benign", "ports": "22"}
    await db_session.execute(
        text(
            "INSERT INTO observables (id, kind, value, base_confidence, current_confidence, article_count, reputation) "
            "VALUES (:id, 'ipv4', '198.51.100.99', 0.8, 0.8, 0, CAST(:rep AS jsonb))"
        ),
        {"id": oid, "rep": json.dumps(reputation)},
    )

    await conn.run_sync(run(migration.upgrade))
    row = (
        await db_session.execute(
            text("SELECT asn, asn_org, geo_country, noise_class, reputation FROM observables WHERE id = :id"),
            {"id": oid},
        )
    ).one()
    assert tuple(row) == (10439, "CARINET", "US", "benign", {"ports": "22"})

    await conn.run_sync(run(migration.downgrade))
    rep = (
        await db_session.execute(text("SELECT reputation FROM observables WHERE id = :id"), {"id": oid})
    ).scalar_one()
    assert rep == {**reputation, "country": "US"}
    await conn.run_sync(run(migration.upgrade))


# ── Team Cymru bulk WHOIS: one connection, one permit ───────────────


async def test_cymru_bulk_lookup_answers_every_ip_over_one_connection(whois):
    adapter = get_adapter("cymru", gateway=_gateway("cymru"))

    answers = await adapter.bulk_lookup(["71.6.135.131", "240.0.0.1"])

    assert answers["71.6.135.131"]["asn"] == 10439 and answers["71.6.135.131"]["prefix"] == "71.6.128.0/17"
    assert answers["240.0.0.1"] == {"found": False, "note": "not announced in BGP"}
    assert whois.connections == 1 and whois.sent == bulk_query(["71.6.135.131", "240.0.0.1"])
    assert await SourceGateway("cymru").used_today() == 1
    # Nothing to ask: no connection.
    assert await adapter.bulk_lookup([]) == {} and whois.connections == 1


async def test_cymru_bulk_lookup_records_a_failed_connection(whois, monkeypatch):
    async def refused(host, port):
        raise ConnectionRefusedError

    monkeypatch.setattr("app.enrichment.adapters.cymru._connect", refused)
    adapter = get_adapter("cymru", gateway=_gateway("cymru"))
    with pytest.raises(OSError):
        await adapter.bulk_lookup(["71.6.135.131"])
    assert await SourceGateway("cymru").used_today() == 1, "the permit was taken and the failure recorded"
