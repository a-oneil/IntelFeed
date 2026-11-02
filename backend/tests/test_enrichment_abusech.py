"""abuse.ch ThreatFox, URLhaus and MalwareBazaar: export matching, lookups,
the shared Auth-Key, and that nothing is sent without one.

No abuse.ch Auth-Key exists in this environment, so the fixtures in
``tests/fixtures/enrichment/abusech_*`` are built from the official
documentation's example responses and export column layouts (each file says
so), trimmed. Every request goes through a real SourceGateway onto an
``httpx.MockTransport``; nothing reaches abuse.ch.
"""

import importlib
import io
import json
import uuid
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from sqlalchemy import select

from app.core.encryption import encrypt_value
from app.enrichment import pipeline
from app.enrichment import queue as q
from app.enrichment.adapters.abusech import (
    MalwareBazaarAdapter,
    ThreatFoxAdapter,
    URLhausAdapter,
    read_export,
    sync_export,
)
from app.enrichment.console import console, detail
from app.enrichment.gateway import AuthFailed, NeedsKey, SourceGateway
from app.enrichment.manifest import Egress, Key
from app.enrichment.registry import (
    DEFAULT_SOURCES,
    SHARED_KEY_GROUPS,
    SOURCE_REGISTRY,
    get_adapter,
    source_gateway,
)
from app.models.enrichment import EnrichmentSource, EntityContext, EntityRelationClaim
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import MalwareFamily
from app.models.observable import Observable
from app.models.tool import Tool

FIXTURES = Path(__file__).parent / "fixtures" / "enrichment"
THREATFOX_CSV = (FIXTURES / "abusech_threatfox_full.csv").read_text()
URLHAUS_CSV = (FIXTURES / "abusech_urlhaus_full.csv").read_text()
SEARCH_IOC = json.loads((FIXTURES / "abusech_threatfox_search_ioc.json").read_text())
URLHAUS_URL = json.loads((FIXTURES / "abusech_urlhaus_url.json").read_text())
URLHAUS_HOST = json.loads((FIXTURES / "abusech_urlhaus_host.json").read_text())
BAZAAR = json.loads((FIXTURES / "abusech_bazaar_get_info.json").read_text())

ABUSECH = ("threatfox", "urlhaus", "malwarebazaar")
SHA256 = "b325c92fa540edeb89b95dbfd4400c1cb33599c66859a87aead820e568a2ebe7"


def _zipped(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("full.csv", text)
    return buf.getvalue()


def _server(body=None, status: int = 200):
    """A fake abuse.ch: ``body`` is bytes (an export) or a dict (an API answer)."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if status != 200:
            return httpx.Response(status, headers={"Retry-After": "600"}, json={"query_status": "unknown_auth_key"})
        if isinstance(body, bytes):
            return httpx.Response(200, content=body)
        return httpx.Response(200, json=body)

    handler.requests = requests
    return handler


def _gateway(source_type: str, handler, key: str | None) -> SourceGateway:
    return SourceGateway(
        source_type,
        rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        api_key=key,
        shared_key_group="abuse_ch",
        requires_key=True,
        inner=httpx.MockTransport(handler),
    )


def _key() -> str:
    """A fresh key per test: gateway buckets are keyed by it, and tests share Redis."""
    return f"test-{uuid.uuid4().hex}"


async def _claims(db, source_type, entity_id=None) -> list[EntityRelationClaim]:
    query = select(EntityRelationClaim).where(EntityRelationClaim.source_type == source_type)
    if entity_id is not None:
        query = query.where(EntityRelationClaim.entity_id == entity_id)
    return list((await db.execute(query.order_by(EntityRelationClaim.target_key))).scalars())


async def _edges_to(db, observable_id) -> dict[tuple[str, str, str], EntityRelationship]:
    rows = (
        await db.execute(
            select(EntityRelationship).where(
                EntityRelationship.target_type == "observable", EntityRelationship.target_id == observable_id
            )
        )
    ).scalars()
    return {(r.source_type, str(r.source_id), r.relationship_type): r for r in rows}


async def _context(db, entity_id, source_type) -> dict:
    rows = (
        await db.execute(
            select(EntityContext).where(EntityContext.entity_id == entity_id, EntityContext.source_type == source_type)
        )
    ).scalars()
    return {r.key: r.value for r in rows}


@pytest.fixture
async def ledger(db_session):
    """The ledger the fixtures' IOCs land on, and the families IntelFeed tracks."""
    obs = {
        "ip": Observable(kind="ipv4", value="139.180.203.104", status="active"),
        "c2_url": Observable(kind="url", value="http://harold.jetos.com:3606/is-ready", status="active"),
        "sample": Observable(kind="sha256", value=SHA256, status="active", role="exploit"),
        # In the export, but aging: not written.
        "aging": Observable(kind="domain", value="payload-host.example.net", status="aging"),
        "unknown_c2": Observable(kind="ipv4", value="94.103.84.81", status="active"),
        "exe_url": Observable(kind="url", value="http://vektorex.com/source/Z/5016223.exe", status="active"),
        "png_url": Observable(kind="url", value="http://vektorex.com/source/Z/Order%20839.png", status="active"),
        "host": Observable(kind="domain", value="vektorex.com", status="active"),
        "quiet": Observable(kind="domain", value="quiet-host-1234.com", status="active"),
    }
    families = {
        "Cobalt Strike": Tool(name="Cobalt Strike"),
        "Houdini": MalwareFamily(name="Houdini"),
        "Agent Tesla": MalwareFamily(name="Agent Tesla"),
        "AZORult": MalwareFamily(name="AZORult"),
        "Loki": MalwareFamily(name="Loki"),
        "Adwind": MalwareFamily(name="Adwind"),
    }
    db_session.add_all([*obs.values(), *families.values()])
    for source_type in ABUSECH:
        db_session.add(EnrichmentSource(source_type=source_type, display_name=source_type, is_enabled=True))
    await db_session.flush()
    return {"obs": obs, "families": families}


# ── The manifests ────────────────────────────────────────────────────


def test_three_sources_one_key_manual_lookups_not_for_profit():
    assert SHARED_KEY_GROUPS["abuse_ch"] == list(ABUSECH)
    seeds = {s["source_type"]: s for s in DEFAULT_SOURCES}
    for source_type in ABUSECH:
        cls = SOURCE_REGISTRY[source_type]
        assert cls.requires == (Key(),) and cls.shared_key_group == "abuse_ch"
        # A lookup sends the observable to abuse.ch: never on its own.
        assert cls.egress == Egress.SHARES_IOC and cls.default_trigger_mode == "manual"
        assert cls.license.commercial_ok is False
        assert cls.scope == {"status": ("active",)}
        assert seeds[source_type]["default_trigger_mode"] == "manual"
    assert [j.key for j in ThreatFoxAdapter.jobs] == ["threatfox-sync"]
    assert [j.key for j in URLhausAdapter.jobs] == ["urlhaus-sync"]
    assert MalwareBazaarAdapter.jobs == ()


def test_reading_the_exports():
    rows = list(read_export(io.StringIO(THREATFOX_CSV)))
    assert len(rows) == 6
    assert rows[0]["ioc_value"] == "139.180.203.104:443" and rows[0]["malware_printable"] == "Cobalt Strike"
    assert ThreatFoxAdapter.export_keys(rows[0]) == [("ipv4", "139.180.203.104")]
    assert ThreatFoxAdapter.export_keys(rows[3]) == [("sha256", SHA256)]

    rows = list(read_export(io.StringIO(URLHAUS_CSV)))
    assert [r["url_status"] for r in rows] == ["online", "offline", "offline"]
    # A URL speaks for itself and for its host.
    assert URLhausAdapter.export_keys(rows[0]) == [
        ("url", "http://vektorex.com/source/Z/5016223.exe"),
        ("domain", "vektorex.com"),
    ]


# ── ThreatFox export ─────────────────────────────────────────────────


async def test_threatfox_export_matches_active_observables_and_claims_families(db_session, ledger):
    obs, families = ledger["obs"], ledger["families"]
    key, handler = _key(), _server(_zipped(THREATFOX_CSV))
    stats = await sync_export(db_session, _gateway("threatfox", handler, key), key, ThreatFoxAdapter)

    # One download, the key in its path.
    assert len(handler.requests) == 1
    assert handler.requests[0].url.path == f"/v2/files/exports/{key}/full.csv.zip"
    assert stats == {"rows": 6, "matched": 4, "updated": 4, "withdrawn": 0, "stopped": None}

    ip = obs["ip"]
    # The role fills a blank column, from the best-confidence entry; a set one stays.
    assert ip.role == "c2" and obs["c2_url"].role == "c2"
    assert obs["sample"].role == "exploit"
    assert obs["aging"].role is None and await _context(db_session, obs["aging"].id, "threatfox") == {}

    # The connection is the family's, as the matrix stores it.
    edges = await _edges_to(db_session, ip.id)
    cobalt = edges[("tool", str(families["Cobalt Strike"].id), "communicates_with")]
    assert (cobalt.source, cobalt.confidence) == ("enrichment", "probable")
    assert cobalt.description == "ThreatFox: botnet C2, 75% confidence, first seen 2020-12-06"
    houdini = await _edges_to(db_session, obs["c2_url"].id)
    assert ("malware", str(families["Houdini"].id), "communicates_with") in houdini
    tesla = await _edges_to(db_session, obs["sample"].id)
    assert ("malware", str(families["Agent Tesla"].id), "uses") in tesla

    # Sliver isn't tracked: held, not created. "Unknown malware" names no family.
    claims = {c.target_name: c for c in await _claims(db_session, "threatfox", ip.id)}
    assert claims["Sliver"].held_reason == "unknown" and claims["Sliver"].target_id is None
    assert claims["Sliver"].evidence.endswith("(https://example.org/report/sliver)")
    assert (await db_session.execute(select(Tool).where(Tool.name == "Sliver"))).scalar_one_or_none() is None
    assert await _claims(db_session, "threatfox", obs["unknown_c2"].id) == []

    context = await _context(db_session, ip.id, "threatfox")
    assert context["threat_type"] == "botnet C2"
    assert context["confidence"] == 75
    assert context["malware"] == ["Cobalt Strike", "Sliver"]
    assert (context["first_seen"], context["last_seen"]) == ("2020-12-06", "2021-02-01")
    assert context["tags"] == ["c2", "Sliver"]
    assert context["reference"] == {"url": "https://example.org/report/sliver"}
    assert context["link"] == {"url": "https://threatfox.abuse.ch/ioc/12/", "label": "ThreatFox"}

    # The same export again changes nothing.
    before = [(c.target_key, c.target_id) for c in await _claims(db_session, "threatfox")]
    stats = await sync_export(
        db_session, _gateway("threatfox", _server(_zipped(THREATFOX_CSV)), key), key, ThreatFoxAdapter
    )
    assert stats["updated"] == 0
    assert [(c.target_key, c.target_id) for c in await _claims(db_session, "threatfox")] == before


async def test_an_ioc_that_leaves_the_export_is_withdrawn(db_session, ledger):
    obs, families = ledger["obs"], ledger["families"]
    key = _key()
    await sync_export(db_session, _gateway("threatfox", _server(_zipped(THREATFOX_CSV)), key), key, ThreatFoxAdapter)
    assert await _edges_to(db_session, obs["ip"].id)

    fewer = "\n".join(line for line in THREATFOX_CSV.splitlines() if "139.180.203.104" not in line)
    stats = await sync_export(db_session, _gateway("threatfox", _server(_zipped(fewer)), key), key, ThreatFoxAdapter)
    assert stats["withdrawn"] == 1
    assert await _claims(db_session, "threatfox", obs["ip"].id) == []
    assert await _context(db_session, obs["ip"].id, "threatfox") == {}
    assert await _edges_to(db_session, obs["ip"].id) == {}
    # A filled role stays: it is the observable's now. Others keep theirs.
    assert obs["ip"].role == "c2"
    assert ("malware", str(families["Houdini"].id), "communicates_with") in await _edges_to(
        db_session, obs["c2_url"].id
    )


async def test_an_empty_export_withdraws_nothing_and_a_refusal_stops(db_session, ledger):
    key = _key()
    await sync_export(db_session, _gateway("threatfox", _server(_zipped(THREATFOX_CSV)), key), key, ThreatFoxAdapter)
    claims = len(await _claims(db_session, "threatfox"))

    header_only = "\n".join(line for line in THREATFOX_CSV.splitlines() if line.startswith("#"))
    stats = await sync_export(
        db_session, _gateway("threatfox", _server(_zipped(header_only)), key), key, ThreatFoxAdapter
    )
    assert stats["stopped"] == "empty_export" and stats["withdrawn"] == 0
    assert len(await _claims(db_session, "threatfox")) == claims

    stats = await sync_export(db_session, _gateway("threatfox", _server(status=429), key), key, ThreatFoxAdapter)
    assert stats["stopped"] == "rate_limited"
    assert len(await _claims(db_session, "threatfox")) == claims


async def test_an_export_error_never_shows_the_key(db_session, ledger):
    key = _key()
    # A rejected key is the gateway's AuthFailed; any other error status is the export's own.
    with pytest.raises(AuthFailed) as raised:
        await sync_export(db_session, _gateway("urlhaus", _server(status=401), key), key, URLhausAdapter)
    assert "401" in str(raised.value) and key not in str(raised.value)
    key = _key()  # the rejected key is refused before it is sent again
    with pytest.raises(RuntimeError) as raised:
        await sync_export(db_session, _gateway("urlhaus", _server(status=500), key), key, URLhausAdapter)
    assert "500" in str(raised.value) and key not in str(raised.value)


# ── URLhaus export ───────────────────────────────────────────────────


async def test_urlhaus_export_matches_urls_and_their_hosts(db_session, ledger, client, admin_headers):
    obs, families = ledger["obs"], ledger["families"]
    key = _key()
    stats = await sync_export(db_session, _gateway("urlhaus", _server(_zipped(URLHAUS_CSV)), key), key, URLhausAdapter)
    assert stats == {"rows": 3, "matched": 3, "updated": 3, "withdrawn": 0, "stopped": None}

    exe = await _context(db_session, obs["exe_url"].id, "urlhaus")
    assert exe["url_status"] == "online" and exe["threat"] == "malware distribution"
    assert exe["tags"] == ["AZORult", "exe"]
    assert exe["link"] == {"url": "https://urlhaus.abuse.ch/url/121319/", "label": "URLhaus"}
    assert obs["exe_url"].role == "delivery"
    # A tag naming a tracked family is claimed; "exe" names none and is dropped, not held.
    assert ("malware", str(families["AZORult"].id), "uses") in await _edges_to(db_session, obs["exe_url"].id)
    assert [c.target_name for c in await _claims(db_session, "urlhaus", obs["exe_url"].id)] == ["AZORult"]

    host = await _context(db_session, obs["host"].id, "urlhaus")
    assert (host["url_status"], host["urls"], host["online_urls"]) == ("online", 2, 1)
    assert host["tags"] == ["AZORult", "exe", "Loki"]
    assert host["link"]["url"] == "https://urlhaus.abuse.ch/host/vektorex.com/"
    host_edges = await _edges_to(db_session, obs["host"].id)
    assert {s for s, _, _ in host_edges} == {"malware"} and len(host_edges) == 2
    assert obs["host"].role is None  # a host serving malware may be a compromised site

    # Online is a threat flag; offline is history, shown neutral.
    body = (await client.get(f"/api/entities/observable/{obs['exe_url'].id}/context", headers=admin_headers)).json()
    assert {"source_type": "urlhaus", "key": "url_status", "label": "URLhaus · online", "tone": "danger"} in body[
        "badges"
    ]
    body = (await client.get(f"/api/entities/observable/{obs['png_url'].id}/context", headers=admin_headers)).json()
    badge = next(b for b in body["badges"] if b["source_type"] == "urlhaus")
    assert (badge["label"], badge["tone"]) == ("URLhaus · offline", "neutral")


async def test_abusech_context_is_hidden_from_visitors(db_session, ledger, client, monkeypatch):
    from app.config import settings

    key = _key()
    await sync_export(db_session, _gateway("urlhaus", _server(_zipped(URLHAUS_CSV)), key), key, URLhausAdapter)
    monkeypatch.setattr(settings, "public_read_only_enabled", True)
    resp = await client.get(f"/api/entities/observable/{ledger['obs']['exe_url'].id}/context")
    assert "urlhaus" not in resp.text


# ── No key, no request ───────────────────────────────────────────────


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a request left without a key")

    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)


@pytest.fixture
def worker_sessions(db_session, monkeypatch):
    @asynccontextmanager
    async def fake_session():
        yield db_session

    monkeypatch.setattr(importlib.import_module("app.workers.enrichment_tasks"), "_get_worker_session", fake_session)


async def test_without_a_key_nothing_is_sent_and_the_console_says_so(db_session, ledger, worker_sessions, no_network):
    from app.workers import enrichment_tasks

    # The jobs stop before their download.
    assert (await enrichment_tasks._run_threatfox_sync())["stopped"] == "needs_key"
    assert (await enrichment_tasks._run_urlhaus_sync())["stopped"] == "needs_key"

    # A lookup a person asks for is refused at the gateway, and nothing is stored.
    results = await pipeline.enrich_entity(
        "observable",
        ledger["obs"]["ip"].id,
        "139.180.203.104",
        db_session,
        trigger="manual",
        source_types=list(ABUSECH),
    )
    statuses = {r["source_type"]: r["status"] for r in results}
    assert (statuses["threatfox"], statuses["urlhaus"]) == ("needs_key", "needs_key")
    assert await _context(db_session, ledger["obs"]["ip"].id, "threatfox") == {}

    # The gateway and the adapters both refuse on their own.
    row = (
        await db_session.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "malwarebazaar"))
    ).scalar_one()
    with pytest.raises(NeedsKey):
        await source_gateway(row, None).acquire()
    adapter = get_adapter("malwarebazaar", gateway=_gateway("malwarebazaar", _server(BAZAAR), None))
    with pytest.raises(NeedsKey):
        await adapter.enrich("observable", SHA256)
    assert not await adapter.check_health()

    data = await console(db_session)
    sources = {s["source_type"]: s for s in data["sources"]}
    for source_type in ABUSECH:
        assert sources[source_type]["status"] == "needs_key"
        assert sources[source_type]["attention"] == "needs an API key before it can run"
        assert sources[source_type]["key"] == "abuse_ch"
        assert sources[source_type]["key_status"] == "missing"
    # One missing key is one problem, however many sources share it.
    (missing,) = [a for a in data["attention"] if a["action"] and a["action"].get("key") == "abuse_ch"]
    assert missing["label"] == "abuse.ch Auth-Key"
    assert missing["action"] == {"kind": "key", "key": "abuse_ch", "label": "Add key"}
    assert sorted(missing["sources"]) == sorted(sources[t]["label"] for t in ABUSECH)


# ── One key for three ────────────────────────────────────────────────


async def test_one_key_serves_all_three_from_one_bucket(db_session, ledger, worker_sessions, monkeypatch):
    from app.workers import enrichment_tasks

    key = _key()
    rows = {
        r.source_type: r
        for r in (
            await db_session.execute(select(EnrichmentSource).where(EnrichmentSource.source_type.in_(ABUSECH)))
        ).scalars()
    }
    rows["urlhaus"].api_key_encrypted = encrypt_value(key)
    for row in rows.values():
        row.rate_limit_config = {"requests_per_period": 5, "period_seconds": 3600}
    await db_session.flush()

    for source_type in ABUSECH:
        assert await pipeline.resolve_api_key(rows[source_type], None, db_session) == key
    gateways = {st: source_gateway(rows[st], key) for st in ABUSECH}
    assert len({g.scope for g in gateways.values()}) == 1
    assert next(iter(gateways.values())).scope.startswith("abuse_ch:")

    # The ThreatFox job finds the key on its URLhaus sibling and spends from the shared bucket.
    handler = _server(_zipped(THREATFOX_CSV))
    real = source_gateway

    def wired(source, api_key, **kwargs):
        g = real(source, api_key, **kwargs)
        g._inner = httpx.MockTransport(handler)
        return g

    monkeypatch.setattr(pipeline, "source_gateway", wired)
    stats = await enrichment_tasks._run_threatfox_sync()
    assert stats["matched"] == 4 and handler.requests[0].url.path == f"/v2/files/exports/{key}/full.csv.zip"
    assert await gateways["malwarebazaar"].remaining() == 4
    assert await gateways["urlhaus"].used_today() == 1


# ── Lookups (manual only) ────────────────────────────────────────────


async def test_lookups_are_queued_only_when_asked(db_session, ledger):
    obs = ledger["obs"]["ip"]
    for row in (
        await db_session.execute(select(EnrichmentSource).where(EnrichmentSource.source_type.in_(ABUSECH)))
    ).scalars():
        row.trigger_mode = "manual"
    await db_session.flush()
    queued = await q.enqueue(db_session, "observable", obs.id, obs.value, lane="new")
    assert not set(queued) & set(ABUSECH)
    queued = await q.enqueue(db_session, "observable", obs.id, obs.value, lane="manual", source_types=list(ABUSECH))
    assert set(queued) == set(ABUSECH)


async def _lookup(
    db_session, ledger, source_type: str, observable, body, refresh: bool = False
) -> tuple[list[dict], list[httpx.Request]]:
    key = _key()
    row = (
        await db_session.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == source_type))
    ).scalar_one()
    row.api_key_encrypted = encrypt_value(key)
    await db_session.flush()
    handler = _server(body)

    def wired(source, api_key):
        g = source_gateway(source, api_key)
        g._inner = httpx.MockTransport(handler)
        return get_adapter(source.source_type, api_key=api_key, config=source.config, gateway=g)

    with patch.object(pipeline, "adapter_for_source", wired):
        results = await pipeline.enrich_entity(
            "observable",
            observable.id,
            observable.value,
            db_session,
            trigger="manual",
            source_types=[source_type],
            refresh=refresh,
        )
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity

    await apply_enrichment_results_to_entity(db_session, "observable", observable.id, results)
    for request in handler.requests:
        assert request.headers["Auth-Key"] == key
    return results, handler.requests


async def test_threatfox_lookup_searches_an_ip_by_prefix_and_keeps_exact_matches(db_session, ledger):
    ip = ledger["obs"]["ip"]
    (result,), requests = await _lookup(db_session, ledger, "threatfox", ip, SEARCH_IOC)
    assert result["status"] == "success"
    assert json.loads(requests[0].content) == {
        "query": "search_ioc",
        "search_term": "139.180.203.104",
        "exact_match": False,
    }
    # 139.180.203.10:443 came back from the prefix search and is not this IP.
    assert result["parsed_data"]["malware"] == ["Cobalt Strike"]
    assert ip.role == "c2"
    assert ("tool", str(ledger["families"]["Cobalt Strike"].id), "communicates_with") in await _edges_to(
        db_session, ip.id
    )


async def test_urlhaus_lookup_shows_blocklists_and_status(db_session, ledger):
    url = Observable(kind="url", value=URLHAUS_URL["url"], status="active")
    db_session.add(url)
    await db_session.flush()
    (result,), requests = await _lookup(db_session, ledger, "urlhaus", url, URLHAUS_URL)
    assert requests[0].url.path == "/v1/url/" and b"url=http" in requests[0].content
    context = await _context(db_session, url.id, "urlhaus")
    assert context["url_status"] == "online"
    assert context["blacklists"] == {
        "columns": ["List", "Status"],
        "rows": [["Spamhaus DBL", "abused_legit_malware"], ["SURBL", "listed"]],
    }

    host = ledger["obs"]["host"]
    (result,), requests = await _lookup(db_session, ledger, "urlhaus", host, URLHAUS_HOST)
    assert requests[0].url.path == "/v1/host/"
    # The API's count of URLs on the host, not just the ones it returned.
    assert result["parsed_data"]["urls"] == 120


async def test_bazaar_lookup_claims_its_signature_and_shows_the_sample(db_session, ledger):
    sample = Observable(kind="sha256", value=BAZAAR["data"][0]["sha256_hash"], status="active")
    db_session.add(sample)
    await db_session.flush()
    (result,), requests = await _lookup(db_session, ledger, "malwarebazaar", sample, BAZAAR)
    assert b"query=get_info" in requests[0].content
    assert sample.role == "payload"
    assert ("malware", str(ledger["families"]["Adwind"].id), "uses") in await _edges_to(db_session, sample.id)
    context = await _context(db_session, sample.id, "malwarebazaar")
    assert (context["file_type"], context["signature"], context["delivery_method"]) == (
        "jar",
        "Adwind",
        "e-mail attachment",
    )
    assert context["first_seen"] == "2020-02-28" and context["tags"] == ["Adwind", "jar", "qua"]
    assert context["vendor_intel"]["rows"] == [["ReversingLabs", "ByteCode-JAVA.Trojan.Adwind"], ["Triage", "adwind"]]


async def test_an_export_withdraws_only_what_it_wrote(db_session, ledger):
    ip = ledger["obs"]["ip"]
    key = _key()
    fewer = _zipped("\n".join(line for line in THREATFOX_CSV.splitlines() if "139.180.203.104" not in line))

    # A lookup reaches what the export doesn't hold: the export leaves it be.
    await _lookup(db_session, ledger, "threatfox", ip, SEARCH_IOC)
    looked_up = await _context(db_session, ip.id, "threatfox")
    stats = await sync_export(db_session, _gateway("threatfox", _server(fewer), key), key, ThreatFoxAdapter)
    assert stats["withdrawn"] == 0
    assert await _context(db_session, ip.id, "threatfox") == looked_up
    assert await _edges_to(db_session, ip.id)

    # The export answers it, and so owns it: once it leaves, it is withdrawn.
    full = _zipped(THREATFOX_CSV)
    await sync_export(db_session, _gateway("threatfox", _server(full), key), key, ThreatFoxAdapter)
    stats = await sync_export(db_session, _gateway("threatfox", _server(fewer), key), key, ThreatFoxAdapter)
    assert stats["withdrawn"] == 1
    assert await _context(db_session, ip.id, "threatfox") == {}

    # A lookup after an export answer takes it over.
    await sync_export(db_session, _gateway("threatfox", _server(full), key), key, ThreatFoxAdapter)
    await _lookup(db_session, ledger, "threatfox", ip, SEARCH_IOC, refresh=True)
    stats = await sync_export(db_session, _gateway("threatfox", _server(fewer), key), key, ThreatFoxAdapter)
    assert stats["withdrawn"] == 0
    assert await _context(db_session, ip.id, "threatfox") == looked_up


async def test_a_lookup_answer_that_finds_nothing_is_not_found(db_session, ledger):
    quiet = ledger["obs"]["quiet"]
    (result,), _ = await _lookup(db_session, ledger, "threatfox", quiet, {"query_status": "no_result", "data": []})
    assert result["parsed_data"] == {"found": False}


async def test_console_detail_names_the_family_side_of_the_connection(db_session, ledger):
    body = await detail(db_session, "threatfox")
    relations = {o["field"]: o["target"] for o in body["outputs"] if o["kind"] == "relationship"}
    assert relations == {
        "c2_families": "relationship: communicates with malware family or tool",
        "families": "relationship: uses malware family",
    }
