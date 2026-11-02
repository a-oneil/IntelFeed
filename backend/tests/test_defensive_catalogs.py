"""MITRE CAPEC, CTID control mappings and MITRE D3FEND: catalog jobs that
resolve weaknesses' attack patterns and give techniques their controls and
countermeasures.

Responses are trimmed recordings of the live files (2026-10-28) in
``tests/fixtures/enrichment``, served through a real SourceGateway (its Redis
bucket, budget and breaker) by ``httpx.MockTransport``.
"""

import importlib.util
import io
import json
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select, text

from app.enrichment.capec import CAPEC_CSV_URL, parse_capec_csv, sync_capec, technique_patterns
from app.enrichment.ctid import MAPPING_URLS, parse_mappings, sync_ctid, technique_controls
from app.enrichment.d3fend import countermeasures, read_mappings, sync_d3fend
from app.enrichment.gateway import USER_AGENT, SourceGateway
from app.models.capec import CAPECPattern
from app.models.cwe import CWE
from app.models.enrichment import EnrichmentSource, EntityContext
from app.models.entity_field_claim import EntityFieldClaim
from app.models.mitigation import Mitigation, TTPMitigation
from app.models.ttp import TTP
from app.workers.db import SOURCE_DISABLED

FIXTURES = Path(__file__).parent / "fixtures" / "enrichment"
CAPEC_CSV = (FIXTURES / "capec_1000_sample.csv").read_text()
NIST = json.loads((FIXTURES / "ctid_nist_800_53_sample.json").read_text())
CIS = json.loads((FIXTURES / "ctid_cis_sample.json").read_text())
D3FEND_CSV = (FIXTURES / "d3fend_full_mappings_sample.csv").read_text()
D3FEND_T1059 = json.loads((FIXTURES / "d3fend_t1059.json").read_text())
D3FEND_VERSION = {"version": "1.6.0", "ontology_version": "1.6.0"}


def _gateway(source_type: str, handler, **kwargs) -> SourceGateway:
    return SourceGateway(
        source_type,
        rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        inner=httpx.MockTransport(handler),
        **kwargs,
    )


def _zip(csv_text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("1000.csv", csv_text)
    return buf.getvalue()


class _Upstream:
    """URL → response body; anything else is a 404. ``refuse`` answers 429."""

    def __init__(self, routes: dict[str, bytes | str | dict], refuse: str | None = None):
        self.routes = routes
        self.refuse = refuse
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if url == self.refuse:
            return httpx.Response(429, headers={"Retry-After": "600"})
        body = self.routes.get(url)
        if body is None:
            return httpx.Response(404)
        if isinstance(body, dict):
            return httpx.Response(200, json=body)
        return httpx.Response(200, content=body.encode() if isinstance(body, str) else body)


def _capec(csv_text: str = CAPEC_CSV) -> _Upstream:
    return _Upstream({CAPEC_CSV_URL: _zip(csv_text)})


def _ctid(**kwargs) -> _Upstream:
    return _Upstream({MAPPING_URLS["nist"]: NIST, MAPPING_URLS["cis"]: CIS}, **kwargs)


D3FEND_MAPPINGS_URL = "https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend-full-mappings.csv"


def _d3fend(**kwargs) -> _Upstream:
    return _Upstream(
        {"https://d3fend.mitre.org/api/version.json": D3FEND_VERSION, D3FEND_MAPPINGS_URL: D3FEND_CSV}, **kwargs
    )


async def _source(db, source_type: str, **fields) -> None:
    db.add(
        EnrichmentSource(
            source_type=source_type,
            display_name=source_type,
            is_enabled=fields.pop("is_enabled", True),
            trigger_mode="manual",
            config={},
            rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
            **fields,
        )
    )
    await db.flush()


async def _ttps(db, *technique_ids: str, **fields) -> dict[str, TTP]:
    ttps = {t: TTP(technique_id=t, technique_name=f"Technique {t}", **fields) for t in technique_ids}
    db.add_all(ttps.values())
    await db.flush()
    return ttps


async def _context(db, entity_id, source_type) -> dict:
    rows = (
        await db.execute(
            select(EntityContext).where(EntityContext.entity_id == entity_id, EntityContext.source_type == source_type)
        )
    ).scalars()
    return {r.key: r.value for r in rows}


# ── CAPEC ────────────────────────────────────────────────────────────


def test_capec_rows_from_the_csv():
    patterns = {p["capec_id"]: p for p in parse_capec_csv(CAPEC_CSV)}

    assert set(patterns) == {"CAPEC-1", "CAPEC-66", "CAPEC-112", "CAPEC-248"}
    injection = patterns["CAPEC-248"]
    assert (injection["name"], injection["abstraction"], injection["status"]) == ("Command Injection", "Meta", "Stable")
    assert injection["cwe_ids"] == ["CWE-77"]
    # Only ATT&CK entries become technique ids; OWASP and WASC mappings don't.
    assert injection["technique_ids"] == []
    assert patterns["CAPEC-112"]["technique_ids"] == ["T1110"]
    assert patterns["CAPEC-1"]["technique_ids"] == ["T1574.010"]
    assert patterns["CAPEC-66"]["cwe_ids"] == ["CWE-89", "CWE-1286"]


def test_patterns_by_technique():
    by_technique = technique_patterns(parse_capec_csv(CAPEC_CSV))
    assert by_technique == {
        "T1574.010": [
            {
                "capec_id": "CAPEC-1",
                "name": "Accessing Functionality Not Properly Constrained by ACLs",
                "abstraction": "Standard",
            }
        ],
        "T1110": [{"capec_id": "CAPEC-112", "name": "Brute Force", "abstraction": "Meta"}],
    }


@pytest.fixture
async def capec_world(db_session):
    await _source(db_session, "capec")
    ttps = await _ttps(db_session, "T1110", "T1574.010", "T1059")
    cwe = CWE(cwe_id="CWE-77", name="Command Injection", kind="weakness", capec_ids=["CAPEC-248", "CAPEC-15"])
    db_session.add(cwe)
    await db_session.flush()
    return ttps, cwe


async def test_capec_sync_fills_the_catalog_and_technique_context(db_session, capec_world, client, auth_headers):
    ttps, cwe = capec_world
    upstream = _capec()

    stats = await sync_capec(db_session, _gateway("capec", upstream))

    assert stats == {"patterns": 4, "techniques": 2, "stopped": None}
    assert [str(r.url) for r in upstream.requests] == [CAPEC_CSV_URL]
    assert upstream.requests[0].headers["User-Agent"] == USER_AGENT
    stored = await db_session.get(CAPECPattern, "CAPEC-248")
    assert (stored.name, stored.cwe_ids) == ("Command Injection", ["CWE-77"])

    # The CWE's own CAPEC ids resolve to names; one the catalog lacks keeps a null.
    resp = await client.get("/api/cwes/CWE-77", headers=auth_headers)
    assert resp.json()["capec_patterns"] == [
        {"capec_id": "CAPEC-248", "name": "Command Injection"},
        {"capec_id": "CAPEC-15", "name": None},
    ]

    resp = await client.get(f"/api/entities/ttp/{ttps['T1110'].id}/context", headers=auth_headers)
    (source,) = [s for s in resp.json()["sources"] if s["source_type"] == "capec"]
    assert source["license"]["name"] == "CAPEC terms of use"
    (patterns,) = source["items"]
    assert patterns["display"] == "table"
    assert patterns["value"] == {
        "columns": ["CAPEC", "Pattern", "Abstraction"],
        "rows": [["CAPEC-112", "Brute Force", "Meta"]],
    }
    assert await _context(db_session, ttps["T1059"].id, "capec") == {}


async def test_capec_resync_drops_withdrawn_patterns_and_mappings(db_session, capec_world):
    ttps, _ = capec_world
    await sync_capec(db_session, _gateway("capec", _capec()))
    assert await _context(db_session, ttps["T1110"].id, "capec")

    # A release where CAPEC-112 no longer maps to ATT&CK and CAPEC-66 is gone.
    lines = [
        line.replace("TAXONOMY NAME:ATTACK:ENTRY ID:1110:ENTRY NAME:Brute Force::::", "")
        for line in CAPEC_CSV.splitlines(keepends=True)
        if not line.startswith("66,")
    ]
    stats = await sync_capec(db_session, _gateway("capec", _capec("".join(lines))))

    assert stats["patterns"] == 3
    assert await db_session.get(CAPECPattern, "CAPEC-66") is None
    assert await _context(db_session, ttps["T1110"].id, "capec") == {}
    assert await _context(db_session, ttps["T1574.010"].id, "capec")


async def test_capec_sync_stops_cleanly_on_a_refusal(db_session, capec_world):
    upstream = _capec()
    gateway = _gateway("capec", upstream)
    await gateway._trip("throttle", 600)

    stats = await sync_capec(db_session, gateway)

    assert stats["stopped"] == "breaker_open"
    assert upstream.requests == []
    assert (await db_session.execute(select(func.count()).select_from(CAPECPattern))).scalar_one() == 0


# ── CTID control mappings ────────────────────────────────────────────


def test_controls_by_technique_in_control_order():
    cis = parse_mappings(CIS)
    ids, chips = technique_controls(cis["T1059"])

    assert ids == ["CIS-2.5", "CIS-9.7", "CIS-10.7", "CIS-13.7"]
    assert chips[0] == "CIS-2.5 Allowlist Authorized Software"
    # Non-mappable rows carry no technique and are skipped.
    assert None not in cis and "T1496.002" not in parse_mappings(NIST)


@pytest.fixture
async def ctid_world(db_session):
    await _source(db_session, "ctid")
    ttps = await _ttps(db_session, "T1059", "T1059.001", "T1078", "T1105")
    ttps["T1105"].nist_controls = ["AC-04"]  # from an earlier mapping that has since dropped it
    # A real ATT&CK mitigation and one an extraction invented, both on T1059.
    real = Mitigation(mitre_id="M1038", name="Execution Prevention", cis_controls=["CIS 2.7"], nist_controls=[])
    invented = Mitigation(mitre_id="M9999", name="Script blocking", cis_controls=[], nist_controls=["CM-7"])
    db_session.add_all([real, invented])
    await db_session.flush()
    db_session.add_all(
        [
            TTPMitigation(ttp_id=ttps["T1059"].id, mitigation_id=real.id),
            TTPMitigation(ttp_id=ttps["T1059"].id, mitigation_id=invented.id),
        ]
    )
    await db_session.flush()
    return ttps, real, invented


async def test_ctid_sync_writes_controls_onto_techniques(db_session, ctid_world, client, auth_headers):
    ttps, real, invented = ctid_world
    upstream = _ctid()

    stats = await sync_ctid(db_session, _gateway("ctid", upstream))

    assert stats == {"nist_techniques": 3, "cis_techniques": 3, "updated": 4, "stopped": None}
    assert [str(r.url) for r in upstream.requests] == [MAPPING_URLS["nist"], MAPPING_URLS["cis"]]
    t1059 = ttps["T1059"]
    assert t1059.nist_controls[:5] == ["AC-02", "AC-03", "AC-05", "AC-06", "AC-17"]
    assert len(t1059.nist_controls) == 23  # CM-02 is mapped twice, kept once
    assert t1059.cis_controls == ["CIS-2.5", "CIS-9.7", "CIS-10.7", "CIS-13.7"]
    # Sub-techniques get their own mapping, not their parent's.
    assert ttps["T1059.001"].cis_controls == ["CIS-2.7", "CIS-9.7", "CIS-10.1", "CIS-10.7", "CIS-13.7"]
    # A technique the mappings dropped is cleared.
    assert (ttps["T1105"].nist_controls, ttps["T1105"].cis_controls) == (None, None)

    claims = (
        await db_session.execute(
            select(EntityFieldClaim.field).where(
                EntityFieldClaim.entity_id == t1059.id, EntityFieldClaim.source_ref == "ctid"
            )
        )
    ).scalars()
    assert sorted(claims) == ["cis_controls", "nist_controls"]

    # The mappings don't name ATT&CK mitigations: no mitigation is touched,
    # real M-id or invented.
    await db_session.refresh(real)
    await db_session.refresh(invented)
    assert (real.cis_controls, real.nist_controls) == (["CIS 2.7"], [])
    assert (invented.cis_controls, invented.nist_controls) == ([], ["CM-7"])

    resp = await client.get("/api/ttps/by-technique/T1059", headers=auth_headers)
    assert resp.json()["cis_controls"] == ["CIS-2.5", "CIS-9.7", "CIS-10.7", "CIS-13.7"]
    resp = await client.get(f"/api/entities/ttp/{t1059.id}/context", headers=auth_headers)
    (source,) = [s for s in resp.json()["sources"] if s["source_type"] == "ctid"]
    nist, cis = source["items"]
    assert (nist["label"], nist["display"]) == ("NIST 800-53 rev5", "chips")
    assert "AC-06 Least Privilege" in nist["value"]
    assert cis["value"][-1] == "CIS-13.7 Deploy a Host-Based Intrusion Prevention Solution"


async def test_ctid_sync_writes_nothing_when_a_framework_is_refused(db_session, ctid_world):
    ttps, *_ = ctid_world

    stats = await sync_ctid(db_session, _gateway("ctid", _ctid(refuse=MAPPING_URLS["cis"])))

    assert stats["stopped"] == "rate_limited"
    assert ttps["T1059"].nist_controls is None
    assert ttps["T1105"].nist_controls == ["AC-04"]


# ── D3FEND ───────────────────────────────────────────────────────────

OWN = read_mappings(io.StringIO(D3FEND_CSV))


def test_countermeasures_match_d3fends_own_answer():
    """The table for T1059 holds what D3FEND's API answers for it."""
    api = {
        (b["def_tech_label"]["value"], b["def_tactic_label"]["value"])
        for b in D3FEND_T1059["off_to_def"]["results"]["bindings"]
        if "def_tech_label" in b
    }
    rows = countermeasures("T1059", OWN)

    assert {(r["technique"], r["tactic"]) for r in rows} == api
    assert len(rows) == 15
    # Ordered by D3FEND's tactics, then name.
    assert rows[0] == {"technique": "File Encryption", "tactic": "Harden"}
    assert rows[-1] == {"technique": "Restore File", "tactic": "Restore"}
    # SPARTA's space techniques aren't ATT&CK ids.
    assert all(t.startswith("T") for t in OWN)


def test_countermeasures_follow_the_attack_hierarchy():
    # A sub-technique the file lists nothing for takes its parent's.
    assert countermeasures("T1059.001", OWN) == countermeasures("T1059", OWN)
    # A parent takes its sub-techniques'.
    parent = {r["technique"] for r in countermeasures("T1003", OWN)}
    children = {r["technique"] for t in ("T1003.001", "T1003.005") for r in countermeasures(t, OWN)}
    assert parent == children and parent
    assert countermeasures("T1110", OWN) == []


async def test_d3fend_sync_writes_the_countermeasures_table(db_session, client, auth_headers):
    await _source(db_session, "d3fend")
    ttps = await _ttps(db_session, "T1059", "T1059.001", "T1003", "T1110")
    upstream = _d3fend()

    stats = await sync_d3fend(db_session, _gateway("d3fend", upstream))

    assert stats == {"version": "1.6.0", "mapped": 3, "techniques": 3, "stopped": None}
    assert [str(r.url) for r in upstream.requests] == [
        "https://d3fend.mitre.org/api/version.json",
        D3FEND_MAPPINGS_URL,
    ]
    assert await _context(db_session, ttps["T1110"].id, "d3fend") == {}

    resp = await client.get(f"/api/entities/ttp/{ttps['T1059'].id}/context", headers=auth_headers)
    (source,) = [s for s in resp.json()["sources"] if s["source_type"] == "d3fend"]
    table, link = source["items"]
    assert table["value"]["columns"] == ["Defensive technique", "Tactic"]
    assert len(table["value"]["rows"]) == 15
    assert table["value"]["rows"][0] == ["File Encryption", "Harden"]
    assert link["value"] == {
        "url": "https://d3fend.mitre.org/offensive-technique/attack/T1059/",
        "label": "D3FEND · T1059",
    }


async def test_d3fend_sync_stops_cleanly_on_a_refusal(db_session):
    """A budget of one request covers the version check, not the file."""
    await _source(db_session, "d3fend")
    ttps = await _ttps(db_session, "T1059")
    upstream = _d3fend()

    stats = await sync_d3fend(db_session, _gateway("d3fend", upstream, daily_budget=1))

    assert stats["stopped"] == "budget_exhausted"
    assert len(upstream.requests) == 1
    assert await _context(db_session, ttps["T1059"].id, "d3fend") == {}


# ── Jobs ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("source_type", ["capec", "ctid", "d3fend"])
async def test_a_disabled_source_skips_its_job(db_session, monkeypatch, source_type):
    import app.workers.enrichment_tasks as tasks

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.setattr(tasks, "_get_worker_session", session)
    await _source(db_session, source_type, is_enabled=False)

    assert await getattr(tasks, f"_run_{source_type}_sync")() == SOURCE_DISABLED


async def test_the_job_uses_the_source_row_and_gateway(db_session, monkeypatch):
    import app.workers.enrichment_tasks as tasks
    from app.enrichment import gateway as gw

    @asynccontextmanager
    async def session():
        yield db_session

    upstream = _ctid()
    monkeypatch.setattr(tasks, "_get_worker_session", session)
    monkeypatch.setattr(
        SourceGateway, "transport", lambda self: gw._GatewayTransport(self, httpx.MockTransport(upstream))
    )
    await _source(db_session, "ctid", daily_budget=1)

    stats = await tasks._run_ctid_sync()

    # The row's budget of one request covers the NIST file, not CIS's.
    assert stats["stopped"] == "budget_exhausted"
    assert len(upstream.requests) == 1


# ── Migration ────────────────────────────────────────────────────────


async def test_migration_adds_and_drops_the_catalog_and_control_columns(db_session):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).parent.parent / "alembic" / "versions" / "c4p3d3f5n6d7_capec_and_technique_controls.py"
    spec = importlib.util.spec_from_file_location("defensive_catalogs_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.down_revision == "f7n2e3t4c5x6"

    def run(step):
        def go(sync_conn):
            with Operations.context(MigrationContext.configure(sync_conn)):
                step()

        return go

    async def state() -> tuple[set[str], bool]:
        columns = await db_session.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = 'ttps'")
        )
        table = await db_session.execute(text("SELECT to_regclass('capec_patterns') IS NOT NULL"))
        return {r[0] for r in columns} & {"nist_controls", "cis_controls"}, table.scalar_one()

    connection = await db_session.connection()
    await connection.run_sync(run(migration.downgrade))
    assert await state() == (set(), False)
    await connection.run_sync(run(migration.upgrade))
    assert await state() == ({"nist_controls", "cis_controls"}, True)
