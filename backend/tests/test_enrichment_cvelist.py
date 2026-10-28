"""cvelistV5 + CISA-ADP: parsing real records into columns and context, the
score's rank against NVD, SSVC, and the two jobs (per-record backfill, delta
zips) through the source's gateway.

The records in ``fixtures/enrichment/cvelist.json`` are trimmed live ones:
CVE-2024-3400 (CNA CVSS + CISA-ADP SSVC + KEV), CVE-2024-41713 (no CNA
metrics; CISA-ADP scored it) and CVE-2025-12534 (rejected), plus a trimmed
listing of the repository's releases.
"""

import importlib.util
import io
import json
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text

import app.workers.enrichment_tasks as tasks
from app.enrichment import gateway as gw
from app.enrichment.adapters.cvelist import CVEListAdapter, parse_record, record_result, record_url
from app.enrichment.entity_updater import apply_enrichment_results_to_entity
from app.enrichment.gateway import USER_AGENT, SourceGateway
from app.enrichment.registry import SOURCE_REGISTRY
from app.models.cve import CVE
from app.models.cwe import CWE, CVEWeakness
from app.models.enrichment import EnrichmentResult, EnrichmentSource, EntityContext

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "enrichment" / "cvelist.json").read_text())
PAN_OS = FIXTURE["cna_and_cisa_adp"]["body"]
MITEL = FIXTURE["adp_cvss_only"]["body"]
REJECTED = FIXTURE["rejected"]["body"]
RELEASES = FIXTURE["releases"]["body"]


class _Upstream:
    """Answers by URL fragment, first match wins; records every request."""

    def __init__(self):
        self.routes: list[tuple[str, list]] = []
        self.requests: list[httpx.Request] = []

    def route(self, fragment: str, *replies) -> None:
        self.routes.append((fragment, list(replies)))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for fragment, replies in self.routes:
            if fragment in str(request.url):
                return (replies.pop(0) if len(replies) > 1 else replies[0])()
        return httpx.Response(404)


@pytest.fixture
def upstream(monkeypatch):
    server = _Upstream()

    def transport(self):
        return gw._GatewayTransport(self, self._inner or httpx.MockTransport(server))

    monkeypatch.setattr(SourceGateway, "transport", transport)
    return server


@pytest.fixture
def worker_session(db_session, monkeypatch):
    @asynccontextmanager
    async def fake_session():
        yield db_session

    monkeypatch.setattr(tasks, "_get_worker_session", fake_session)


def _record(body) -> callable:
    return lambda: httpx.Response(200, json=body)


def _status(status: int) -> callable:
    return lambda: httpx.Response(status)


async def _source_row(db_session, **fields) -> EnrichmentSource:
    cls = SOURCE_REGISTRY["cvelist"]
    defaults = {
        "rate_limit_config": {"requests_per_period": 100, "period_seconds": 60},
        "daily_budget": cls.quota.daily_budget,
    }
    row = EnrichmentSource(
        source_type="cvelist",
        display_name=cls.display_name,
        is_enabled=True,
        trigger_mode="manual",
        **{**defaults, **fields},
    )
    db_session.add(row)
    await db_session.flush()
    return row


def _result(parsed: dict, source_type: str = "cvelist") -> dict:
    return {"source_type": source_type, "status": "success", "parsed_data": parsed}


async def _context(db, cve_pk) -> dict:
    rows = (
        await db.execute(
            select(EntityContext).where(EntityContext.entity_id == cve_pk, EntityContext.source_type == "cvelist")
        )
    ).scalars()
    return {r.key: r.value for r in rows}


# ── Parsing ──────────────────────────────────────────────────────────


def test_record_urls_follow_the_repository_layout():
    base = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
    assert record_url("CVE-2024-3400") == f"{base}/2024/3xxx/CVE-2024-3400.json"
    assert record_url("CVE-2024-41713") == f"{base}/2024/41xxx/CVE-2024-41713.json"
    assert record_url("CVE-2026-103995") == f"{base}/2026/103xxx/CVE-2026-103995.json"
    assert record_url("CVE-2024-XXXX") is None


def test_a_record_with_cna_and_cisa_adp_containers():
    parsed = parse_record(PAN_OS)

    assert parsed["state"] == "PUBLISHED" and parsed["assigner"] == "palo_alto"
    assert parsed["description"].startswith("A command injection as a result of arbitrary file creation")
    assert parsed["cna_cvss"] == {
        "score": 10.0,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "version": "3.1",
    }
    assert parsed["adp_cvss"] is None
    assert parsed["cvss_scored_by"] == "palo_alto · CVSS 3.1"
    assert (parsed["ssvc_exploitation"], parsed["ssvc_automatable"], parsed["ssvc_technical_impact"]) == (
        "active",
        "yes",
        "total",
    )
    assert parsed["ssvc_timestamp"] == "2024-04-17T04:00:13.543064Z"
    assert parsed["weaknesses"] == ["CWE-77", "CWE-20"]
    assert parsed["capec"] == ["CAPEC-248"]
    # Only the affected ranges, not the CNA's list of unaffected versions.
    assert parsed["affected"][0] == {
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "version": "10.2.0",
        "fixed": "10.2.9-h1",
    }
    assert all(row["product"] == "PAN-OS" for row in parsed["affected"])
    assert parsed["solutions"].startswith("We strongly advise customers")
    assert parsed["workarounds"].startswith("Recommended Mitigation")
    assert parsed["references"][0]["url"] == "https://security.paloaltonetworks.com/CVE-2024-3400"
    assert parsed["adp_cpes"][0].startswith("cpe:2.3:o:paloaltonetworks:pan-os:")


def test_cisa_scores_a_cve_its_cna_left_unscored():
    parsed = parse_record(MITEL)

    assert parsed["cna_cvss"] is None
    assert parsed["adp_cvss"]["score"] == 9.1
    assert parsed["cvss_severity"] == "CRITICAL"
    assert parsed["cvss_scored_by"] == "CISA-ADP · CVSS 3.1"
    # MITRE writes "n/a" for vendor, product and version: no row says nothing.
    assert parsed["affected"] == []


def test_a_rejected_record_carries_only_its_state():
    parsed = parse_record(REJECTED)

    assert parsed == {
        "found": True,
        "cve_id": "CVE-2025-12534",
        "state": "REJECTED",
        "assigner": "GitLab",
        "published": None,
        "updated": "2026-10-27T22:18:54.557Z",
        "rejected_reason": "This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.",
    }


def test_a_stored_result_keeps_only_the_records_metadata():
    data = record_result(PAN_OS)
    assert data.raw_response == {"cveMetadata": PAN_OS["cveMetadata"]}
    assert data.ttl_hours == 90 * 24


async def test_a_lookup_fetches_the_raw_record_and_a_404_is_not_found(upstream):
    upstream.route("CVE-2024-3400.json", _record(PAN_OS))
    adapter = CVEListAdapter(gateway=SourceGateway("cvelist"))

    data = await adapter.enrich("cve", "CVE-2024-3400")
    assert data.parsed_data["ssvc_exploitation"] == "active"
    assert str(upstream.requests[0].url) == FIXTURE["cna_and_cisa_adp"]["url"]
    assert upstream.requests[0].headers["User-Agent"] == USER_AGENT

    missing = await adapter.enrich("cve", "CVE-2024-3401")
    assert missing.parsed_data == {"found": False} and missing.ttl_hours == 30 * 24

    # A malformed id never leaves the box.
    sent = len(upstream.requests)
    assert (await adapter.enrich("cve", "CVE-2024-XXXXX")).parsed_data == {"found": False}
    assert len(upstream.requests) == sent


# ── Columns: rank against NVD, severity, SSVC ────────────────────────


async def test_nvd_outranks_the_cna_and_the_severity_goes_with_the_score(db_session):
    cve = CVE(cve_id="CVE-2024-3400", severity="UNKNOWN")
    db_session.add(cve)
    await db_session.flush()
    nvd = {"cvss_score": 9.8, "cvss_severity": "CRITICAL", "description": "NVD's text."}

    await apply_enrichment_results_to_entity(
        db_session, "cve", cve.id, [_result(parse_record(PAN_OS)), _result(nvd, "nvd")]
    )

    assert float(cve.cvss_score) == 9.8
    # Extraction's UNKNOWN isn't blank, so NVD's severity can't fill it; the
    # CNA's severity follows only a score the CNA wrote.
    assert cve.severity == "UNKNOWN"


async def test_the_cna_score_fills_a_blank_cve_with_its_severity(db_session):
    cve = CVE(cve_id="CVE-2024-3400", severity="UNKNOWN")
    db_session.add(cve)
    await db_session.flush()

    assert await apply_enrichment_results_to_entity(db_session, "cve", cve.id, [_result(parse_record(PAN_OS))])

    assert (float(cve.cvss_score), cve.severity) == (10.0, "CRITICAL")
    assert cve.description.startswith("A command injection")
    assert (cve.ssvc_exploitation, cve.ssvc_automatable, cve.ssvc_technical_impact) == ("active", "yes", "total")


async def test_cisas_score_fills_only_what_nvd_and_the_cna_left(db_session):
    scored = CVE(cve_id="CVE-2024-41713", cvss_score=Decimal("7.5"), severity="HIGH")
    blank = CVE(cve_id="CVE-2024-41714")
    db_session.add_all([scored, blank])
    await db_session.flush()

    await apply_enrichment_results_to_entity(db_session, "cve", scored.id, [_result(parse_record(MITEL))])
    await apply_enrichment_results_to_entity(db_session, "cve", blank.id, [_result(parse_record(MITEL))])

    assert (float(scored.cvss_score), scored.severity) == (7.5, "HIGH")
    assert (float(blank.cvss_score), blank.severity) == (9.1, "CRITICAL")


async def test_a_newer_ssvc_assessment_replaces_the_old_one(db_session):
    cve = CVE(cve_id="CVE-2024-3400", ssvc_exploitation="poc", ssvc_automatable="no")
    db_session.add(cve)
    await db_session.flush()

    await apply_enrichment_results_to_entity(db_session, "cve", cve.id, [_result(parse_record(PAN_OS))])

    assert (cve.ssvc_exploitation, cve.ssvc_automatable) == ("active", "yes")


async def test_a_rejected_record_writes_no_column(db_session):
    cve = CVE(cve_id="CVE-2025-12534")
    db_session.add(cve)
    await db_session.flush()

    assert not await apply_enrichment_results_to_entity(db_session, "cve", cve.id, [_result(parse_record(REJECTED))])
    assert cve.description is None


# ── A record applied by the jobs: context, badge, CWE links ──────────


async def test_an_applied_record_stores_context_badges_and_cwe_links(client, auth_headers, db_session):
    cve = CVE(cve_id="CVE-2024-3400")
    cwe = CWE(cwe_id="CWE-77", name="Command Injection")
    db_session.add_all([cve, cwe])
    await db_session.flush()
    await _source_row(db_session)

    changed = await tasks._apply_cvelist_record(db_session, cve.id, record_result(PAN_OS), {"CWE-77": cwe.id})
    await db_session.flush()

    assert changed
    stored = await _context(db_session, cve.id)
    assert stored["assigner"] == "palo_alto"
    assert stored["capec"] == ["CAPEC-248"]
    assert stored["affected"]["columns"] == ["Vendor", "Product", "From", "Fixed in"]
    assert stored["affected"]["rows"][0] == ["Palo Alto Networks", "PAN-OS", "10.2.0", "10.2.9-h1"]
    links = {
        w.cwe_ref: w
        for w in (await db_session.execute(select(CVEWeakness).where(CVEWeakness.cve_id == cve.id))).scalars()
    }
    assert set(links) == {"CWE-77", "CWE-20"}
    assert links["CWE-77"].cwe_id_fk == cwe.id and links["CWE-20"].cwe_id_fk is None
    assert {w.source for w in links.values()} == {"cvelist"}
    assert links["CWE-77"].assigner == "palo_alto"

    body = (await client.get(f"/api/entities/cve/{cve.id}/context", headers=auth_headers)).json()
    assert {
        "source_type": "cvelist",
        "key": "ssvc_exploitation",
        "label": "SSVC exploitation · active",
        "tone": "critical",
        "field": "ssvc_exploitation",
    } in body["badges"]
    (source,) = [s for s in body["sources"] if s["source_type"] == "cvelist"]
    assert source["license"]["name"] == "CVE Program terms of use"


@pytest.mark.parametrize(
    ("key", "value", "tone"),
    [
        ("ssvc_exploitation", "active", "critical"),
        ("ssvc_exploitation", "poc", "medium"),
        ("ssvc_exploitation", "none", "neutral"),
        ("state", "REJECTED", "warning"),
        ("state", "PUBLISHED", None),
    ],
)
def test_badge_tones(key, value, tone):
    from app.enrichment.context import _badge, contexts_for

    (context,) = [c for c in contexts_for(CVEListAdapter, "cve") if c.key == key]
    badge = _badge(CVEListAdapter, context, value, "cve")
    assert (badge or {}).get("tone") == tone


async def test_an_unchanged_record_keeps_one_result_row(db_session):
    cve = CVE(cve_id="CVE-2024-3400")
    db_session.add(cve)
    await db_session.flush()

    for _ in range(2):
        await tasks._apply_cvelist_record(db_session, cve.id, record_result(PAN_OS), {})
        await db_session.flush()

    rows = (
        (await db_session.execute(select(EnrichmentResult).where(EnrichmentResult.entity_id == cve.id))).scalars().all()
    )
    assert len(rows) == 1


# ── Backfill: one record per unchecked CVE ───────────────────────────


async def test_backfill_fetches_unchecked_cves_only(db_session, worker_session, upstream):
    await _source_row(db_session)
    unchecked = CVE(cve_id="CVE-2024-3400")
    checked = CVE(cve_id="CVE-2024-41713")
    db_session.add_all([unchecked, checked])
    await db_session.flush()
    db_session.add(
        EnrichmentResult(
            entity_type="cve",
            entity_id=checked.id,
            source_type="cvelist",
            raw_response={},
            parsed_data={"found": True},
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    await db_session.flush()
    upstream.route("CVE-2024-3400.json", _record(PAN_OS))

    stats = await tasks._run_cvelist_backfill()

    assert stats == {"fetched": 1, "updated": 1, "not_found": 0, "failed": 0, "pending": 1, "stopped": None}
    assert [str(r.url) for r in upstream.requests] == [FIXTURE["cna_and_cisa_adp"]["url"]]
    await db_session.refresh(unchecked)
    assert unchecked.ssvc_exploitation == "active" and unchecked.cvss_score == Decimal("10.0")
    # Checked now: the next run has nothing to fetch.
    assert (await tasks._run_cvelist_backfill())["pending"] == 0


async def test_backfill_puts_cves_missing_a_score_first(db_session, worker_session, upstream):
    await _source_row(db_session, rate_limit_config={"requests_per_period": 1, "period_seconds": 86400})
    db_session.add_all(
        [CVE(cve_id="CVE-2024-41713", cvss_score=Decimal("9.1"), description="x"), CVE(cve_id="CVE-2024-3400")]
    )
    await db_session.flush()
    upstream.route("cvelistV5", _status(404))

    await tasks._run_cvelist_backfill()

    assert "CVE-2024-3400" in str(upstream.requests[0].url)


async def test_backfill_stops_on_a_throttle_and_keeps_what_it_did(db_session, worker_session, upstream):
    await _source_row(db_session)
    rows = [CVE(cve_id=f"CVE-2024-340{i}") for i in range(3)]
    db_session.add_all(rows)
    await db_session.flush()
    upstream.route("cvelistV5", _record(PAN_OS), _status(429))

    stats = await tasks._run_cvelist_backfill()

    assert stats["stopped"] == "rate_limited"
    assert stats["fetched"] == 1 and len(upstream.requests) == 2
    results = (await db_session.execute(select(EnrichmentResult.entity_id))).scalars().all()
    assert len(results) == 1


async def test_backfill_stops_cleanly_when_paused_or_out_of_budget(db_session, worker_session, upstream):
    from app.services.redis_client import get_redis_bytes

    await _source_row(db_session, daily_budget=0)
    db_session.add(CVE(cve_id="CVE-2024-3400"))
    await db_session.flush()
    upstream.route("cvelistV5", _record(PAN_OS))

    assert (await tasks._run_cvelist_backfill())["stopped"] == "budget_exhausted"
    await (await get_redis_bytes()).set(gw.paused_key(), b"1")
    assert (await tasks._run_cvelist_backfill())["stopped"] == "paused"
    assert upstream.requests == []


# ── Delta sync: hourly zips, only our records read ───────────────────


def _zip(*records) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for record in records:
            zf.writestr(f"deltaCves/{record['cveMetadata']['cveId']}.json", json.dumps(record))
    return buf.getvalue()


def _not_ours(cve_id: str) -> dict:
    return {**PAN_OS, "cveMetadata": {**PAN_OS["cveMetadata"], "cveId": cve_id}}


def _release_download(asset: str, body: bytes):
    """github.com redirects a release download to its asset host."""
    return [
        (f"release-assets.githubusercontent.com/{asset}", lambda: httpx.Response(200, content=body)),
        (
            f"/{asset}",
            lambda: httpx.Response(302, headers={"Location": f"https://release-assets.githubusercontent.com/{asset}"}),
        ),
    ]


async def test_delta_sync_applies_only_our_records_and_moves_its_cursor(
    db_session, worker_session, upstream, monkeypatch
):
    source = await _source_row(db_session, last_synced_at=datetime(2026, 10, 27, 22, 30, tzinfo=UTC))
    pan_os, mitel = CVE(cve_id="CVE-2024-3400"), CVE(cve_id="CVE-2024-41713", severity="UNKNOWN")
    db_session.add_all([pan_os, mitel])
    await db_session.flush()
    upstream.route("api.github.com/repos/CVEProject/cvelistV5/releases", _record(RELEASES))
    end_of_day = _zip(_not_ours("CVE-2026-99001"), MITEL)
    today = _zip(PAN_OS, _not_ours("CVE-2026-99002"), _not_ours("CVE-2026-99003"))
    for fragment, reply in _release_download("2026-10-27_delta_CVEs_at_end_of_day.zip", end_of_day):
        upstream.route(fragment, reply)
    for fragment, reply in _release_download("2026-10-28_delta_CVEs_at_1300Z.zip", today):
        upstream.route(fragment, reply)
    read: list[str] = []
    real_read = zipfile.ZipFile.read

    def spy(self, name, pwd=None):
        read.append(name)
        return real_read(self, name, pwd)

    monkeypatch.setattr(zipfile.ZipFile, "read", spy)

    stats = await tasks._run_cvelist_delta_sync()

    assert stats == {"deltas": 2, "records": 5, "ours": 2, "updated": 2, "gap": False, "stopped": None}
    assert read == ["deltaCves/CVE-2024-41713.json", "deltaCves/CVE-2024-3400.json"]
    assert all(r.headers["User-Agent"] == USER_AGENT for r in upstream.requests)
    assert await SourceGateway("cvelist").used_today() == len(upstream.requests) == 5
    await db_session.refresh(mitel)
    assert (mitel.cvss_score, mitel.severity) == (Decimal("9.1"), "CRITICAL")
    await db_session.refresh(source)
    assert source.last_synced_at == datetime(2026, 10, 28, 13, 26, 9, tzinfo=UTC)
    # Nothing new since: the next run lists releases and reads no zip.
    upstream.requests.clear()
    assert (await tasks._run_cvelist_delta_sync())["deltas"] == 0
    assert len(upstream.requests) == 1


def test_delta_picking_per_day():
    def pick(since):
        deltas, gap = tasks.pick_cvelist_deltas(RELEASES, since)
        return [url.rsplit("/", 1)[1] for _, url in deltas], gap

    # First run: only the newest; the backfill has the rest.
    assert pick(None) == (["2026-10-28_delta_CVEs_at_1300Z.zip"], False)
    # Same day: the newest hourly zip holds everything since midnight.
    assert pick(datetime(2026, 10, 28, 1, 30, tzinfo=UTC)) == (["2026-10-28_delta_CVEs_at_1300Z.zip"], False)
    # Across midnight: yesterday's end-of-day zip, then today's newest.
    assert pick(datetime(2026, 10, 27, 22, 30, tzinfo=UTC)) == (
        ["2026-10-27_delta_CVEs_at_end_of_day.zip", "2026-10-28_delta_CVEs_at_1300Z.zip"],
        False,
    )
    # Older than the listing: what's listed, and the gap is reported.
    assert pick(datetime(2026, 10, 20, tzinfo=UTC))[1] is True


async def test_delta_sync_stops_cleanly_on_a_refusal(db_session, worker_session, upstream):
    source = await _source_row(db_session, last_synced_at=datetime(2026, 10, 27, 22, 30, tzinfo=UTC))
    upstream.route("api.github.com", _record(RELEASES))
    upstream.route("releases/download", _status(429))

    stats = await tasks._run_cvelist_delta_sync()

    assert stats["stopped"] == "rate_limited" and stats["deltas"] == 0
    await db_session.refresh(source)
    assert source.last_synced_at == datetime(2026, 10, 27, 22, 30, tzinfo=UTC)

    # The 429 opened the breaker: the next run sends nothing.
    upstream.requests.clear()
    assert (await tasks._run_cvelist_delta_sync())["stopped"] == "breaker_open"
    assert upstream.requests == []


async def test_delta_sync_refuses_an_oversized_zip(db_session, worker_session, upstream, monkeypatch):
    await _source_row(db_session)
    monkeypatch.setattr(tasks, "_CVELIST_DELTA_MAX_BYTES", 10)
    upstream.route("api.github.com", _record(RELEASES))
    for fragment, reply in _release_download("2026-10-28_delta_CVEs_at_1300Z.zip", _zip(PAN_OS)):
        upstream.route(fragment, reply)

    with pytest.raises(ValueError, match="larger than"):
        await tasks._run_cvelist_delta_sync()


# ── Migration ────────────────────────────────────────────────────────


async def test_migration_adds_and_drops_the_ssvc_columns(db_session):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).parent.parent / "alembic" / "versions" / "f7s8v9c0d1e2_cve_ssvc.py"
    spec = importlib.util.spec_from_file_location(f"cve_ssvc_{uuid.uuid4().hex}", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    def run(step):
        def go(sync_conn):
            with Operations.context(MigrationContext.configure(sync_conn)):
                step()

        return go

    async def columns() -> set[str]:
        rows = await db_session.execute(
            text(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_name = 'cves' AND column_name LIKE 'ssvc_%'"
            )
        )
        return set(rows.scalars())

    connection = await db_session.connection()
    await connection.run_sync(run(migration.downgrade))
    assert await columns() == set()
    await connection.run_sync(run(migration.upgrade))
    assert await columns() == {"ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact"}
