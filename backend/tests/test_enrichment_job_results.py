"""Scheduled jobs apply their answers through the source's field map and
context, report fetched / changed / written, and leave unchanged rows alone."""

import io
import json
import zipfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

import app.workers.enrichment_tasks as tasks
from app.enrichment.adapters.cisa_kev import kev_result
from app.enrichment.adapters.cvelist import (
    affected_pairs,
    cpe_pairs,
    iter_zip,
    member_cve_id,
    parse_record,
    pick_baseline,
)
from app.enrichment.adapters.github_poc import parse_search
from app.enrichment.adapters.nvd import nvd_result
from app.models.cve import CVE
from app.models.cve_affected import CVEAffected
from app.models.enrichment import EntityContext
from app.services.claim_provenance import record_claim
from app.workers import task_tracking
from app.workers.job_registry import JOB_REGISTRY


@pytest.fixture
def worker_session(db_session, monkeypatch):
    @asynccontextmanager
    async def fake_session():
        yield db_session

    monkeypatch.setattr(tasks, "_get_worker_session", fake_session)


# ── Without a database ──────────────────────────────────────────────


def test_source_jobs_report_the_three_counts():
    detail = task_tracking._task_detail((), {}, {"total_scores": 10, "updated": 3}, tasks.run_epss_bulk_sync.name)
    assert detail["result"] == {"fetched": 10, "changed": 3, "written": 3, "total_scores": 10, "updated": 3}
    # A job outside the enrichment sources passes through untouched.
    assert task_tracking.job_counts("app.workers.maintenance.prune_engine_tables", {"rows": 1}) == {"rows": 1}
    disabled = {"skipped": "source disabled"}
    assert task_tracking.job_counts(tasks.run_epss_bulk_sync.name, disabled) == disabled


def _stats(*keys: str) -> dict:
    """A job's result after a run that did nothing: every count 0, ``stopped`` None."""
    return {k: (None if k == "stopped" else 0) for k in keys}


#: Each source job's result keys, as the job declares them.
SOURCE_JOB_RESULTS = {
    "epss-bulk-sync": _stats("fetched", "changed", "written", "updated", "total_scores", "score_changes"),
    "cve-nvd-refresh": _stats("fetched", "changed", "written", "checked", "score_changes", "pages", "total"),
    "cve-nvd-backfill": _stats(
        "fetched", "changed", "written", "enriched", "failed", "skipped_invalid", "stopped", "total", "pending"
    ),
    "reenrich-cve-nvd": _stats(
        "fetched", "changed", "written", "attempted", "enriched", "with_config", "affected_products", "stopped"
    ),
    "sync-kev-feed": _stats("fetched", "changed", "written", "new", "updated", "skipped", "errors", "kev_additions"),
    "mitre-attack-sync": {"enterprise": _stats("techniques_created", "techniques_updated")},
    "osv-delta-sync": _stats("fetched", "changed", "written", "listed", "tracked", "failed", "stopped"),
    "malpedia-sync": _stats(
        "fetched",
        "changed",
        "written",
        "families_updated",
        "tools_updated",
        "actors_updated",
        "families_seen",
        "stopped",
    ),
    "github-poc-scan": _stats("fetched", "changed", "written", "scanned", "pocs_found", "stopped"),
    "cvelist-backfill": _stats("fetched", "changed", "written", "updated", "not_found", "pending", "stopped"),
    "cvelist-delta-sync": _stats("fetched", "changed", "written", "deltas", "records", "ours", "updated", "stopped"),
    "wikipedia-bulk-sync": _stats("fetched", "changed", "written", "country", "vendor", "total", "failed", "stopped"),
    "cymru-bulk-sync": _stats("due", "fetched", "changed", "written", "unannounced"),
    "threatfox-sync": _stats("rows", "matched", "updated", "withdrawn", "stopped"),
    "urlhaus-sync": _stats("rows", "matched", "updated", "withdrawn", "stopped"),
    "misp-galaxy-sync": _stats("fetched", "changed", "written", "matched", "clusters", "alias_rows"),
    "metasploit-sync": _stats("fetched", "changed", "written", "modules_seen", "cves_matched", "cves_updated"),
    "refresh-cwe-catalog": _stats("parsed", "inserted", "updated"),
    "sync-ransomware-victims": _stats("new_disclosures", "new_victims", "updated_victims", "new_groups", "stopped"),
    "ransomware-group-profiles": _stats("looked_up", "found", "updated", "failed", "stopped"),
    "sync-cybergeist-feeds": {**_stats("fetched", "changed", "written"), "actors": {}, "malware": {}},
    "wikidata-sync": _stats("looked_up", "found", "updated", "failed", "stopped"),
    "endoflife-sync": _stats("catalog", "matched", "updated", "failed", "withdrawn", "stopped"),
    "tranco-sync": _stats("listed", "matched", "ranked", "dropped", "flagged", "victims", "changed", "written"),
    "capec-sync": _stats("patterns", "techniques", "stopped"),
    "ctid-mappings-sync": _stats("nist_techniques", "cis_techniques", "updated", "stopped"),
    "d3fend-sync": {**_stats("mapped", "techniques", "stopped"), "version": None},
    "etda-sync": _stats("cards", "matched", "updated", "ambiguous", "unmatched", "withdrawn", "stopped"),
    "github-repo-sync": _stats("fetched", "changed", "written", "failed", "skipped", "stopped"),
}


def test_every_source_job_reports_the_three_counts_or_declares_none():
    assert set(SOURCE_JOB_RESULTS) == {name for name, job in JOB_REGISTRY.items() if job.get("source")}
    for name, result in SOURCE_JOB_RESULTS.items():
        job = JOB_REGISTRY[name]
        counted = task_tracking.job_counts(job["task"], dict(result))
        if job.get("counts") is False:
            assert counted == result, name
        else:
            assert [counted[k] for k in ("fetched", "changed", "written")] == [0, 0, 0], name


def test_sweep_answers_name_the_sweep_instead_of_the_record():
    entry = {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "PAN-OS Command Injection",
        "dateAdded": "2024-04-12",
        "shortDescription": "A command injection in GlobalProtect.",
        "requiredAction": "Apply mitigations.",
        "dueDate": "2024-04-19",
        "knownRansomwareCampaignUse": "Known",
    }
    kev = kev_result(entry, via="kev-sync")
    assert kev.raw_response == {"via": "kev-sync", "cveID": "CVE-2024-3400"}
    assert kev.parsed_data["in_kev"] is True
    assert (kev.parsed_data["vendor"], kev.parsed_data["known_ransomware_use"]) == ("Palo Alto Networks", "Known")
    assert kev_result(entry).raw_response == entry, "a lookup keeps the whole entry"

    nvd = {
        "nvd_data": {
            "id": "CVE-2024-3400",
            "published": "2024-04-12T08:15:06.230",
            "lastModified": "2024-04-20T01:00:00.000",
            "weaknesses": [{"description": [{"value": "CWE-77"}]}, {"description": []}],
        },
        "description": "A command injection in PAN-OS.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "references": [{"url": "https://example.test/advisory", "source": "psirt", "tags": None}],
    }
    answer = nvd_result(nvd, via="cve-nvd-refresh")
    assert answer.raw_response == {"via": "cve-nvd-refresh", "id": "CVE-2024-3400"}
    assert answer.ttl_hours == 168
    assert (answer.parsed_data["cvss_score"], answer.parsed_data["cvss_severity"]) == (10.0, "CRITICAL")
    assert answer.parsed_data["weaknesses"] == ["CWE-77"]
    assert answer.parsed_data["references"] == [{"url": "https://example.test/advisory", "source": "psirt", "tags": []}]
    # No score: no severity either.
    assert nvd_result({**nvd, "cvss_score": None}).parsed_data["cvss_severity"] is None


def test_a_poc_search_carries_its_maturity():
    hit = {"total_count": 4, "items": [{"name": "x", "html_url": "https://github.com/a/x", "stargazers_count": 120}]}
    assert parse_search("CVE-2024-1", hit)["exploit_maturity"] == "weaponized"
    assert parse_search("CVE-2024-1", {"items": []})["exploit_maturity"] == "none"


def _zip(members: dict[str, bytes], streamed: bool) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            if streamed:
                # Written as a stream: sizes follow the data in a descriptor.
                with archive.open(name, "w", force_zip64=False) as fh:
                    fh.write(data)
            else:
                archive.writestr(name, data)
    return out.getvalue()


@pytest.mark.parametrize("streamed", [False, True])
def test_the_baseline_reader_streams_only_wanted_records(streamed):
    records = {f"cves/2024/1xxx/CVE-2024-{i}.json": json.dumps({"n": i}).encode() * 20 for i in range(1000, 1100)}
    data = _zip({"cves/": b"", **records}, streamed)
    got = dict(iter_zip(io.BytesIO(data), lambda name: member_cve_id(name) in {"CVE-2024-1005", "CVE-2024-1099"}))
    assert got == {n: records[n] for n in records if n.endswith(("1005.json", "1099.json"))}


def test_the_baseline_is_found_in_a_release_listing():
    releases = [
        {"assets": [{"name": "2026-10-29_delta_CVEs_at_0100Z.zip", "browser_download_url": "d"}]},
        {"assets": [{"name": "2026-10-29_all_CVEs_at_midnight.zip.zip", "browser_download_url": "b"}]},
    ]
    assert pick_baseline(releases) == ("2026-10-29_all_CVEs_at_midnight.zip.zip", "b")
    assert pick_baseline(releases[:1]) is None


RECORD = {
    "cveMetadata": {"cveId": "CVE-2024-3400", "state": "PUBLISHED", "assignerShortName": "palo_alto"},
    "containers": {
        "cna": {
            "descriptions": [{"lang": "en", "value": "A command injection in PAN-OS."}],
            "affected": [
                {
                    "vendor": "Palo Alto Networks",
                    "product": "PAN-OS",
                    "versions": [{"version": "10.2.0", "lessThan": "10.2.9-h1", "status": "affected"}],
                }
            ],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-77"}]}],
        },
        "adp": [
            {
                "providerMetadata": {"shortName": "CISA-ADP"},
                "metrics": [{"other": {"type": "kev", "content": {"dateAdded": "2024-04-12"}}}],
                "affected": [{"cpes": ["cpe:2.3:o:paloaltonetworks:pan-os:10.2.0:*:*:*:*:*:*:*"]}],
            }
        ],
    },
}


def test_a_record_gives_kev_date_and_affected_pairs():
    parsed = parse_record(RECORD)
    assert parsed["adp_kev_date_added"] == "2024-04-12"
    assert affected_pairs(parsed) == [
        {"vendor": "palo_alto_networks", "product": "pan-os", "version_start": "10.2.0", "version_end": "10.2.9-h1"}
    ]
    assert cpe_pairs(parsed["adp_cpes"]) == [
        {"vendor": "paloaltonetworks", "product": "pan-os", "version_start": None, "version_end": None}
    ]


# ── With the database ───────────────────────────────────────────────


async def test_a_cvelist_record_writes_affected_rows_and_the_kev_date(db_session):
    from app.enrichment.adapters.cvelist import record_result
    from app.enrichment.pipeline import apply_source_result

    cve = CVE(cve_id="CVE-2024-3400")
    db_session.add(cve)
    await db_session.flush()

    await apply_source_result(db_session, "cve", cve.id, "cvelist", record_result(RECORD))
    await db_session.flush()

    rows = (
        await db_session.execute(select(CVEAffected.cpe_vendor, CVEAffected.source).where(CVEAffected.cve_id == cve.id))
    ).all()
    assert set(rows) == {("palo_alto_networks", "cna"), ("paloaltonetworks", "cisa_adp")}
    await db_session.refresh(cve)
    assert str(cve.kev_date_added) == "2024-04-12"
    assert cve.description == "A command injection in PAN-OS."


@pytest.fixture
def nvd_answers(monkeypatch):
    import app.services.system_settings as ss
    from app.intelligence import cve as cve_mod

    answers: dict[str, dict | None] = {}
    looked_up: list[str] = []

    async def fake_setting(key, db=None):
        return None

    async def fake_enrich(cve_id, gateway, api_key=None):
        looked_up.append(cve_id)
        return answers.get(cve_id)

    monkeypatch.setattr(ss, "get_setting", fake_setting)
    monkeypatch.setattr(cve_mod, "enrich_from_nvd", fake_enrich)
    return answers, looked_up


async def test_nvd_backfill_looks_up_cves_another_source_described(db_session, worker_session, nvd_answers):
    answers, looked_up = nvd_answers
    described = CVE(cve_id="CVE-2026-80001", description="From the CNA record.", cvss_score=9.0)
    db_session.add(described)
    await db_session.flush()
    await record_claim(
        db_session,
        entity_type="cve",
        entity_id=described.id,
        field="cvss_score",
        value=9.0,
        source_kind="enrichment",
        source_ref="cvelist",
    )
    answers["CVE-2026-80001"] = {
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "description": "From the CNA record.",
        "nvd_data": {"id": "CVE-2026-80001"},
    }

    stats = await tasks._run_cve_nvd_backfill()

    assert looked_up == ["CVE-2026-80001"]
    assert stats["fetched"] == 1 and stats["written"] == 1
    await db_session.refresh(described)
    # NVD's score outranks the CNA's; the record is kept.
    assert float(described.cvss_score) == 10.0
    assert described.nvd_data["id"] == "CVE-2026-80001"


async def test_nvd_refresh_never_wipes_a_score_with_none(db_session, worker_session, nvd_answers, monkeypatch):
    from app.intelligence import cve as cve_mod

    cve = CVE(cve_id="CVE-2026-80002", cvss_score=8.1, nvd_data={"id": "CVE-2026-80002"})
    db_session.add(cve)
    await db_session.flush()
    record = {"cvss_score": None, "severity": "UNKNOWN", "nvd_data": {"id": "CVE-2026-80002"}}

    async def changes(start, end, gateway, api_key=None, start_index=0):
        return [record], 1

    monkeypatch.setattr(cve_mod, "fetch_nvd_changes", changes)

    await tasks._run_cve_nvd_refresh()

    await db_session.refresh(cve)
    assert float(cve.cvss_score) == 8.1


async def test_epss_rewrites_only_changed_scores(db_session, monkeypatch):
    from tests.test_epss_sync import _run_sync_with

    earlier = datetime(2026, 1, 1, tzinfo=UTC)
    same = CVE(cve_id="CVE-2026-80010", epss_score=0.2, epss_percentile=0.5, epss_updated_at=earlier)
    moved = CVE(cve_id="CVE-2026-80011", epss_score=0.2, epss_percentile=0.5, epss_updated_at=earlier)
    # The same score, its percentile drifting under a point: not rewritten.
    drifted = CVE(cve_id="CVE-2026-80012", epss_score=0.2, epss_percentile=0.5, epss_updated_at=earlier)
    ranked = CVE(cve_id="CVE-2026-80013", epss_score=0.2, epss_percentile=0.5, epss_updated_at=earlier)
    db_session.add_all([same, moved, drifted, ranked])
    await db_session.flush()

    stats = await _run_sync_with(
        db_session,
        {
            "CVE-2026-80010": (0.2, 0.5),
            "CVE-2026-80011": (0.3, 0.6),
            "CVE-2026-80012": (0.2, 0.504),
            "CVE-2026-80013": (0.2, 0.52),
        },
    )

    assert (stats["fetched"], stats["changed"], stats["written"]) == (4, 2, 2)
    await db_session.refresh(drifted)
    await db_session.refresh(ranked)
    assert (drifted.epss_percentile, drifted.epss_updated_at) == (0.5, earlier)
    assert ranked.epss_percentile == 0.52
    await db_session.refresh(same)
    await db_session.refresh(moved)
    assert same.epss_updated_at == earlier
    assert moved.epss_score == 0.3
    context = dict(
        (
            await db_session.execute(
                select(EntityContext.key, EntityContext.value).where(
                    EntityContext.entity_id == moved.id, EntityContext.source_type == "epss"
                )
            )
        ).all()
    )
    assert context["epss"] == 0.3 and context["percentile"] == 0.6
    untouched = (await db_session.execute(select(EntityContext).where(EntityContext.entity_id == same.id))).all()
    assert untouched == []


def test_a_decimal_column_equals_the_same_float_score():
    """An unchanged CVSS score (Decimal in the column, float from the source)
    is not a change, so refreshes don't rewrite the row."""
    from decimal import Decimal

    from app.enrichment.entity_updater import _equal

    assert _equal(Decimal("9.8"), 9.8)
    assert not _equal(Decimal("9.8"), 9.9)
    assert not _equal(None, 9.8)
    assert _equal(["a"], ["a"])
