"""Source manifests: what they generate (seed rows, job registry entries,
gateways), the switch that skips a disabled source's jobs, the rate ceiling,
and the migration off the scheduled trigger mode."""

import importlib
import importlib.util
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from sqlalchemy import select, text

from app.enrichment.base import EnrichmentAdapter
from app.enrichment.entity_updater import FILTERS, RESOLVERS, _get_model_map
from app.enrichment.manifest import Column, Policy
from app.enrichment.registry import (
    ADAPTER_REGISTRY,
    CATALOG_REGISTRY,
    DEFAULT_SOURCES,
    SOURCE_REGISTRY,
    source_gateway,
)
from app.models.enrichment import EnrichmentSource
from app.workers.db import SOURCE_DISABLED
from app.workers.job_registry import JOB_REGISTRY

# Every source-owned job as JOB_REGISTRY had it before the manifests: the key,
# task and default schedule prod's beat and schedule overrides are keyed on.
JOBS_BEFORE = {
    "epss-bulk-sync": (
        "app.workers.enrichment_tasks.run_epss_bulk_sync",
        {"type": "crontab", "minute": "30", "hour": "6"},
    ),
    "mitre-attack-sync": (
        "app.workers.enrichment_tasks.run_mitre_attack_sync",
        {"type": "crontab", "minute": "0", "hour": "3", "day_of_week": "0"},
    ),
    "misp-galaxy-sync": (
        "app.workers.enrichment_tasks.run_misp_galaxy_sync",
        {"type": "crontab", "minute": "30", "hour": "3", "day_of_week": "0"},
    ),
    "malpedia-sync": (
        "app.workers.enrichment_tasks.run_malpedia_sync",
        {"type": "crontab", "minute": "0", "hour": "1", "day_of_week": "6"},
    ),
    "metasploit-sync": (
        "app.workers.enrichment_tasks.run_metasploit_sync",
        {"type": "crontab", "minute": "45", "hour": "3", "day_of_week": "0"},
    ),
    "osv-delta-sync": (
        "app.workers.enrichment_tasks.run_osv_delta_sync",
        {"type": "crontab", "minute": "40", "hour": "*"},
    ),
    "cve-nvd-refresh": (
        "app.workers.enrichment_tasks.run_cve_nvd_refresh",
        {"type": "crontab", "minute": "0", "hour": "*"},
    ),
    "cve-nvd-backfill": (
        "app.workers.enrichment_tasks.run_cve_nvd_backfill",
        {"type": "crontab", "minute": "30", "hour": "1"},
    ),
    "reenrich-cve-nvd": ("app.workers.maintenance.reenrich_cve_nvd", {"type": "crontab", "minute": "5", "hour": "3"}),
    "github-poc-scan": (
        "app.workers.enrichment_tasks.run_github_poc_scan",
        {"type": "crontab", "minute": "0", "hour": "5"},
    ),
    "wikipedia-bulk-sync": (
        "app.workers.enrichment_tasks.run_wikipedia_bulk_sync",
        {"type": "crontab", "minute": "0", "hour": "4", "day_of_week": "3"},
    ),
    "sync-kev-feed": ("app.workers.intel_feed_tasks.sync_kev_feed", {"type": "crontab", "minute": "15", "hour": "*/6"}),
    "refresh-cwe-catalog": (
        "app.workers.intel_feed_tasks.refresh_cwe_catalog",
        {"type": "crontab", "minute": "45", "hour": "3", "day_of_week": "1"},
    ),
    "sync-ransomware-victims": (
        "app.workers.intel_feed_tasks.sync_ransomware_victims",
        {"type": "interval", "seconds": 1800},
    ),
    "sync-cybergeist-feeds": (
        "app.workers.intel_feed_tasks.sync_cybergeist_feeds",
        {"type": "crontab", "minute": "30", "hour": "2"},
    ),
    "cvelist-backfill": ("app.workers.enrichment_tasks.run_cvelist_backfill", {"type": "crontab", "minute": "20"}),
    "cvelist-delta-sync": ("app.workers.enrichment_tasks.run_cvelist_delta_sync", {"type": "crontab", "minute": "40"}),
    # Sources added since.
    "wikidata-sync": (
        "app.workers.enrichment_tasks.run_wikidata_sync",
        {"type": "crontab", "minute": "30", "hour": "4", "day_of_week": "4"},
    ),
    "endoflife-sync": (
        "app.workers.enrichment_tasks.run_endoflife_sync",
        {"type": "crontab", "minute": "15", "hour": "5"},
    ),
    "tranco-sync": ("app.workers.enrichment_tasks.run_tranco_sync", {"type": "crontab", "minute": "20", "hour": "4"}),
    "cymru-bulk-sync": (
        "app.workers.enrichment_tasks.run_cymru_bulk_sync",
        {"type": "crontab", "minute": "25", "hour": "*/6"},
    ),
    "capec-sync": (
        "app.workers.enrichment_tasks.run_capec_sync",
        {"type": "crontab", "minute": "0", "hour": "4", "day_of_week": "1"},
    ),
    "ctid-mappings-sync": (
        "app.workers.enrichment_tasks.run_ctid_sync",
        {"type": "crontab", "minute": "15", "hour": "4", "day_of_week": "0"},
    ),
    "d3fend-sync": (
        "app.workers.enrichment_tasks.run_d3fend_sync",
        {"type": "crontab", "minute": "30", "hour": "4", "day_of_week": "0"},
    ),
    "etda-sync": (
        "app.workers.enrichment_tasks.run_etda_sync",
        {"type": "crontab", "minute": "15", "hour": "4", "day_of_week": "2"},
    ),
    "ransomware-group-profiles": (
        "app.workers.enrichment_tasks.run_ransomware_group_profiles",
        {"type": "crontab", "minute": "50", "hour": "*/4"},
    ),
    "threatfox-sync": (
        "app.workers.enrichment_tasks.run_threatfox_sync",
        {"type": "crontab", "minute": "35", "hour": "4"},
    ),
    "urlhaus-sync": (
        "app.workers.enrichment_tasks.run_urlhaus_sync",
        {"type": "crontab", "minute": "50", "hour": "*/6"},
    ),
    "github-repo-sync": (
        "app.workers.enrichment_tasks.run_github_repo_sync",
        {"type": "crontab", "minute": "15", "hour": "5", "day_of_week": "2"},
    ),
}

JOB_SOURCE = {
    "github-repo-sync": "github_repo",
    "epss-bulk-sync": "epss",
    "mitre-attack-sync": "mitre_attack",
    "misp-galaxy-sync": "misp_galaxy",
    "malpedia-sync": "malpedia",
    "metasploit-sync": "metasploit",
    "osv-delta-sync": "osv",
    "cve-nvd-refresh": "nvd",
    "cve-nvd-backfill": "nvd",
    "reenrich-cve-nvd": "nvd",
    "github-poc-scan": "github_poc",
    "wikipedia-bulk-sync": "wikipedia",
    "sync-kev-feed": "cisa_kev",
    "refresh-cwe-catalog": "mitre_cwe",
    "sync-ransomware-victims": "ransomware_live",
    "sync-cybergeist-feeds": "cybergeist",
    "cvelist-backfill": "cvelist",
    "cvelist-delta-sync": "cvelist",
    "wikidata-sync": "wikidata",
    "endoflife-sync": "endoflife",
    "tranco-sync": "tranco",
    "cymru-bulk-sync": "cymru",
    "capec-sync": "capec",
    "ctid-mappings-sync": "ctid",
    "d3fend-sync": "d3fend",
    "etda-sync": "etda",
    "ransomware-group-profiles": "ransomware_live",
    "threatfox-sync": "threatfox",
    "urlhaus-sync": "urlhaus",
}


# ── What the manifests generate ──────────────────────────────────────


def test_source_jobs_keep_their_keys_tasks_and_schedules():
    owned = {k: j for k, j in JOB_REGISTRY.items() if "source" in j}
    assert {k: (j["task"], j["default_schedule"]) for k, j in owned.items()} == JOBS_BEFORE
    assert {k: j["source"] for k, j in owned.items()} == JOB_SOURCE
    assert all(j["category"] == "enrichment" for j in owned.values())
    assert JOB_REGISTRY["github-poc-scan"]["settings_keys"] == ["github_poc_batch_limit", "github_poc_rescan_days"]
    assert JOB_REGISTRY["reenrich-cve-nvd"]["settings_keys"] == ["cve_reenrich_batch_size"]
    assert "scheduled-enrichment-check" not in JOB_REGISTRY


def test_every_source_has_a_seed_row_from_its_manifest():
    rows = {s["source_type"]: s for s in DEFAULT_SOURCES}
    assert set(rows) == set(SOURCE_REGISTRY)
    for source_type, cls in SOURCE_REGISTRY.items():
        row = rows[source_type]
        assert row["default_rate_limit"] == cls.quota.rate_limit_config
        assert row["default_daily_budget"] == cls.quota.daily_budget
        assert row["default_trigger_mode"] in ("auto", "manual")
        expected = bool(cls.jobs) if cls.default_enabled is None else cls.default_enabled
        assert row["default_enabled"] is expected, source_type
    assert set(CATALOG_REGISTRY) == {
        "misp_galaxy",
        "metasploit",
        "mitre_cwe",
        "ransomware_live",
        "cybergeist",
        "wikidata",
        "endoflife",
        "tranco",
        "capec",
        "ctid",
        "d3fend",
        "etda",
        "github_repo",
    }
    assert all(cls.kind == "catalog" and not issubclass(cls, EnrichmentAdapter) for cls in CATALOG_REGISTRY.values())
    assert all(cls.kind == "lookup" for cls in ADAPTER_REGISTRY.values())


def test_every_column_output_names_a_real_column():
    models = _get_model_map()
    for source_type, cls in SOURCE_REGISTRY.items():
        for column in cls.columns():
            assert column.entity_type in cls.applies_to, (source_type, column.target)
            name, _, key = column.path.partition(".")
            assert hasattr(models[column.entity_type], name), (source_type, column.target)
            if column.filter:
                assert column.filter in FILTERS
            if column.resolve:
                assert column.resolve in RESOLVERS
            if column.clears:
                # A column a source may empty is rewritten whole, newer wins.
                # The shared infra tag is the one ranked exception: Shodan's
                # tags outrank GreyNoise's RIOT, and emptying it follows rank.
                expected = Policy.RANK if column.target == "observable.infra_tag" else Policy.NEWER_WINS
                assert column.policy == expected, (source_type, column.target)
            if column.follows:
                leader = next(c for c in cls.columns() if c.target == column.follows)
                assert leader.policy != Policy.UNION and not leader.follows
        targets: dict[str, set] = {}
        for column in cls.columns():
            targets.setdefault(column.target, set()).add(column.policy)
        assert all(len(p) == 1 for p in targets.values()), source_type


def test_outputs_sharing_a_target_agree_on_policy_across_sources():
    by_target: dict[str, set[Policy]] = {}
    for cls in SOURCE_REGISTRY.values():
        for column in cls.columns():
            if not column.follows:
                by_target.setdefault(column.target, set()).add(column.policy)
    assert all(len(policies) == 1 for policies in by_target.values())


def test_supported_entity_types_and_requires_api_key_read_the_manifest():
    vt = ADAPTER_REGISTRY["virustotal"]
    assert vt.supported_entity_types == ["observable"] and vt.requires_api_key
    assert not ADAPTER_REGISTRY["greynoise"].requires_api_key
    assert ADAPTER_REGISTRY["wikipedia"]().supports_entity("cwe")


# ── Gateways from manifests ──────────────────────────────────────────


def _row(source_type: str, **fields) -> EnrichmentSource:
    defaults = SOURCE_REGISTRY[source_type].quota
    return EnrichmentSource(
        source_type=source_type,
        rate_limit_config=fields.pop("rate_limit_config", defaults.rate_limit_config),
        daily_budget=fields.pop("daily_budget", defaults.daily_budget),
        **fields,
    )


def test_a_keyed_quota_applies_with_a_key_on_a_default_row():
    row = _row("github_poc")
    assert source_gateway(row, None).capacity == 10
    assert source_gateway(row, "ghp_token").capacity == 30
    tuned = _row("github_poc", rate_limit_config={"requests_per_period": 5, "period_seconds": 60})
    assert source_gateway(tuned, "ghp_token").capacity == 5  # an admin's choice stands
    assert source_gateway(_row("malpedia"), "key").capacity == 30  # no keyed quota


def test_nvd_runs_at_its_keyless_limit_unless_keyed():
    row = _row("nvd")
    keyless, keyed = source_gateway(row, None), source_gateway(row, "nvd-key")
    assert (keyless.capacity, keyless.period) == (5, 30)
    assert (keyed.capacity, keyed.period) == (50, 30)
    # An admin's own rate stands, within the limit of the quota in use.
    tuned = _row("nvd", rate_limit_config={"requests_per_period": 20, "period_seconds": 30})
    assert source_gateway(tuned, "nvd-key").capacity == 20
    assert (source_gateway(tuned, None).capacity, source_gateway(tuned, None).period) == (5, 30)
    # The sweep jobs' pacing fits inside either window.
    from app.intelligence.cve import nvd_request_pace

    assert 30 / nvd_request_pace(None) <= 5 and 30 / nvd_request_pace("nvd-key") <= 50


@pytest.mark.parametrize(
    ("rate", "api_key", "runs_at"),
    [
        ((20, 30), None, (5, 30)),  # keyless, same period: the keyless ceiling
        ((4, 30), None, (4, 30)),  # under it: as saved
        ((20, 60), None, (10, 60)),  # another period: the ceiling's rate over it
        ((10, 60), None, (10, 60)),  # the ceiling's rate exactly
        ((1, 1), None, (5, 30)),  # too short a period for one request: the ceiling
        ((80, 30), "nvd-key", (50, 30)),  # keyed: the keyed ceiling
        ((200, 120), "nvd-key", (200, 120)),
        ((300, 120), "nvd-key", (200, 120)),
    ],
)
def test_a_stored_rate_never_exceeds_the_ceiling_in_use(rate, api_key, runs_at):
    row = _row("nvd", rate_limit_config={"requests_per_period": rate[0], "period_seconds": rate[1]})
    gateway = source_gateway(row, api_key)
    assert (gateway.capacity, gateway.period) == runs_at


async def test_catalog_job_gateway_uses_its_row(db_session):
    from app.enrichment.pipeline import gateway_for

    gateway, _ = await gateway_for(db_session, "misp_galaxy")
    assert (gateway.capacity, gateway.period, gateway.daily_budget) == (10, 3600, 50)

    db_session.add(_row("misp_galaxy", display_name="MISP Galaxy", daily_budget=7))
    await db_session.flush()
    gateway, _ = await gateway_for(db_session, "misp_galaxy")
    assert gateway.daily_budget == 7


# ── A disabled source's jobs skip ────────────────────────────────────


def _job_body(task: str):
    module_name, fn = task.rsplit(".", 1)
    return getattr(importlib.import_module(module_name), f"_{fn}")


@pytest.fixture
def worker_sessions(db_session, monkeypatch):
    @asynccontextmanager
    async def fake_session():
        yield db_session

    for module in ("enrichment_tasks", "intel_feed_tasks", "maintenance"):
        monkeypatch.setattr(importlib.import_module(f"app.workers.{module}"), "_get_worker_session", fake_session)


@pytest.mark.parametrize("key", sorted(JOB_SOURCE))
async def test_a_disabled_sources_jobs_skip(key, db_session, worker_sessions, monkeypatch):
    import httpx

    def no_network(*args, **kwargs):
        raise AssertionError("a skipped job sent a request")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_network)
    source_type = JOB_REGISTRY[key]["source"]
    db_session.add(_row(source_type, display_name=source_type, is_enabled=False))
    await db_session.flush()

    assert await _job_body(JOB_REGISTRY[key]["task"])() == SOURCE_DISABLED


async def test_a_job_runs_when_its_source_has_no_row_yet(db_session, worker_sessions, monkeypatch):
    import app.workers.intel_feed_tasks as intel_feed_tasks
    from app.intelligence import external_feeds

    async def fake_sync(db):
        return {"new": 0}

    monkeypatch.setattr(external_feeds, "sync_kev_feed", fake_sync)
    assert await intel_feed_tasks._sync_kev_feed() == {"new": 0}

    db_session.add(_row("cisa_kev", display_name="CISA KEV", is_enabled=True))
    await db_session.flush()
    assert await intel_feed_tasks._sync_kev_feed() == {"new": 0}


# ── Catalog sources have no lookup ───────────────────────────────────


async def test_catalog_rows_are_not_looked_up(db_session):
    from app.enrichment.pipeline import enrich_entity

    db_session.add(_row("cybergeist", display_name="Cybergeist", is_enabled=True, trigger_mode="manual"))
    await db_session.flush()
    results = await enrich_entity(
        "threat_actor", uuid.uuid4(), "APT28", db_session, trigger="manual", source_types=["cybergeist"]
    )
    assert results == []


async def test_catalog_rows_offer_no_entity_types_and_no_test(client, admin_headers, db_session):
    row = _row("metasploit", display_name="Metasploit modules", is_enabled=True, health_status="unknown", config={})
    db_session.add(row)
    await db_session.flush()

    listed = (await client.get("/api/enrichment/sources", headers=admin_headers)).json()
    (item,) = [s for s in listed if s["source_type"] == "metasploit"]
    assert item["supported_entity_types"] == []

    # A catalog source takes no key, so there is no key to test.
    from app.enrichment.keys import credential_for

    assert credential_for("metasploit") is None
    resp = await client.post("/api/enrichment/keys/metasploit/test", headers=admin_headers)
    assert resp.status_code == 404


async def test_a_key_whose_sources_only_run_jobs_is_untestable(db_session):
    """github_token's sources include a catalog one; with only that one's row
    there is no lookup to probe it through."""
    from app.enrichment.keys import test_key

    db_session.add(_row("github_repo", display_name="GitHub repos", is_enabled=True, config={}))
    await db_session.flush()
    assert (await test_key(db_session, "github_token"))["status"] == "untestable"


def test_every_source_says_what_it_is():
    for source_type, cls in SOURCE_REGISTRY.items():
        assert isinstance(cls.about, str) and cls.about.strip(), source_type


# ── The rate ceiling ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("source_type", "body", "key", "status"),
    [
        ("nvd", {"rate_limit_config": {"requests_per_period": 5, "period_seconds": 30}}, None, 200),
        ("nvd", {"rate_limit_config": {"requests_per_period": 6, "period_seconds": 30}}, None, 400),
        ("nvd", {"rate_limit_config": {"requests_per_period": 50, "period_seconds": 30}}, "k", 200),
        ("nvd", {"rate_limit_config": {"requests_per_period": 60, "period_seconds": 30}}, "k", 400),
        # 100 per minute is twice NVD's keyed 50 per 30 s.
        ("nvd", {"rate_limit_config": {"requests_per_period": 100, "period_seconds": 60}}, "k", 200),
        ("nvd", {"rate_limit_config": {"requests_per_period": 101, "period_seconds": 60}}, "k", 400),
        ("github_poc", {"rate_limit_config": {"requests_per_period": 30, "period_seconds": 60}}, None, 400),
        ("github_poc", {"rate_limit_config": {"requests_per_period": 30, "period_seconds": 60}}, "t", 200),
        ("wikipedia", {"rate_limit_config": {"requests_per_period": 500, "period_seconds": 60}}, None, 200),
    ],
)
async def test_put_refuses_a_rate_above_the_ceiling(
    source_type, body, key, status, client, admin_headers, db_session, monkeypatch
):
    """The ceiling is the keyed one when the source resolves a key (here its
    instance setting, set under Keys), else the keyless one."""
    import app.services.system_settings as ss

    async def setting(name, db=None):
        return key if name in ("nvd_api_key", "github_token") and key else ""

    monkeypatch.setattr(ss, "get_setting", setting)
    row = _row(source_type, display_name=source_type, is_enabled=True, health_status="unknown", config={})
    db_session.add(row)
    await db_session.flush()

    resp = await client.put(f"/api/enrichment/sources/{row.id}", json=body, headers=admin_headers)

    assert resp.status_code == status, resp.text
    if status == 400:
        assert resp.json()["error"]["code"] == "rate_above_ceiling"
        assert "at most" in resp.json()["error"]["message"]
    else:
        assert resp.json()["rate_limit_config"] == body["rate_limit_config"]


async def test_put_refuses_the_scheduled_trigger_mode(client, admin_headers, db_session):
    row = _row("epss", display_name="FIRST EPSS", is_enabled=True, health_status="unknown", config={})
    db_session.add(row)
    await db_session.flush()
    resp = await client.put(
        f"/api/enrichment/sources/{row.id}", json={"trigger_mode": "scheduled"}, headers=admin_headers
    )
    assert resp.json()["error"]["code"] == "validation_error"


# ── Migration: off the scheduled trigger mode ────────────────────────


def _migration():
    path = Path(__file__).parent.parent / "alembic" / "versions" / "d5m6a7n8f9s0_enrichment_manifests.py"
    spec = importlib.util.spec_from_file_location("d5m6a7n8f9s0", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_migration_turns_scheduled_rows_manual_and_leaves_disabled_rows_off(db_session):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    # The test schema comes from the models, which no longer have the columns.
    await db_session.execute(
        text(
            "ALTER TABLE enrichment_sources ADD COLUMN daily_budget_used integer NOT NULL DEFAULT 0, "
            "ADD COLUMN schedule_interval_hours integer NOT NULL DEFAULT 24, "
            "ADD COLUMN next_scheduled_at timestamptz"
        )
    )
    rows = {
        "epss": (False, "scheduled"),
        "nvd": (False, "auto"),
        "vulncheck": (False, "scheduled"),  # no jobs: stays off
        "shodan": (True, "auto"),
    }
    for source_type, (enabled, mode) in rows.items():
        db_session.add(
            _row(source_type, display_name=source_type, is_enabled=enabled, trigger_mode=mode, health_status="unknown")
        )
    db_session.add(
        _row(
            "wikipedia",
            display_name="Wikipedia",
            is_enabled=True,
            trigger_mode="auto",
            rate_limit_config={"requests_per_period": 10, "period_seconds": 60},
        )
    )
    await db_session.flush()

    def upgrade(sync_conn):
        with Operations.context(MigrationContext.configure(sync_conn)):
            _migration().upgrade()

    await (await db_session.connection()).run_sync(upgrade)
    db_session.expire_all()

    after = {
        r.source_type: (r.is_enabled, r.trigger_mode)
        for r in (await db_session.execute(select(EnrichmentSource))).scalars()
    }
    # An admin's off switch stands, jobs or not.
    assert after == {
        "epss": (False, "manual"),
        "nvd": (False, "auto"),
        "vulncheck": (False, "manual"),
        "shodan": (True, "auto"),
        "wikipedia": (True, "auto"),
    }
    wiki = (
        await db_session.execute(select(EnrichmentSource).where(EnrichmentSource.source_type == "wikipedia"))
    ).scalar_one()
    assert wiki.rate_limit_config == {"requests_per_period": 20, "period_seconds": 60}
    columns = {
        c
        for (c,) in await db_session.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = 'enrichment_sources'")
        )
    }
    assert not columns & {"daily_budget_used", "schedule_interval_hours", "next_scheduled_at"}


# ── Field map: claims on every write ─────────────────────────────────


async def test_every_column_write_records_its_source(db_session):
    from app.enrichment.entity_updater import apply_enrichment_results_to_entity
    from app.models.entity_field_claim import EntityFieldClaim
    from app.models.observable import Observable
    from app.models.tool import Tool

    tool = Tool(name="Mimikatz")
    obs = Observable(kind="ipv4", value="45.33.32.157", base_confidence=0.8, current_confidence=0.8)
    db_session.add_all([tool, obs])
    await db_session.flush()

    await apply_enrichment_results_to_entity(
        db_session,
        "tool",
        tool.id,
        [
            {"source_type": "mitre_attack", "status": "success", "parsed_data": {"aliases": ["Mimi1", "Shared"]}},
            {
                "source_type": "malpedia",
                "status": "success",
                "parsed_data": {"alt_names": ["shared", "Mimi2"], "malpedia_url": "https://m/x"},
            },
            {
                "source_type": "wikipedia",
                "status": "success",
                "parsed_data": {"wikipedia_url": "https://w/M", "wikipedia_content": "text"},
            },
        ],
    )
    await apply_enrichment_results_to_entity(
        db_session,
        "observable",
        obs.id,
        [{"source_type": "shodan", "status": "success", "parsed_data": {"ports": "22", "tags": "vpn"}}],
    )

    claims = {
        (c.field, c.source_ref, c.value_text)
        for c in (
            await db_session.execute(select(EntityFieldClaim).where(EntityFieldClaim.entity_id.in_([tool.id, obs.id])))
        ).scalars()
    }
    assert claims == {
        ("aliases", "mitre_attack", "Mimi1, Shared"),
        ("aliases", "malpedia", "Mimi2"),
        ("malpedia_url", "malpedia", "https://m/x"),
        ("wikipedia_url", "wikipedia", "https://w/M"),
        ("wikipedia_content", "wikipedia", "text"),
        ("reputation.ports", "shodan", "22"),
        ("reputation.shodan_tags", "shodan", "vpn"),
        ("infra_tag", "shodan", "vpn"),
    }


def test_column_paths():
    column = Column("detection_ratio", "observable.reputation.vt_ratio", Policy.NEWER_WINS)
    assert (column.entity_type, column.path) == ("observable", "reputation.vt_ratio")


async def test_the_jobs_view_names_each_jobs_source(client, admin_headers, monkeypatch):
    import app.api.job_schedules as job_schedules

    monkeypatch.setattr(job_schedules, "read_overrides_from_redis", lambda: {})
    listed = (await client.get("/api/job-schedules", headers=admin_headers)).json()["jobs"]
    jobs = {j["name"]: j for j in listed}
    assert jobs["epss-bulk-sync"]["source"] == "epss"
    assert jobs["resolve-cve-affected"]["source"] is None


async def test_seeding_starts_job_sources_on_but_manual(db_session, monkeypatch):
    """A fresh install runs the catalog jobs but makes no per-entity lookups
    until an admin turns a source to auto."""
    import app.database as database
    from app.main import _seed_enrichment_sources

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.setattr(database, "async_session", session)
    await _seed_enrichment_sources()

    rows = {r.source_type: r for r in (await db_session.execute(select(EnrichmentSource))).scalars()}
    assert set(rows) == {s["source_type"] for s in DEFAULT_SOURCES}
    for src in DEFAULT_SOURCES:
        row = rows[src["source_type"]]
        assert row.is_enabled is src["default_enabled"]
        assert row.trigger_mode == src["default_trigger_mode"], src["source_type"]
    # On only so its jobs run: per-entity lookups wait for an admin.
    assert rows["mitre_attack"].is_enabled and rows["mitre_attack"].trigger_mode == "manual"
    # The CVE sources and the IP sources run on their own from the start.
    for source_type in ("nvd", "epss", "cisa_kev", "osv", "cvelist", "shodan", "greynoise", "cymru"):
        assert (rows[source_type].is_enabled, rows[source_type].trigger_mode) == (True, "auto"), source_type


# ── Manifest parts: match, requires, ttl, concurrency, egress ────────


def _manifest_class(**attrs):
    """A throwaway adapter class with the given manifest attributes."""
    from app.enrichment.base import EnrichmentData
    from app.enrichment.manifest import Egress, License, Quota

    async def enrich(self, entity_type, entity_value):
        return attrs.pop("_answer", None) or EnrichmentData(raw_response={}, parsed_data={})

    body = {
        "source_type": "test_source",
        "display_name": "Test",
        "applies_to": {"cve": None},
        "quota": Quota(10, 60, daily_budget=100),
        "egress": Egress.LOW,
        "license": License("test"),
        "enrich": enrich,
        **attrs,
    }
    return type("TestSource", (EnrichmentAdapter,), body)


def test_applies_to_takes_a_match_and_keeps_its_shape():
    from app.enrichment.manifest import Match

    cls = _manifest_class(
        applies_to={
            "threat_actor": Match(column="mitre_id"),
            "observable": Match(("ipv4",)),
            "cve": None,
        }
    )
    # Readers of applies_to still see entity_type -> kinds.
    assert cls.applies_to == {"threat_actor": None, "observable": ("ipv4",), "cve": None}
    assert cls.match == {"threat_actor": Match(column="mitre_id"), "observable": Match(("ipv4",))}
    assert cls.supported_entity_types == ["threat_actor", "observable", "cve"]


def test_a_match_names_the_column_an_entity_is_looked_up_by():
    from app.enrichment.manifest import Match

    cls = _manifest_class(applies_to={"ransomware_victim": Match(column="domain"), "cve": None, "tool": None})
    assert cls.lookup_column("ransomware_victim") == "domain"
    assert cls.lookup_column("cve") == "cve_id"  # the type's identifier
    assert cls.lookup_column("tool") == "name"


def test_requires_takes_keys():
    from app.enrichment.manifest import Key

    own = _manifest_class(requires=(Key(),))
    assert own.requires_api_key and own.required_keys() == (Key(),)

    shared = _manifest_class(requires=(Key("abuse_ch"),))
    assert shared.requires_api_key and shared.required_keys() == (Key("abuse_ch"),)
    assert Key("abuse_ch") != Key()

    assert not _manifest_class(requires=()).requires_api_key


def test_the_quota_in_use_sets_the_concurrency_cap(monkeypatch):
    from app.enrichment import registry
    from app.enrichment.manifest import Quota

    cls = _manifest_class(quota=Quota(5, 30, 100, concurrency=1, keyed=Quota(50, 30, 100, concurrency=3)))
    monkeypatch.setitem(registry.SOURCE_REGISTRY, "test_source", cls)
    row = EnrichmentSource(
        source_type="test_source", rate_limit_config={"requests_per_period": 5, "period_seconds": 30}
    )
    assert source_gateway(row, None).concurrency == 1
    assert source_gateway(row, "key").concurrency == 3
    assert Quota(1, 1, None).concurrency == 2  # the default


def test_sources_that_share_iocs_are_seeded_manual_unless_their_manifest_says_auto():
    from app.enrichment.manifest import Egress
    from app.enrichment.registry import seed_trigger_mode

    assert seed_trigger_mode(_manifest_class(egress=Egress.SHARES_IOC)) == "manual"
    assert seed_trigger_mode(_manifest_class(egress=Egress.SHARES_IOC, default_trigger_mode="auto")) == "auto"
    sharing = {
        row["source_type"]: row["default_trigger_mode"]
        for row in DEFAULT_SOURCES
        if SOURCE_REGISTRY[row["source_type"]].egress == Egress.SHARES_IOC
    }
    # Shodan and GreyNoise only answer from their own scans of the internet;
    # VirusTotal and abuse.ch wait to be asked.
    assert {st for st, mode in sharing.items() if mode == "auto"} == {"shodan", "greynoise"}


async def test_a_backfill_source_job_runs_in_the_backfill_lane(db_session, monkeypatch):
    import sys

    from app.enrichment.gateway import _lane
    from app.workers.db import source_job

    module = sys.modules[__name__]

    @asynccontextmanager
    async def session():
        yield db_session

    monkeypatch.setattr(module, "_get_worker_session", session, raising=False)

    @source_job("nvd", lane="backfill")
    async def _backfill():
        return _lane.get()

    @source_job("nvd")
    async def _refresh():
        return _lane.get()

    assert await _backfill() == "backfill"
    assert await _refresh() is None
    assert _lane.get() is None


def test_bulk_catch_up_jobs_run_in_the_backfill_lane():
    import app.workers.enrichment_tasks as tasks
    import app.workers.maintenance as maintenance

    # Re-fetches of whole sets stop at BACKFILL_SHARE of the daily budget,
    # leaving the rest to new CVEs and people's lookups.
    for job in (tasks._run_cve_nvd_backfill, tasks._run_cvelist_backfill, maintenance._reenrich_cve_nvd):
        assert job.lane == "backfill", job.__name__


@pytest.mark.parametrize("source_type", ["nvd", "epss", "cisa_kev", "osv", "cvelist"])
def test_cve_sources_are_seeded_on_and_auto(source_type):
    row = next(s for s in DEFAULT_SOURCES if s["source_type"] == source_type)
    assert (row["default_enabled"], row["default_trigger_mode"]) == (True, "auto")
