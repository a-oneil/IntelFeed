"""Tests for the ATT&CK matrix heat-map endpoint (GET /api/attack/matrix)."""

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.attack import TACTIC_ORDER
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.telemetry_source import TelemetrySource
from app.models.ttp import TTP, EntryTTP


async def _delete_matrix_cache_keys():
    try:
        from app.services.redis_client import get_redis

        r = await get_redis()
        keys = [k async for k in r.scan_iter(match="intelfeed:attack:matrix:*")]
        if keys:
            await r.delete(*keys)
    except Exception:
        pass  # Redis unavailable — endpoint cache is a no-op then too


@pytest_asyncio.fixture(autouse=True)
async def _flush_matrix_cache():
    """The endpoint caches in Redis (shared with the dev app); flush its keys
    before each test so tests see fresh DB state, and after so test fixture
    payloads never get served to the dev frontend."""
    await _delete_matrix_cache_keys()
    yield
    await _delete_matrix_cache_keys()


@pytest_asyncio.fixture
async def matrix_seed(db_session: AsyncSession, test_feed: Feed) -> dict:
    now = datetime.now(UTC)

    phishing = TTP(
        technique_id="T1566",
        technique_name="Phishing",
        tactic="initial-access",
        tactics=["initial-access"],
        matrix_domain="enterprise",
        article_count=7,
    )
    spearphish = TTP(
        technique_id="T1566.001",
        technique_name="Spearphishing Attachment",
        tactic="initial-access",
        tactics=["initial-access"],
        is_subtechnique=True,
        parent_technique_id="T1566",
        matrix_domain="enterprise",
        article_count=2,
    )
    cmd = TTP(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="execution",
        tactics=["execution"],
        matrix_domain="enterprise",
        article_count=3,
    )
    multi = TTP(
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        tactic="privilege-escalation",
        tactics=["privilege-escalation", "defense-evasion"],
        matrix_domain="enterprise",
        article_count=0,
    )
    deprecated = TTP(
        technique_id="T1064",
        technique_name="Scripting",
        tactic="execution",
        tactics=["execution", "defense-evasion"],
        matrix_domain="enterprise",
        is_deprecated=True,
        article_count=0,
    )
    ics = TTP(
        technique_id="T0800",
        technique_name="Activate Firmware Update Mode",
        tactic="inhibit-response-function",
        tactics=["inhibit-response-function"],
        matrix_domain="ics",
        article_count=0,
    )
    ttps = [phishing, spearphish, cmd, multi, deprecated, ics]
    db_session.add_all(ttps)

    entry_recent = Entry(
        feed_id=test_feed.id,
        title="Recent entry",
        guid="matrix-recent",
        url="https://example.com/matrix/recent",
        published_at=now - timedelta(days=5),
    )
    entry_mid = Entry(
        feed_id=test_feed.id,
        title="Mid entry",
        guid="matrix-mid",
        url="https://example.com/matrix/mid",
        published_at=now - timedelta(days=60),
    )
    entry_old = Entry(
        feed_id=test_feed.id,
        title="Old entry",
        guid="matrix-old",
        url="https://example.com/matrix/old",
        published_at=now - timedelta(days=400),
    )
    db_session.add_all([entry_recent, entry_mid, entry_old])
    await db_session.flush()

    db_session.add_all(
        [
            EntryTTP(entry_id=entry_recent.id, ttp_id=cmd.id),
            EntryTTP(entry_id=entry_mid.id, ttp_id=cmd.id),
            EntryTTP(entry_id=entry_old.id, ttp_id=cmd.id),
            EntryTTP(entry_id=entry_recent.id, ttp_id=spearphish.id),
        ]
    )

    db_session.add(
        TelemetrySource(
            name="Sysmon",
            category="endpoint",
            log_types=["Command Execution"],
            enabled=True,
        )
    )
    db_session.add_all(
        [
            # Deployable: telemetry satisfies its data sources
            DetectionRule(
                rule_type="sigma",
                title="Suspicious interpreter",
                rule_content="detection: {}",
                source_ttps=["T1059"],
                data_sources=["Command Execution"],
                is_draft=False,
            ),
            # Library-only: rule exists but its telemetry is missing
            DetectionRule(
                rule_type="sigma",
                title="Phishing attachment",
                rule_content="detection: {}",
                source_ttps=["T1566"],
                data_sources=["Quantum Flux Telemetry"],
                is_draft=False,
            ),
            # Draft: must not count as a rule at all
            DetectionRule(
                rule_type="sigma",
                title="Draft spearphish",
                rule_content="detection: {}",
                source_ttps=["T1566.001"],
                data_sources=[],
                is_draft=True,
            ),
        ]
    )
    await db_session.flush()
    return {"ttps": ttps}


def _find_cell(data: dict, tactic_id: str, technique_id: str) -> dict | None:
    for col in data["tactics"]:
        if col["id"] != tactic_id:
            continue
        for c in col["techniques"]:
            if c["technique_id"] == technique_id:
                return c
    return None


def _all_technique_ids(data: dict) -> set[str]:
    ids: set[str] = set()
    for col in data["tactics"]:
        for c in col["techniques"]:
            ids.add(c["technique_id"])
            for s in c.get("subtechniques", []):
                ids.add(s["technique_id"])
    return ids


@pytest.mark.asyncio
async def test_matrix_tactic_ordering_and_domain_filter(client: AsyncClient, auth_headers: dict, matrix_seed: dict):
    resp = await client.get("/api/attack/matrix", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["domain"] == "enterprise"
    # Kill-chain order, restricted to tactics that actually have techniques
    seeded_tactics = {"initial-access", "execution", "privilege-escalation", "defense-evasion"}
    expected = [slug for slug in TACTIC_ORDER["enterprise"] if slug in seeded_tactics]
    assert [t["id"] for t in data["tactics"]] == expected

    ids = _all_technique_ids(data)
    assert "T1059" in ids
    assert "T0800" not in ids  # ICS technique excluded from enterprise
    assert _find_cell(data, "execution", "T1059") is not None

    # ICS domain has its own kill-chain order and techniques
    resp = await client.get("/api/attack/matrix", params={"domain": "ics"}, headers=auth_headers)
    assert resp.status_code == 200
    ics = resp.json()
    assert [t["id"] for t in ics["tactics"]] == ["inhibit-response-function"]
    assert _find_cell(ics, "inhibit-response-function", "T0800") is not None
    assert "T1059" not in _all_technique_ids(ics)


@pytest.mark.asyncio
async def test_matrix_window_filtering(client: AsyncClient, auth_headers: dict, matrix_seed: dict):
    # All-time: uses the model's article_count rollup
    resp = await client.get("/api/attack/matrix", headers=auth_headers)
    assert resp.status_code == 200
    cell = _find_cell(resp.json(), "execution", "T1059")
    assert cell["article_count"] == 3

    # 30-day window: only the entry published 5 days ago
    resp = await client.get("/api/attack/matrix", params={"days": 30}, headers=auth_headers)
    cell = _find_cell(resp.json(), "execution", "T1059")
    assert cell["article_count"] == 1

    # 90-day window: 5-day and 60-day entries, not the 400-day one
    resp = await client.get("/api/attack/matrix", params={"days": 90}, headers=auth_headers)
    cell = _find_cell(resp.json(), "execution", "T1059")
    assert cell["article_count"] == 2


@pytest.mark.asyncio
async def test_matrix_coverage_flags(client: AsyncClient, auth_headers: dict, matrix_seed: dict):
    resp = await client.get("/api/attack/matrix", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    covered = _find_cell(data, "execution", "T1059")
    assert covered["has_rule"] is True
    assert covered["deployable"] is True
    assert covered["coverage"] == "covered"
    assert covered["rule_count"] == 1

    library_only = _find_cell(data, "initial-access", "T1566")
    assert library_only["has_rule"] is True
    assert library_only["deployable"] is False
    assert library_only["coverage"] == "library_only"
    assert "Quantum Flux Telemetry" in library_only["missing_data_sources"]

    # Draft rules don't count — the sub-technique has no effective rule
    sub = library_only["subtechniques"][0]
    assert sub["technique_id"] == "T1566.001"
    assert sub["has_rule"] is False
    assert sub["deployable"] is False
    assert sub["coverage"] == "no_rule"

    summary = data["coverage_summary"]
    assert summary["covered"] == 1
    assert summary["library_only"] == 1


@pytest.mark.asyncio
async def test_matrix_subtechnique_nesting_and_rollup(client: AsyncClient, auth_headers: dict, matrix_seed: dict):
    resp = await client.get("/api/attack/matrix", headers=auth_headers)
    data = resp.json()

    parent = _find_cell(data, "initial-access", "T1566")
    assert parent is not None
    assert [s["technique_id"] for s in parent["subtechniques"]] == ["T1566.001"]
    # Sub-techniques are nested, not top-level cells
    assert _find_cell(data, "initial-access", "T1566.001") is None
    # Rollup = parent's own count + sub counts (7 + 2 all-time)
    assert parent["rollup_article_count"] == 9
    assert data["max_article_count"] >= 9


@pytest.mark.asyncio
async def test_matrix_deprecated_and_multi_tactic(client: AsyncClient, auth_headers: dict, matrix_seed: dict):
    resp = await client.get("/api/attack/matrix", headers=auth_headers)
    data = resp.json()
    assert "T1064" not in _all_technique_ids(data)  # deprecated excluded by default

    # Multi-tactic techniques appear in every relevant column
    assert _find_cell(data, "privilege-escalation", "T1548") is not None
    assert _find_cell(data, "defense-evasion", "T1548") is not None

    resp = await client.get("/api/attack/matrix", params={"include_deprecated": "true"}, headers=auth_headers)
    data = resp.json()
    deprecated = _find_cell(data, "execution", "T1064")
    assert deprecated is not None
    assert deprecated["is_deprecated"] is True
