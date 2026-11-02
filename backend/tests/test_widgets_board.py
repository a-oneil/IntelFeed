"""Smoke tests for the round-2 dashboard board widgets.

Mirrors tests/test_widgets.py: hit the endpoint with auth, assert 200 and the
top-level response shape. A few tests seed rows to prove the aggregate actually
counts something rather than only surviving on an empty database.
"""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from httpx import AsyncClient

from app.models.cve import CVE
from app.models.entry_signal import EntrySignal
from app.models.entry_state import UserEntryState
from app.models.user_entity_watch import UserEntityWatch


@pytest.mark.asyncio
async def test_overview(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/overview", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "headline" in data
    assert "entities" in data
    assert "series" in data
    for key in ("entries", "radar", "unread", "detections"):
        assert key in data["headline"]
        assert "count" in data["headline"][key]
    # All eight workbench entity types are represented.
    types = {e["type"] for e in data["entities"]}
    assert types == {
        "threat_actor",
        "malware",
        "tool",
        "cve",
        "ttp",
        "vendor",
        "product",
        "country",
    }
    assert all("count" in e and "trend" in e for e in data["entities"])
    assert isinstance(data["series"]["entries"], list)


@pytest.mark.asyncio
async def test_overview_date_range(client: AsyncClient, auth_headers: dict):
    resp = await client.get(
        "/api/widgets/overview",
        headers=auth_headers,
        params={"date_from": "2026-01-01", "date_to": "2026-03-04"},
    )
    assert resp.status_code == 200
    # Series is zero-filled across the whole window, one point per day.
    assert len(resp.json()["series"]["entries"]) == 63


@pytest.mark.asyncio
async def test_watchlist_pulse_empty(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/watchlist-pulse", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["window_days"] == 14


@pytest.mark.asyncio
async def test_watchlist_pulse_with_watch(
    client: AsyncClient, auth_headers: dict, db_session, test_user, test_threat_actor
):
    db_session.add(
        UserEntityWatch(
            created_by=test_user.id,
            entity_type="threat_actor",
            entity_id=test_threat_actor.id,
            mode="watch",
        )
    )
    await db_session.flush()

    resp = await client.get("/api/widgets/watchlist-pulse", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["name"] == "APT29"
    assert items[0]["entity_type"] == "threat_actor"
    # 14-day window → 15 inclusive day buckets.
    assert len(items[0]["points"]) == 15
    assert items[0]["total"] == 0


@pytest.mark.asyncio
async def test_ransomware_pulse(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/ransomware-pulse", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "weeks" in data
    assert "groups" in data
    assert data["groups"][-1] == "Other"
    assert "victims" in data["totals"]
    assert "groups_active" in data["totals"]


@pytest.mark.asyncio
async def test_rules_attention(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/rules-attention", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total_rules" in data
    assert "stale_count" in data


@pytest.mark.asyncio
async def test_targeting_grid(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/targeting-grid", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "regions" in data
    assert "rows" in data
    assert "max_cell" in data


@pytest.mark.asyncio
async def test_kev_deadlines(client: AsyncClient, auth_headers: dict, db_session):
    # The widget counts days from the server's local date (``date.today()``),
    # so the due date is built from the same calendar, not from UTC.
    due = date.today() + timedelta(days=5)
    db_session.add(
        CVE(
            cve_id="CVE-2026-90001",
            cvss_score=9.8,
            severity="critical",
            is_kev=True,
            kev_due_date=due,
            exploit_sources=[{"source": "kev", "vendorProject": "Acme", "product": "Widget"}],
        )
    )
    await db_session.flush()

    resp = await client.get("/api/widgets/kev-deadlines", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["due_7d"] == 1
    item = next(i for i in data["items"] if i["cve_id"] == "CVE-2026-90001")
    assert item["days_left"] == 5
    assert item["vendor"] == "Acme"
    assert item["kev_due_date"] == due.isoformat()


@pytest.mark.asyncio
async def test_triage_flow(client: AsyncClient, auth_headers: dict, db_session, test_user, test_entry):
    db_session.add(
        UserEntryState(
            user_id=test_user.id,
            entry_id=test_entry.id,
            is_read=True,
            read_at=datetime.now(UTC) - timedelta(days=1),
        )
    )
    await db_session.flush()

    resp = await client.get("/api/widgets/triage-flow", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "days" in data
    assert "backlog" in data
    # Calendar-aligned: exactly `days` full days ending today, no partial leading
    # column (an unaligned start used to emit a 15th, near-empty phantom day).
    assert len(data["days"]) == 14
    assert data["days"][-1]["date"] == datetime.now(UTC).date().isoformat()
    assert sum(d["read"] for d in data["days"]) == 1


@pytest.mark.asyncio
async def test_triage_flow_counts_arrival_not_publication(
    client: AsyncClient, auth_headers: dict, db_session, test_entry
):
    """Intake is measured by fetched_at.

    Regression guard: it used to key off published_at, so anything backdated (or
    missing a publish date entirely, like this fixture) never showed as arriving —
    the intake arm silently undercounted by several times.
    """
    test_entry.published_at = datetime.now(UTC) - timedelta(days=400)
    await db_session.flush()

    resp = await client.get("/api/widgets/triage-flow", headers=auth_headers, params={"days": 14})
    assert resp.status_code == 200
    days = resp.json()["days"]
    assert sum(d["arrived"] for d in days) == 1
    assert days[-1]["arrived"] == 1


@pytest.mark.asyncio
async def test_campaign_momentum(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/campaign-momentum", headers=auth_headers)
    assert resp.status_code == 200
    assert "items" in resp.json()


@pytest.mark.asyncio
async def test_under_reported(client: AsyncClient, auth_headers: dict, db_session, test_entry):
    test_entry.published_at = datetime.now(UTC) - timedelta(days=1)
    db_session.add(
        EntrySignal(
            entry_id=test_entry.id,
            signal_type="under_reported",
            score=1.0,
            explanation="CVE-2026-0001 is KEV-listed but only 1 source covering it",
            payload={"cve_ids": ["CVE-2026-0001"], "feeds_covering": 1},
        )
    )
    await db_session.flush()

    resp = await client.get("/api/widgets/under-reported", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["feeds_covering"] == 1
    assert items[0]["cve_ids"] == ["CVE-2026-0001"]


@pytest.mark.asyncio
async def test_morning_briefing_empty(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/morning-briefing", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "generated_at" in data


@pytest.mark.asyncio
async def test_relationship_inbox(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/relationship-inbox", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    for key in ("claimed", "adjudicated", "confirmed"):
        assert key in data["ladder"]
    assert "items" in data


@pytest.mark.asyncio
async def test_playbook_drift_no_watches(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/widgets/playbook-drift", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total_new"] == 0


@pytest.mark.asyncio
async def test_playbook_drift_detects_new_technique(
    client: AsyncClient, auth_headers: dict, db_session, test_user, test_entry, test_threat_actor, test_ttp
):
    """An actor+technique pair seen only inside the window counts as drift."""
    from app.models.threat_actor import EntryThreatActor
    from app.models.ttp import EntryTTP

    db_session.add(
        UserEntityWatch(
            created_by=test_user.id,
            entity_type="threat_actor",
            entity_id=test_threat_actor.id,
            mode="watch",
        )
    )
    test_entry.published_at = datetime.now(UTC) - timedelta(days=2)
    db_session.add(EntryThreatActor(entry_id=test_entry.id, threat_actor_id=test_threat_actor.id))
    db_session.add(EntryTTP(entry_id=test_entry.id, ttp_id=test_ttp.id))
    await db_session.flush()

    resp = await client.get("/api/widgets/playbook-drift", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_new"] == 1
    assert data["items"][0]["actor_name"] == "APT29"
    assert data["items"][0]["additions"][0]["technique_id"] == "T1566.001"


@pytest.mark.asyncio
async def test_board_widgets_require_auth(client: AsyncClient):
    resp = await client.get("/api/widgets/overview")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_wide_time_range_is_accepted(client: AsyncClient, auth_headers: dict):
    """The 'all' range sends days=36500; endpoints must not 422 on it.

    Regression guard: these bounds used to cap at 90/365, so the widgets
    silently fell back to their empty state whenever the dashboard range was
    set to 1y or All.
    """
    for path in ("/api/widgets/new-cves", "/api/widgets/new-actors", "/api/widgets/new-detections"):
        resp = await client.get(path, headers=auth_headers, params={"days": 36500})
        assert resp.status_code == 200, f"{path} rejected days=36500"

    resp = await client.get("/api/analytics/velocity", headers=auth_headers, params={"days": 36500})
    assert resp.status_code == 200
    resp = await client.get("/api/analytics/trending/threat_actor", headers=auth_headers, params={"days": 36500})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_day_window_endpoints_accept_the_full_range_band(client: AsyncClient, auth_headers: dict):
    """The 24h range sends days=1 and widgets clamp "all" to 365 — both must pass.

    Regression guard: these were ge=7/le=90, so selecting 24h on the dashboard
    returned 400 and the widget rendered its empty state instead of the data.
    """
    for path in ("/api/widgets/watchlist-pulse", "/api/widgets/triage-flow"):
        for days in (1, 14, 365):
            resp = await client.get(path, headers=auth_headers, params={"days": days})
            assert resp.status_code == 200, f"{path} rejected days={days}"
            if path.endswith("triage-flow"):
                assert len(resp.json()["days"]) == days, f"{path} days={days} grid length"


@pytest.mark.asyncio
async def test_kev_matches_exposes_kev_fields(client: AsyncClient, auth_headers: dict, db_session):
    """kev-matches now carries is_kev + kev_due_date for the deadline column."""
    from app.models.entry import Entry
    from app.models.feed import Feed

    feed = Feed(title="KEV Feed", url="https://example.com/kev.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, title="KEV entry", guid=f"kev-{uuid.uuid4()}", url="https://example.com/a")
    cve = CVE(
        cve_id="CVE-2026-90002",
        cvss_score=9.1,
        severity="critical",
        is_kev=True,
        kev_due_date=(datetime.now(UTC) + timedelta(days=10)).date(),
        exploit_availability="active_exploitation",
    )
    db_session.add_all([entry, cve])
    await db_session.flush()

    from app.models.cve import EntryCVE

    db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
    await db_session.flush()

    resp = await client.get("/api/widgets/kev-matches", headers=auth_headers)
    assert resp.status_code == 200
    row = next(r for r in resp.json() if r["cve_id"] == "CVE-2026-90002")
    assert row["is_kev"] is True
    assert row["kev_due_date"] is not None
