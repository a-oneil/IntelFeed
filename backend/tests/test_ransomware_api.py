"""Tests for the ransomware victim tracker API (Phase 3)."""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from app.models.country import Country
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.threat_actor import ThreatActor
from app.models.user_entity_watch import UserEntityWatch


def _disc(
    victim_id,
    group_id,
    *,
    source="ransomware.live",
    hours_ago=2,
    sector="healthcare",
    country_id=None,
    group_raw="Qilin",
):
    return VictimDisclosure(
        victim_id=victim_id,
        group_id=group_id,
        group_name_raw=group_raw,
        posted_at=datetime.now(UTC) - timedelta(hours=hours_ago),
        sector=sector,
        country_id=country_id,
        source=source,
        guid=uuid.uuid4().hex[:32],
        leak_site_url="http://leak.example/x",
        claimed_data="180K records",
    )


@pytest.fixture
async def seeded(db_session):
    us = Country(name="United States", iso_code="US", aliases=[])
    se = Country(name="Sweden", iso_code="SE", aliases=[])
    qilin = ThreatActor(name="Qilin", actor_type="ransomware")
    lockbit = ThreatActor(name="LockBit", actor_type="ransomware")
    db_session.add_all([us, se, qilin, lockbit])
    await db_session.flush()

    now = datetime.now(UTC)
    v1 = RansomwareVictim(
        name="St. Vessel Health",
        domain="stvessel.example",
        country_id=us.id,
        sector="healthcare",
        first_seen_at=now - timedelta(hours=48),
        last_seen_at=now,
        disclosure_count=2,
    )
    v2 = RansomwareVictim(
        name="Brügmann Fertigung",
        domain="bruegmann.example",
        country_id=se.id,
        sector="manufacturing",
        first_seen_at=now - timedelta(hours=10),
        last_seen_at=now,
        disclosure_count=1,
    )
    db_session.add_all([v1, v2])
    await db_session.flush()

    # v1 re-listed by two groups; v2 once.
    db_session.add_all(
        [
            _disc(v1.id, qilin.id, hours_ago=2, sector="healthcare", country_id=us.id, group_raw="Qilin"),
            _disc(v1.id, lockbit.id, hours_ago=40, sector="healthcare", country_id=us.id, group_raw="LockBit"),
            _disc(v2.id, qilin.id, hours_ago=8, sector="manufacturing", country_id=se.id, group_raw="Qilin"),
        ]
    )
    await db_session.flush()
    return {"v1": v1.id, "v2": v2.id, "qilin": qilin.id, "lockbit": lockbit.id, "us": us.id, "se": se.id}


@pytest.mark.asyncio
async def test_list_disclosures_and_filters(client, auth_headers, seeded):
    r = await client.get("/api/ransomware/disclosures", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert len(body["items"]) == 3
    # Newest first.
    assert body["items"][0]["is_new"] is True
    first = body["items"][0]
    assert first["group_name"] in {"Qilin", "LockBit"}
    assert first["group_color"] in {"qilin", "lockbit"}

    # Filter by group.
    r = await client.get("/api/ransomware/disclosures", params={"group": "LockBit"}, headers=auth_headers)
    assert r.json()["total"] == 1

    # Filter by sector.
    r = await client.get("/api/ransomware/disclosures", params={"sector": "manufacturing"}, headers=auth_headers)
    assert r.json()["total"] == 1

    # Filter by country ISO.
    r = await client.get("/api/ransomware/disclosures", params={"country": "SE"}, headers=auth_headers)
    assert r.json()["total"] == 1

    # Search.
    r = await client.get("/api/ransomware/disclosures", params={"q": "vessel"}, headers=auth_headers)
    assert r.json()["total"] == 2


@pytest.mark.asyncio
async def test_watched_only_and_watch_flag(client, auth_headers, seeded, test_user, db_session):
    db_session.add(
        UserEntityWatch(created_by=test_user.id, entity_type="ransomware_victim", entity_id=seeded["v1"], mode="watch")
    )
    await db_session.flush()

    r = await client.get("/api/ransomware/disclosures", params={"watched_only": "true"}, headers=auth_headers)
    body = r.json()
    assert body["total"] == 2  # both v1 disclosures
    assert all(item["watched"] for item in body["items"])


@pytest.mark.asyncio
async def test_stats(client, auth_headers, seeded):
    r = await client.get("/api/ransomware/stats", params={"days": 90}, headers=auth_headers)
    assert r.status_code == 200
    s = r.json()
    assert s["totals"]["victims"] == 3
    assert s["totals"]["groups_active"] == 2
    assert s["totals"]["sectors_hit"] == 2
    # groups leaderboard: Qilin has 2, LockBit 1.
    names = {g["name"]: g["victims"] for g in s["groups"]}
    assert names.get("Qilin") == 2
    assert names.get("LockBit") == 1
    assert s["most_active_group"]["name"] == "Qilin"
    # sectors + countries present.
    assert {x["sector"] for x in s["sectors"]} == {"healthcare", "manufacturing"}
    assert any(c["iso_code"] == "US" and c["victims"] == 2 for c in s["countries"])
    # Timeseries: contiguous weekly buckets, stopping before the current week.
    # That last week is still in progress, so plotting it would show a partial
    # -bucket cliff. Whether the 40h-old disclosure lands before this week's
    # Monday depends on what day the suite runs, so the expected total is
    # derived from the same cutoff rather than hard-coded.
    points = s["timeseries"]
    assert len(points) >= 1

    now = datetime.now(UTC)
    current_week_start = (now - timedelta(days=now.weekday())).date()
    week_starts = [date.fromisoformat(p["week_start"]) for p in points]

    assert all(ws < current_week_start for ws in week_starts)
    assert all(b - a == timedelta(days=7) for a, b in zip(week_starts, week_starts[1:]))
    assert week_starts[-1] == current_week_start - timedelta(days=7)

    expected = sum(1 for hours_ago in (2, 8, 40) if (now - timedelta(hours=hours_ago)).date() < current_week_start)
    assert sum(p["count"] for p in points) == expected


@pytest.mark.asyncio
async def test_stats_watchlist_exposure(client, auth_headers, seeded, test_user, db_session):
    db_session.add_all(
        [
            UserEntityWatch(
                created_by=test_user.id, entity_type="threat_actor", entity_id=seeded["qilin"], mode="watch"
            ),
            UserEntityWatch(
                created_by=test_user.id, entity_type="ransomware_victim", entity_id=seeded["v2"], mode="watch"
            ),
        ]
    )
    await db_session.flush()
    r = await client.get("/api/ransomware/stats", params={"days": 90}, headers=auth_headers)
    s = r.json()
    kinds = {(e["kind"], e["name"]): e for e in s["watchlist_exposure"]}
    assert kinds[("watched group", "Qilin")]["hit"] is True
    assert kinds[("watched org", "Brügmann Fertigung")]["hit"] is True
    assert s["totals"]["watchlist_hits"] >= 2


@pytest.mark.asyncio
async def test_victim_detail(client, auth_headers, seeded):
    r = await client.get(f"/api/ransomware/victims/{seeded['v1']}", headers=auth_headers)
    assert r.status_code == 200
    v = r.json()
    assert v["name"] == "St. Vessel Health"
    assert v["disclosure_count"] == 2
    assert len(v["disclosures"]) == 2
    assert {g["name"] for g in v["groups"]} == {"Qilin", "LockBit"}


@pytest.mark.asyncio
async def test_victim_detail_404(client, auth_headers, seeded):
    r = await client.get(f"/api/ransomware/victims/{uuid.uuid4()}", headers=auth_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_group_victims(client, auth_headers, seeded):
    r = await client.get(f"/api/ransomware/groups/{seeded['qilin']}/victims", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2  # Qilin listed v1 and v2
    names = {item["name"] for item in body["items"]}
    assert names == {"St. Vessel Health", "Brügmann Fertigung"}
