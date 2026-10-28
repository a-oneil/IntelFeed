"""Tests for the ransomware leak-site / victim tracker (Phase 2).

Covers the adapter parse/incremental-filter and the resolver/dedup path:
domain vs name dedup, one org re-listed by a second group = 1 victim / 2 disclosures,
group→ThreatActor(actor_type=ransomware), country-by-ISO, sector normalization, and
(source, guid) idempotency on re-run.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import func, select

from app.adapters.base import ParsedFeedMeta
from app.adapters.ransomware_live import RansomwareLiveAdapter, make_disclosure_guid
from app.enrichment.gateway import SourceGateway
from app.intelligence.ransomware_sync import sync_ransomware_victims
from app.models.country import Country
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.threat_actor import ThreatActor
from app.models.user import User
from app.models.user_entity_watch import UserEntityWatch

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _raw(victim, group, discovered, *, domain=None, country="SE", activity="Healthcare", claim_url=None):
    return {
        "victim": victim,
        "group": group,
        "discovered": discovered,
        "attackdate": discovered,
        "domain": domain,
        "country": country,
        "activity": activity,
        "claim_url": claim_url or f"http://leak.example/{victim}",
        "description": "180K records / 420GB",
    }


class _StubAdapter(RansomwareLiveAdapter):
    """Returns pre-parsed entries from raw dicts, bypassing HTTP (reuses _parse_victim)."""

    SOURCE = "ransomware.live"

    def __init__(self, raws):
        self._raws = raws

    async def fetch_entries(self, config, since=None):
        cutoff = since or _EPOCH
        entries = [e for r in self._raws if (e := self._parse_victim(r, cutoff)) is not None]
        return ParsedFeedMeta(title="stub"), entries


@pytest.fixture
async def sweden(db_session):
    c = Country(name="Sweden", iso_code="SE", aliases=[])
    db_session.add(c)
    await db_session.commit()
    return c


# --- adapter --------------------------------------------------------------


@pytest.mark.asyncio
async def test_adapter_parses_and_filters_by_cutoff():
    now = datetime.now(UTC)
    recent = (now - timedelta(hours=1)).isoformat()
    old = (now - timedelta(days=30)).isoformat()
    rows = [
        _raw("Acme Corp", "qilin", recent, domain="acme.com"),
        _raw("Old Victim", "lockbit", old, domain="old.com"),
    ]
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = rows

    with patch("app.adapters.ransomware_live.httpx.AsyncClient") as mock_client:
        instance = mock_client.return_value.__aenter__.return_value
        instance.get.return_value = mock_resp
        adapter = RansomwareLiveAdapter(SourceGateway("ransomware_live"))
        _meta, entries = await adapter.fetch_entries({}, since=now - timedelta(days=1))

    # Old Victim is older than the cutoff → filtered out.
    assert len(entries) == 1
    e = entries[0]
    assert e.metadata["victim"] == "Acme Corp"
    assert e.metadata["group"] == "qilin"
    assert e.metadata["domain"] == "acme.com"
    assert e.metadata["country"] == "SE"
    assert e.metadata["activity"] == "Healthcare"
    # guid is stable for the same (source, group, victim, discovered).
    assert e.guid == make_disclosure_guid("ransomware.live", "qilin", "Acme Corp", recent)


# --- resolver / dedup -----------------------------------------------------


@pytest.mark.asyncio
async def test_sync_creates_victim_group_and_disclosure(db_session, sweden):
    disc = datetime.now(UTC).isoformat()
    adapter = _StubAdapter([_raw("St. Vessel Health", "qilin", disc, domain="stvessel.example")])
    stats = await sync_ransomware_victims(db_session, since=_EPOCH, adapters=[adapter], catalog={})

    assert stats["new_disclosures"] == 1
    assert stats["new_victims"] == 1
    assert stats["new_groups"] == 1

    victim = (await db_session.execute(select(RansomwareVictim))).scalar_one()
    assert victim.name == "St. Vessel Health"
    assert victim.domain == "stvessel.example"
    assert victim.country_id == sweden.id  # resolved via ISO code "SE"
    assert victim.sector == "healthcare"  # normalized from "Healthcare"
    assert victim.disclosure_count == 1

    group = (await db_session.execute(select(ThreatActor).where(ThreatActor.name == "qilin"))).scalar_one()
    assert group.actor_type == "ransomware"

    disclosure = (await db_session.execute(select(VictimDisclosure))).scalar_one()
    assert disclosure.victim_id == victim.id
    assert disclosure.group_id == group.id
    assert disclosure.group_name_raw == "qilin"
    assert disclosure.source == "ransomware.live"
    assert disclosure.claimed_data == "180K records / 420GB"


@pytest.mark.asyncio
async def test_relisting_by_second_group_is_one_victim_two_disclosures(db_session, sweden):
    d1 = datetime.now(UTC).isoformat()
    d2 = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    adapter = _StubAdapter(
        [
            _raw("St. Vessel Health", "qilin", d1, domain="stvessel.example"),
            _raw("St. Vessel Health", "lockbit", d2, domain="stvessel.example"),
        ]
    )
    stats = await sync_ransomware_victims(db_session, since=_EPOCH, adapters=[adapter], catalog={})

    assert stats["new_victims"] == 1
    assert stats["new_disclosures"] == 2

    victim = (await db_session.execute(select(RansomwareVictim))).scalar_one()
    assert victim.disclosure_count == 2
    disclosure_count = await db_session.scalar(select(func.count()).select_from(VictimDisclosure))
    assert disclosure_count == 2
    # Two distinct ransomware groups were created.
    result = await db_session.execute(select(ThreatActor).where(ThreatActor.actor_type == "ransomware"))
    groups = result.scalars().all()
    assert {g.name for g in groups} == {"qilin", "lockbit"}


@pytest.mark.asyncio
async def test_domain_dedup_across_name_variants(db_session, sweden):
    d1 = datetime.now(UTC).isoformat()
    d2 = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    adapter = _StubAdapter(
        [
            _raw("St Vessel Health", "qilin", d1, domain="stvessel.example"),
            _raw("St. Vessel Health, Inc.", "qilin", d2, domain="stvessel.example"),
        ]
    )
    await sync_ransomware_victims(db_session, since=_EPOCH, adapters=[adapter], catalog={})

    victims = (await db_session.execute(select(RansomwareVictim))).scalars().all()
    assert len(victims) == 1  # matched on domain despite different name surface forms
    assert victims[0].disclosure_count == 2


@pytest.mark.asyncio
async def test_guid_idempotent_on_rerun(db_session, sweden):
    disc = datetime.now(UTC).isoformat()
    raws = [_raw("Acme Corp", "qilin", disc, domain="acme.example")]

    first = await sync_ransomware_victims(db_session, since=_EPOCH, adapters=[_StubAdapter(raws)], catalog={})
    assert first["new_disclosures"] == 1

    second = await sync_ransomware_victims(db_session, since=_EPOCH, adapters=[_StubAdapter(raws)], catalog={})
    assert second["new_disclosures"] == 0
    assert second["skipped_existing"] == 1

    total = await db_session.scalar(select(func.count()).select_from(VictimDisclosure))
    assert total == 1


@pytest.mark.asyncio
async def test_group_folds_into_tracked_actor_and_skips_junk(db_session, sweden):
    """Slugs resolve through the app's resolver onto already-tracked actors instead of
    creating duplicates: 'alphv' → BlackCat (via its ALPHV alias), 'lockbit3' → LockBit
    (via de-versioned 'lockbit'), and junk 'J' links no actor."""
    blackcat = ThreatActor(name="BlackCat", aliases=["ALPHV"], actor_type="ransomware")
    lockbit = ThreatActor(name="LockBit", aliases=["LockBit 3.0"], actor_type="ransomware")
    db_session.add_all([blackcat, lockbit])
    await db_session.flush()

    catalog = {
        "alphv": {"name": "alphv", "altname": "blackcat"},
        "lockbit3": {"name": "lockbit3", "altname": None},
    }
    t0 = datetime.now(UTC)
    adapter = _StubAdapter(
        [
            _raw("Org A", "alphv", t0.isoformat(), domain="a.example"),
            _raw("Org B", "lockbit3", (t0 + timedelta(hours=1)).isoformat(), domain="b.example"),
            _raw("Org C", "J", (t0 + timedelta(hours=2)).isoformat(), domain="c.example"),
        ]
    )
    stats = await sync_ransomware_victims(db_session, since=_EPOCH, adapters=[adapter], catalog=catalog)

    # No new ransomware actors — everything folded or skipped.
    assert stats["new_groups"] == 0

    async def _disc(org):
        return (
            await db_session.execute(
                select(VictimDisclosure)
                .join(RansomwareVictim, VictimDisclosure.victim_id == RansomwareVictim.id)
                .where(RansomwareVictim.name == org)
            )
        ).scalar_one()

    assert (await _disc("Org A")).group_id == blackcat.id
    assert (await _disc("Org B")).group_id == lockbit.id
    junk = await _disc("Org C")
    assert junk.group_id is None
    assert junk.group_name_raw == "J"

    # Matched actors learned the leak-site slug as an alias for next time.
    await db_session.refresh(lockbit)
    assert "lockbit3" in (lockbit.aliases or [])


# --- watchlist alert emission (Phase 5) -----------------------------------


@pytest.mark.asyncio
async def test_watchlist_alert_emission(db_session, monkeypatch):
    from app.intelligence import ransomware_sync as rs
    from app.intelligence.sectors import sector_uuid

    user = User(username="watcher", password_hash="x", role="user")
    sector_watcher = User(username="hospital-ciso", password_hash="x", role="user")
    victim = RansomwareVictim(name="Acme Corp", first_seen_at=_EPOCH, last_seen_at=_EPOCH, disclosure_count=1)
    group = ThreatActor(name="Qilin", actor_type="ransomware")
    db_session.add_all([user, sector_watcher, victim, group])
    await db_session.flush()
    db_session.add_all(
        [
            UserEntityWatch(created_by=user.id, entity_type="ransomware_victim", entity_id=victim.id, mode="watch"),
            # Sector interest is a per-user watch like any other (the global my_sectors setting is gone).
            UserEntityWatch(
                created_by=sector_watcher.id, entity_type="sector", entity_id=sector_uuid("healthcare"), mode="watch"
            ),
        ]
    )
    await db_session.flush()

    published: list = []
    monkeypatch.setattr(rs, "publish_event", lambda uid, ev, data: published.append((uid, ev, data)))

    new_disclosures = [
        {
            "disclosure_id": "d1",
            "victim_id": str(victim.id),
            "victim_name": "Acme Corp",
            "group_id": str(group.id),
            "group_name": "Qilin",
            "sector": "healthcare",
            "sector_label": "Healthcare",
            "country_id": None,
            "posted_at": datetime.now(UTC).isoformat(),
            "leak_site_url": None,
            "source": "ransomware.live",
        }
    ]
    sent = await rs.emit_watchlist_alerts(db_session, new_disclosures)

    # One per-user org hit + one per-user sector hit.
    assert sent == 2
    assert any(
        uid == str(user.id) and ev == "ransomware_disclosure" and data["reason"] == "watched org"
        for uid, ev, data in published
    )
    assert any(uid == str(sector_watcher.id) and data["reason"] == "watched sector" for uid, _ev, data in published)


@pytest.mark.asyncio
async def test_watchlist_alert_no_watchers_is_silent(db_session, monkeypatch):
    from app.intelligence import ransomware_sync as rs

    victim = RansomwareVictim(name="Nobody Watches", first_seen_at=_EPOCH, last_seen_at=_EPOCH)
    db_session.add(victim)
    await db_session.flush()

    calls: list = []
    monkeypatch.setattr(rs, "publish_event", lambda *a: calls.append(a))

    sent = await rs.emit_watchlist_alerts(
        db_session,
        [
            {
                "disclosure_id": "d",
                "victim_id": str(victim.id),
                "victim_name": "Nobody Watches",
                "group_id": None,
                "group_name": None,
                "sector": "manufacturing",
                "sector_label": "Manufacturing",
                "country_id": None,
                "posted_at": datetime.now(UTC).isoformat(),
                "leak_site_url": None,
                "source": "ransomware.live",
            }
        ],
    )
    assert sent == 0
    assert calls == []
