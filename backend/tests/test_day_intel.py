"""Tests for the /entries/day-intel day-divider aggregation.

Covers the top-entity picks, the exploited-first CVE preference, and the
actively-exploited / new-today signals.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.entry_sector import EntrySector
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP

# Fixed reference so the window and first_seen_at math are deterministic.
NOW = datetime.now(UTC)
WINDOW_MID = NOW - timedelta(hours=6)
SINCE = (NOW - timedelta(hours=12)).isoformat()
BEFORE = NOW.isoformat()


async def _entry(db_session, feed_id, n, when=WINDOW_MID):
    e = Entry(
        feed_id=feed_id,
        title=f"Entry {n}",
        guid=f"day-intel-{n}",
        url=f"https://example.com/{n}",
        published_at=when,
    )
    db_session.add(e)
    await db_session.flush()
    return e


@pytest.fixture
async def seeded(db_session):
    """A day window with two actors, malware, a technique, a sector, and two
    CVEs — one loud-but-benign, one KEV-exploited-but-quiet."""
    feed = Feed(title="Intel Feed", url="https://example.com/f.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    e1 = await _entry(db_session, feed.id, 1)
    e2 = await _entry(db_session, feed.id, 2)
    e3 = await _entry(db_session, feed.id, 3)

    # Top threat_actor: mentioned in 2 entries, first tracked inside the window (new).
    top_actor = ThreatActor(name="APT-Test", first_seen_at=WINDOW_MID)
    # Runner-up threat_actor: 1 entry, first tracked long ago (not new).
    old_actor = ThreatActor(name="OldActor", first_seen_at=NOW - timedelta(days=30))
    malware = MalwareFamily(name="LockBit", first_seen_at=NOW - timedelta(days=30))
    ttp = TTP(technique_id="T9999", technique_name="Test Technique")
    db_session.add_all([top_actor, old_actor, malware, ttp])
    await db_session.flush()

    db_session.add_all(
        [
            EntryThreatActor(entry_id=e1.id, threat_actor_id=top_actor.id),
            EntryThreatActor(entry_id=e2.id, threat_actor_id=top_actor.id),
            EntryThreatActor(entry_id=e3.id, threat_actor_id=old_actor.id),
            EntryMalware(entry_id=e1.id, malware_family_id=malware.id),
            EntryTTP(entry_id=e1.id, ttp_id=ttp.id),
            EntryTTP(entry_id=e2.id, ttp_id=ttp.id),
            EntryTTP(entry_id=e3.id, ttp_id=ttp.id),
            EntrySector(entry_id=e1.id, sector="healthcare"),
            EntrySector(entry_id=e2.id, sector="healthcare"),
        ]
    )

    # Loud CVE: 3 mentions, not exploited. Quiet CVE: 1 mention, KEV + active.
    loud = CVE(cve_id="CVE-2026-1111", is_kev=False, cvss_score=7.5, severity="high")
    kev = CVE(
        cve_id="CVE-2026-2222",
        is_kev=True,
        exploit_availability="active_exploitation",
        cvss_score=9.8,
        severity="critical",
    )
    db_session.add_all([loud, kev])
    await db_session.flush()
    db_session.add_all(
        [
            EntryCVE(entry_id=e1.id, cve_id=loud.id),
            EntryCVE(entry_id=e2.id, cve_id=loud.id),
            EntryCVE(entry_id=e3.id, cve_id=loud.id),
            EntryCVE(entry_id=e1.id, cve_id=kev.id),
        ]
    )
    await db_session.flush()
    return feed


async def test_day_intel_top_entities(client, auth_headers, seeded):
    resp = await client.get(
        "/api/entries/day-intel",
        params={"since": SINCE, "before": BEFORE},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["threat_actor"]["name"] == "APT-Test"
    assert data["threat_actor"]["count"] == 2
    assert data["malware"]["name"] == "LockBit"
    assert data["ttp"]["technique_id"] == "T9999"
    assert data["ttp"]["name"] == "Test Technique"
    assert data["ttp"]["count"] == 3
    assert data["sector"]["slug"] == "healthcare"
    assert data["sector"]["name"] == "Healthcare"
    assert data["sector"]["count"] == 2


async def test_day_intel_cve_prefers_exploited_over_frequency(client, auth_headers, seeded):
    """The KEV CVE (1 mention) should beat the louder non-KEV CVE (3 mentions)."""
    resp = await client.get(
        "/api/entries/day-intel",
        params={"since": SINCE, "before": BEFORE},
        headers=auth_headers,
    )
    data = resp.json()
    assert data["cve"]["name"] == "CVE-2026-2222"
    assert data["cve"]["kev"] is True
    assert data["cve"]["cvss_score"] == 9.8
    assert data["cve"]["severity"] == "critical"


async def test_day_intel_signals(client, auth_headers, seeded):
    resp = await client.get(
        "/api/entries/day-intel",
        params={"since": SINCE, "before": BEFORE},
        headers=auth_headers,
    )
    signals = resp.json()["signals"]
    assert signals["actively_exploited"] == 1
    assert signals["new"] is not None
    assert signals["new"]["type"] == "threat_actor"
    assert signals["new"]["name"] == "APT-Test"
    assert signals["new"]["total"] == 1


async def test_day_intel_empty_window(client, auth_headers, db_session):
    resp = await client.get(
        "/api/entries/day-intel",
        params={"since": SINCE, "before": BEFORE},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["threat_actor"] is None
    assert data["cve"] is None
    assert data["signals"]["actively_exploited"] == 0
    assert data["signals"]["new"] is None


async def test_entries_exploited_cves_filter(client, auth_headers, seeded):
    """Clicking the badge filters the list to the articles behind its number.

    Only Entry 1 mentions the KEV CVE; Entries 2 and 3 mention the loud
    non-exploited one, so they must drop out.
    """
    resp = await client.get(
        "/api/entries",
        params={"since": SINCE, "before": BEFORE, "exploited_cves": "true"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    titles = [e["title"] for e in resp.json()["items"]]
    assert titles == ["Entry 1"]

    count = await client.get(
        "/api/entries/count",
        params={"since": SINCE, "before": BEFORE, "exploited_cves": "true"},
        headers=auth_headers,
    )
    assert count.json()["total"] == 1


async def test_entries_exploited_cves_filter_omitted_is_unfiltered(client, auth_headers, seeded):
    resp = await client.get(
        "/api/entries",
        params={"since": SINCE, "before": BEFORE},
        headers=auth_headers,
    )
    assert len(resp.json()["items"]) == 3


async def test_entries_exploited_cves_counts_active_exploitation_without_kev(client, auth_headers, db_session, seeded):
    """Active exploitation alone qualifies — KEV membership is not required.

    The two columns are set by different writers (CISA's catalog vs. analysts
    and the extraction pipeline), so the filter has to accept either.
    """
    e4 = await _entry(db_session, seeded.id, 4)
    cve = CVE(cve_id="CVE-2026-3333", is_kev=False, exploit_availability="active_exploitation")
    db_session.add(cve)
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=e4.id, cve_id=cve.id))
    await db_session.flush()

    resp = await client.get(
        "/api/entries",
        params={"since": SINCE, "before": BEFORE, "exploited_cves": "true"},
        headers=auth_headers,
    )
    assert sorted(e["title"] for e in resp.json()["items"]) == ["Entry 1", "Entry 4"]


@pytest.mark.parametrize(
    "entity_type,name_attr,expected",
    [
        ("threat_actor", "top_actor", ["Entry 1", "Entry 2"]),
        ("malware", "malware", ["Entry 1"]),
        ("ttp", "ttp", ["Entry 1", "Entry 2", "Entry 3"]),
    ],
)
async def test_entries_entity_filter(client, auth_headers, db_session, seeded, entity_type, name_attr, expected):
    """Each chip's entity filter returns exactly the entries behind its count."""
    from sqlalchemy import select

    lookup = {
        "threat_actor": (ThreatActor, "APT-Test"),
        "malware": (MalwareFamily, "LockBit"),
        "ttp": (TTP, "T9999"),
    }
    model, ident = lookup[entity_type]
    col = TTP.technique_id if entity_type == "ttp" else model.name
    entity = (await db_session.execute(select(model).where(col == ident))).scalar_one()

    resp = await client.get(
        "/api/entries",
        params={
            "since": SINCE,
            "before": BEFORE,
            "entity_type": entity_type,
            "entity_id": str(entity.id),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert sorted(e["title"] for e in resp.json()["items"]) == expected


async def test_entries_sector_filter(client, auth_headers, seeded):
    resp = await client.get(
        "/api/entries",
        params={"since": SINCE, "before": BEFORE, "sector": "healthcare"},
        headers=auth_headers,
    )
    assert sorted(e["title"] for e in resp.json()["items"]) == ["Entry 1", "Entry 2"]


async def test_entries_entity_filter_rejects_unknown_type(client, auth_headers, seeded):
    resp = await client.get(
        "/api/entries",
        params={"entity_type": "campaign", "entity_id": "00000000-0000-0000-0000-000000000001"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


async def test_entries_entity_filter_rejects_half_a_filter(client, auth_headers, seeded):
    """A type with no id would otherwise pass through as no filter at all."""
    resp = await client.get(
        "/api/entries",
        params={"entity_type": "threat_actor"},
        headers=auth_headers,
    )
    assert resp.status_code == 422
