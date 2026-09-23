"""Tests for correlation event detection."""

import uuid

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.correlation_events import CorrelationEvent, correlate_new_entities
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP


@pytest_asyncio.fixture
async def corr_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Correlation Test Blog", url="https://example.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


# --- CorrelationEvent serialization ---


def test_correlation_event_roundtrip():
    event = CorrelationEvent(
        event_type="new_ttp_for_known_actor",
        entry_id=uuid.uuid4(),
        source_entity_type="ttp",
        source_entity_id=uuid.uuid4(),
        source_entity_label="T1059.001",
        related_entity_type="threat_actor",
        related_entity_id=uuid.uuid4(),
        related_entity_label="APT29",
        context="New TTP found alongside APT29",
    )
    d = event.to_dict()
    restored = CorrelationEvent.from_dict(d)

    assert restored.event_type == event.event_type
    assert restored.entry_id == event.entry_id
    assert restored.source_entity_id == event.source_entity_id
    assert restored.related_entity_label == "APT29"


# --- new_ttp_for_known_actor ---


@pytest.mark.asyncio
async def test_new_ttp_for_known_actor(db_session: AsyncSession, corr_feed: Feed):
    """A new TTP in an article mentioning a known actor triggers an event."""
    actor = ThreatActor(name="APT28", aliases=[], article_count=5)
    ttp = TTP(technique_id="T1566.001", technique_name="Phishing", tactic="initial-access", article_count=1)
    entry = Entry(feed_id=corr_feed.id, title="Test", guid="ce-4", content_text="test")
    db_session.add_all([actor, ttp, entry])
    await db_session.flush()

    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
    db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id))
    await db_session.flush()

    events = await correlate_new_entities(db_session, entry.id)
    types = [e.event_type for e in events]
    assert "new_ttp_for_known_actor" in types


# --- new_ttp_for_known_malware ---


@pytest.mark.asyncio
async def test_new_ttp_for_known_malware(db_session: AsyncSession, corr_feed: Feed):
    """A new TTP in an article mentioning known malware triggers an event."""
    malware = MalwareFamily(name="Cobalt Strike", malware_type="backdoor", article_count=3)
    ttp = TTP(technique_id="T1059.001", technique_name="PowerShell", tactic="execution", article_count=1)
    entry = Entry(feed_id=corr_feed.id, title="Test", guid="ce-5", content_text="test")
    db_session.add_all([malware, ttp, entry])
    await db_session.flush()

    db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=malware.id))
    db_session.add(EntryTTP(entry_id=entry.id, ttp_id=ttp.id))
    await db_session.flush()

    events = await correlate_new_entities(db_session, entry.id)
    types = [e.event_type for e in events]
    assert "new_ttp_for_known_malware" in types


# --- No events when nothing interesting ---


@pytest.mark.asyncio
async def test_no_events_for_all_new_entities(db_session: AsyncSession, corr_feed: Feed):
    """When all entities are new (no prior context), no correlation events should fire."""
    actor = ThreatActor(name="BrandNew", aliases=[], article_count=1)
    entry = Entry(feed_id=corr_feed.id, title="Test", guid="ce-7", content_text="test")
    db_session.add_all([actor, entry])
    await db_session.flush()

    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
    await db_session.flush()

    events = await correlate_new_entities(db_session, entry.id)
    # new actor only = no interesting correlation
    assert len(events) == 0
