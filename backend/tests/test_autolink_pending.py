"""Pending autolink tier: dictionary-word matches held for AI confirmation.

Covers the common-word classification, scan-time provisional flagging, the
store diversion into pending_autolink_matches, and the one-pass AI reconcile
(promote / reject) path.
"""

import uuid
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import select

import app.intelligence.autolinker as autolinker_mod
from app.intelligence.autolink_reconcile import reconcile_pending_autolinks
from app.intelligence.autolinker import (
    EntityVocabulary,
    is_common_english_word,
    scan_text,
    store_autolink_matches,
)
from app.models.entry import Entry
from app.models.false_positive_record import FalsePositiveRecord
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.pending_autolink import PendingAutolinkMatch


def _make_malware(name, aliases=None):
    malware = MagicMock()
    malware.id = uuid.uuid4()
    malware.name = name
    malware.aliases = aliases or []
    return malware


def _build_and_activate(actors=None, malware=None):
    vocab = EntityVocabulary()
    vocab.build_from_entities(actors or [], malware or [])
    autolinker_mod._vocabulary = vocab
    autolinker_mod._vocab_version = vocab.version
    return vocab


@pytest.fixture
def pending_tier_on(monkeypatch):
    monkeypatch.setattr(autolinker_mod, "pending_tier_enabled", lambda: True)


# ── Classification ──────────────────────────────────────────────────


def test_common_word_classification():
    for word in ("royal", "inc", "navy", "hive", "medusa", "Royal"):
        assert is_common_english_word(word), word
    for word in ("emotet", "lockbit", "qakbot", "apt29", "cozy bear", ""):
        assert not is_common_english_word(word), word


def test_vocab_flags_provisional_forms():
    vocab = _build_and_activate(malware=[_make_malware("Royal"), _make_malware("Emotet")])
    entries = {e.surface_form: e for payload in vocab.automaton.values() for e in payload}
    assert entries["Royal"].is_provisional
    assert not entries["Emotet"].is_provisional


# ── Scan-time provisional flag ──────────────────────────────────────


def test_scan_marks_common_word_match_provisional(pending_tier_on):
    _build_and_activate(malware=[_make_malware("Royal")])
    matches = scan_text("Cyber vulnerability sweep picks up Royal Navy drones sending data to China.")
    royal = [m for m in matches if m["canonical_name"] == "Royal"]
    assert len(royal) == 1
    assert royal[0]["provisional"] is True


def test_scan_multiword_alias_rescues_from_pending(pending_tier_on):
    _build_and_activate(malware=[_make_malware("Royal", aliases=["Royal Ransomware"])])
    matches = scan_text("The Royal Ransomware operation, known simply as Royal, hit healthcare.")
    royal = [m for m in matches if m["canonical_name"] == "Royal"]
    assert len(royal) == 1
    assert royal[0]["provisional"] is False


def test_scan_coined_name_never_provisional(pending_tier_on):
    _build_and_activate(malware=[_make_malware("Emotet")])
    matches = scan_text("Samples of Emotet were found in the wild.")
    assert matches and matches[0]["provisional"] is False


def test_scan_pending_tier_disabled(monkeypatch):
    monkeypatch.setattr(autolinker_mod, "pending_tier_enabled", lambda: False)
    _build_and_activate(malware=[_make_malware("Royal")])
    matches = scan_text("Cyber vulnerability sweep picks up Royal ransomware drops.")
    royal = [m for m in matches if m["canonical_name"] == "Royal"]
    assert len(royal) == 1
    assert royal[0]["provisional"] is False
    # Inside a longer name ("Royal Navy") the context is doubtful: with no AI
    # to ask, it is dropped rather than linked.
    assert not [m for m in scan_text("The Royal Navy flew drones.") if m["canonical_name"] == "Royal"]


# ── Store diversion + reconcile ─────────────────────────────────────


@pytest_asyncio.fixture
async def entry(db_session):
    feed = Feed(title="CyberWire Daily", url="https://cw.example/feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    row = Entry(
        feed_id=feed.id,
        title="A private route to public risk.",
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://example.com/{uuid.uuid4()}",
        content_text="Cyber vulnerability sweep picks up Royal Navy drones.",
    )
    db_session.add(row)
    await db_session.flush()
    return row


@pytest_asyncio.fixture
async def royal_malware(db_session):
    malware = MalwareFamily(name="Royal", aliases=["Royal Ransomware"], article_count=5)
    db_session.add(malware)
    await db_session.flush()
    return malware


def _provisional_match(malware):
    return {
        "entity_type": "malware",
        "entity_id": str(malware.id),
        "canonical_name": malware.name,
        "surface_form": "Royal",
        "surface_forms": ["Royal"],
        "confidence": "high",
        "source": "auto_link",
        "paragraph_indices": [2],
        "provisional": True,
    }


@pytest.mark.asyncio
async def test_store_diverts_provisional_to_pending(db_session, entry, royal_malware):
    stored = await store_autolink_matches(db_session, entry.id, [_provisional_match(royal_malware)])
    assert stored == []

    junction = (
        await db_session.execute(select(EntryMalware).where(EntryMalware.entry_id == entry.id))
    ).scalar_one_or_none()
    assert junction is None

    pending = (
        await db_session.execute(select(PendingAutolinkMatch).where(PendingAutolinkMatch.entry_id == entry.id))
    ).scalar_one()
    assert pending.entity_type == "malware"
    assert pending.canonical_name == "Royal"
    assert pending.resolved_at is None
    await db_session.refresh(royal_malware)
    assert royal_malware.article_count == 5  # unchanged


@pytest.mark.asyncio
async def test_reconcile_promotes_confirmed_entity(db_session, entry, royal_malware):
    await store_autolink_matches(db_session, entry.id, [_provisional_match(royal_malware)])

    parsed = {"malware": [{"name": "Royal Ransomware", "aliases": []}]}
    counts = await reconcile_pending_autolinks(db_session, entry.id, parsed)
    assert counts == {"promoted": 1, "rejected": 0}

    junction = (await db_session.execute(select(EntryMalware).where(EntryMalware.entry_id == entry.id))).scalar_one()
    assert junction.malware_family_id == royal_malware.id
    assert junction.source == "auto_link"
    pending = (
        await db_session.execute(select(PendingAutolinkMatch).where(PendingAutolinkMatch.entry_id == entry.id))
    ).scalar_one()
    assert pending.resolution == "promoted"
    await db_session.refresh(royal_malware)
    assert royal_malware.article_count == 6


@pytest.mark.asyncio
async def test_reconcile_promotes_cross_slot_mention(db_session, entry, royal_malware):
    # The AI filed the ransomware brand under threat_actors; our entity is malware.
    await store_autolink_matches(db_session, entry.id, [_provisional_match(royal_malware)])
    counts = await reconcile_pending_autolinks(db_session, entry.id, {"threat_actors": [{"name": "Royal"}]})
    assert counts["promoted"] == 1


@pytest.mark.asyncio
async def test_reconcile_rejects_unconfirmed_entity(db_session, entry, royal_malware, admin_user):
    await store_autolink_matches(db_session, entry.id, [_provisional_match(royal_malware)])

    parsed = {"malware": [{"name": "Gunra"}], "threat_actors": [], "tools": []}
    counts = await reconcile_pending_autolinks(db_session, entry.id, parsed)
    assert counts == {"promoted": 0, "rejected": 1}

    junction = (
        await db_session.execute(select(EntryMalware).where(EntryMalware.entry_id == entry.id))
    ).scalar_one_or_none()
    assert junction is None
    pending = (
        await db_session.execute(select(PendingAutolinkMatch).where(PendingAutolinkMatch.entry_id == entry.id))
    ).scalar_one()
    assert pending.resolution == "rejected"
    fp = (
        await db_session.execute(select(FalsePositiveRecord).where(FalsePositiveRecord.source_entry_id == entry.id))
    ).scalar_one()
    assert fp.extraction_source == "ai_reconcile"
    assert fp.entity_value == "Royal"
    await db_session.refresh(royal_malware)
    assert royal_malware.article_count == 5  # never bumped


@pytest.mark.asyncio
async def test_reconcile_noop_without_pending_rows(db_session, entry):
    counts = await reconcile_pending_autolinks(db_session, entry.id, {"malware": [{"name": "Royal"}]})
    assert counts == {"promoted": 0, "rejected": 0}


# ── Feed policy: the AI never reads the entry → drop, don't hold ────


@pytest.fixture
def drop_counter(monkeypatch):
    dropped: list[int] = []

    async def _count(n):
        dropped.append(n)

    monkeypatch.setattr(autolinker_mod, "_count_dropped_ai_off", _count)
    return dropped


async def _rows(db_session, entry):
    pending = (
        (await db_session.execute(select(PendingAutolinkMatch).where(PendingAutolinkMatch.entry_id == entry.id)))
        .scalars()
        .all()
    )
    junction = (await db_session.execute(select(EntryMalware).where(EntryMalware.entry_id == entry.id))).scalars().all()
    return pending, junction


@pytest.mark.asyncio
async def test_feed_ai_off_drops_provisional_match(db_session, entry, royal_malware, drop_counter):
    feed = await db_session.get(Feed, entry.feed_id)
    feed.ai_analysis_enabled = False
    await db_session.flush()

    stored = await store_autolink_matches(db_session, entry.id, [_provisional_match(royal_malware)])

    assert stored == []
    pending, junction = await _rows(db_session, entry)
    assert pending == [] and junction == []
    assert drop_counter == [1]
    await db_session.refresh(royal_malware)
    assert royal_malware.article_count == 5


@pytest.mark.asyncio
async def test_feed_mode_none_drops_provisional_match(db_session, entry, royal_malware, drop_counter):
    feed = await db_session.get(Feed, entry.feed_id)
    feed.intel_extraction_mode = "none"
    await db_session.flush()

    await store_autolink_matches(db_session, entry.id, [_provisional_match(royal_malware)])

    pending, junction = await _rows(db_session, entry)
    assert pending == [] and junction == []
    assert drop_counter == [1]


@pytest.mark.asyncio
async def test_feed_ai_off_keeps_non_provisional_matches(db_session, entry, royal_malware, drop_counter):
    feed = await db_session.get(Feed, entry.feed_id)
    feed.ai_analysis_enabled = False
    await db_session.flush()
    match = {**_provisional_match(royal_malware), "provisional": False, "surface_form": "Royal Ransomware"}

    stored = await store_autolink_matches(db_session, entry.id, [match])

    assert len(stored) == 1
    assert drop_counter == []


@pytest.mark.asyncio
async def test_feed_ai_on_holds_provisional_match(db_session, entry, royal_malware, drop_counter):
    await store_autolink_matches(db_session, entry.id, [_provisional_match(royal_malware)])

    pending, junction = await _rows(db_session, entry)
    assert len(pending) == 1 and junction == []
    assert drop_counter == []


@pytest.mark.asyncio
async def test_instance_ai_off_links_instantly(db_session, entry, royal_malware, drop_counter, monkeypatch):
    """Instance AI off: the pending tier is off as a whole, so dictionary-word
    names link at once (the legacy behaviour) rather than being dropped."""
    from app.config import settings as env_settings
    from app.services.ai_eligibility import entry_will_get_ai_analysis

    monkeypatch.setattr(env_settings, "ai_one_pass_enabled", False)
    assert not await entry_will_get_ai_analysis(db_session, entry.id)

    vocab_malware = MagicMock(id=royal_malware.id, aliases=[])
    vocab_malware.name = "Royal"
    _build_and_activate(malware=[vocab_malware])
    matches = scan_text("The sweep picks up Royal samples on two hosts.")
    assert matches and matches[0]["provisional"] is False

    stored = await store_autolink_matches(db_session, entry.id, matches)

    assert len(stored) == 1
    pending, junction = await _rows(db_session, entry)
    assert pending == [] and len(junction) == 1
    assert drop_counter == []


@pytest.mark.asyncio
async def test_ai_eligibility_predicate(db_session, entry, monkeypatch):
    from app.config import settings as env_settings
    from app.services.ai_eligibility import entry_will_get_ai_analysis

    feed = await db_session.get(Feed, entry.feed_id)
    assert await entry_will_get_ai_analysis(db_session, entry.id)

    feed.ai_analysis_enabled = False
    await db_session.flush()
    assert not await entry_will_get_ai_analysis(db_session, entry.id)

    feed.ai_analysis_enabled = True
    feed.intel_extraction_mode = "none"
    await db_session.flush()
    assert not await entry_will_get_ai_analysis(db_session, entry.id)

    feed.intel_extraction_mode = "manual"
    await db_session.flush()
    assert await entry_will_get_ai_analysis(db_session, entry.id)

    monkeypatch.setattr(env_settings, "ai_one_pass_enabled", False)
    assert not await entry_will_get_ai_analysis(db_session, entry.id)


@pytest.mark.asyncio
async def test_drop_counter_round_trip(monkeypatch):
    store: dict[str, int] = {}

    class FakeRedis:
        async def incrby(self, key, n):
            store[key] = store.get(key, 0) + n
            return store[key]

        async def expire(self, key, ttl):
            return True

        async def mget(self, keys):
            return [store.get(k) for k in keys]

    async def _get_redis():
        return FakeRedis()

    monkeypatch.setattr(autolinker_mod, "get_redis", _get_redis)
    await autolinker_mod._count_dropped_ai_off(3)
    await autolinker_mod._count_dropped_ai_off(2)
    assert await autolinker_mod.dropped_ai_off_count(days=30) == 5
