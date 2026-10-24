"""Signal engine: per-signal firing behavior, IDF weighting, scoring task, job_runs."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.intelligence.signals import (
    DEFAULT_FIRING_RATES,
    SignalHit,
    compute_entry_signals,
    compute_priority_score,
    idf_weight,
)
from app.models.country import Country
from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.entry_signal import EntrySignal
from app.models.feed import Feed
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor

NOW = datetime.now(UTC)


@pytest_asyncio.fixture
async def reliable_feed(db_session) -> Feed:
    feed = Feed(title="Vendor Blog", url="https://vendor.example/feed", feed_type="rss", reliability_rating="A")
    db_session.add(feed)
    await db_session.flush()
    return feed


async def _make_entry(db_session, feed, *, title="Report", published_at=None, word_count=None, url=None) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title=title,
        guid=f"guid-{uuid.uuid4()}",
        url=url or f"https://example.com/{uuid.uuid4()}",
        content_text="content",
        published_at=published_at or NOW,
        word_count=word_count,
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


async def _link_actor(db_session, entry, name, *, article_count=1, first_seen=None) -> ThreatActor:
    actor = ThreatActor(name=name, article_count=article_count)
    if first_seen:
        actor.first_seen_at = first_seen
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
    await db_session.flush()
    return actor


@pytest.mark.asyncio
async def test_novel_entity_fires_on_first_mention(db_session, reliable_feed):
    entry = await _make_entry(db_session, reliable_feed)
    await _link_actor(db_session, entry, "BrandNewActor", article_count=1)

    hits = await compute_entry_signals(db_session, entry)
    types = {h.signal_type for h in hits}
    assert "novel_entity" in types
    novel = next(h for h in hits if h.signal_type == "novel_entity")
    assert "BrandNewActor" in novel.explanation
    # A/B-reliability feed + novel entity + no echo → scoop fires too
    assert "scoop" in types


@pytest.mark.asyncio
async def test_novel_entity_quiet_for_established_entity(db_session, reliable_feed):
    old = NOW - timedelta(days=400)
    entry = await _make_entry(db_session, reliable_feed)
    actor = ThreatActor(name="OldActor", article_count=50)
    actor.first_seen_at = old
    db_session.add(actor)
    await db_session.flush()
    for i in range(3):
        prior = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(days=30 + i))
        db_session.add(EntryThreatActor(entry_id=prior.id, threat_actor_id=actor.id))
    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, entry)
    assert "novel_entity" not in {h.signal_type for h in hits}


@pytest.mark.asyncio
async def test_novel_entity_survives_entity_becoming_established(db_session, reliable_feed):
    """The first entry keeps its first-mention badge on re-score.

    Regression: novelty read the entity's current article_count, so the 72h
    rescore sweep stripped the badge from the founding entry once the entity
    accumulated later coverage.
    """
    first = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(days=2))
    actor = ThreatActor(name="EstablishedLater", article_count=50)
    actor.first_seen_at = NOW - timedelta(days=100)
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=first.id, threat_actor_id=actor.id))
    later = None
    for i in range(4):
        later = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(hours=3 - i))
        db_session.add(EntryThreatActor(entry_id=later.id, threat_actor_id=actor.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, first)
    novel = next((h for h in hits if h.signal_type == "novel_entity"), None)
    assert novel is not None
    assert "First mention" in novel.explanation
    # Later entries see 4+ prior articles — not novel for them
    hits_later = await compute_entry_signals(db_session, later)
    assert "novel_entity" not in {h.signal_type for h in hits_later}


@pytest.mark.asyncio
async def test_new_pairing_fires_for_founding_entry_only(db_session, reliable_feed):
    """First evidence entry carries the pairing signal permanently; later
    evidence entries never claim it (regression: the created-within-1h check
    erased the signal on every rescore)."""
    from app.models.entity_relationship import EntityRelationship

    founder = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(days=5))
    follower = await _make_entry(db_session, reliable_feed)
    actor = ThreatActor(name="PairActor", article_count=10)
    malware = MalwareFamily(name="PairMalware", article_count=10)
    db_session.add_all([actor, malware])
    await db_session.flush()
    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=actor.id,
            target_type="malware",
            target_id=malware.id,
            relationship_type="uses",
            source="co_occurrence",
            confidence="probable",  # trust gate: only vetted pairings surface
            evidence_entry_ids=[founder.id, follower.id],
        )
    )
    await db_session.flush()

    hits = await compute_entry_signals(db_session, founder)
    assert "new_pairing" in {h.signal_type for h in hits}
    hits_follower = await compute_entry_signals(db_session, follower)
    assert "new_pairing" not in {h.signal_type for h in hits_follower}


@pytest.mark.asyncio
async def test_new_pairing_gated_on_trust_ladder(db_session, reliable_feed):
    """A raw, unvetted co-occurrence edge (possible) or one the adjudicator
    ruled coincidental must NOT surface as a novel pairing — that was the
    Void Blizzard <-> Libya bystander-country false positive."""
    from app.models.entity_relationship import EntityRelationship

    founder = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(days=5))
    actor = ThreatActor(name="BystanderActor", article_count=10)
    country = Country(name="Bystanderland", iso_code="BY")
    db_session.add_all([actor, country])
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="country",
        target_id=country.id,
        relationship_type="targets",
        source="co_occurrence",
        confidence="possible",  # single co-mention, unvetted
        evidence_entry_ids=[founder.id],
    )
    db_session.add(edge)
    await db_session.flush()

    hits = await compute_entry_signals(db_session, founder)
    assert "new_pairing" not in {h.signal_type for h in hits}

    # Promoted by corroboration → now trustworthy → surfaces.
    edge.confidence = "probable"
    await db_session.flush()
    hits = await compute_entry_signals(db_session, founder)
    assert "new_pairing" in {h.signal_type for h in hits}

    # Adjudicator later rules it coincidental (demoted back to possible) → gone.
    edge.confidence = "possible"
    edge.adjudication_verdict = "coincidental"
    await db_session.flush()
    hits = await compute_entry_signals(db_session, founder)
    assert "new_pairing" not in {h.signal_type for h in hits}


@pytest.mark.asyncio
async def test_novel_entity_cve_first_seen_only(db_session, reliable_feed):
    """CVEs have no article_count — novelty fires on first_seen recency alone, not on old CVEs."""
    entry = await _make_entry(db_session, reliable_feed)
    fresh = CVE(cve_id="CVE-2026-5555")  # first_seen_at defaults to now
    stale = CVE(cve_id="CVE-2020-0001")
    stale.first_seen_at = NOW - timedelta(days=400)
    db_session.add_all([fresh, stale])
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=entry.id, cve_id=fresh.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, entry)
    novel = next((h for h in hits if h.signal_type == "novel_entity"), None)
    assert novel is not None
    assert "CVE-2026-5555" in novel.explanation

    old_entry = await _make_entry(db_session, reliable_feed)
    db_session.add(EntryCVE(entry_id=old_entry.id, cve_id=stale.id))
    await db_session.flush()
    hits_old = await compute_entry_signals(db_session, old_entry)
    assert "novel_entity" not in {h.signal_type for h in hits_old}


@pytest.mark.asyncio
async def test_entity_resurgence(db_session, reliable_feed):
    old = NOW - timedelta(days=400)
    actor = ThreatActor(name="DormantActor", article_count=10)
    actor.first_seen_at = old
    db_session.add(actor)
    await db_session.flush()

    for i in range(4):
        old_entry = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(days=200 + i))
        db_session.add(EntryThreatActor(entry_id=old_entry.id, threat_actor_id=actor.id))
    new_entry = await _make_entry(db_session, reliable_feed, published_at=NOW)
    db_session.add(EntryThreatActor(entry_id=new_entry.id, threat_actor_id=actor.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, new_entry)
    resurgence = next((h for h in hits if h.signal_type == "entity_resurgence"), None)
    assert resurgence is not None
    assert "DormantActor" in resurgence.explanation
    assert resurgence.payload["gap_days"] >= 190


@pytest.mark.asyncio
async def test_feed_echo_and_convergence(db_session, reliable_feed):
    """4 shared entities across entries: earlier peer → echo on the later entry."""
    other_feed = Feed(title="Aggregator", url="https://agg.example/feed", feed_type="rss")
    db_session.add(other_feed)
    await db_session.flush()

    original = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(hours=5))
    echo = await _make_entry(db_session, other_feed, published_at=NOW)

    actor = ThreatActor(name="SharedActor", article_count=10)
    malware = MalwareFamily(name="SharedMalware", article_count=10)
    db_session.add_all([actor, malware])
    cve1 = CVE(cve_id="CVE-2026-1111")
    cve2 = CVE(cve_id="CVE-2026-2222")
    db_session.add_all([cve1, cve2])
    await db_session.flush()
    for entry in (original, echo):
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=malware.id))
        db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve1.id))
        db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve2.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, echo)
    echo_hit = next((h for h in hits if h.signal_type == "feed_echo"), None)
    assert echo_hit is not None
    assert echo_hit.payload["duplicate_of"] == str(original.id)
    assert echo_hit.payload["ratio"] >= 0.7
    # The original (earlier) entry must NOT be an echo of the later one
    hits_original = await compute_entry_signals(db_session, original)
    assert "feed_echo" not in {h.signal_type for h in hits_original}


async def _thread_with(db_session, members: list[tuple], *, title="Qilin hits hospital chain", sources=4):
    """Create a story thread with (entry, role, duplicate_of) members."""
    from sqlalchemy import text as sql

    thread_id = uuid.uuid4()
    await db_session.execute(
        sql(
            "INSERT INTO story_threads (id, slug, title, status, entry_count, source_count, echo_count) "
            "VALUES (:id, :slug, :title, 'open', :n, :src, 0)"
        ),
        {"id": thread_id, "slug": f"t-{thread_id.hex[:8]}", "title": title, "n": len(members), "src": sources},
    )
    for entry, role, duplicate_of in members:
        await db_session.execute(
            sql(
                "INSERT INTO story_thread_entries (id, thread_id, entry_id, role, similarity, "
                "duplicate_of_entry_id, source_key) VALUES (:id, :t, :e, :role, 0.95, :dup, 'x.example')"
            ),
            {"id": uuid.uuid4(), "t": thread_id, "e": entry.id, "role": role, "dup": duplicate_of},
        )
    await db_session.flush()
    return thread_id


@pytest.mark.asyncio
async def test_thread_membership_answers_the_echo_signal(db_session, reliable_feed):
    """A folded re-report is an echo because the sweeper folded it, not because
    it happens to share two extracted entities inside 72 hours."""
    original = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(hours=5))
    repeat = await _make_entry(db_session, reliable_feed, published_at=NOW)
    thread_id = await _thread_with(db_session, [(original, "origin", None), (repeat, "echo", original.id)], sources=7)

    hits = await compute_entry_signals(db_session, repeat)

    echo_hit = next((h for h in hits if h.signal_type == "feed_echo"), None)
    assert echo_hit is not None
    assert echo_hit.score == 1.0
    assert echo_hit.payload["source"] == "story_thread"
    assert echo_hit.payload["duplicate_of"] == str(original.id)
    assert echo_hit.payload["thread_id"] == str(thread_id)
    assert "7 outlets" in echo_hit.explanation
    # An echo is never also corroboration.
    assert "source_convergence" not in {h.signal_type for h in hits}


@pytest.mark.asyncio
async def test_thread_outlets_answer_the_convergence_signal(db_session, reliable_feed):
    entry = await _make_entry(db_session, reliable_feed, published_at=NOW)
    await _thread_with(db_session, [(entry, "beat", None)], sources=6)

    hits = await compute_entry_signals(db_session, entry)

    conv = next((h for h in hits if h.signal_type == "source_convergence"), None)
    assert conv is not None
    assert conv.payload["source_count"] == 6
    assert conv.payload["source"] == "story_thread"
    assert conv.score == 1.0  # 6/6, capped


@pytest.mark.asyncio
async def test_a_thread_beat_is_not_penalised_as_an_echo(db_session, reliable_feed):
    """The behaviour that changes: shared entities used to be enough.

    Two articles sharing four entities trip the overlap probe every time — see
    test_feed_echo_and_convergence. When the sweeper has judged the later one a
    distinct beat, that verdict stands: it compared the article against the
    whole story rather than counting junction rows.
    """
    other_feed = Feed(title="Aggregator", url="https://agg.example/feed", feed_type="rss")
    db_session.add(other_feed)
    await db_session.flush()
    original = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(hours=5))
    follow_up = await _make_entry(db_session, other_feed, published_at=NOW)

    actor = ThreatActor(name="BeatActor", article_count=10)
    malware = MalwareFamily(name="BeatMalware", article_count=10)
    db_session.add_all([actor, malware])
    cve1 = CVE(cve_id="CVE-2026-3333")
    cve2 = CVE(cve_id="CVE-2026-4444")
    db_session.add_all([cve1, cve2])
    await db_session.flush()
    for entry in (original, follow_up):
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=malware.id))
        db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve1.id))
        db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve2.id))
    await db_session.flush()
    await _thread_with(db_session, [(original, "origin", None), (follow_up, "beat", None)], sources=5)

    hits = await compute_entry_signals(db_session, follow_up)

    assert "feed_echo" not in {h.signal_type for h in hits}
    assert next(h for h in hits if h.signal_type == "source_convergence").payload["source"] == "story_thread"


@pytest.mark.asyncio
async def test_unthreaded_entries_keep_using_the_entity_probe(db_session, reliable_feed):
    """44% of the corpus can never be threaded, and nothing is threaded before
    its first sweep — the probe has to stay the answer for all of it."""
    original = await _make_entry(db_session, reliable_feed, published_at=NOW - timedelta(hours=5))
    repeat = await _make_entry(db_session, reliable_feed, published_at=NOW)
    actor = ThreatActor(name="ProbeActor", article_count=10)
    malware = MalwareFamily(name="ProbeMalware", article_count=10)
    db_session.add_all([actor, malware])
    cve = CVE(cve_id="CVE-2026-5555")
    cve2 = CVE(cve_id="CVE-2026-6666")
    db_session.add_all([cve, cve2])
    await db_session.flush()
    for entry in (original, repeat):
        db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=malware.id))
        db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
        db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve2.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, repeat)

    echo_hit = next(h for h in hits if h.signal_type == "feed_echo")
    assert echo_hit.payload.get("source") != "story_thread"
    assert echo_hit.payload["ratio"] >= 0.7


@pytest.mark.asyncio
async def test_thread_signals_can_be_switched_off(db_session, reliable_feed):
    from sqlalchemy import text as sql

    from app.services import system_settings

    entry = await _make_entry(db_session, reliable_feed, published_at=NOW)
    await _thread_with(db_session, [(entry, "beat", None)], sources=6)
    # The singleton settings row is seeded at app startup, not by create_all.
    await db_session.execute(
        sql("INSERT INTO system_settings (id, settings, secrets) VALUES (1, '{}', '{}') ON CONFLICT (id) DO NOTHING")
    )
    try:
        await system_settings.update_settings(db_session, {"thread_signals_enabled": False})

        hits = await compute_entry_signals(db_session, entry)

        assert not [h for h in hits if h.payload.get("source") == "story_thread"]
    finally:
        # The cache is process-global; don't leak "off" into the next test.
        system_settings.invalidate_cache()


@pytest.mark.asyncio
async def test_rescore_covers_every_member_of_a_changed_thread(db_session, reliable_feed, monkeypatch):
    """One more outlet on a story re-scores the whole story, not the newcomer."""
    from app.workers import signal_tasks

    members = [await _make_entry(db_session, reliable_feed, published_at=NOW) for _ in range(3)]
    thread_id = await _thread_with(
        db_session, [(m, "origin" if i == 0 else "beat", None) for i, m in enumerate(members)], sources=5
    )
    await db_session.commit()

    monkeypatch.setattr(signal_tasks, "_get_worker_session", lambda: _NullCtx(db_session))
    monkeypatch.setattr(signal_tasks, "_engine_enabled", _always_enabled)

    count = await signal_tasks._rescore_entries_for_threads([str(thread_id)], limit=100)

    assert count == 3
    for member in members:
        await db_session.refresh(member)
        assert member.scored_at is not None


async def _always_enabled(_db) -> bool:
    return True


class _NullCtx:
    """Hands the test session to a worker function without closing it."""

    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *_exc):
        return False


@pytest.mark.asyncio
async def test_convergence_counts_domains_not_feeds(db_session, reliable_feed):
    """Three feeds all rebroadcasting the same site = one source; three distinct
    sites = convergence (regression: feed_id counting inflated independence)."""
    actor = ThreatActor(name="ConvergeActor", article_count=10)
    actor.first_seen_at = NOW - timedelta(days=100)
    malware = MalwareFamily(name="ConvergeMalware", article_count=10)
    malware.first_seen_at = NOW - timedelta(days=100)
    db_session.add_all([actor, malware])
    await db_session.flush()

    async def _covered_entry(feed_title, url):
        feed = Feed(title=feed_title, url=f"https://{feed_title}.example/feed", feed_type="rss")
        db_session.add(feed)
        await db_session.flush()
        e = await _make_entry(db_session, feed, published_at=NOW - timedelta(hours=1), url=url)
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
        db_session.add(EntryMalware(entry_id=e.id, malware_family_id=malware.id))
        return e

    entry = await _make_entry(db_session, reliable_feed, url="https://original.example/post")
    db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
    db_session.add(EntryMalware(entry_id=entry.id, malware_family_id=malware.id))
    for i in range(3):
        await _covered_entry(f"mirror{i}", f"https://mirror.example/repost-{i}")
    await db_session.flush()

    hits = await compute_entry_signals(db_session, entry)
    # original.example + mirror.example = 2 sources, below the 3-source floor
    assert "source_convergence" not in {h.signal_type for h in hits}

    for i in range(2):
        await _covered_entry(f"indie{i}", f"https://indie{i}.example/analysis")
    await db_session.flush()
    hits = await compute_entry_signals(db_session, entry)
    conv = next((h for h in hits if h.signal_type == "source_convergence"), None)
    assert conv is not None
    assert conv.payload["source_count"] == 4  # original + mirror + indie0 + indie1


def test_collapse_name_twins_dedupes_by_name():
    """Actor/malware sharing a display name collapse to one subject; the actor
    wins the tie. Distinct names survive."""
    from app.intelligence.correlation import _collapse_name_twins

    actor_id, malware_id, other_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    labels = {
        ("threat_actor", actor_id): "Qilin",
        ("malware", malware_id): "Qilin",
        ("malware", other_id): "LockBit",
    }
    collapsed = _collapse_name_twins(
        {("threat_actor", actor_id), ("malware", malware_id), ("malware", other_id)}, labels
    )
    assert len(collapsed) == 2  # Qilin (twin) + LockBit
    assert ("threat_actor", actor_id) in collapsed  # actor kept as Qilin's representative
    assert ("malware", malware_id) not in collapsed


@pytest.mark.asyncio
async def test_convergence_ignores_actor_malware_name_twins(db_session, reliable_feed):
    """Qilin-the-group and Qilin-the-ransomware are one subject: coverage that
    shares only the twin must NOT clear the >=2-shared-entities convergence bar
    (regression: 'N sources converged on Qilin, Qilin')."""
    actor = ThreatActor(name="Qilin", article_count=10)
    actor.first_seen_at = NOW - timedelta(days=100)
    malware = MalwareFamily(name="Qilin", article_count=10)
    malware.first_seen_at = NOW - timedelta(days=100)
    db_session.add_all([actor, malware])
    await db_session.flush()

    async def _covered(host):
        feed = Feed(title=host, url=f"https://{host}/feed", feed_type="rss")
        db_session.add(feed)
        await db_session.flush()
        e = await _make_entry(db_session, feed, published_at=NOW - timedelta(hours=1), url=f"https://{host}/post")
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
        db_session.add(EntryMalware(entry_id=e.id, malware_family_id=malware.id))
        return e

    anchor = await _make_entry(db_session, reliable_feed, url="https://original.example/post")
    db_session.add(EntryThreatActor(entry_id=anchor.id, threat_actor_id=actor.id))
    db_session.add(EntryMalware(entry_id=anchor.id, malware_family_id=malware.id))
    covered = [await _covered("a.example"), await _covered("b.example")]
    await db_session.flush()

    # Twin collapses to one subject → candidates share only 1 entity → no convergence.
    hits = await compute_entry_signals(db_session, anchor)
    assert "source_convergence" not in {h.signal_type for h in hits}

    # Add a genuinely distinct shared subject (a CVE) → 2 subjects across 3 domains → converges.
    cve = CVE(cve_id="CVE-2026-7777")
    db_session.add(cve)
    await db_session.flush()
    for e in [anchor, *covered]:
        db_session.add(EntryCVE(entry_id=e.id, cve_id=cve.id))
    await db_session.flush()
    hits = await compute_entry_signals(db_session, anchor)
    assert "source_convergence" in {h.signal_type for h in hits}


@pytest.mark.asyncio
async def test_severity_and_under_reported(db_session, reliable_feed):
    entry = await _make_entry(db_session, reliable_feed)
    cve = CVE(
        cve_id="CVE-2026-9999",
        cvss_score=9.8,
        is_kev=True,
        kev_date_added=NOW.date() - timedelta(days=2),
        github_poc_count=3,
        exploit_availability="weaponized",
        epss_percentile=0.99,
    )
    db_session.add(cve)
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, entry)
    types = {h.signal_type for h in hits}
    assert {"kev_added", "weaponized_poc", "epss_high", "critical_cvss", "under_reported"} <= types
    assert "epss_jump" not in types  # no recorded jump — static percentile is epss_high now
    under = next(h for h in hits if h.signal_type == "under_reported")
    assert "CVE-2026-9999" in under.explanation
    assert under.payload["feeds_covering"] == 1


@pytest.mark.asyncio
async def test_epss_jump_fires_on_recent_recorded_jump(db_session, reliable_feed):
    entry = await _make_entry(db_session, reliable_feed)
    jumped = CVE(
        cve_id="CVE-2026-7777",
        epss_score=0.82,
        epss_previous_score=0.08,
        epss_changed_at=NOW - timedelta(days=1),
        epss_percentile=0.90,
    )
    db_session.add(jumped)
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=entry.id, cve_id=jumped.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, entry)
    jump = next((h for h in hits if h.signal_type == "epss_jump"), None)
    assert jump is not None
    assert "8% to 82%" in jump.explanation

    # A jump recorded a month before the entry's window is stale — no signal
    stale_entry = await _make_entry(db_session, reliable_feed)
    stale = CVE(
        cve_id="CVE-2026-5551",
        epss_score=0.82,
        epss_previous_score=0.08,
        epss_changed_at=NOW - timedelta(days=30),
        epss_percentile=0.90,
    )
    db_session.add(stale)
    await db_session.flush()
    db_session.add(EntryCVE(entry_id=stale_entry.id, cve_id=stale.id))
    await db_session.flush()
    hits_stale = await compute_entry_signals(db_session, stale_entry)
    assert "epss_jump" not in {h.signal_type for h in hits_stale}


@pytest.mark.asyncio
async def test_under_reported_quiet_when_cve_widely_covered(db_session, reliable_feed):
    """Articles sharing only the CVE with the scored entry still count as coverage.

    Regression: the old implementation reused the convergence probe (>=2 shared
    entities), so CVE-only peer articles were invisible and a widely covered
    severe CVE was reported as single-source.
    """
    cve = CVE(cve_id="CVE-2026-8888", cvss_score=9.8, is_kev=True, kev_date_added=NOW.date() - timedelta(days=30))
    db_session.add(cve)
    await db_session.flush()

    entry = await _make_entry(db_session, reliable_feed)
    db_session.add(EntryCVE(entry_id=entry.id, cve_id=cve.id))
    for i in range(3):
        peer_feed = Feed(title=f"Peer {i}", url=f"https://peer{i}.example/feed", feed_type="rss")
        db_session.add(peer_feed)
        await db_session.flush()
        peer = await _make_entry(db_session, peer_feed, published_at=NOW - timedelta(days=i + 1))
        db_session.add(EntryCVE(entry_id=peer.id, cve_id=cve.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, entry)
    assert "under_reported" not in {h.signal_type for h in hits}


@pytest.mark.asyncio
async def test_pir_match_signal(db_session, reliable_feed, test_user):
    entry = await _make_entry(db_session, reliable_feed)
    req = IntelligenceRequirement(created_by=test_user.id, title="Track ransomware", priority="high")
    db_session.add(req)
    await db_session.flush()
    db_session.add(
        RequirementMatch(requirement_id=req.id, entry_id=entry.id, match_type="keyword", matched_on="ransomware")
    )
    await db_session.flush()

    hits = await compute_entry_signals(db_session, entry)
    pir = next((h for h in hits if h.signal_type == "pir_match"), None)
    assert pir is not None
    assert pir.payload["count"] == 1


@pytest.mark.asyncio
async def test_research_depth(db_session, reliable_feed, test_ttp):
    from app.models.ttp import TTP, EntryTTP

    entry = await _make_entry(db_session, reliable_feed, word_count=3000)
    ttps = [test_ttp]
    for i in range(2):
        t = TTP(technique_id=f"T15{i}0", technique_name=f"Tech {i}", tactic="execution")
        db_session.add(t)
        await db_session.flush()
        ttps.append(t)
    for t in ttps:
        db_session.add(EntryTTP(entry_id=entry.id, ttp_id=t.id))
    await db_session.flush()

    hits = await compute_entry_signals(db_session, entry)
    assert "research_depth" in {h.signal_type for h in hits}


def test_feedback_attributed_to_top_signal_only():
    from app.intelligence.signals import attribute_feedback_votes

    # Entry had a rare novelty signal (strong contributor) alongside a common
    # pir_match; the downvote must land on novelty only, not smear into interest.
    rows = [
        ("fb1", -1, "novel_entity", 1.0),
        ("fb1", -1, "pir_match", 1.0),
        ("fb2", 1, "kev_added", 1.0),
        ("fb2", 1, "feed_echo", 1.0),  # echo never attributed
    ]
    votes = attribute_feedback_votes(rows, DEFAULT_FIRING_RATES)
    assert votes == {"novelty": [-1], "severity": [1]}
    assert "interest" not in votes
    assert "coverage" not in votes


def test_idf_weight_math():
    assert idf_weight(0.05) == pytest.approx(1.0)
    assert idf_weight(0.43) < 0.3  # PIR-swamp rate → near-floor weight
    assert idf_weight(0.005) > 1.7  # rare signal → strong weight
    assert idf_weight(0.0) == pytest.approx(idf_weight(0.001))  # rate floored at 0.001
    assert idf_weight(1.0) == 0.1  # clamped floor


def test_priority_score_echo_negative():
    hits = [SignalHit("feed_echo", 1.0, "echo")]
    assert compute_priority_score(hits, DEFAULT_FIRING_RATES) < 0
    hits = [SignalHit("novel_entity", 1.0, "new"), SignalHit("under_reported", 1.0, "quiet")]
    score = compute_priority_score(hits, DEFAULT_FIRING_RATES)
    assert score > 2  # two rare signals


def test_priority_score_multipliers():
    hits = [SignalHit("kev_added", 1.0, "kev")]
    base = compute_priority_score(hits)
    boosted = compute_priority_score(hits, multipliers={"severity": 2.0})
    assert boosted == pytest.approx(base * 2, rel=1e-3)


@pytest.mark.asyncio
async def test_score_entry_persists_and_upserts(db_session, reliable_feed, monkeypatch):
    from app.workers.signal_tasks import score_entry

    entry = await _make_entry(db_session, reliable_feed)
    await _link_actor(db_session, entry, "PersistActor", article_count=1)

    score1 = await score_entry(db_session, entry.id)
    assert score1 is not None and score1 > 0
    await db_session.flush()

    rows = (await db_session.execute(select(EntrySignal).where(EntrySignal.entry_id == entry.id))).scalars().all()
    assert {r.signal_type for r in rows} >= {"novel_entity"}
    first_count = len(rows)

    # Re-score: upsert, not append
    score2 = await score_entry(db_session, entry.id)
    await db_session.flush()
    rows2 = (await db_session.execute(select(EntrySignal).where(EntrySignal.entry_id == entry.id))).scalars().all()
    assert len(rows2) == first_count
    assert score2 == pytest.approx(score1)

    await db_session.refresh(entry)
    assert entry.priority_score == pytest.approx(score1)
    assert entry.scored_at is not None


@pytest.mark.asyncio
async def test_triage_signals_mode_shape(client, auth_headers, db_session, reliable_feed, monkeypatch):
    from app.workers.signal_tasks import score_entry

    entry = await _make_entry(db_session, reliable_feed, title="Signal Entry")
    await _link_actor(db_session, entry, "TriageActor", article_count=1)
    await score_entry(db_session, entry.id)
    await db_session.commit()

    # The radar threshold otherwise comes from Redis, where the running dev
    # stack's rates job keeps a p95 that has nothing to do with this fixture.
    async def fixed_threshold():
        return 0.1, True

    monkeypatch.setattr("app.intelligence.signals.get_radar_threshold", fixed_threshold)

    resp = await client.get("/api/entries/triage?mode=signals", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) == {"items", "total"}
    assert data["total"] >= 1
    item = data["items"][0]
    assert set(item.keys()) == {"entry", "priority_score", "priority_reasons", "priority_components"}
    assert item["priority_reasons"]


@pytest.mark.asyncio
async def test_job_run_recorded(db_session, monkeypatch):
    from contextlib import asynccontextmanager

    from app.models.job_run import JobRun
    from app.workers import task_tracking

    @asynccontextmanager
    async def fake_session():
        yield db_session

    monkeypatch.setattr("app.workers.db.worker_session", fake_session)
    # _record_run uses run_async — run inline instead since we're already async
    recorded = {}

    def fake_run_async(coro):
        recorded["coro"] = coro

    monkeypatch.setattr("app.workers.db.run_async", fake_run_async)

    task_tracking._record_run("app.workers.enrichment_tasks.run_epss_bulk_sync", "tid-1", "success", None, None)
    await recorded["coro"]
    await db_session.flush()

    rows = (await db_session.execute(select(JobRun))).scalars().all()
    assert len(rows) == 1
    assert rows[0].job_key == "epss-bulk-sync"
    assert rows[0].status == "success"


# ── Phase 3: watchlist, chips, surfaced triage ─────────────────────


@pytest.mark.asyncio
async def test_watchlist_crud(client, auth_headers, db_session, reliable_feed):
    actor = ThreatActor(name="WatchedActor", article_count=5)
    db_session.add(actor)
    await db_session.flush()
    await db_session.commit()

    body = {"entity_type": "threat_actor", "entity_id": str(actor.id), "mode": "watch", "boost": 1.5}
    resp = await client.put("/api/intelligence/watchlist", json=body, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["mode"] == "watch"

    # Upsert flips mode without duplicating
    body["mode"] = "mute"
    resp = await client.put("/api/intelligence/watchlist", json=body, headers=auth_headers)
    assert resp.status_code == 200
    listed = (await client.get("/api/intelligence/watchlist", headers=auth_headers)).json()
    assert len(listed) == 1
    assert listed[0]["mode"] == "mute"

    resp = await client.delete(f"/api/intelligence/watchlist/threat_actor/{actor.id}", headers=auth_headers)
    assert resp.status_code == 200
    listed = (await client.get("/api/intelligence/watchlist", headers=auth_headers)).json()
    assert listed == []


@pytest.mark.asyncio
async def test_mute_suppresses_in_signals_triage(db_session, reliable_feed, test_user, monkeypatch):
    from app.models.user_entity_watch import UserEntityWatch
    from app.services.triage import get_triage_entries_signals
    from app.workers.signal_tasks import score_entry

    entry = await _make_entry(db_session, reliable_feed, title="Muted actor entry")
    actor = await _link_actor(db_session, entry, "AnnoyingActor", article_count=1)
    await score_entry(db_session, entry.id)
    await db_session.flush()

    async def fixed_threshold():
        return 0.1, True

    monkeypatch.setattr("app.intelligence.signals.get_radar_threshold", fixed_threshold)

    result = await get_triage_entries_signals(db_session, test_user.id, user_id_for_watches=test_user.id)
    assert any(i["entry"]["id"] == str(entry.id) for i in result["items"])

    db_session.add(
        UserEntityWatch(created_by=test_user.id, entity_type="threat_actor", entity_id=actor.id, mode="mute")
    )
    await db_session.flush()
    result = await get_triage_entries_signals(db_session, test_user.id, user_id_for_watches=test_user.id)
    assert not any(i["entry"]["id"] == str(entry.id) for i in result["items"])


@pytest.mark.asyncio
async def test_entries_list_chips_when_surfaced(client, auth_headers, db_session, reliable_feed, monkeypatch):
    from app.config import settings as env_settings
    from app.workers.signal_tasks import score_entry

    # Surfacing ships on; this test checks the switch both ways.
    monkeypatch.setattr(env_settings, "signal_engine_surface", False)
    entry = await _make_entry(db_session, reliable_feed, title="Chip entry")
    await _link_actor(db_session, entry, "ChipActor", article_count=1)
    await score_entry(db_session, entry.id)
    await db_session.commit()

    async def fixed_threshold():
        return 0.1, True

    monkeypatch.setattr("app.intelligence.signals.get_radar_threshold", fixed_threshold)

    # Surface off (default): no chip fields populated
    resp = await client.get("/api/entries?limit=50", headers=auth_headers)
    assert resp.status_code == 200
    item = next(i for i in resp.json()["items"] if i["id"] == str(entry.id))
    assert item["priority_score"] is None
    assert item["top_signals"] == []

    # Surface on: chips present
    monkeypatch.setattr(env_settings, "signal_engine_surface", True)
    resp = await client.get("/api/entries?limit=50", headers=auth_headers)
    item = next(i for i in resp.json()["items"] if i["id"] == str(entry.id))
    assert item["priority_score"] is not None
    assert item["top_signals"], item
    assert "type" in item["top_signals"][0] and "explanation" in item["top_signals"][0]


# ── Phase 5: pipeline run visibility ───────────────────────────────


@pytest.mark.asyncio
async def test_pipeline_stage_decorator_records_run(db_session, reliable_feed, monkeypatch):
    from contextlib import asynccontextmanager

    from app.models.entry_pipeline_run import EntryPipelineRun
    from app.workers.pipeline_logging import pipeline_stage

    entry = await _make_entry(db_session, reliable_feed, title="Pipeline run entry")

    @asynccontextmanager
    async def fake_session():
        yield db_session

    recorded = {}

    def fake_run_async(coro):
        recorded["coro"] = coro

    monkeypatch.setattr("app.workers.db.worker_session", fake_session)
    monkeypatch.setattr("app.workers.db.run_async", fake_run_async)

    @pipeline_stage("autolink")
    def fake_task(entry_id: str):
        return "ok"

    assert fake_task(str(entry.id)) == "ok"
    await recorded["coro"]
    await db_session.flush()

    runs = (
        (await db_session.execute(select(EntryPipelineRun).where(EntryPipelineRun.entry_id == entry.id)))
        .scalars()
        .all()
    )
    assert len(runs) == 1
    assert runs[0].stage == "autolink"
    assert runs[0].status == "success"
    assert runs[0].duration_ms is not None

    # Error path records status=error and re-raises
    @pipeline_stage("extract")
    def failing_task(entry_id: str):
        raise ValueError("boom")

    with pytest.raises(ValueError):
        failing_task(str(entry.id))
    await recorded["coro"]
    await db_session.flush()
    runs = (
        (await db_session.execute(select(EntryPipelineRun).where(EntryPipelineRun.entry_id == entry.id)))
        .scalars()
        .all()
    )
    statuses = {(r.stage, r.status) for r in runs}
    assert ("extract", "error") in statuses


@pytest.mark.asyncio
async def test_pipeline_stage_decorator_stores_dict_return_as_detail(db_session, reliable_feed, monkeypatch):
    """A stage task that returns a dict (the adjudicate stage's verdict counts)
    gets it persisted as the run's ``detail``; string returns leave it empty."""
    from contextlib import asynccontextmanager

    from app.models.entry_pipeline_run import EntryPipelineRun
    from app.workers.pipeline_logging import pipeline_stage

    entry = await _make_entry(db_session, reliable_feed, title="Pipeline detail entry")

    @asynccontextmanager
    async def fake_session():
        yield db_session

    recorded = {}

    def fake_run_async(coro):
        recorded["coro"] = coro

    monkeypatch.setattr("app.workers.db.worker_session", fake_session)
    monkeypatch.setattr("app.workers.db.run_async", fake_run_async)

    @pipeline_stage("adjudicate")
    def adjudicate_task(entry_id: str):
        return {"mode": "shadow", "items": 3, "verdicts": {"keep": 2, "remove": 1}}

    assert adjudicate_task(str(entry.id))["items"] == 3
    await recorded["coro"]
    await db_session.flush()

    run = (
        await db_session.execute(
            select(EntryPipelineRun).where(
                EntryPipelineRun.entry_id == entry.id, EntryPipelineRun.stage == "adjudicate"
            )
        )
    ).scalar_one()
    assert run.status == "success"
    assert run.detail == {"mode": "shadow", "items": 3, "verdicts": {"keep": 2, "remove": 1}}


def test_pipeline_stage_extracts_entry_id_from_bind_tasks():
    from app.workers.pipeline_logging import _extract_entry_id

    eid = str(uuid.uuid4())
    assert _extract_entry_id((eid,), {}) == eid  # plain positional
    assert _extract_entry_id((object(), eid), {}) == eid  # bind task (self first)
    assert _extract_entry_id((object(), [None]), {"entry_id": eid}) == eid  # chord callback kwargs
    assert _extract_entry_id((object(),), {}) is None


@pytest.mark.asyncio
async def test_entry_runs_endpoint_and_retry(
    client, auth_headers, admin_headers, db_session, reliable_feed, monkeypatch
):
    from app.models.entry_pipeline_run import EntryPipelineRun

    entry = await _make_entry(db_session, reliable_feed, title="Runs endpoint entry")
    db_session.add(EntryPipelineRun(entry_id=entry.id, stage="autolink", status="success", duration_ms=12))
    db_session.add(EntryPipelineRun(entry_id=entry.id, stage="extract", status="error", error="boom"))
    await db_session.commit()

    resp = await client.get(f"/api/engine/entries/{entry.id}/runs", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    runs = {r["stage"]: r for r in body["runs"]}
    assert runs["autolink"]["status"] == "success"
    assert runs["extract"]["status"] == "error"
    assert runs["extract"]["retryable"] is True
    # The whole pipeline is listed in execution order, not just the stages that
    # wrote a row; translation only appears when it ran.
    assert [r["stage"] for r in body["runs"]] == [s for s in PROCESSING_STAGE_ORDER_FOR_TEST if s != "translate"]
    assert runs["score"]["status"] == "not_run"
    assert runs["analyze"]["status"] == "not_run"
    assert body["status"] == "errored"

    sent = {}

    class FakeResult:
        id = "task-123"

    def fake_send_task(name, kwargs=None, **_):
        sent["name"] = name
        sent["kwargs"] = kwargs
        return FakeResult()

    monkeypatch.setattr("app.workers.celery_app.celery_app.send_task", fake_send_task)
    resp = await client.post(f"/api/engine/entries/{entry.id}/stages/extract/retry", headers=admin_headers)
    assert resp.status_code == 200
    assert sent["name"].endswith("extract_entry_intel_task")
    assert sent["kwargs"] == {"entry_id": str(entry.id)}

    resp = await client.post(f"/api/engine/entries/{entry.id}/stages/translate/retry", headers=admin_headers)
    assert resp.status_code == 422


PROCESSING_STAGE_ORDER_FOR_TEST = [
    "translate",
    "autolink",
    "observables",
    "telegram_links",
    "extract",
    "cooccurrence",
    "correlation",
    "requirements",
    "score",
    "analyze",
    "adjudicate",
    "automate",
]


@pytest.mark.asyncio
async def test_entry_runs_endpoint_lists_ai_stages_from_request_row(client, auth_headers, db_session, reliable_feed):
    """The AI analysis writes no pipeline run, so the popover reads its state
    from the analysis-request row — and reports a queued review behind it."""
    from app.api.engine import PROCESSING_STAGE_ORDER
    from app.models.ai_analysis import AIAnalysisRequest
    from app.models.entry_pipeline_run import EntryPipelineRun

    assert PROCESSING_STAGE_ORDER == PROCESSING_STAGE_ORDER_FOR_TEST

    entry = await _make_entry(db_session, reliable_feed, title="AI stages entry")
    for stage in ("autolink", "extract", "score", "automate"):
        db_session.add(EntryPipelineRun(entry_id=entry.id, stage=stage, status="success", duration_ms=5))
    db_session.add(AIAnalysisRequest(entry_id=entry.id, status="submitted"))
    await db_session.commit()

    resp = await client.get(f"/api/engine/entries/{entry.id}/runs", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    runs = {r["stage"]: r for r in body["runs"]}
    assert runs["analyze"]["status"] == "queued"
    assert runs["analyze"]["detail"] == {"waiting_on": "ai_worker"}
    assert runs["analyze"]["label"] == "AI analysis"
    assert runs["adjudicate"]["status"] == "queued"
    assert runs["adjudicate"]["detail"] == {"waiting_on": "analysis"}
    # Scored, but the AI has not had its say: still in flight for the reader.
    assert body["status"] == "in_flight"

    req = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
    ).scalar_one()
    req.status = "completed"
    req.completed_at = datetime.now(UTC)
    req.adjudication_status = "skipped_off"
    await db_session.commit()

    body = (await client.get(f"/api/engine/entries/{entry.id}/runs", headers=auth_headers)).json()
    runs = {r["stage"]: r for r in body["runs"]}
    assert runs["analyze"]["status"] == "success"
    assert runs["adjudicate"]["status"] == "skipped"
    assert runs["adjudicate"]["detail"] == {"skipped": "off"}
    assert body["status"] == "complete"


@pytest.mark.asyncio
async def test_entry_runs_endpoint_empty_before_logging(client, auth_headers, db_session, reliable_feed):
    entry = await _make_entry(db_session, reliable_feed, title="Pre-logging entry")
    resp = await client.get(f"/api/engine/entries/{entry.id}/runs", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == {"status": "unknown", "runs": []}


@pytest.mark.asyncio
async def test_retry_pipeline_stage_requires_admin(client, auth_headers):
    resp = await client.post(f"/api/engine/entries/{uuid.uuid4()}/stages/extract/retry", headers=auth_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_stage_runs_endpoint(client, auth_headers, db_session, reliable_feed):
    from app.models.entry_pipeline_run import EntryPipelineRun

    entry = await _make_entry(db_session, reliable_feed, title="Stage runs entry")
    db_session.add(EntryPipelineRun(entry_id=entry.id, stage="extract", status="success", duration_ms=8))
    db_session.add(EntryPipelineRun(entry_id=entry.id, stage="extract", status="error", error="deadlock"))
    await db_session.commit()

    resp = await client.get("/api/engine/pipeline/stages/extract/runs", headers=auth_headers)
    assert resp.status_code == 200
    runs = resp.json()["runs"]
    assert len(runs) == 2
    assert {r["status"] for r in runs} == {"success", "error"}
    assert all(r["entry_title"] == "Stage runs entry" for r in runs)
    assert all(r["retryable"] is True for r in runs)

    resp = await client.get("/api/engine/pipeline/stages/extract/runs?status=error", headers=auth_headers)
    assert [r["status"] for r in resp.json()["runs"]] == ["error"]
    assert resp.json()["runs"][0]["error"] == "deadlock"

    resp = await client.get("/api/engine/pipeline/stages/nope/runs", headers=auth_headers)
    assert resp.status_code == 422


def test_job_run_detail_clipping():
    from app.workers.task_tracking import _task_detail

    detail = _task_detail(
        ("x" * 500,),
        {"feed_id": "abc", "big": list(range(50))},
        {"updated": 5, "nested": {"deep": {"too_deep": 1}}},
    )
    assert detail["args"][0].startswith("x") and len(detail["args"][0]) == 201  # clipped + ellipsis
    assert detail["kwargs"]["feed_id"] == "abc"
    assert len(detail["kwargs"]["big"]) == 11  # 10 items + overflow marker
    assert detail["kwargs"]["big"][10] == "… +40 more"
    assert detail["result"]["updated"] == 5
    assert isinstance(detail["result"]["nested"]["deep"], str)  # depth-limited to str
    assert _task_detail((), {}, None) is None


@pytest.mark.asyncio
async def test_job_run_detail_recorded(db_session, monkeypatch):
    from contextlib import asynccontextmanager

    from app.models.job_run import JobRun
    from app.workers import task_tracking

    @asynccontextmanager
    async def fake_session():
        yield db_session

    monkeypatch.setattr("app.workers.db.worker_session", fake_session)
    recorded = {}

    def fake_run_async(coro):
        recorded["coro"] = coro

    monkeypatch.setattr("app.workers.db.run_async", fake_run_async)

    task_tracking._record_run(
        "app.workers.enrichment_tasks.run_epss_bulk_sync",
        "tid-2",
        "success",
        None,
        None,
        detail=task_tracking._task_detail((), {}, {"updated": 1250, "total_scores": 18420}),
    )
    await recorded["coro"]
    await db_session.flush()

    row = (await db_session.execute(select(JobRun))).scalars().one()
    assert row.detail == {"result": {"updated": 1250, "total_scores": 18420}}


# ── Phase 7: signal conditions + radar feedback ────────────────────


@pytest.mark.asyncio
async def test_signal_automation_conditions(db_session, reliable_feed, test_user):
    from app.automation.conditions import evaluate_conditions
    from app.models.user_entity_watch import UserEntityWatch
    from app.workers.signal_tasks import score_entry

    entry = await _make_entry(db_session, reliable_feed, title="Condition entry")
    actor = await _link_actor(db_session, entry, "ConditionActor", article_count=1)
    await score_entry(db_session, entry.id)
    await db_session.flush()
    await db_session.refresh(entry)

    # priority_score_above
    assert await evaluate_conditions(
        db_session, entry, {"type": "priority_score_above", "config": {"min": 0.1}}, test_user.id
    )
    assert not await evaluate_conditions(
        db_session, entry, {"type": "priority_score_above", "config": {"min": 999}}, test_user.id
    )

    # has_signal
    assert await evaluate_conditions(
        db_session, entry, {"type": "has_signal", "config": {"types": ["novel_entity"]}}, test_user.id
    )
    assert not await evaluate_conditions(
        db_session, entry, {"type": "has_signal", "config": {"types": ["kev_added"]}}, test_user.id
    )

    # entity_watchlisted
    assert not await evaluate_conditions(db_session, entry, {"type": "entity_watchlisted", "config": {}}, test_user.id)
    db_session.add(
        UserEntityWatch(created_by=test_user.id, entity_type="threat_actor", entity_id=actor.id, mode="watch")
    )
    await db_session.flush()
    assert await evaluate_conditions(db_session, entry, {"type": "entity_watchlisted", "config": {}}, test_user.id)


@pytest.mark.asyncio
async def test_radar_feedback_endpoint(client, auth_headers, db_session, reliable_feed):
    from app.models.entry_signal_feedback import EntrySignalFeedback

    entry = await _make_entry(db_session, reliable_feed, title="Feedback entry")
    await db_session.commit()

    resp = await client.put(
        "/api/engine/radar-feedback", json={"entry_id": str(entry.id), "verdict": 1}, headers=auth_headers
    )
    assert resp.status_code == 200
    # Flip to noise — upsert, not duplicate
    resp = await client.put(
        "/api/engine/radar-feedback", json={"entry_id": str(entry.id), "verdict": -1}, headers=auth_headers
    )
    assert resp.status_code == 200
    rows = (await db_session.execute(select(EntrySignalFeedback))).scalars().all()
    assert len(rows) == 1 and rows[0].verdict == -1
    # Clear
    resp = await client.put(
        "/api/engine/radar-feedback", json={"entry_id": str(entry.id), "verdict": 0}, headers=auth_headers
    )
    assert resp.status_code == 200
    rows = (await db_session.execute(select(EntrySignalFeedback))).scalars().all()
    assert rows == []
