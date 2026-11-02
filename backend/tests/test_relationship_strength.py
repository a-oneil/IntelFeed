"""Tests for R2: component-based relationship strength + pivot payload."""

import importlib.util
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy import text as sql_text

from app.intelligence.correlation import (
    _compute_relationship_strength,
    _monthly_trend,
    _strength_tier,
    create_cooccurrence_relationships,
    pivot_from_entity,
)
from app.models.country import Country, EntryCountry
from app.models.country_junction import ThreatActorTargetCountry
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor


def test_strength_components():
    now = datetime.now(UTC)
    # corroboration saturates at the configured article count (default 8)
    sat, _ = _compute_relationship_strength([1.0], 8, now)
    more, _ = _compute_relationship_strength([1.0], 100, now)
    assert sat == pytest.approx(more, abs=1e-9)
    # fresh + close + fully corroborated ≈ sum of the weights (≈ 1.0)
    assert sat == pytest.approx(0.45 + 0.40 + 0.15, abs=0.01)
    # closeness is the mean of the top-3 per-article scores
    _, closeness = _compute_relationship_strength([1.0, 0.5, 0.25, 0.1], 4, now)
    assert closeness == pytest.approx((1.0 + 0.5 + 0.25) / 3, abs=1e-9)
    # recency decays with the age of the newest evidence
    fresh, _ = _compute_relationship_strength([1.0], 1, now)
    stale, _ = _compute_relationship_strength([1.0], 1, now - timedelta(days=900))
    assert fresh > stale
    # a single distant, year-old co-mention lands in the weak band
    weak, _ = _compute_relationship_strength([0.25], 1, now - timedelta(days=365))
    assert weak < 0.3


def test_strength_tier_boundaries():
    assert _strength_tier(0.75) == "strong"
    assert _strength_tier(0.5) == "moderate"
    assert _strength_tier(0.1) == "weak"


def test_monthly_trend_buckets():
    now = datetime.now(UTC)
    trend = _monthly_trend([now, now, now - timedelta(days=40)])
    assert len(trend) == 12
    assert trend[-1] == 2  # both current-month dates in the newest bucket
    assert sum(trend) == 3


@pytest.mark.asyncio
async def test_pivot_strength_and_typed_join(db_session, test_feed, test_threat_actor):
    malware = MalwareFamily(name="StrengthLoader")
    db_session.add(malware)
    await db_session.flush()

    now = datetime.now(UTC)
    for i in range(2):
        e = Entry(
            feed_id=test_feed.id,
            title=f"strength {i}",
            guid=f"strength-{i}",
            url=f"https://example.com/st/{i}",
            published_at=now - timedelta(days=i),
            content_hash=f"strength-hash-{i}",
        )
        db_session.add(e)
        await db_session.flush()
        db_session.add_all(
            [
                EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
                EntryMalware(entry_id=e.id, malware_family_id=malware.id, paragraph_indices=[0]),
            ]
        )
        await db_session.flush()
        await create_cooccurrence_relationships(db_session, e.id)

    pivot = await pivot_from_entity(db_session, "threat_actor", test_threat_actor.id)
    rel_items = pivot["related"]["malwares"]
    assert len(rel_items) == 1
    item = rel_items[0]

    s = item["strength"]
    assert s["articles"] == 2
    assert s["sources"] == 1
    assert 0 < s["score"] <= 1
    assert item["proximity_score"] == s["score"]  # badge reads an honest 0–1 now
    assert s["tier"] in ("weak", "moderate", "strong")
    assert s["last_seen"] is not None
    assert sum(s["trend"]) == 2

    # typed layer joined onto the co-occurring row instead of being dropped
    assert item["relationship_type"] == "uses"
    assert item["relationship_direction"] == "outbound"
    assert item["relationship_confidence"] in ("possible", "probable")
    assert pivot["related_counts"]["malwares"] == 1


@pytest.mark.asyncio
async def test_pivot_limit_and_window(db_session, test_feed, test_threat_actor):
    m1 = MalwareFamily(name="LoaderOne")
    m2 = MalwareFamily(name="LoaderTwo")
    db_session.add_all([m1, m2])
    await db_session.flush()

    now = datetime.now(UTC)
    fresh = Entry(
        feed_id=test_feed.id,
        title="fresh",
        guid="lw-fresh",
        url="https://example.com/f",
        published_at=now - timedelta(days=1),
        content_hash="lw-f",
    )
    old = Entry(
        feed_id=test_feed.id,
        title="old",
        guid="lw-old",
        url="https://example.com/o",
        published_at=now - timedelta(days=400),
        content_hash="lw-o",
    )
    db_session.add_all([fresh, old])
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=fresh.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
            EntryMalware(entry_id=fresh.id, malware_family_id=m1.id, paragraph_indices=[0]),
            EntryThreatActor(entry_id=old.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
            EntryMalware(entry_id=old.id, malware_family_id=m2.id, paragraph_indices=[0]),
        ]
    )
    await db_session.flush()

    full = await pivot_from_entity(db_session, "threat_actor", test_threat_actor.id)
    assert full["related_counts"]["malwares"] == 2

    limited = await pivot_from_entity(db_session, "threat_actor", test_threat_actor.id, limit_per_type=1)
    assert len(limited["related"]["malwares"]) == 1
    assert limited["related_counts"]["malwares"] == 2
    # ranked by strength: the fresh relationship outranks the year-old one
    assert limited["related"]["malwares"][0]["name"] == "LoaderOne"

    windowed = await pivot_from_entity(db_session, "threat_actor", test_threat_actor.id, window_days=30)
    assert [m["name"] for m in windowed["related"]["malwares"]] == ["LoaderOne"]


@pytest.mark.asyncio
async def test_country_pivot_verb_annotation(db_session, test_feed, test_threat_actor):
    country = Country(name="Testland", iso_code="TL")
    db_session.add(country)
    await db_session.flush()

    e = Entry(
        feed_id=test_feed.id, title="geo", guid="geo-1", url="https://example.com/g", published_at=datetime.now(UTC)
    )
    db_session.add(e)
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
            EntryCountry(entry_id=e.id, country_id=country.id, paragraph_indices=[0], role="target"),
            ThreatActorTargetCountry(threat_actor_id=test_threat_actor.id, country_id=country.id),
        ]
    )
    await db_session.flush()

    pivot = await pivot_from_entity(db_session, "country", country.id)
    actors = pivot["related"]["threat_actors"]
    assert actors
    assert actors[0]["country_relationship"] == "targets"


@pytest.mark.asyncio
async def test_country_infrastructure_verb(db_session, test_feed, test_threat_actor):
    country = Country(name="Infraland", iso_code="IF")
    db_session.add(country)
    await db_session.flush()

    e = Entry(
        feed_id=test_feed.id,
        title="infra",
        guid="infra-1",
        url="https://example.com/if",
        published_at=datetime.now(UTC),
    )
    db_session.add(e)
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
            EntryCountry(entry_id=e.id, country_id=country.id, paragraph_indices=[0], role="infrastructure"),
        ]
    )
    await db_session.flush()

    pivot = await pivot_from_entity(db_session, "country", country.id)
    actors = pivot["related"]["threat_actors"]
    assert actors
    assert actors[0]["country_relationship"] == "infrastructure"


@pytest.mark.asyncio
async def test_pivot_offset_and_sort(db_session, test_feed, test_threat_actor):
    m_fresh = MalwareFamily(name="FreshOne")
    m_bulk = MalwareFamily(name="BulkTwo")
    db_session.add_all([m_fresh, m_bulk])
    await db_session.flush()

    now = datetime.now(UTC)
    # m_fresh: one recent article; m_bulk: two old articles (more evidence, weaker recency)
    entries = [
        (m_fresh, "os-fresh", 1),
        (m_bulk, "os-old-a", 300),
        (m_bulk, "os-old-b", 310),
    ]
    for malware, guid, age in entries:
        e = Entry(
            feed_id=test_feed.id,
            title=guid,
            guid=guid,
            url=f"https://example.com/{guid}",
            published_at=now - timedelta(days=age),
            content_hash=guid,
        )
        db_session.add(e)
        await db_session.flush()
        db_session.add_all(
            [
                EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
                EntryMalware(entry_id=e.id, malware_family_id=malware.id, paragraph_indices=[0]),
            ]
        )
        await db_session.flush()

    by_articles = await pivot_from_entity(db_session, "threat_actor", test_threat_actor.id, sort="articles")
    assert [m["name"] for m in by_articles["related"]["malwares"]] == ["BulkTwo", "FreshOne"]

    offset_page = await pivot_from_entity(
        db_session, "threat_actor", test_threat_actor.id, sort="articles", limit_per_type=1, offset=1
    )
    assert [m["name"] for m in offset_page["related"]["malwares"]] == ["FreshOne"]
    assert offset_page["related_counts"]["malwares"] == 2


@pytest.mark.asyncio
async def test_direction_migration_round_trip(db_session, test_threat_actor):
    """Execute the direction-fix migration's SQL against seeded rows, both ways."""
    malware_row = MalwareFamily(name="MigrationLoader")
    db_session.add(malware_row)
    await db_session.flush()
    # Capture ids up front — expire_all() below would force lazy IO on access.
    actor_id, malware_id = test_threat_actor.id, malware_row.id

    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "c2a2b3c4d5f9_fix_relationship_direction.py"
    spec = importlib.util.spec_from_file_location("mig_c2a2b3c4d5f9", path)
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)

    class _Recorder:
        def __init__(self):
            self.statements: list[str] = []

        def execute(self, sql):
            self.statements.append(sql)

    e1, e2 = uuid.uuid4(), uuid.uuid4()
    db_session.add_all(
        [
            # Pre-fix inverted storage: "malware uses actor"
            EntityRelationship(
                source_type="malware",
                source_id=malware_row.id,
                target_type="threat_actor",
                target_id=test_threat_actor.id,
                relationship_type="uses",
                confidence="probable",
                source="co_occurrence",
                evidence_entry_ids=[e1],
            ),
            # Correctly-directed duplicate — upgrade must merge, not collide
            EntityRelationship(
                source_type="threat_actor",
                source_id=test_threat_actor.id,
                target_type="malware",
                target_id=malware_row.id,
                relationship_type="uses",
                confidence="possible",
                source="co_occurrence",
                evidence_entry_ids=[e2],
            ),
        ]
    )
    await db_session.flush()

    rec = _Recorder()
    mig.op = rec
    mig.upgrade()
    for stmt in rec.statements:
        await db_session.execute(sql_text(stmt))
    db_session.expire_all()

    rows = (await db_session.execute(select(EntityRelationship))).scalars().all()
    assert len(rows) == 1
    merged = rows[0]
    assert (merged.source_type, merged.source_id) == ("threat_actor", actor_id)
    assert (merged.target_type, merged.target_id) == ("malware", malware_id)
    assert set(merged.evidence_entry_ids) == {e1, e2}
    assert merged.confidence == "probable"  # stronger confidence kept in the merge

    rec_down = _Recorder()
    mig.op = rec_down
    mig.downgrade()
    for stmt in rec_down.statements:
        await db_session.execute(sql_text(stmt))
    db_session.expire_all()

    rows = (await db_session.execute(select(EntityRelationship))).scalars().all()
    assert len(rows) == 1
    reverted = rows[0]
    assert (reverted.source_type, reverted.target_type) == ("malware", "threat_actor")


@pytest.mark.asyncio
async def test_graph_edges_carry_typed_verbs(db_session, test_feed, test_threat_actor):
    """R4: graph edges use the typed verb, oriented semantically, with provenance."""
    from app.intelligence.correlation import build_entity_graph
    from app.intelligence.correlation_cache import invalidate_entity_cache

    malware = MalwareFamily(name="GraphLoader")
    db_session.add(malware)
    await db_session.flush()

    e = Entry(
        feed_id=test_feed.id,
        title="graph",
        guid="graph-1",
        url="https://example.com/gr",
        published_at=datetime.now(UTC),
    )
    db_session.add(e)
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
            EntryMalware(entry_id=e.id, malware_family_id=malware.id, paragraph_indices=[0]),
        ]
    )
    await db_session.flush()
    await create_cooccurrence_relationships(db_session, e.id)

    def _actor_malware_edge(graph):
        return next(
            (
                ed
                for ed in graph["edges"]
                if {ed["source"].split("-", 1)[0], ed["target"].split("-", 1)[0]} == {"threat_actor", "malware"}
            ),
            None,
        )

    # A single co-mention reaches the "possible" signal tier — the map shows
    # every claim tier now, so the edge is drawn immediately, marked possible.
    rel = (await db_session.execute(select(EntityRelationship))).scalar_one()
    assert rel.confidence == "possible"
    signal_edge = _actor_malware_edge(await build_entity_graph(db_session, "malware", malware.id))
    assert signal_edge is not None
    assert signal_edge["confidence"] == "possible"

    # Promote it; the edge keeps its verb and carries the new tier. Graphs are
    # cached in Redis, so the earlier result has to be dropped first.
    rel.confidence = "probable"
    await db_session.flush()
    await invalidate_entity_cache("malware", str(malware.id))

    # Viewed from the MALWARE side: the edge must still read actor -uses-> malware.
    edge = _actor_malware_edge(await build_entity_graph(db_session, "malware", malware.id))
    assert edge is not None
    assert edge["label"] == "uses"
    assert edge["source"].startswith("threat_actor-")
    assert edge["target"].startswith("malware-")
    assert edge["provenance"] == "co_occurrence"
    assert edge["confidence"] == "probable"


@pytest.mark.asyncio
async def test_relationship_signals_endpoint(client, auth_headers, db_session, test_threat_actor):
    malware = MalwareFamily(name="SignalLoader")
    db_session.add(malware)
    await db_session.flush()
    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=test_threat_actor.id,
            target_type="malware",
            target_id=malware.id,
            relationship_type="uses",
            confidence="probable",
            source="co_occurrence",
            evidence_entry_ids=[],
        )
    )
    await db_session.flush()

    # POST, not GET: the table sends every loaded row's id, which overflowed
    # gunicorn's request-line limit as a query string.
    resp = await client.post(
        "/api/entity-relationships/signals/threat_actor",
        json={"ids": [str(test_threat_actor.id)]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    sig = resp.json()[str(test_threat_actor.id)]
    assert sig["count"] == 1
    assert sig["top"][0]["verb"] == "uses"
    assert sig["top"][0]["direction"] == "outbound"
    assert sig["top"][0]["other_label"] == "SignalLoader"


@pytest.mark.asyncio
async def test_decay_stale_relationships(db_session, test_feed, test_threat_actor):
    from app.workers.maintenance import decay_stale_relationships

    m_stale = MalwareFamily(name="StaleLoader")
    m_fresh = MalwareFamily(name="FreshLoader")
    db_session.add_all([m_stale, m_fresh])
    await db_session.flush()

    now = datetime.now(UTC)
    old_entry = Entry(
        feed_id=test_feed.id,
        title="old",
        guid="decay-old",
        url="https://example.com/do",
        published_at=now - timedelta(days=400),
    )
    new_entry = Entry(
        feed_id=test_feed.id,
        title="new",
        guid="decay-new",
        url="https://example.com/dn",
        published_at=now - timedelta(days=5),
    )
    db_session.add_all([old_entry, new_entry])
    await db_session.flush()

    stale = EntityRelationship(
        source_type="threat_actor",
        source_id=test_threat_actor.id,
        target_type="malware",
        target_id=m_stale.id,
        relationship_type="uses",
        confidence="probable",
        source="co_occurrence",
        evidence_entry_ids=[old_entry.id],
    )
    fresh = EntityRelationship(
        source_type="threat_actor",
        source_id=test_threat_actor.id,
        target_type="malware",
        target_id=m_fresh.id,
        relationship_type="uses",
        confidence="probable",
        source="co_occurrence",
        evidence_entry_ids=[new_entry.id],
    )
    db_session.add_all([stale, fresh])
    await db_session.flush()

    demoted = await decay_stale_relationships(db_session, now - timedelta(days=180))
    assert demoted == 1
    await db_session.refresh(stale)
    await db_session.refresh(fresh)
    assert stale.confidence == "possible"
    assert fresh.confidence == "probable"


@pytest.mark.asyncio
async def test_evidence_count_promotes_confidence(db_session, test_feed, test_threat_actor):
    from app.models.feed import Feed

    malware = MalwareFamily(name="PromoLoader")
    second_feed = Feed(title="Second Feed", url="https://feed2.example.com/rss", feed_type="rss")
    db_session.add_all([malware, second_feed])
    await db_session.flush()

    # Each sighting is a same-paragraph co-mention and starts "possible"; the
    # third distinct evidence entry promotes to "probable" by corroboration —
    # but only because the evidence spans two distinct feeds (a single chatty
    # source can't self-promote).
    feeds = [test_feed.id, test_feed.id, second_feed.id]
    for i in range(3):
        e = Entry(feed_id=feeds[i], title=f"promo {i}", guid=f"promo-{i}", url=f"https://example.com/p/{i}")
        db_session.add(e)
        await db_session.flush()
        db_session.add_all(
            [
                EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
                EntryMalware(entry_id=e.id, malware_family_id=malware.id, paragraph_indices=[0]),
            ]
        )
        await db_session.flush()
        await create_cooccurrence_relationships(db_session, e.id)
        rel = (
            (await db_session.execute(select(EntityRelationship).where(EntityRelationship.target_id == malware.id)))
            .scalars()
            .one()
        )
        if i < 2:
            assert rel.confidence == "possible"  # same-feed evidence never promotes

    assert rel.confidence == "probable"
    assert len(rel.evidence_entry_ids) == 3


@pytest.mark.asyncio
async def test_coincidental_verdict_blocks_promotion(db_session, test_feed, test_threat_actor):
    from app.models.feed import Feed

    malware = MalwareFamily(name="CoincLoader")
    second_feed = Feed(title="Other Feed", url="https://feed3.example.com/rss", feed_type="rss")
    db_session.add_all([malware, second_feed])
    await db_session.flush()

    rel = EntityRelationship(
        source_type="threat_actor",
        source_id=test_threat_actor.id,
        target_type="malware",
        target_id=malware.id,
        relationship_type="uses",
        confidence="possible",
        source="co_occurrence",
        adjudication_verdict="coincidental",
        evidence_entry_ids=[],
    )
    db_session.add(rel)
    await db_session.flush()

    # Pile on multi-feed, same-paragraph evidence — normally an instant promote.
    for i, fid in enumerate([test_feed.id, second_feed.id, test_feed.id]):
        e = Entry(feed_id=fid, title=f"coinc {i}", guid=f"coinc-{i}", url=f"https://example.com/c/{i}")
        db_session.add(e)
        await db_session.flush()
        db_session.add_all(
            [
                EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
                EntryMalware(entry_id=e.id, malware_family_id=malware.id, paragraph_indices=[0]),
            ]
        )
        await db_session.flush()
        await create_cooccurrence_relationships(db_session, e.id)

    await db_session.refresh(rel)
    assert rel.confidence == "possible"  # adjudicated coincidental — never re-promoted
    assert len(rel.evidence_entry_ids) == 3  # evidence still accumulates


# ── Source reliability weighting ────────────────────────────────────


def test_reliability_multiplier_bands():
    from app.intelligence.correlation import _reliability_multiplier

    # A/B boost, D/E penalize, C / F ("cannot be judged") / unrated are neutral
    assert _reliability_multiplier("A") == _reliability_multiplier("B") > 1.0
    assert _reliability_multiplier("D") == _reliability_multiplier("E") < 1.0
    for neutral in ("C", "F", None):
        assert _reliability_multiplier(neutral) == 1.0


def test_reliability_weighted_corroboration_math():
    now = datetime.now(UTC)
    # A weighted (fractional) article count moves corroboration monotonically:
    # 2 articles from A-rated feeds (2 × 1.15) > 2 unrated > 2 from E-rated (2 × 0.85)
    boosted, _ = _compute_relationship_strength([0.5], 2 * 1.15, now)
    neutral, _ = _compute_relationship_strength([0.5], 2.0, now)
    penalized, _ = _compute_relationship_strength([0.5], 2 * 0.85, now)
    assert boosted > neutral > penalized


@pytest.mark.asyncio
async def test_pivot_reliability_weights_evidence(db_session, test_threat_actor):
    """Identical evidence from an A-rated feed outranks it from an E-rated feed."""
    reliable = Feed(title="A Source", url="https://a.example/feed", feed_type="rss", reliability_rating="A")
    dubious = Feed(title="E Source", url="https://e.example/feed", feed_type="rss", reliability_rating="E")
    db_session.add_all([reliable, dubious])
    await db_session.flush()

    m_hi = MalwareFamily(name="HighRelLoader")
    m_lo = MalwareFamily(name="LowRelLoader")
    db_session.add_all([m_hi, m_lo])
    await db_session.flush()

    now = datetime.now(UTC)
    for feed, malware, tag in ((reliable, m_hi, "hi"), (dubious, m_lo, "lo")):
        for i in range(2):
            # Adjacent paragraphs so closeness stays below the 1.0 cap and the
            # reliability multiplier is visible in both components.
            e = Entry(
                feed_id=feed.id,
                title=f"rel {tag} {i}",
                guid=f"relw-{tag}-{i}",
                url=f"https://example.com/{tag}/{i}",
                published_at=now - timedelta(days=i),
                content_hash=f"relw-{tag}-hash-{i}",
            )
            db_session.add(e)
            await db_session.flush()
            db_session.add_all(
                [
                    EntryThreatActor(entry_id=e.id, threat_actor_id=test_threat_actor.id, paragraph_indices=[0]),
                    EntryMalware(entry_id=e.id, malware_family_id=malware.id, paragraph_indices=[1]),
                ]
            )
            await db_session.flush()

    pivot = await pivot_from_entity(db_session, "threat_actor", test_threat_actor.id)
    by_name = {m["name"]: m for m in pivot["related"]["malwares"]}
    hi, lo = by_name["HighRelLoader"], by_name["LowRelLoader"]
    assert hi["strength"]["score"] > lo["strength"]["score"]
    # displayed article counts stay integers (weighting only affects the score)
    assert hi["strength"]["articles"] == 2
    assert lo["strength"]["articles"] == 2


# ── Specificity (IDF) damping ────────────────────────────────────


def test_specificity_math():
    from app.intelligence.correlation import _specificity

    # Ubiquitous counterpart (CrowdStrike-scale: ~5% of corpus) sinks low.
    assert _specificity(5738, 125343) < 0.35
    # Obscure counterpart stays near 1.0.
    assert _specificity(2, 125343) > 0.9
    # No corpus size → damping disabled.
    assert _specificity(100, None) is None
    assert _specificity(100, 0) is None
