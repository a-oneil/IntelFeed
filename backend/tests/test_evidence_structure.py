"""Evidence structure: story clustering over a relationship's evidence.

Vectors are built to sit at stated cosine distances (same convention as
test_story_threads) so a threshold change fails the test that owns it.
"""

import math
import uuid
from datetime import UTC, datetime, timedelta

import pytest_asyncio
from sqlalchemy import text

from app.config import settings
from app.intelligence.evidence_structure import (
    attach_evidence_structure,
    classify_shape,
    has_story_cluster,
    single_link_clusters,
    story_cluster_counts,
)
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.vector_types import to_literal

NOW = datetime.now(UTC)
DIM = 768


def unit(*, similarity: float, axis: int = 1) -> list[float]:
    """A 768-d unit vector whose cosine to e1 is exactly ``similarity``."""
    vec = [0.0] * DIM
    vec[0] = similarity
    vec[axis] = math.sqrt(max(0.0, 1.0 - similarity * similarity))
    return vec


def cluster_vec(cluster_axis: int) -> list[float]:
    """Vectors sharing a cluster_axis are identical (cosine 1.0) and nearly
    orthogonal to every other cluster's vectors (cosine 0)."""
    vec = [0.0] * DIM
    vec[cluster_axis] = 1.0
    return vec


@pytest_asyncio.fixture
async def feed(db_session) -> Feed:
    f = Feed(title="Outlet", url="https://outlet.example/feed", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


async def make_entry(db_session, feed, *, vec: list[float], published: datetime | None = None) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title=f"entry {uuid.uuid4().hex[:8]}",
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://outlet.example/{uuid.uuid4()}",
        content_text="x" * 400,
        published_at=published or NOW,
    )
    db_session.add(entry)
    await db_session.flush()
    await db_session.execute(
        text(
            "INSERT INTO entry_embeddings (entry_id, embedding, model, content_hash) "
            "VALUES (:e, (:v)::halfvec, 'test', :h)"
        ),
        {"e": entry.id, "v": to_literal(vec), "h": uuid.uuid4().hex},
    )
    return entry


def prox(entry, score: float = 0.9) -> dict:
    return {
        "entry_id": str(entry.id),
        "score": score,
        "published_at": entry.published_at.isoformat() if entry.published_at else None,
    }


class TestClustering:
    def test_two_groups_and_a_singleton(self):
        vecs = [cluster_vec(1), cluster_vec(1), cluster_vec(2), cluster_vec(2), cluster_vec(3)]
        clusters = single_link_clusters(vecs, 0.75)
        sizes = sorted(len(c) for c in clusters)
        assert sizes == [1, 2, 2]

    def test_below_threshold_never_joins(self):
        vecs = [unit(similarity=1.0), unit(similarity=0.74, axis=2)]
        assert len(single_link_clusters(vecs, 0.75)) == 2

    def test_at_threshold_joins(self):
        vecs = [unit(similarity=1.0), unit(similarity=0.76, axis=2)]
        assert len(single_link_clusters(vecs, 0.76)) == 1


class TestShapes:
    def test_classify(self):
        assert classify_shape(2, 8) == "recurring"
        assert classify_shape(1, 3) == "single_story"
        assert classify_shape(0, 5) == "scattered"
        assert classify_shape(0, 2) == "thin"


class TestAttach:
    async def test_flag_off_is_a_noop(self, db_session, feed, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", False)
        e1 = await make_entry(db_session, feed, vec=cluster_vec(1))
        item = {"proximity_entries": [prox(e1), prox(e1)]}
        await attach_evidence_structure(db_session, [item])
        assert "evidence_structure" not in item

    async def test_two_incidents_read_as_recurring(self, db_session, feed, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        a = [
            await make_entry(db_session, feed, vec=cluster_vec(1), published=NOW - timedelta(days=i)) for i in range(2)
        ]
        b = [
            await make_entry(db_session, feed, vec=cluster_vec(2), published=NOW - timedelta(days=30 + i))
            for i in range(3)
        ]
        loner = await make_entry(db_session, feed, vec=cluster_vec(3), published=NOW - timedelta(days=60))
        item = {"proximity_entries": [prox(e) for e in a + b + [loner]]}

        await attach_evidence_structure(db_session, [item])

        es = item["evidence_structure"]
        assert es["shape"] == "recurring"
        assert [s["entries"] for s in es["stories"]] == [2, 3]  # newest story first
        assert es["loose"] == 1
        assert es["sampled"] == 6

    async def test_far_apart_cluster_is_not_asserting(self, db_session, feed, monkeypatch):
        """A story that only names the pair paragraphs apart (low proximity)
        is shared coverage, not an assertion — with 3+ entries that's the
        roundup-noise shape."""
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        entries = [await make_entry(db_session, feed, vec=cluster_vec(1)) for _ in range(3)]
        item = {"proximity_entries": [prox(e, score=0.1) for e in entries]}

        await attach_evidence_structure(db_session, [item])

        assert item["evidence_structure"]["shape"] == "scattered"
        assert item["evidence_structure"]["stories"] == []

    async def test_single_mention_is_thin(self, db_session, feed, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        e1 = await make_entry(db_session, feed, vec=cluster_vec(1))
        item = {"proximity_entries": [prox(e1)]}
        await attach_evidence_structure(db_session, [item])
        assert item["evidence_structure"]["shape"] == "thin"

    async def test_no_vectors_makes_no_claim(self, db_session, feed, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        item = {"proximity_entries": [prox_stub(), prox_stub(), prox_stub()]}
        await attach_evidence_structure(db_session, [item])
        assert "evidence_structure" not in item

    async def test_story_cluster_carries_thread_title(self, db_session, feed, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        entries = [await make_entry(db_session, feed, vec=cluster_vec(1)) for _ in range(2)]
        thread_id = uuid.uuid4()
        await db_session.execute(
            text(
                "INSERT INTO story_threads (id, slug, title) VALUES (:i, 'zimbra-webmail', 'Zimbra webmail intrusion')"
            ),
            {"i": thread_id},
        )
        for e in entries:
            await db_session.execute(
                text("INSERT INTO story_thread_entries (id, thread_id, entry_id) VALUES (:i, :t, :e)"),
                {"i": uuid.uuid4(), "t": thread_id, "e": e.id},
            )
        item = {"proximity_entries": [prox(e) for e in entries]}

        await attach_evidence_structure(db_session, [item])

        story = item["evidence_structure"]["stories"][0]
        assert story["slug"] == "zimbra-webmail"
        assert story["title"] == "Zimbra webmail intrusion"


def prox_stub() -> dict:
    return {"entry_id": str(uuid.uuid4()), "score": 0.9, "published_at": NOW.isoformat()}


class TestPromotionFloor:
    async def test_story_cluster_passes(self, db_session, feed, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        entries = [await make_entry(db_session, feed, vec=cluster_vec(1)) for _ in range(2)]
        assert await has_story_cluster(db_session, [e.id for e in entries]) is True

    async def test_all_scatter_fails(self, db_session, feed, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        entries = [await make_entry(db_session, feed, vec=cluster_vec(i + 1)) for i in range(3)]
        assert await has_story_cluster(db_session, [e.id for e in entries]) is False

    async def test_missing_vectors_are_unknown(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        assert await has_story_cluster(db_session, [uuid.uuid4(), uuid.uuid4()]) is None

    async def test_counts_are_per_key(self, db_session, feed, monkeypatch):
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        a = [await make_entry(db_session, feed, vec=cluster_vec(1)) for _ in range(2)]
        b = [await make_entry(db_session, feed, vec=cluster_vec(i + 2)) for i in range(2)]
        counts = await story_cluster_counts(db_session, {"a": [e.id for e in a], "b": [e.id for e in b]})
        assert counts == {"a": 1, "b": 0}


class TestCacheVariant:
    def test_flag_folds_into_variant(self, monkeypatch):
        from app.intelligence.correlation_cache import confidence_cache_variant

        monkeypatch.setattr(settings, "relationship_evidence_structure", False)
        off = confidence_cache_variant()
        monkeypatch.setattr(settings, "relationship_evidence_structure", True)
        on = confidence_cache_variant()
        assert off != on
        assert "es0.75" in on
