"""Relationship adjudication worker — edge collection and verdict application."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.malware_family import MalwareFamily
from app.models.user import User
from app.workers.relationship_adjudication_tasks import (
    _adjudicate_batch_async,
    collect_adjudicable_edges,
)


@pytest.mark.asyncio
async def test_collect_serializes_claims_with_deduped_headlines(db_session, test_feed, test_threat_actor):
    malware = MalwareFamily(name="AdjLoader")
    db_session.add(malware)
    await db_session.flush()

    entry_ids = []
    for i, title in enumerate(["APT deploys AdjLoader", "APT deploys AdjLoader", "AdjLoader spreads"]):
        e = Entry(
            feed_id=test_feed.id,
            title=title,
            guid=f"adj-{i}",
            url=f"https://example.com/adj/{i}",
            published_at=datetime.now(UTC) - timedelta(days=i),
        )
        db_session.add(e)
        await db_session.flush()
        entry_ids.append(e.id)

    rel = EntityRelationship(
        source_type="threat_actor",
        source_id=test_threat_actor.id,
        target_type="malware",
        target_id=malware.id,
        relationship_type="uses",
        confidence="probable",
        source="co_occurrence",
        evidence_entry_ids=entry_ids,
    )
    db_session.add(rel)
    await db_session.flush()

    items = await collect_adjudicable_edges(db_session)
    assert len(items) == 1
    assert items[0]["edge_id"] == str(rel.id)
    assert "uses AdjLoader (malware)" in items[0]["claim"]
    # syndicated duplicate title deduped
    assert len(items[0]["evidence"]) == 2


@pytest.mark.asyncio
@pytest.mark.committed_db
async def test_verdicts_apply_confidence_changes(
    db_session, test_feed, test_threat_actor, admin_user: User, monkeypatch
):
    m1 = MalwareFamily(name="CorrLoader")
    m2 = MalwareFamily(name="CoincLoader")
    m3 = MalwareFamily(name="UnsureLoader")
    db_session.add_all([m1, m2, m3])
    await db_session.flush()

    def _rel(target):
        return EntityRelationship(
            source_type="threat_actor",
            source_id=test_threat_actor.id,
            target_type="malware",
            target_id=target.id,
            relationship_type="uses",
            confidence="probable",
            source="co_occurrence",
            evidence_entry_ids=[uuid.uuid4() for _ in range(3)],
        )

    r1, r2, r3 = _rel(m1), _rel(m2), _rel(m3)
    db_session.add_all([r1, r2, r3])
    await db_session.commit()  # batch opens its own session

    async def fake_run_task(**kwargs):
        return {
            "verdicts": [
                {"edge_id": str(r1.id), "verdict": "corroborated", "reason": "known pairing"},
                {"edge_id": str(r2.id), "verdict": "coincidental", "reason": "roundup co-mention"},
                {"edge_id": str(r3.id), "verdict": "unsure", "reason": "thin headlines"},
                {"edge_id": str(uuid.uuid4()), "verdict": "corroborated", "reason": "hallucinated id"},
            ]
        }

    import app.workers.relationship_adjudication_tasks as mod

    monkeypatch.setattr(mod, "run_task", fake_run_task)

    # worker_session builds its own engine from settings — rebind it to the test DB
    from contextlib import asynccontextmanager

    from sqlalchemy.ext.asyncio import AsyncSession as _AS
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from tests.conftest import TEST_DATABASE_URL

    @asynccontextmanager
    async def fake_worker_session():
        engine = create_async_engine(TEST_DATABASE_URL)
        factory = async_sessionmaker(engine, class_=_AS, expire_on_commit=False)
        try:
            async with factory() as session:
                yield session
        finally:
            await engine.dispose()

    monkeypatch.setattr(mod, "worker_session", fake_worker_session)

    items = [
        {"edge_id": str(r1.id), "claim": "x", "evidence": []},
        {"edge_id": str(r2.id), "claim": "y", "evidence": []},
        {"edge_id": str(r3.id), "claim": "z", "evidence": []},
    ]
    stats = await _adjudicate_batch_async(items)
    assert stats["status"] == "adjudicated"
    assert stats["corroborated"] == 1 and stats["coincidental"] == 1 and stats["unsure"] == 1
    assert stats["unknown_ids"] == 1

    db_session.expire_all()  # the batch wrote via its own session
    rows = {str(r.id): r for r in (await db_session.execute(select(EntityRelationship))).scalars().all()}
    assert rows[str(r1.id)].confidence == "confirmed"
    assert rows[str(r1.id)].adjudication_verdict == "corroborated"
    assert rows[str(r2.id)].confidence == "possible"
    assert rows[str(r2.id)].adjudication_verdict == "coincidental"
    assert rows[str(r3.id)].confidence == "probable"  # unsure leaves confidence alone
    assert rows[str(r3.id)].adjudication_verdict == "unsure"
    assert all(r.adjudicated_at is not None for r in rows.values())

    # adjudicated edges never re-collected
    assert await collect_adjudicable_edges(db_session) == []


# --------------------------------------------------------------------------- dossier context


async def _edge_with_evidence(db, feed, actor, malware, *, link_evidence_to_actor: bool = False):
    """A probable actor→malware edge with three evidence entries."""
    from app.models.threat_actor import EntryThreatActor

    entry_ids = []
    for i in range(3):
        e = Entry(
            feed_id=feed.id,
            title=f"Dossier evidence {i}",
            guid=f"dossier-{uuid.uuid4().hex[:8]}",
            url=f"https://example.com/dossier/{uuid.uuid4().hex[:8]}",
            published_at=datetime.now(UTC) - timedelta(days=i),
        )
        db.add(e)
        await db.flush()
        entry_ids.append(e.id)
        if link_evidence_to_actor:
            db.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    rel = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="malware",
        target_id=malware.id,
        relationship_type="uses",
        confidence="probable",
        source="co_occurrence",
        evidence_entry_ids=entry_ids,
    )
    db.add(rel)
    await db.flush()
    return rel


@pytest.mark.asyncio
async def test_dossier_context_reaches_the_prompt(db_session, test_feed, test_threat_actor):
    """Headlines assume the reader knows who the actor is; the profile paragraph
    is what turns an honest `unsure` into a verdict."""
    from app.workers.relationship_adjudication_tasks import _render_edges_block

    test_threat_actor.description = "Abuses identity providers by resetting MFA through help desks."
    malware = MalwareFamily(name="DossierLoader", description="Loader dropped after valid-session access.")
    db_session.add_all([test_threat_actor, malware])
    await db_session.flush()

    await _edge_with_evidence(db_session, test_feed, test_threat_actor, malware)

    items = await collect_adjudicable_edges(db_session, limit=10)
    assert len(items) == 1
    names = {d["name"] for d in items[0]["dossiers"]}
    assert names == {f"{test_threat_actor.name} (threat_actor)", "DossierLoader (malware)"}

    block = _render_edges_block(items)
    assert "profile of DossierLoader (malware): Loader dropped" in block
    # The context rides inside edges_block, which every stored version of the
    # prompt already renders — a new template variable would land nowhere.
    assert "evidence headlines:" in block


@pytest.mark.asyncio
async def test_dossier_withheld_when_it_restates_the_evidence(db_session, test_feed, test_threat_actor):
    """The assessment is written from the entity's recent articles. When those
    are also the edge's evidence, handing it over lets the model corroborate
    itself."""
    test_threat_actor.description = "Everything known about this actor comes from these same articles."
    malware = MalwareFamily(name="SelfRefLoader")
    db_session.add_all([test_threat_actor, malware])
    await db_session.flush()

    await _edge_with_evidence(db_session, test_feed, test_threat_actor, malware, link_evidence_to_actor=True)

    items = await collect_adjudicable_edges(db_session, limit=10)
    assert len(items) == 1
    assert "dossiers" not in items[0], "dossier should be withheld when it is the evidence restated"


@pytest.mark.asyncio
async def test_dossier_can_be_switched_off(db_session, test_feed, test_threat_actor, monkeypatch):
    from app.workers import relationship_adjudication_tasks as mod

    test_threat_actor.description = "Some assessment."
    malware = MalwareFamily(name="OffLoader", description="Also assessed.")
    db_session.add_all([test_threat_actor, malware])
    await db_session.flush()
    await _edge_with_evidence(db_session, test_feed, test_threat_actor, malware)

    # Settings is a frozen pydantic model, so the override goes on the class.
    real_get = type(mod.settings).get

    def _get(self, key, *a, **kw):
        if key == "relationship_adjudication_dossier":
            return False
        return real_get(self, key, *a, **kw)

    monkeypatch.setattr(type(mod.settings), "get", _get)
    items = await collect_adjudicable_edges(db_session, limit=10)
    assert len(items) == 1
    assert "dossiers" not in items[0]


def test_dossier_setting_is_registered():
    from app.config import settings
    from app.services.system_settings import _ENGINE_SECTION_GROUPS, CONFIGURABLE_KEYS

    assert CONFIGURABLE_KEYS.get("relationship_adjudication_dossier") is bool
    assert "relationship_adjudication_dossier" in _ENGINE_SECTION_GROUPS
    assert settings.relationship_adjudication_dossier is True
