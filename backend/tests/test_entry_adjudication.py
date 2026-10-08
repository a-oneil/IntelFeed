"""Adjudicate stage (commit 2): gates, manifest, verdict validation, shadow writes."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_analysis import AIAnalysisRequest
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.pending_autolink import PendingAutolinkMatch
from app.models.system_setting import SystemSettings
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.services import entry_adjudication as adj
from app.services.entry_adjudication import (
    ACTION_EDGE_DEMOTE,
    ACTION_IOC_DROP,
    ACTION_MERGE,
    ACTION_UNLINK,
    ACTION_VETO,
    ReviewItem,
    _validate_verdicts,
    apply_verdicts,
    build_manifest,
    enqueue_adjudication,
)


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch):
    import app.services.system_settings as ss_mod

    monkeypatch.setattr(ss_mod, "_cache", None)
    monkeypatch.setattr(ss_mod, "_cache_ts", 0.0)
    yield


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    """Budget + breaker touch Redis; stub them so tests are DB-only."""

    async def _always_fits(max_per_hour: int) -> bool:
        return True

    async def _never_trips(ratio: float, pct: float) -> bool:
        return False

    monkeypatch.setattr(adj, "_consume_hour_budget", _always_fits)
    monkeypatch.setattr(adj, "_rolling_breaker", _never_trips)


@pytest_asyncio.fixture
async def feed(db_session) -> Feed:
    f = Feed(title="Warlock Feed", url="https://adj.example/feed", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


ARTICLE = (
    "The Warlock ransomware crew, which some trackers call Warlock Group, claimed Water Utility Co "
    "on its leak site this week after the utility reported outages it first blamed on the storm.\n\n"
    "Defenders should watch for Cobalt Strike beacons. Full indicators are on our blog at "
    "blog.vendor-research.example."
)


async def _seed_settings(db_session, **overrides):
    values = {"adjudication_mode": "shadow", "adjudication_trigger": "all", **overrides}
    db_session.add(SystemSettings(id=1, settings=values, secrets={}))
    await db_session.flush()


async def _make_entry(db_session, feed, *, score=0.6) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title="Warlock Ransomware Attackers Hit Water and Energy Utilities",
        guid=f"guid-{uuid.uuid4()}",
        content_text=ARTICLE,
        published_at=datetime.now(UTC),
        priority_score=score,
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


async def _request(db_session, entry, status="completed") -> AIAnalysisRequest:
    row = AIAnalysisRequest(
        entry_id=entry.id, status=status, custom_id=f"ea-{entry.id}", completed_at=datetime.now(UTC)
    )
    db_session.add(row)
    await db_session.flush()
    return row


async def _link_actor(db_session, entry, name, *, source="auto_link", minted=False, article_count=3, aliases=None):
    actor = ThreatActor(
        name=name,
        aliases=aliases or [],
        article_count=article_count,
        created_from_entry_id=entry.id if minted else None,
        created_via="ai_extraction" if minted else None,
    )
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntryThreatActor(
            entry_id=entry.id,
            threat_actor_id=actor.id,
            confidence="medium",
            source=source,
            matched_names=[name],
            paragraph_indices=[2],
            extracted_at=datetime.now(UTC),
        )
    )
    await db_session.flush()
    return actor


def _payload(**overrides) -> dict:
    base = {"summary": "s", "threat_actors": [], "malware": [], "tools": []}
    base.update(overrides)
    return base


# ------------------------------------------------------------------ gates


@pytest.mark.asyncio
async def test_enqueue_off_records_skip(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="off")
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.SKIPPED_OFF
    assert row.adjudication_status == adj.SKIPPED_OFF


@pytest.mark.asyncio
async def test_enqueue_all_trigger_is_pending(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    row = await _request(db_session, entry)
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.PENDING
    assert row.adjudication_status == adj.PENDING


@pytest.mark.asyncio
async def test_enqueue_echo_skipped(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry, status="reused_echo")
    status = await enqueue_adjudication(db_session, entry.id, {}, _payload(_reused_from=str(uuid.uuid4())))
    assert status == adj.SKIPPED_ECHO


@pytest.mark.asyncio
async def test_enqueue_created_trigger_needs_something_new(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_trigger="created")
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)
    # Only an autolinker link to an established entity: nothing new.
    await _link_actor(db_session, entry, "Warlock")
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.SKIPPED_NOTHING_NEW
    # A minted entity on the same entry flips it.
    await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    entry2 = await _make_entry(db_session, feed)
    await _request(db_session, entry2)
    await _link_actor(db_session, entry2, "Nightspire", source="ai", minted=True, article_count=1)
    assert await enqueue_adjudication(db_session, entry2.id, {}, _payload()) == adj.PENDING
    # Counts from store_entry_analysis count too, without any DB lookup.
    entry3 = await _make_entry(db_session, feed)
    await _request(db_session, entry3)
    assert await enqueue_adjudication(db_session, entry3.id, {"relationships": 1}, _payload()) == adj.PENDING


@pytest.mark.asyncio
async def test_enqueue_score_floor(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_min_priority_score=0.5)
    low = await _make_entry(db_session, feed, score=0.08)
    await _request(db_session, low)
    assert await enqueue_adjudication(db_session, low.id, {}, _payload()) == adj.SKIPPED_SCORE
    high = await _make_entry(db_session, feed, score=0.62)
    await _request(db_session, high)
    assert await enqueue_adjudication(db_session, high.id, {}, _payload()) == adj.PENDING


@pytest.mark.asyncio
async def test_enqueue_budget_exhausted_waits(db_session: AsyncSession, feed, monkeypatch):
    await _seed_settings(db_session)

    async def _full(max_per_hour: int) -> bool:
        return False

    monkeypatch.setattr(adj, "_consume_hour_budget", _full)
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.SKIPPED_BUDGET


@pytest.mark.asyncio
async def test_enqueue_creates_request_row_for_manual_runs(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    assert await enqueue_adjudication(db_session, entry.id, {}, _payload()) == adj.PENDING
    row = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
    ).scalar_one()
    assert row.status == "completed" and row.adjudication_status == adj.PENDING


# ------------------------------------------------------------------ manifest


@pytest.mark.asyncio
async def test_manifest_lists_links_with_provenance_and_candidates(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    # The catalogue already holds Warlock as malware with 14 articles.
    warlock = MalwareFamily(name="Warlock", aliases=["Warlock Ransomware"], article_count=14)
    db_session.add(warlock)
    await db_session.flush()
    db_session.add(
        EntryMalware(
            entry_id=entry.id,
            malware_family_id=warlock.id,
            confidence="high",
            source="auto_link",
            matched_names=["Warlock"],
            paragraph_indices=[2],
            extracted_at=datetime.now(UTC),
        )
    )
    # The analysis minted a duplicate actor and a victim-as-actor.
    group = await _link_actor(db_session, entry, "Warlock Group", source="ai", minted=True, article_count=1)
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    # And promoted a dictionary-word actor from the pending tier.
    storm = await _link_actor(db_session, entry, "Storm", source="auto_link")
    db_session.add(
        PendingAutolinkMatch(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            canonical_name="Storm",
            matched_names=["storm"],
            paragraph_indices=[2],
            confidence="medium",
            source_weight=1.0,
            resolved_at=datetime.now(UTC),
            resolution="promoted",
        )
    )
    await db_session.flush()
    items, block = await build_manifest(db_session, entry, _payload())
    by_id = {it.item_id: it for it in items}

    w = by_id[f"link:malware:{warlock.id}"]
    assert w.source == "auto_link" and not w.minted_here
    assert "autolinker" in w.line and "14 articles" in w.line and "Warlock ransomware crew" in w.line

    g = by_id[f"link:threat_actor:{group.id}"]
    assert g.minted_here
    assert "NEW, created by this article" in g.line
    # The nearest-name lookup found the malware entry (normalised "warlock group" → "warlock"
    # via the alias index when it exists; the exact/alias matcher otherwise).
    assert any(c["name"] == "Warlock" for c in g.candidates) or "nearest existing names" in g.line

    v = by_id[f"link:threat_actor:{victim.id}"]
    assert v.minted_here and "nearest existing names: none" in v.line

    s = by_id[f"link:threat_actor:{storm.id}"]
    assert s.promoted and "pending tier" in s.line
    assert block.count("\n") >= 4


@pytest.mark.asyncio
async def test_manifest_edges_and_ai_iocs(db_session: AsyncSession, feed):
    entry = await _make_entry(db_session, feed)
    warlock = await _link_actor(db_session, entry, "Warlock", source="ai")
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=warlock.id,
            target_type="tool",
            target_id=cobalt.id,
            relationship_type="uses",
            confidence="probable",
            source="auto_extracted",
            description="Defenders should watch for Cobalt Strike beacons",
            evidence_entry_ids=[entry.id],
        )
    )
    entry.observable_candidates = [
        {"kind": "domain", "value": "blog.vendor-research.example", "origin": "ai", "evidence": "our blog"},
        {"kind": "ipv4", "value": "10.0.0.1", "origin": "scan"},
    ]
    await db_session.flush()

    items, block = await build_manifest(db_session, entry, _payload())
    kinds = {it.kind for it in items}
    assert {"link", "edge", "ioc"} <= kinds
    edge = next(it for it in items if it.kind == "edge")
    assert "Warlock uses Cobalt Strike" in edge.line and "Defenders should watch" in edge.line
    iocs = [it for it in items if it.kind == "ioc"]
    assert [it.ioc_value for it in iocs] == ["blog.vendor-research.example"]  # scan-origin excluded
    assert "staged by the AI" in iocs[0].line


# ------------------------------------------------------------------ validation


def _item(item_id, kind="link", minted=False, candidates=None, entity_type="threat_actor"):
    return ReviewItem(
        item_id=item_id,
        kind=kind,
        line="",
        entity_type=entity_type,
        entity_id=uuid.uuid4(),
        name=item_id,
        minted_here=minted,
        candidates=candidates or [],
    )


def test_validate_matrix_and_defaults():
    items = [
        _item("link:threat_actor:a"),
        _item(
            "link:threat_actor:b",
            minted=True,
            candidates=[
                {
                    "name": "Warlock",
                    "aliases": ["Warlock Ransomware"],
                    "entity_type": "malware",
                    "entity_id": "x",
                    "article_count": 14,
                }
            ],
        ),
        _item("edge:1", kind="edge"),
        _item("ioc:domain:x", kind="ioc"),
    ]
    result = {
        "verdicts": [
            {"item_id": "link:threat_actor:a", "verdict": "veto", "confidence": "high", "reason": "not minted here"},
            {
                "item_id": "link:threat_actor:b",
                "verdict": "merge",
                "confidence": "high",
                "merge_into": "warlock ransomware",
            },
            {"item_id": "edge:1", "verdict": "remove", "confidence": "high"},
            {"item_id": "ioc:domain:x", "verdict": "drop", "confidence": "medium"},
            {"item_id": "link:nope", "verdict": "remove"},
        ]
    }
    verdicts, stats = _validate_verdicts(result, items)
    by = {v.item.item_id: v for v in verdicts}
    assert by["link:threat_actor:a"].verdict == "keep"  # veto only on minted entities
    assert by["link:threat_actor:b"].verdict == "merge" and by["link:threat_actor:b"].merge_target["name"] == "Warlock"
    assert by["edge:1"].verdict == "keep"  # remove is not an edge verdict
    assert by["ioc:domain:x"].verdict == "drop"
    assert stats["unknown"] == 1


def test_validate_merge_to_unlisted_name_is_keep_and_duplicates_void_all():
    item = _item(
        "link:threat_actor:b",
        minted=True,
        candidates=[{"name": "Warlock", "aliases": [], "entity_type": "malware", "entity_id": "x", "article_count": 1}],
    )
    verdicts, _ = _validate_verdicts(
        {"verdicts": [{"item_id": item.item_id, "verdict": "merge", "merge_into": "Scattered Spider"}]}, [item]
    )
    assert verdicts[0].verdict == "keep"

    other = _item("link:threat_actor:c")
    verdicts, stats = _validate_verdicts(
        {
            "verdicts": [
                {"item_id": other.item_id, "verdict": "remove", "confidence": "high"},
                {"item_id": other.item_id, "verdict": "keep"},
            ]
        },
        [other],
    )
    assert stats["duplicate"] and verdicts[0].verdict == "keep"


def test_validate_reclassify_needs_valid_type():
    item = _item("link:threat_actor:a")
    ok, _ = _validate_verdicts(
        {"verdicts": [{"item_id": item.item_id, "verdict": "reclassify", "suggested_type": "malware"}]}, [item]
    )
    bad, _ = _validate_verdicts(
        {"verdicts": [{"item_id": item.item_id, "verdict": "reclassify", "suggested_type": "planet"}]}, [item]
    )
    assert ok[0].verdict == "reclassify" and ok[0].suggested_type == "malware"
    assert bad[0].verdict == "keep"


# ------------------------------------------------------------------ shadow writes


@pytest.mark.asyncio
async def test_shadow_writes_proposals_and_mutates_nothing(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    group = await _link_actor(db_session, entry, "Warlock Group", source="ai", minted=True, article_count=1)
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    db_session.add(
        EntryTool(
            entry_id=entry.id,
            tool_id=cobalt.id,
            confidence="low",
            source="ai",
            matched_names=["Cobalt Strike"],
            extracted_at=datetime.now(UTC),
        )
    )
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=group.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        description="watch for Cobalt Strike beacons",
        evidence_entry_ids=[entry.id],
    )
    db_session.add(edge)
    entry.observable_candidates = [{"kind": "domain", "value": "blog.vendor-research.example", "origin": "ai"}]
    await db_session.flush()

    items, _ = await build_manifest(db_session, entry, _payload())
    # Give the merge item a candidate by hand (the alias index is not populated in tests).
    for it in items:
        if it.entity_id == group.id:
            it.candidates = [
                {
                    "entity_type": "threat_actor",
                    "entity_id": str(storm.id),
                    "name": "Storm",
                    "aliases": [],
                    "article_count": 3,
                }
            ]
    result = {
        "verdicts": [
            {
                "item_id": f"link:threat_actor:{storm.id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": "weather",
            },
            {"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"},
            {
                "item_id": f"link:threat_actor:{group.id}",
                "verdict": "merge",
                "confidence": "high",
                "merge_into": "Storm",
            },
            {"item_id": f"link:tool:{cobalt.id}", "verdict": "remove", "confidence": "medium", "reason": "advice"},
            {"item_id": f"edge:{edge.id}", "verdict": "demote", "confidence": "medium", "reason": "generic advice"},
            {
                "item_id": "ioc:domain:blog.vendor-research.example",
                "verdict": "drop",
                "confidence": "high",
                "reason": "own blog",
            },
        ]
    }
    verdicts, _ = _validate_verdicts(result, items)
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["mode"] == "shadow" and detail["applied"] == 0
    assert detail["verdicts"] == {"remove": 2, "veto": 1, "merge": 1, "demote": 1, "drop": 1}
    assert detail["breaker"] is True  # 6 of 6 items destructive

    # Nothing changed: junctions, edge, candidates all intact.
    assert (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id))
    ).scalars().all().__len__() == 3
    assert (await db_session.get(EntityRelationship, edge.id)).confidence == "probable"
    assert (await db_session.get(Entry, entry.id)).observable_candidates[0]["value"] == "blog.vendor-research.example"
    assert await db_session.get(ThreatActor, victim.id) is not None

    # Proposals landed in the two logs the queues read.
    link_rows = (
        (await db_session.execute(select(EntityLinkValidationLog).where(EntityLinkValidationLog.entry_id == entry.id)))
        .scalars()
        .all()
    )
    assert [r.action for r in link_rows] == ["shadow_remove"] and link_rows[0].entity_id == storm.id
    maint = {
        (r.action, r.entity_type): r for r in (await db_session.execute(select(EntityMaintenanceLog))).scalars().all()
    }
    assert (ACTION_VETO, "threat_actor") in maint and maint[(ACTION_VETO, "threat_actor")].before["entity"][
        "name"
    ] == "Water Utility Co"
    assert maint[(ACTION_MERGE, "threat_actor")].after["merge_into"] == "Storm"
    assert maint[(ACTION_UNLINK, "tool")].entity_id == cobalt.id
    assert maint[(ACTION_EDGE_DEMOTE, "relationship")].entity_id == edge.id
    assert maint[(ACTION_IOC_DROP, "observable")].after["value"] == "blog.vendor-research.example"
    assert all(r.mode == "shadow" and r.applied is False for r in maint.values())
    assert (await db_session.get(Entry, entry.id)).last_link_validation_at is not None


@pytest.mark.asyncio
async def test_positive_evidence_override_keeps_extracted_names(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    warlock = await _link_actor(db_session, entry, "Warlock")
    items, _ = await build_manifest(db_session, entry, _payload())
    verdicts, _ = _validate_verdicts(
        {"verdicts": [{"item_id": f"link:threat_actor:{warlock.id}", "verdict": "remove", "confidence": "high"}]}, items
    )
    cfg = await adj._settings(db_session)
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(threat_actors=[{"name": "Warlock"}]), cfg)
    assert detail["keep_overridden"] == 1 and detail["verdicts"] == {"keep": 1}
    assert not (await db_session.execute(select(EntityLinkValidationLog))).scalars().all()


# ------------------------------------------------------------------ worker task end to end


@pytest.mark.asyncio
async def test_task_reviews_entry_with_stubbed_model(db_session: AsyncSession, feed, monkeypatch):
    """_adjudicate_entry: warms settings, builds the manifest, calls the task,
    files shadow proposals, stamps the request row, returns the run detail."""
    from contextlib import asynccontextmanager

    from app.models.user import User
    from app.workers import adjudication_tasks as tasks

    await _seed_settings(db_session)
    system = User(username="system", password_hash="x", role="system")
    db_session.add(system)
    await db_session.flush()
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)
    storm = await _link_actor(db_session, entry, "Storm")
    # The current analysis result the task reads the payload from.
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task_row = AITask(
        name="entry_analysis", display_name="t", description="", category="extraction", default_prompt_template="x"
    )
    db_session.add(task_row)
    await db_session.flush()
    db_session.add(
        AIResult(
            entry_id=entry.id,
            target_type="entry",
            target_id=entry.id,
            is_current=True,
            task_id=task_row.id,
            prompt_used="",
            raw_response="",
            parsed_result=_payload(),
        )
    )
    await db_session.flush()

    @asynccontextmanager
    async def fake_session():
        yield db_session

    captured = {}

    async def fake_run_task(db, user_id, task_name, variables, **kwargs):
        captured["task_name"] = task_name
        captured["variables"] = variables
        return {
            "_extraction_status": "success",
            "verdicts": [
                {
                    "item_id": f"link:threat_actor:{storm.id}",
                    "verdict": "remove",
                    "confidence": "high",
                    "reason": "weather",
                }
            ],
            "assessment": {"verdict": "ok", "reason": ""},
        }

    class _Lock:
        def set(self, *a, **k):
            return True

        def delete(self, *a, **k):
            return 1

    async def fake_system_user(db):
        return system.id

    async def noop_commit():
        await db_session.flush()

    monkeypatch.setattr(tasks, "worker_session", fake_session)
    monkeypatch.setattr(tasks.redis, "from_url", lambda *a, **k: _Lock())
    monkeypatch.setattr("app.ai.engine.run_task", fake_run_task)
    monkeypatch.setattr("app.services.system_user.get_system_user_id", fake_system_user)
    monkeypatch.setattr(db_session, "commit", noop_commit)

    detail = await tasks._adjudicate_entry(entry.id)

    assert captured["task_name"] == "entry_adjudication"
    assert captured["variables"]["item_count"] == 1
    assert f"link:threat_actor:{storm.id}" in captured["variables"]["manifest_block"]
    assert detail["mode"] == "shadow" and detail["verdicts"] == {"remove": 1}
    row = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
    ).scalar_one()
    assert row.adjudication_status == adj.COMPLETED and row.adjudicated_at is not None
    log = (await db_session.execute(select(EntityLinkValidationLog))).scalar_one()
    assert log.action == "shadow_remove" and log.entity_id == storm.id


@pytest.mark.asyncio
async def test_task_records_off_without_calling_model(db_session: AsyncSession, feed, monkeypatch):
    from contextlib import asynccontextmanager

    from app.workers import adjudication_tasks as tasks

    await _seed_settings(db_session, adjudication_mode="off")
    entry = await _make_entry(db_session, feed)
    await _request(db_session, entry)

    @asynccontextmanager
    async def fake_session():
        yield db_session

    class _Lock:
        def set(self, *a, **k):
            return True

        def delete(self, *a, **k):
            return 1

    async def boom(*a, **k):
        raise AssertionError("model must not be called when mode is off")

    async def noop_commit():
        await db_session.flush()

    monkeypatch.setattr(tasks, "worker_session", fake_session)
    monkeypatch.setattr(tasks.redis, "from_url", lambda *a, **k: _Lock())
    monkeypatch.setattr("app.ai.engine.run_task", boom)
    monkeypatch.setattr(db_session, "commit", noop_commit)

    detail = await tasks._adjudicate_entry(entry.id)
    assert detail == {"skipped": "off", "mode": "off"}
    row = (
        await db_session.execute(select(AIAnalysisRequest).where(AIAnalysisRequest.entry_id == entry.id))
    ).scalar_one()
    assert row.adjudication_status == adj.SKIPPED_OFF


# ------------------------------------------------------------------ hygiene feed + drawer endpoint (commit 3)


async def _adjudication_result(db_session, entry):
    """An AIResult for the adjudication task, so link rows can carry its id."""
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task = AITask(
        name=adj.TASK_NAME, display_name="r", description="", category="extraction", default_prompt_template="x"
    )
    db_session.add(task)
    await db_session.flush()
    result = AIResult(
        entry_id=entry.id,
        target_type=adj.TARGET_TYPE,
        target_id=entry.id,
        is_current=True,
        task_id=task.id,
        prompt_used="",
        raw_response="",
        parsed_result={},
    )
    db_session.add(result)
    await db_session.flush()
    return result


@pytest.mark.asyncio
async def test_feed_tags_origin_and_filters_adjudicator_rows(client, admin_headers, db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    result = await _adjudication_result(db_session, entry)

    # One adjudicator link verdict (carries the adjudication result id), one
    # legacy validator row (no result), one adjudicator veto row.
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            entity_name_snapshot="Storm",
            action="shadow_remove",
            reason="weather",
            ai_result_id=result.id,
        )
    )
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            entity_name_snapshot="Storm",
            action="shadow_remove",
            reason="nightly",
        )
    )
    db_session.add(
        EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=victim.id,
            action=ACTION_VETO,
            mode="shadow",
            before={
                "entry_id": str(entry.id),
                "entity": {"name": "Water Utility Co", "aliases": [], "article_count": 1},
            },
            after={"reason": "victim organisation", "confidence": "high"},
            reasoning="victim organisation",
            applied=False,
        )
    )
    await db_session.commit()

    resp = await client.get(
        "/api/admin/hygiene/feed", params={"pending": "true", "origin": "adjudicator"}, headers=admin_headers
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()["rows"]
    assert {r["origin"] for r in rows} == {"adjudicator"}
    actions = sorted(r["action"] for r in rows)
    assert actions == [ACTION_VETO, "shadow_remove"]
    veto = next(r for r in rows if r["action"] == ACTION_VETO)
    assert veto["subject"].startswith("Veto: Water Utility Co")
    assert veto["actions"] == ["apply", "dismiss"]
    assert {link["kind"] for link in veto["links"]} == {"entity", "entry"}

    resp = await client.get(
        "/api/admin/hygiene/feed", params={"pending": "true", "origin": "legacy"}, headers=admin_headers
    )
    rows = resp.json()["rows"]
    assert len(rows) == 1 and rows[0]["origin"] == "legacy" and rows[0]["reason"] == "nightly"

    stats = (await client.get("/api/admin/hygiene/stats", headers=admin_headers)).json()
    assert stats["adjudication_mode"] == "shadow" and stats["adjudication_pending"] == 2

    # The drawer endpoint keys the same rows by manifest item id.
    resp = await client.get(f"/api/engine/entries/{entry.id}/adjudication", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    by_id = {v["item_id"]: v for v in body["verdicts"]}
    assert by_id[f"link:threat_actor:{storm.id}"]["verdict"] == "remove"
    assert by_id[f"link:threat_actor:{victim.id}"]["verdict"] == "veto"
    assert all(v["applied"] is False for v in body["verdicts"])


# ------------------------------------------------------------------ apply mode (commit 4)


async def _verdicts_for(db_session, entry, raw):
    items, _ = await build_manifest(db_session, entry, _payload())
    verdicts, _ = _validate_verdicts({"verdicts": raw}, items)
    return items, verdicts


@pytest.mark.asyncio
async def test_apply_removes_links_at_high_confidence_and_files_the_rest(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    warlock = await _link_actor(db_session, entry, "Warlock", article_count=14)
    keep_me = await _link_actor(db_session, entry, "Nightspire", article_count=5)
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {
                "item_id": f"link:threat_actor:{storm.id}",
                "verdict": "remove",
                "confidence": "high",
                "reason": "weather",
            },
            {
                "item_id": f"link:threat_actor:{warlock.id}",
                "verdict": "remove",
                "confidence": "medium",
                "reason": "hmm",
            },
        ],
    )
    cfg = await adj._settings(db_session)
    cfg["breaker_pct"] = 1.0  # 2 of 3 destructive would trip the default breaker; that case has its own test
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["mode"] == "apply" and detail["applied"] == 1 and detail["shadowed"] == 1
    linked = {
        r.threat_actor_id
        for r in (await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id)))
        .scalars()
        .all()
    }
    assert linked == {warlock.id, keep_me.id}  # Storm gone, medium-confidence Warlock kept
    await db_session.refresh(storm)
    assert storm.article_count == 2
    logs = {
        (r.entity_id, r.action) for r in (await db_session.execute(select(EntityLinkValidationLog))).scalars().all()
    }
    assert logs == {(storm.id, "removed"), (warlock.id, "shadow_remove")}


@pytest.mark.asyncio
async def test_apply_veto_deletes_only_when_nothing_else_holds_the_entity(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    victim = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    shared = await _link_actor(db_session, entry, "Warlock Group", source="ai", minted=True, article_count=2)
    other = await _make_entry(db_session, feed)
    db_session.add(
        EntryThreatActor(
            entry_id=other.id,
            threat_actor_id=shared.id,
            confidence="high",
            source="auto_link",
            matched_names=["Warlock Group"],
            extracted_at=datetime.now(UTC),
        )
    )
    await db_session.flush()
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"},
            {"item_id": f"link:threat_actor:{shared.id}", "verdict": "veto", "confidence": "high", "reason": "dupe"},
        ],
    )
    cfg = await adj._settings(db_session)
    cfg["breaker_pct"] = 1.0  # two of two are destructive; don't trip the breaker here
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["applied"] == 2
    assert await db_session.get(ThreatActor, victim.id) is None  # one article, nothing else: deleted
    assert await db_session.get(ThreatActor, shared.id) is not None  # another article links it: kept
    await db_session.refresh(shared)
    assert shared.article_count == 1
    rows = {r.action: r for r in (await db_session.execute(select(EntityMaintenanceLog))).scalars().all()}
    assert rows[ACTION_VETO].entity_id == victim.id and rows[ACTION_VETO].after["deleted"] is True
    assert rows[ACTION_VETO].before["entity"]["name"] == "Water Utility Co"
    assert rows[ACTION_UNLINK].entity_id == shared.id and rows[ACTION_UNLINK].after["deleted"] is False
    assert all(r.applied and r.mode == "apply" for r in rows.values())


@pytest.mark.asyncio
async def test_apply_demotes_edge_like_the_nightly_job_and_drops_iocs(db_session: AsyncSession, feed):
    from app.models.observable import EntryObservable, Observable

    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    warlock = await _link_actor(db_session, entry, "Warlock", source="ai", article_count=14)
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=warlock.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        description="watch for Cobalt Strike beacons",
        evidence_entry_ids=[entry.id],
    )
    rejected = EntityRelationship(
        source_type="threat_actor",
        source_id=warlock.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="targets",
        confidence="possible",
        source="analyst_rejected",
        evidence_entry_ids=[entry.id],
    )
    db_session.add_all([edge, rejected])
    obs = Observable(kind="sha256", value="9f3a" * 16, sighting_count=1, article_count=1)
    db_session.add(obs)
    await db_session.flush()
    db_session.add(EntryObservable(entry_id=entry.id, observable_id=obs.id, source="ai", confidence="high"))
    entry.observable_candidates = [{"kind": "domain", "value": "blog.vendor-research.example", "origin": "ai"}]
    await db_session.flush()

    items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {"item_id": f"edge:{edge.id}", "verdict": "demote", "confidence": "high", "reason": "generic advice"},
            {
                "item_id": "ioc:domain:blog.vendor-research.example",
                "verdict": "drop",
                "confidence": "high",
                "reason": "own blog",
            },
            {"item_id": f"ioc:sha256:{'9f3a' * 16}", "verdict": "drop", "confidence": "high", "reason": "sample"},
        ],
    )
    assert not any(it.item_id == f"edge:{rejected.id}" for it in items)  # analyst-rejected edges never listed
    cfg = await adj._settings(db_session)
    cfg["breaker_pct"] = 1.0
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.flush()

    assert detail["applied"] == 3
    edge = await db_session.get(EntityRelationship, edge.id)
    assert edge.confidence == "possible" and edge.adjudication_verdict == "coincidental" and edge.adjudicated_at
    assert (await db_session.get(Entry, entry.id)).observable_candidates == []
    assert (
        await db_session.execute(select(EntryObservable).where(EntryObservable.entry_id == entry.id))
    ).scalar_one_or_none() is None
    assert (await db_session.get(Observable, obs.id)).sighting_count == 0


@pytest.mark.asyncio
async def test_apply_breaker_downgrades_whole_run_to_proposals(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    entry = await _make_entry(db_session, feed)
    a = await _link_actor(db_session, entry, "Storm")
    b = await _link_actor(db_session, entry, "Nightspire")
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [
            {"item_id": f"link:threat_actor:{a.id}", "verdict": "remove", "confidence": "high"},
            {"item_id": f"link:threat_actor:{b.id}", "verdict": "remove", "confidence": "high"},
        ],
    )
    cfg = await adj._settings(db_session)  # breaker 0.5; 2/2 destructive trips it
    detail = await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    assert detail["breaker"] and detail["mode"] == "shadow" and detail["applied"] == 0
    assert (
        len(
            (await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id)))
            .scalars()
            .all()
        )
        == 2
    )


@pytest.mark.asyncio
async def test_queue_apply_then_restore_recreates_a_vetoed_entity(
    client, admin_headers, db_session: AsyncSession, feed
):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    victim = await _link_actor(
        db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1, aliases=["WUC"]
    )
    _items, verdicts = await _verdicts_for(
        db_session,
        entry,
        [{"item_id": f"link:threat_actor:{victim.id}", "verdict": "veto", "confidence": "high", "reason": "victim"}],
    )
    cfg = await adj._settings(db_session)
    await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)  # shadow proposal
    await db_session.commit()
    row = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == ACTION_VETO))
    ).scalar_one()

    resp = await client.post(f"/api/admin/hygiene/adjudication/{row.id}/apply", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["applied"] is True and resp.json()["detail"]["deleted"] is True
    gone = (
        await db_session.execute(
            select(ThreatActor).where(ThreatActor.id == victim.id).execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    assert gone is None

    resp = await client.post(f"/api/admin/hygiene/adjudication/{row.id}/restore", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["restored"] is True
    back = (
        await db_session.execute(
            select(ThreatActor).where(ThreatActor.id == victim.id).execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    assert back is not None and back.name == "Water Utility Co" and back.aliases == ["WUC"]
    assert (
        await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id))
    ).scalar_one().threat_actor_id == victim.id

    feed_rows = (
        await client.get("/api/admin/hygiene/feed", params={"origin": "adjudicator"}, headers=admin_headers)
    ).json()["rows"]
    assert any(r["action"] == ACTION_VETO and r["payload"]["after"].get("restored") for r in feed_rows)


# ------------------------------------------------------------------ takeover (commit 5)


def test_extraction_prompt_no_longer_judges_links():
    """The one-pass call only extracts; link judgment lives in the adjudicate stage."""
    from app.ai.prompts.defaults import SYSTEM_TASKS

    task = next(t for t in SYSTEM_TASKS if t["name"] == "entry_analysis")
    assert "link_validations" not in task["output_schema"]["properties"]
    assert "link_validations" not in task["output_schema"]["required"]
    assert "linked_entities" not in task["variables"]
    assert "CANDIDATE ENTITY TAGS" not in task["default_prompt_template"]
    assert "link_validations" not in task["default_system_template"]


@pytest.mark.asyncio
async def test_keep_counter_promotes_edge_after_three_distinct_entries(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="apply")
    warlock = ThreatActor(name="Warlock", article_count=14)
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add_all([warlock, cobalt])
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=warlock.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        description="Warlock deploys Cobalt Strike",
        evidence_entry_ids=[],
    )
    db_session.add(edge)
    await db_session.flush()

    async def keep_from(entry):
        edge.evidence_entry_ids = [*(edge.evidence_entry_ids or []), entry.id]
        db_session.add(edge)
        await db_session.flush()
        items, _ = await build_manifest(db_session, entry, _payload())
        verdicts, _ = _validate_verdicts({"verdicts": [{"item_id": f"edge:{edge.id}", "verdict": "keep"}]}, items)
        cfg = await adj._settings(db_session)
        await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
        await db_session.flush()
        await db_session.refresh(edge)

    e1, e2, e3 = [await _make_entry(db_session, feed) for _ in range(3)]
    await keep_from(e1)
    await keep_from(e1)  # same entry again does not count twice
    assert len(edge.reviewer_kept_entry_ids) == 1 and edge.confidence == "probable"
    await keep_from(e2)
    assert len(edge.reviewer_kept_entry_ids) == 2 and edge.confidence == "probable"
    await keep_from(e3)
    assert len(edge.reviewer_kept_entry_ids) == 3
    assert edge.confidence == "confirmed" and edge.adjudication_verdict == "corroborated"


@pytest.mark.asyncio
async def test_keep_counter_never_touches_shadow_or_demoted_edges(db_session: AsyncSession, feed):
    await _seed_settings(db_session, adjudication_mode="shadow")
    entry = await _make_entry(db_session, feed)
    warlock = await _link_actor(db_session, entry, "Warlock", source="ai")
    cobalt = Tool(name="Cobalt Strike", article_count=40)
    db_session.add(cobalt)
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=warlock.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="probable",
        source="auto_extracted",
        evidence_entry_ids=[entry.id],
    )
    db_session.add(edge)
    await db_session.flush()
    items, _ = await build_manifest(db_session, entry, _payload())
    verdicts, _ = _validate_verdicts({"verdicts": [{"item_id": f"edge:{edge.id}", "verdict": "keep"}]}, items)
    cfg = await adj._settings(db_session)
    await apply_verdicts(db_session, entry, verdicts, _payload(), cfg)
    await db_session.refresh(edge)
    assert edge.reviewer_kept_entry_ids == []


@pytest.mark.asyncio
async def test_stale_status_is_a_live_filter(client, admin_headers, db_session: AsyncSession, feed):
    from datetime import timedelta

    entry = await _make_entry(db_session, feed)
    old = ThreatActor(
        name="tortilla crew",
        article_count=1,
        created_via="ai_extraction",
        created_from_entry_id=entry.id,
        first_seen_at=datetime.now(UTC) - timedelta(days=205),
        last_seen_at=datetime.now(UTC) - timedelta(days=205),
    )
    fresh = ThreatActor(
        name="Warlock Group", article_count=1, created_via="ai_extraction", created_from_entry_id=entry.id
    )
    db_session.add_all([old, fresh])
    await db_session.commit()
    resp = await client.get(
        "/api/engine/extraction/entities", params={"status": "stale", "window": "all"}, headers=admin_headers
    )
    assert resp.status_code == 200, resp.text
    names = {i["name"] for i in resp.json()["items"]}
    assert names == {"tortilla crew"}


@pytest.mark.asyncio
async def test_backfill_selects_only_undecided_analysed_entries(db_session: AsyncSession, feed):
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task = AITask(
        name="entry_analysis", display_name="t", description="", category="extraction", default_prompt_template="x"
    )
    db_session.add(task)
    await db_session.flush()

    async def analysed(entry):
        db_session.add(
            AIResult(
                entry_id=entry.id,
                target_type="entry",
                target_id=entry.id,
                is_current=True,
                task_id=task.id,
                prompt_used="",
                raw_response="",
                parsed_result=_payload(),
            )
        )

    undecided = await _make_entry(db_session, feed)
    await analysed(undecided)
    waiting = await _make_entry(db_session, feed)
    await analysed(waiting)
    row = await _request(db_session, waiting)
    row.adjudication_status = adj.SKIPPED_BUDGET
    done = await _make_entry(db_session, feed)
    await analysed(done)
    row = await _request(db_session, done)
    row.adjudication_status = adj.COMPLETED
    row.adjudicated_at = datetime.now(UTC)
    never_analysed = await _make_entry(db_session, feed)
    await db_session.flush()

    picked = set(await adj.select_backfill_entries(db_session))
    assert picked == {undecided.id, waiting.id}
    assert done.id not in picked and never_analysed.id not in picked


@pytest.mark.asyncio
async def test_legacy_proposals_are_shown_to_the_reviewer_then_superseded(db_session: AsyncSession, feed):
    await _seed_settings(db_session)
    entry = await _make_entry(db_session, feed)
    storm = await _link_actor(db_session, entry, "Storm")
    minted = await _link_actor(db_session, entry, "Water Utility Co", source="ai", minted=True, article_count=1)
    db_session.add(
        EntityLinkValidationLog(
            entry_id=entry.id,
            entity_type="threat_actor",
            entity_id=storm.id,
            entity_name_snapshot="Storm",
            action="shadow_remove",
            reason="nightly validator thought it was weather",
        )
    )
    db_session.add(
        EntityMaintenanceLog(
            entity_type="threat_actor",
            entity_id=minted.id,
            action="stale_entity_review",
            mode="shadow",
            before={"entity": {"name": "Water Utility Co"}},
            after={},
            reasoning="1 article, no relationships",
            applied=False,
        )
    )
    await db_session.flush()

    items, block = await build_manifest(db_session, entry, _payload())
    assert "earlier suggestion (retired nightly job): remove — nightly validator thought it was weather" in block
    assert "earlier suggestion (retired nightly job): stale entity review" in block

    legacy = await adj.collect_legacy_rows(db_session, entry, items)
    superseded = await adj.supersede_legacy_proposals(db_session, legacy)
    await db_session.flush()
    assert superseded == 2
    assert (await db_session.execute(select(EntityLinkValidationLog))).scalars().all() == []
    assert (await db_session.execute(select(EntityMaintenanceLog))).scalars().all() == []
