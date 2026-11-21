"""The edge sweep (services/relationship_sweep.py): selection, passages, the
quote rule, and what shadow and apply modes change."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.country import Country
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.entity_relationship import EntityRelationship, RelationshipReview
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.system_setting import SystemSettings
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.services import edge_settlement as es
from app.services import relationship_sweep as sweep_mod
from app.services.relationship_sweep import apply_judgment, build_case, parse_answer, render_case, select_edges

STATED = "The Warlock operators relied on Cobalt Strike for lateral movement."
ARTICLE = f"Researchers tracked a new campaign. {STATED} Patch now."
ROUNDUP = "This week: Warlock claimed a utility. Separately, Cobalt Strike cracks keep circulating."


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch):
    import app.services.system_settings as ss_mod

    monkeypatch.setattr(ss_mod, "_cache", None)
    monkeypatch.setattr(ss_mod, "_cache_ts", 0.0)
    yield


async def _settings(db: AsyncSession, **values) -> None:
    row = await db.get(SystemSettings, 1)
    if row is None:
        db.add(SystemSettings(id=1, settings=values, secrets={}))
    else:
        row.settings = {**(row.settings or {}), **values}
    await db.flush()


async def _feed(db: AsyncSession) -> Feed:
    f = Feed(title=f"Feed {uuid.uuid4().hex[:6]}", url=f"https://sweep.example/{uuid.uuid4()}", feed_type="rss")
    db.add(f)
    await db.flush()
    return f


async def _claim(db: AsyncSession, texts: list[str], **kw) -> EntityRelationship:
    feed = await _feed(db)
    tag = uuid.uuid4().hex[:6]
    actor = ThreatActor(name=f"Warlock {tag}", aliases=["Warlock"])
    tool = Tool(name=f"Cobalt Strike {tag}", aliases=["Cobalt Strike"])
    db.add_all([actor, tool])
    await db.flush()
    entries = []
    for text in texts:
        e = Entry(
            feed_id=feed.id,
            guid=str(uuid.uuid4()),
            title="Warlock campaign",
            url=f"https://sweep.example/{uuid.uuid4()}",
            content_text=text,
            published_at=datetime.now(UTC),
        )
        db.add(e)
        await db.flush()
        db.add_all(
            [
                EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id, paragraph_indices=[0]),
                EntryTool(entry_id=e.id, tool_id=tool.id, paragraph_indices=[0]),
            ]
        )
        entries.append(e)
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="tool",
        target_id=tool.id,
        relationship_type=kw.pop("verb", "uses"),
        confidence="possible",
        source="co_occurrence",
        evidence_entry_ids=[e.id for e in entries],
        created_at=kw.pop("created_at", datetime.now(UTC) - timedelta(days=3)),
        **kw,
    )
    db.add(edge)
    await db.flush()
    return edge


@pytest.mark.asyncio
async def test_the_case_shows_the_sentence_naming_both_ends(db_session: AsyncSession):
    edge = await _claim(db_session, [ARTICLE, ROUNDUP])
    case = await build_case(db_session, edge)
    block = render_case(case)
    assert block.startswith("CLAIM: Warlock ") and "(threat_actor) uses Cobalt Strike " in block
    assert f'sentence: "{STATED}"' in block
    # The roundup has no sentence naming both: each end's first mention instead.
    assert 'is named: "This week: Warlock claimed a utility."' in block
    assert case.passages[0].text == ARTICLE  # the article with a sentence naming both first


@pytest.mark.asyncio
async def test_an_answer_must_quote_its_article(db_session: AsyncSession):
    edge = await _claim(db_session, [ARTICLE])
    case = await build_case(db_session, edge)
    good = parse_answer(
        {"decision": "asserted", "confidence": "high", "article": 1, "quote": STATED, "reason": "Warlock uses it."},
        case,
    )
    assert good.decision == "asserted" and good.rejected is None and good.passage.entry_id == edge.evidence_entry_ids[0]
    invented = parse_answer(
        {
            "decision": "asserted",
            "confidence": "high",
            "article": 1,
            "quote": "Warlock used Cobalt Strike to move laterally.",
            "reason": "Warlock uses it.",
        },
        case,
    )
    assert invented.decision == "unsure" and invented.rejected == "quote not found in the article"
    one_end = parse_answer(
        {
            "decision": "asserted",
            "confidence": "high",
            "article": 1,
            "quote": "Researchers tracked a new campaign",
            "reason": "Warlock",
        },
        case,
    )
    assert one_end.decision == "unsure" and one_end.rejected == "quote does not name both ends"


@pytest.mark.asyncio
async def test_a_correction_must_be_one_the_matrix_allows(db_session: AsyncSession):
    feed = await _feed(db_session)
    actor = ThreatActor(name=f"Warlock {uuid.uuid4().hex[:6]}", aliases=["Warlock"])
    russia = Country(name="Russia", iso_code="RU")
    db_session.add_all([actor, russia])
    await db_session.flush()
    text = "Warlock, a Russia-based crew, hit utilities in Europe."
    e = Entry(feed_id=feed.id, guid=str(uuid.uuid4()), title="t", url="https://sweep.example/r", content_text=text)
    db_session.add(e)
    await db_session.flush()
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="country",
        target_id=russia.id,
        relationship_type="targets",
        confidence="possible",
        source="co_occurrence",
        evidence_entry_ids=[e.id],
    )
    db_session.add(edge)
    await db_session.flush()
    case = await build_case(db_session, edge)
    base = {"confidence": "high", "article": 1, "quote": "Warlock, a Russia-based crew", "reason": "Warlock origin"}
    fixed = parse_answer({**base, "decision": "wrong_verb", "suggested_verb": "attributed to"}, case)
    assert fixed.decision == "wrong_verb" and fixed.suggested_verb == "attributed_to" and not fixed.flip
    bad = parse_answer({**base, "decision": "wrong_verb", "suggested_verb": "drops"}, case)
    assert bad.decision == "unsure" and bad.rejected == "no allowed correction"


@pytest.mark.asyncio
async def test_shadow_records_the_answer_and_changes_nothing(db_session: AsyncSession):
    edge = await _claim(db_session, [ROUNDUP])
    case = await build_case(db_session, edge)
    j = parse_answer(
        {"decision": "not_asserted", "confidence": "high", "reason": "Warlock and Cobalt Strike are separate items."},
        case,
    )
    cfg = {"mode": "shadow", "min_conf": "high"}
    assert await apply_judgment(db_session, case, j, cfg, None) == "recorded"
    assert edge.adjudication_verdict is None
    row = (
        await db_session.execute(select(RelationshipReview).where(RelationshipReview.relationship_id == edge.id))
    ).scalar_one()
    assert (row.reviewer, row.verdict, row.counted) == ("sweep", "demote", False)


@pytest.mark.asyncio
async def test_apply_keeps_a_stated_claim_and_hides_an_unstated_one(db_session: AsyncSession):
    cfg = {"mode": "apply", "min_conf": "high"}
    stated = await _claim(db_session, [ARTICLE])
    case = await build_case(db_session, stated)
    j = parse_answer(
        {"decision": "asserted", "confidence": "high", "article": 1, "quote": STATED, "reason": "Warlock uses it."},
        case,
    )
    assert await apply_judgment(db_session, case, j, cfg, None) == "kept"
    assert stated.adjudication_verdict == es.KEPT and stated.confidence == "probable"

    unstated = await _claim(db_session, [ROUNDUP])
    case = await build_case(db_session, unstated)
    j = parse_answer({"decision": "not_asserted", "confidence": "high", "reason": "Warlock is a separate item."}, case)
    assert await apply_judgment(db_session, case, j, cfg, None) == "demoted"
    assert unstated.adjudication_verdict == es.COINCIDENTAL
    log = (
        await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.entity_id == unstated.id))
    ).scalar_one()
    assert log.applied and log.after["origin"] == "sweep"

    # A medium answer is recorded, not acted on.
    unsure = await _claim(db_session, [ROUNDUP])
    case = await build_case(db_session, unsure)
    j = parse_answer({"decision": "not_asserted", "confidence": "medium", "reason": "Warlock maybe."}, case)
    assert await apply_judgment(db_session, case, j, cfg, None) == "recorded"
    assert unsure.adjudication_verdict is None


@pytest.mark.asyncio
async def test_selection_takes_open_old_edges_not_recently_swept(db_session: AsyncSession):
    cfg = {"batch_size": 50, "min_age_hours": 24, "retry_days": 30}
    old = await _claim(db_session, [ARTICLE])
    young = await _claim(db_session, [ARTICLE], created_at=datetime.now(UTC))
    settled = await _claim(db_session, [ARTICLE], adjudication_verdict=es.KEPT)
    disputed = await _claim(db_session, [ARTICLE], adjudication_verdict=es.DISPUTED)
    swept = await _claim(db_session, [ARTICLE])
    await es.record_review(db_session, swept.id, reviewer=es.SWEEP, verdict=es.UNSURE)
    picked = [e.id for e in await select_edges(db_session, cfg)]
    assert picked[0] == disputed.id
    assert old.id in picked
    assert young.id not in picked and settled.id not in picked and swept.id not in picked


@pytest.mark.asyncio
async def test_a_run_judges_and_commits_each_edge(db_session: AsyncSession, monkeypatch):
    from app.models.user import User

    await _settings(db_session, relationship_sweep_mode="apply")
    db_session.add(User(username="system", password_hash="x", role="system"))
    edge = await _claim(db_session, [ARTICLE])

    async def fake_run_task(**kw):
        assert kw["task_name"] == "relationship_review" and "CLAIM:" in kw["variables"]["claim_block"]
        return {
            "decision": "asserted",
            "confidence": "high",
            "article": 1,
            "quote": STATED,
            "reason": "Warlock uses it.",
        }

    async def no_depth():
        return 0

    async def no_commit():
        return None

    import app.ai.engine as engine
    import app.services.entry_adjudication as adj

    monkeypatch.setattr(engine, "run_task", fake_run_task)
    monkeypatch.setattr(adj, "_ai_queue_depth", no_depth)
    monkeypatch.setattr(db_session, "commit", no_commit)
    stats = await sweep_mod.sweep(db_session, limit=5)
    assert stats["status"] == "ok" and stats.get("kept") == 1
    assert edge.adjudication_verdict == es.KEPT
