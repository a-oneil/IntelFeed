"""Tests for the assessment backfill job (entity AI-summary for empty
descriptions): candidate selection in
app/workers/entity_maintenance_tasks.py::find_assessment_backfill_candidates
and the shared service app/services/entity_summary.py."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE, EntryCVE
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.vendor import EntryVendor, Vendor
from app.services.entity_summary import generate_entity_assessment
from app.workers.entity_maintenance_tasks import find_assessment_backfill_candidates


async def _mk_entries(db: AsyncSession, n: int) -> list[Entry]:
    feed = Feed(title="F", url=f"https://f-{uuid.uuid4().hex[:8]}.example/rss", feed_type="rss")
    db.add(feed)
    await db.flush()
    entries = []
    for _ in range(n):
        e = Entry(
            feed_id=feed.id,
            title="e",
            guid=f"g-{uuid.uuid4().hex[:10]}",
            url=f"https://example.com/{uuid.uuid4().hex[:8]}",
            published_at=datetime(2026, 4, 10, 12, 0, tzinfo=UTC),
        )
        db.add(e)
        entries.append(e)
    await db.flush()
    return entries


@pytest.mark.asyncio
async def test_candidate_selection(db_session: AsyncSession):
    entries = await _mk_entries(db_session, 3)

    bare_actor = ThreatActor(name="Undescribed Actor")
    described_actor = ThreatActor(name="Described Actor", description="already written")
    thin_malware = MalwareFamily(name="Thin Family")
    bare_cve = CVE(cve_id="CVE-2026-0001")
    blank_vendor = Vendor(name="Blank Vendor", description="   ")
    db_session.add_all([bare_actor, described_actor, thin_malware, bare_cve, blank_vendor])
    await db_session.flush()

    for e in entries:
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=bare_actor.id))
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=described_actor.id))
    db_session.add(EntryMalware(entry_id=entries[0].id, malware_family_id=thin_malware.id))
    for e in entries[:2]:
        db_session.add(EntryCVE(entry_id=e.id, cve_id=bare_cve.id))
        db_session.add(EntryVendor(entry_id=e.id, vendor_id=blank_vendor.id))
    await db_session.flush()

    picked = await find_assessment_backfill_candidates(db_session, batch_size=10, min_articles=2)

    picked_ids = {eid for _etype, eid, _hits in picked}
    # described_actor has text, thin_malware is under min_articles, bare_cve is
    # a CVE (NVD owns those descriptions) — all excluded.
    assert picked_ids == {bare_actor.id, blank_vendor.id}
    # Best-covered first.
    assert picked[0][:2] == ("threat_actor", bare_actor.id)
    assert picked[0][2] == 3

    capped = await find_assessment_backfill_candidates(db_session, batch_size=1, min_articles=2)
    assert capped == [("threat_actor", bare_actor.id, 3)]

    # min_articles=1 (the default) reaches the single-article entity too.
    thin = await find_assessment_backfill_candidates(db_session, batch_size=10, min_articles=1)
    assert thin_malware.id in {eid for _etype, eid, _hits in thin}


@pytest.mark.asyncio
async def test_cve_is_never_a_candidate(db_session: AsyncSession):
    """CVE descriptions come from NVD. Writing AI prose there would also drop
    the CVE out of run_cve_nvd_backfill, which selects on description IS NULL."""
    entries = await _mk_entries(db_session, 4)
    cve = CVE(cve_id="CVE-2026-9999")
    db_session.add(cve)
    await db_session.flush()
    for e in entries:
        db_session.add(EntryCVE(entry_id=e.id, cve_id=cve.id))
    await db_session.flush()

    picked = await find_assessment_backfill_candidates(db_session, batch_size=50, min_articles=1)
    assert all(etype != "cve" for etype, _eid, _hits in picked)
    assert cve.id not in {eid for _etype, eid, _hits in picked}


@pytest.mark.asyncio
async def test_recent_attempt_is_skipped_until_retry_window_elapses(db_session: AsyncSession):
    """Ordering is article-count DESC against a fixed budget, so an entity the
    AI keeps failing on would hold a top slot every run without this cooldown."""
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    entries = await _mk_entries(db_session, 3)
    actor = ThreatActor(name="Recently Attempted")
    db_session.add(actor)
    await db_session.flush()
    for e in entries:
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    await db_session.flush()

    assert actor.id in {eid for _t, eid, _h in await find_assessment_backfill_candidates(db_session, 10, 1)}

    task_id = (
        await db_session.execute(select(AITask.id).where(AITask.name == "article_summary").limit(1))
    ).scalar_one_or_none()
    if task_id is None:
        task = AITask(
            name="article_summary",
            display_name="Article Summary",
            category="analysis",
            default_prompt_template="{{ content }}",
        )
        db_session.add(task)
        await db_session.flush()
        task_id = task.id

    attempt = AIResult(
        task_id=task_id,
        target_type="threat_actor",
        target_id=actor.id,
        is_current=True,
        parsed_result={"_extraction_status": "parse_error"},
    )
    db_session.add(attempt)
    await db_session.flush()

    picked = await find_assessment_backfill_candidates(db_session, 10, 1, retry_days=7)
    assert actor.id not in {eid for _t, eid, _h in picked}

    # Once the window elapses the entity is eligible again.
    attempt.created_at = datetime.now(UTC) - timedelta(days=30)
    db_session.add(attempt)
    await db_session.flush()
    picked = await find_assessment_backfill_candidates(db_session, 10, 1, retry_days=7)
    assert actor.id in {eid for _t, eid, _h in picked}


def test_backfill_settings_are_configurable():
    """These are read through settings.get(); a key that is not registered
    silently falls through to None and the knob becomes dead code."""
    from app.config import settings
    from app.services.system_settings import _ENGINE_SECTION_GROUPS, CONFIGURABLE_KEYS

    for key, expected in (
        ("assessment_backfill_batch_size", 50),
        ("assessment_backfill_min_articles", 1),
        ("assessment_backfill_retry_days", 7),
    ):
        assert CONFIGURABLE_KEYS.get(key) is int, f"{key} missing from CONFIGURABLE_KEYS"
        assert key in _ENGINE_SECTION_GROUPS, f"{key} missing a settings group"
        assert getattr(settings, key) == expected


@pytest.mark.asyncio
async def test_only_if_empty_skips_populated(db_session: AsyncSession, test_user):
    actor = ThreatActor(name="Written Actor", description="analyst text")
    db_session.add(actor)
    await db_session.flush()

    run_task = AsyncMock(side_effect=AssertionError("run_task must not be called"))
    with patch("app.ai.engine.run_task", run_task):
        result = await generate_entity_assessment(
            db_session, test_user.id, "threat_actor", actor.id, only_if_empty=True
        )
    assert result["status"] == "already_has_assessment"
    assert actor.description == "analyst text"


@pytest.mark.asyncio
async def test_generates_and_saves_summary(db_session: AsyncSession, test_user):
    entries = await _mk_entries(db_session, 1)
    actor = ThreatActor(name="Bare Actor")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entries[0].id, threat_actor_id=actor.id))
    await db_session.flush()

    run_task = AsyncMock(return_value={"summary": "AI-drafted assessment", "_extraction_status": "success"})
    with patch("app.ai.engine.run_task", run_task):
        result = await generate_entity_assessment(
            db_session, test_user.id, "threat_actor", actor.id, only_if_empty=True
        )
    assert result == {"status": "updated", "summary": "AI-drafted assessment"}
    assert actor.description == "AI-drafted assessment"
    assert run_task.await_count == 1
    # The call is attributed to the entity so it shows on the profile AI tab,
    # lands in the cost breakdown, and gives the backfill its retry cooldown.
    kwargs = run_task.await_args.kwargs
    assert kwargs["target_type"] == "threat_actor"
    assert kwargs["target_id"] == actor.id
    # force: otherwise run_task's dedup guard replays a stored parse_error forever.
    assert kwargs["force"] is True


@pytest.mark.asyncio
async def test_provider_paused_saves_nothing(db_session: AsyncSession, test_user):
    actor = ThreatActor(name="Paused Actor")
    db_session.add(actor)
    await db_session.flush()

    run_task = AsyncMock(
        return_value={"_extraction_status": "provider_paused", "_pause_until": "2026-09-05T12:00:00+00:00"}
    )
    with patch("app.ai.engine.run_task", run_task):
        result = await generate_entity_assessment(db_session, test_user.id, "threat_actor", actor.id)
    assert result["status"] == "provider_paused"
    assert result["pause_until"] == "2026-09-05T12:00:00+00:00"
    assert actor.description is None


@pytest.mark.asyncio
async def test_parse_error_saves_nothing(db_session: AsyncSession, test_user):
    """Ollama repetition loops / max_tokens overflows come back as
    parse_error with raw output — that must never become the assessment."""
    actor = ThreatActor(name="Garbled Actor")
    db_session.add(actor)
    await db_session.flush()

    run_task = AsyncMock(return_value={"raw": "TTP TTP TTP TTP TTP", "_extraction_status": "parse_error"})
    with patch("app.ai.engine.run_task", run_task):
        result = await generate_entity_assessment(db_session, test_user.id, "threat_actor", actor.id)
    assert result == {"status": "ai_error", "ai_status": "parse_error"}
    assert actor.description is None


@pytest.mark.asyncio
async def test_unknown_type_and_missing_entity(db_session: AsyncSession, test_user):
    assert (await generate_entity_assessment(db_session, test_user.id, "nope", uuid.uuid4()))["status"] == (
        "unsupported_type"
    )
    assert (await generate_entity_assessment(db_session, test_user.id, "malware", uuid.uuid4()))["status"] == (
        "not_found"
    )


@pytest.mark.committed_db
async def test_failed_attempt_is_committed_and_visible_to_a_new_session(db_session: AsyncSession, admin_user, _engine):
    """A parse_error attempt must survive the worker session closing.

    run_task only ``add``s + ``flush``es its AIResult, and worker_session exits
    via close() (rollback). Without an explicit commit on the failure path the
    row vanishes, which silently makes the retry window in
    find_assessment_backfill_candidates inert for the exact case it exists for.
    Asserting from a *separate* session is the whole point — the same session
    would see the uncommitted row and pass either way.
    """
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    entries = await _mk_entries(db_session, 3)
    actor = ThreatActor(name=f"Fails Repeatedly {uuid.uuid4().hex[:6]}")
    db_session.add(actor)
    await db_session.flush()
    for e in entries:
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))

    task = (
        await db_session.execute(select(AITask).where(AITask.name == "article_summary").limit(1))
    ).scalar_one_or_none()
    if task is None:
        task = AITask(
            name="article_summary",
            display_name="Article Summary",
            category="analysis",
            default_prompt_template="{{ content }}",
        )
        db_session.add(task)
    await db_session.commit()

    async def _fake_run_task(db, *args, **kwargs):
        # Mirror engine.run_task's failure path: persist a row, flush only.
        db.add(
            AIResult(
                task_id=task.id,
                target_type=kwargs.get("target_type"),
                target_id=kwargs.get("target_id"),
                is_current=True,
                parsed_result={"_extraction_status": "parse_error"},
            )
        )
        await db.flush()
        return {"_extraction_status": "parse_error", "_error": "unparseable"}

    with patch("app.ai.engine.run_task", new=AsyncMock(side_effect=_fake_run_task)):
        result = await generate_entity_assessment(
            db_session, admin_user.id, "threat_actor", actor.id, only_if_empty=True
        )

    assert result["status"] == "ai_error"
    assert result["ai_status"] == "parse_error"

    # A different session cannot see uncommitted work — this is the assertion
    # that fails when the commit is missing.
    async with AsyncSession(bind=_engine, expire_on_commit=False) as other:
        rows = (
            (
                await other.execute(
                    select(AIResult).where(AIResult.target_type == "threat_actor", AIResult.target_id == actor.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1, "failed attempt was rolled back; retry window cannot see it"
        assert rows[0].parsed_result["_extraction_status"] == "parse_error"

        # The failure must not be written as the entity's assessment.
        refreshed = (await other.execute(select(ThreatActor).where(ThreatActor.id == actor.id))).scalar_one()
        assert not (refreshed.description or "").strip()

    # And the committed failure now excludes the entity from the next run.
    picked = await find_assessment_backfill_candidates(db_session, 10, 1, retry_days=7)
    assert actor.id not in {eid for _t, eid, _h in picked}


# --------------------------------------------------------------------------- provenance


@pytest.mark.asyncio
async def test_assessment_is_signed_in_the_claim_ledger(db_session: AsyncSession, test_user):
    """Every other writer of a profile field records who asserted it. Without
    this the AI's own paragraph shows on the profile as unsourced, and a wrong
    one has no trail back to the pass that wrote it."""
    from app.models.entity_field_claim import EntityFieldClaim

    entries = await _mk_entries(db_session, 1)
    actor = ThreatActor(name="Unsigned Actor")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=entries[0].id, threat_actor_id=actor.id))
    await db_session.flush()

    run_task = AsyncMock(return_value={"summary": "Signed assessment text", "_extraction_status": "success"})
    with patch("app.ai.engine.run_task", run_task):
        await generate_entity_assessment(db_session, test_user.id, "threat_actor", actor.id, only_if_empty=True)

    claims = (
        (
            await db_session.execute(
                select(EntityFieldClaim).where(
                    EntityFieldClaim.entity_type == "threat_actor",
                    EntityFieldClaim.entity_id == actor.id,
                    EntityFieldClaim.field == "description",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(claims) == 1
    assert claims[0].source_kind == "ai_assessment"
    assert claims[0].source_ref == "entity_assessment"
    assert claims[0].value_text == "Signed assessment text"


# --------------------------------------------------------------------------- stale refresh


async def _record_assessment(db: AsyncSession, entity_type: str, entity_id, *, days_ago: int, ok: bool = True):
    """An article_summary AIResult standing in for a past assessment run."""
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask

    task_id = (
        await db.execute(select(AITask.id).where(AITask.name == "article_summary").limit(1))
    ).scalar_one_or_none()
    if task_id is None:
        task = AITask(
            name="article_summary",
            display_name="Article Summary",
            category="analysis",
            default_prompt_template="{{ content }}",
        )
        db.add(task)
        await db.flush()
        task_id = task.id

    row = AIResult(
        task_id=task_id,
        target_type=entity_type,
        target_id=entity_id,
        is_current=True,
        parsed_result={"summary": "old paragraph"} if ok else {"_extraction_status": "parse_error"},
    )
    db.add(row)
    await db.flush()
    row.created_at = datetime.now(UTC) - timedelta(days=days_ago)
    db.add(row)
    await db.flush()
    return row


async def _link_fresh(db: AsyncSession, actor: ThreatActor, n: int):
    """n articles linked to the actor *after* its assessment was written."""
    from app.models.threat_actor import EntryThreatActor

    entries = await _mk_entries(db, n)
    for e in entries:
        db.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id, extracted_at=datetime.now(UTC)))
    await db.flush()
    return entries


@pytest.mark.asyncio
async def test_stale_assessment_is_picked_for_refresh(db_session: AsyncSession):
    """The backfill only ever picks empty descriptions, so an entity assessed
    once is never revisited however much has been reported since."""
    from app.workers.entity_maintenance_tasks import find_assessment_refresh_candidates

    actor = ThreatActor(name="Stale Actor", description="written in June")
    db_session.add(actor)
    await db_session.flush()
    await _record_assessment(db_session, "threat_actor", actor.id, days_ago=90)
    await _link_fresh(db_session, actor, 12)

    picked = await find_assessment_refresh_candidates(db_session, 10, 10, retry_days=7)
    assert actor.id in {eid for _t, eid, _n in picked}

    # Below the staleness threshold it stays put.
    quiet = ThreatActor(name="Quiet Actor", description="still accurate")
    db_session.add(quiet)
    await db_session.flush()
    await _record_assessment(db_session, "threat_actor", quiet.id, days_ago=90)
    await _link_fresh(db_session, quiet, 2)
    picked = await find_assessment_refresh_candidates(db_session, 10, 10, retry_days=7)
    assert quiet.id not in {eid for _t, eid, _n in picked}


@pytest.mark.asyncio
async def test_refresh_never_touches_text_the_ai_did_not_write(db_session: AsyncSession):
    """An analyst's or an enrichment feed's description has no successful
    article_summary behind it, and must not be overwritten."""
    from app.workers.entity_maintenance_tasks import find_assessment_refresh_candidates

    analyst = ThreatActor(name="Analyst Written", description="hand-written profile")
    db_session.add(analyst)
    await db_session.flush()
    await _link_fresh(db_session, analyst, 20)

    picked = await find_assessment_refresh_candidates(db_session, 10, 10, retry_days=7)
    assert analyst.id not in {eid for _t, eid, _n in picked}

    # A *failed* past attempt is not authorship either — the row exists only to
    # drive the retry cooldown.
    failed = ThreatActor(name="Failed Attempt", description="hand-written too")
    db_session.add(failed)
    await db_session.flush()
    await _record_assessment(db_session, "threat_actor", failed.id, days_ago=90, ok=False)
    await _link_fresh(db_session, failed, 20)
    picked = await find_assessment_refresh_candidates(db_session, 10, 10, retry_days=7)
    assert failed.id not in {eid for _t, eid, _n in picked}


@pytest.mark.asyncio
async def test_refresh_respects_the_retry_cooldown(db_session: AsyncSession):
    from app.workers.entity_maintenance_tasks import find_assessment_refresh_candidates

    actor = ThreatActor(name="Just Refreshed", description="fresh paragraph")
    db_session.add(actor)
    await db_session.flush()
    await _record_assessment(db_session, "threat_actor", actor.id, days_ago=1)
    await _link_fresh(db_session, actor, 20)

    picked = await find_assessment_refresh_candidates(db_session, 10, 10, retry_days=7)
    assert actor.id not in {eid for _t, eid, _n in picked}


def test_refresh_settings_are_configurable():
    from app.config import settings
    from app.services.system_settings import _ENGINE_SECTION_GROUPS, CONFIGURABLE_KEYS

    for key, kind, expected in (
        ("assessment_refresh_enabled", bool, True),
        ("assessment_refresh_min_new_articles", int, 10),
        ("assessment_refresh_batch_size", int, 10),
    ):
        assert CONFIGURABLE_KEYS.get(key) is kind, f"{key} missing from CONFIGURABLE_KEYS"
        assert key in _ENGINE_SECTION_GROUPS, f"{key} missing a settings group"
        assert getattr(settings, key) == expected
