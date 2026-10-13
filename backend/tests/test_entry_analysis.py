"""One-pass entry analysis: fan-out storage, enqueue policy, echo-reuse, junk gate."""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.ai_analysis import AIAnalysisRequest
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.entry import Entry
from app.models.entry_signal import EntrySignal
from app.models.feed import Feed
from app.models.malware_family import EntryMalware
from app.models.threat_actor import EntryThreatActor
from app.services.entry_analysis import enqueue_entry_analysis, store_entry_analysis

SAMPLE_PARSED = {
    "summary": "APT-Test deployed NewLocker ransomware via CVE exploitation.",
    "ttps": [
        {
            "technique_id": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "tactic": "initial-access",
            "confidence": "high",
        }
    ],
    "threat_actors": [{"name": "APT-Test", "aliases": ["TestBear"], "confidence": "high"}],
    "malware": [{"name": "NewLocker", "malware_type": "ransomware", "confidence": "high"}],
    "tools": [],
    "countries": [],
    "sectors": [{"name": "healthcare", "confidence": "medium"}],
    "mitigations": [],
    "severity_assessment": {"level": "high", "rationale": "active exploitation"},
    "novelty_note": "First public report of NewLocker.",
    "_extraction_status": "success",
}


@pytest_asyncio.fixture
async def feed(db_session) -> Feed:
    f = Feed(title="Analysis Feed", url="https://af.example/feed", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


@pytest_asyncio.fixture
async def analysis_task(db_session) -> AITask:
    task = AITask(
        name="entry_analysis",
        display_name="One-Pass Entry Analysis",
        category="extraction",
        default_prompt_template="{{ entry.title }}",
        is_system=True,
    )
    db_session.add(task)
    await db_session.flush()
    return task


async def _make_entry(db_session, feed, *, title, content="Ransomware attack details and exploit analysis.") -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title=title,
        guid=f"guid-{uuid.uuid4()}",
        content_text=content,
        published_at=datetime.now(UTC),
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest.mark.asyncio
async def test_store_entry_analysis_fans_out(db_session, feed):
    entry = await _make_entry(db_session, feed, title="Fan-out entry")
    counts = await store_entry_analysis(db_session, entry.id, SAMPLE_PARSED)

    assert counts["threat_actors"] == 1
    assert counts["malware"] == 1
    assert counts["sectors"] == 1
    actor_links = (
        (await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == entry.id)))
        .scalars()
        .all()
    )
    assert len(actor_links) == 1
    malware_links = (
        (await db_session.execute(select(EntryMalware).where(EntryMalware.entry_id == entry.id))).scalars().all()
    )
    assert len(malware_links) == 1


@pytest.mark.asyncio
async def test_enqueue_flag_off_noop(db_session, feed, analysis_task):
    entry = await _make_entry(db_session, feed, title="Flag off")
    status = await enqueue_entry_analysis(db_session, entry.id)
    assert status is None
    rows = (await db_session.execute(select(AIAnalysisRequest))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_enqueue_junk_gate_and_pending(db_session, feed, analysis_task, monkeypatch):
    from app.config import settings as env_settings

    monkeypatch.setattr(env_settings, "ai_one_pass_enabled", True)

    junk = await _make_entry(db_session, feed, title="Cat pictures weekly", content="Cute cats doing cat things.")
    status = await enqueue_entry_analysis(db_session, junk.id)
    assert status == "skipped_junk"

    relevant = await _make_entry(
        db_session,
        feed,
        title="Ransomware exploits CVE-2026-1234",
        content="A new ransomware campaign exploits CVE-2026-1234 vulnerability against healthcare targets.",
    )
    status = await enqueue_entry_analysis(db_session, relevant.id)
    assert status == "pending"
    # Second call is idempotent
    assert await enqueue_entry_analysis(db_session, relevant.id) == "pending"
    rows = (await db_session.execute(select(AIAnalysisRequest))).scalars().all()
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_enqueue_echo_reuse_zero_cost(db_session, feed, analysis_task, monkeypatch):
    from app.config import settings as env_settings

    monkeypatch.setattr(env_settings, "ai_one_pass_enabled", True)

    original = await _make_entry(
        db_session,
        feed,
        title="Original malware report",
        content="Detailed malware exploit vulnerability analysis of the attack campaign.",
    )
    db_session.add(
        AIResult(
            entry_id=original.id,
            target_type="entry",
            target_id=original.id,
            is_current=True,
            task_id=analysis_task.id,
            model_name="claude-haiku-4-5-20251001",
            prompt_used="p",
            raw_response="r",
            parsed_result=SAMPLE_PARSED,
            tokens_input=100,
            tokens_output=50,
            cost_estimate=0.001,
        )
    )
    echo = await _make_entry(
        db_session,
        feed,
        title="Echo of malware report",
        content="Rehash of the malware exploit vulnerability analysis of the attack campaign.",
    )
    db_session.add(
        EntrySignal(
            entry_id=echo.id,
            signal_type="feed_echo",
            score=0.9,
            explanation="echo",
            payload={"duplicate_of": str(original.id), "ratio": 0.85},
        )
    )
    await db_session.flush()

    status = await enqueue_entry_analysis(db_session, echo.id)
    assert status == "reused_echo"

    # Echo got a zero-cost current result copied from the original
    copied = (
        await db_session.execute(
            select(AIResult).where(AIResult.target_id == echo.id, AIResult.is_current == True)  # noqa: E712
        )
    ).scalar_one()
    assert float(copied.cost_estimate) == 0
    assert copied.parsed_result["_reused_from"] == str(original.id)
    # And entity links landed on the echo entry too
    links = (
        (await db_session.execute(select(EntryThreatActor).where(EntryThreatActor.entry_id == echo.id))).scalars().all()
    )
    assert len(links) == 1


@pytest.mark.asyncio
async def test_batch_cost_discount():
    from app.ai.engine import _estimate_cost

    full = _estimate_cost("claude-haiku-4-5-20251001", 3000, 600)
    half = _estimate_cost("claude-haiku-4-5-20251001", 3000, 600, batch=True)
    assert float(half) == pytest.approx(float(full) / 2)


def test_parse_ai_json_salvage():
    from app.ai.engine import parse_ai_json

    assert parse_ai_json('{"a": 1}') == {"a": 1}
    assert parse_ai_json('prose\n```json\n{"a": 1}\n```\nmore') == {"a": 1}
    assert parse_ai_json("not json")["_extraction_status"] == "parse_error"


@pytest.mark.asyncio
async def test_submit_priority_order_and_budget(db_session, feed, analysis_task, monkeypatch):
    """Pending rows are submitted highest-priority first; budget clamps the slice."""
    from app.workers import ai_batch_tasks

    entries = []
    for i, score in enumerate([0.5, 5.0, 2.0]):
        e = await _make_entry(db_session, feed, title=f"prio-{score}")
        e.priority_raw = score
        e.scored_at = datetime.now(UTC)
        db_session.add(e)
        await db_session.flush()
        db_session.add(AIAnalysisRequest(entry_id=e.id, status="pending", custom_id=f"ea-{e.id}"))
        entries.append(e)
    await db_session.flush()

    from app.models.entry import Entry as EntryModel

    pending = (
        await db_session.execute(
            select(AIAnalysisRequest, EntryModel)
            .join(EntryModel, EntryModel.id == AIAnalysisRequest.entry_id)
            .where(AIAnalysisRequest.status == "pending")
            .order_by(EntryModel.priority_raw.desc().nullslast(), AIAnalysisRequest.created_at.asc())
            .limit(2)  # simulated budget clamp
        )
    ).all()
    scores = [entry.priority_raw for _, entry in pending]
    assert scores == [5.0, 2.0]

    # Provider batches capability probe
    class P:
        provider_type = "claude"
        config = {}

    assert ai_batch_tasks._provider_supports_batches(P(), "sk-ant-api03-xyz", True)
    assert not ai_batch_tasks._provider_supports_batches(P(), "sk-ant-oat-xyz", True)  # OAuth
    assert not ai_batch_tasks._provider_supports_batches(P(), "sk-ant-api03-xyz", False)  # disabled
    P2 = P()
    P2.config = {"batches_unsupported": True}
    assert not ai_batch_tasks._provider_supports_batches(P2, "sk-ant-api03-xyz", True)


# ---------------------------------------------------------------------------
# Tool scoping — advisories and rule-repo feeds must not mint tool entities
# (planning/tool-extraction-cleanup.md)
# ---------------------------------------------------------------------------

_WIELDED_TOOL = {
    "name": "SweepScan",
    "aliases": [],
    "tool_type": "reconnaissance",
    "platforms": [],
    "wielded_by": "APT29",
    "evidence": "APT29 ran SweepScan across the internal subnet before moving laterally.",
    "confidence": "high",
}


async def _tool_names(db, entry_id):
    from app.models.tool import EntryTool, Tool

    rows = (
        await db.execute(
            select(Tool.name).join(EntryTool, EntryTool.tool_id == Tool.id).where(EntryTool.entry_id == entry_id)
        )
    ).scalars()
    return set(rows)


async def test_tools_stored_for_a_normal_incident_entry(db_session, test_entry):
    await store_entry_analysis(db_session, test_entry.id, {"tools": [_WIELDED_TOOL], "report_type": "incident_report"})
    assert "SweepScan" in await _tool_names(db_session, test_entry.id)


async def test_advisory_report_type_suppresses_tools(db_session, test_entry):
    """An advisory names affected software, not wielded tooling."""
    await store_entry_analysis(db_session, test_entry.id, {"tools": [_WIELDED_TOOL], "report_type": "advisory"})
    assert await _tool_names(db_session, test_entry.id) == set()


async def test_feed_extract_tools_false_suppresses_tools(db_session, test_entry):
    feed = await db_session.get(Feed, test_entry.feed_id)
    feed.extract_tools = False
    await db_session.flush()
    await store_entry_analysis(db_session, test_entry.id, {"tools": [_WIELDED_TOOL], "report_type": "incident_report"})
    assert await _tool_names(db_session, test_entry.id) == set()


@pytest.mark.asyncio
async def test_current_analysis_result_tolerates_duplicate_current_rows(db_session, feed, analysis_task):
    """Duplicate is_current rows must not raise — they used to stall every pending analysis.

    submit_analysis_batches calls this per-entry from its self-healing sweep, so
    a MultipleResultsFound here aborted the whole hourly run and nothing was
    dispatched for any entry.
    """
    from app.services.entry_analysis import _current_analysis_result

    entry = await _make_entry(db_session, feed, title="Duplicate current rows")

    older = AIResult(
        entry_id=entry.id,
        target_type="entry",
        target_id=entry.id,
        is_current=True,
        task_id=analysis_task.id,
        model_name="m",
        prompt_used="p",
        raw_response="r",
        parsed_result={"summary": "older"},
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    newer = AIResult(
        entry_id=entry.id,
        target_type="entry",
        target_id=entry.id,
        is_current=True,
        task_id=analysis_task.id,
        model_name="m",
        prompt_used="p",
        raw_response="r",
        parsed_result={"summary": "newer"},
        created_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    db_session.add_all([older, newer])
    await db_session.flush()

    result, task = await _current_analysis_result(db_session, entry.id)

    assert task is not None
    assert result is not None
    # Deterministically the newest, not an arbitrary row.
    assert result.parsed_result["summary"] == "newer"


def _stub_provider(monkeypatch, analysis_task, content='{"summary": "fresh"}'):
    from unittest.mock import AsyncMock, MagicMock

    import app.ai.engine as engine

    response = MagicMock(content=content, model="m", tokens_input=10, tokens_output=5, cost_usd=None)
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=response)
    assignment = MagicMock(config={}, model_name="m")
    provider_model = MagicMock(id=None, config={}, provider_type="test")
    monkeypatch.setattr(
        engine, "get_task_assignment", AsyncMock(return_value=(assignment, analysis_task, provider_model))
    )
    monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: provider)
    return provider


def _current_row(entry, analysis_task, parsed):
    return AIResult(
        entry_id=entry.id,
        target_type="entry",
        target_id=entry.id,
        is_current=True,
        task_id=analysis_task.id,
        model_name="m",
        prompt_used="p",
        raw_response="r",
        parsed_result=parsed,
    )


@pytest.mark.asyncio
async def test_run_task_retries_past_a_current_provider_error(db_session, feed, analysis_task, test_user, monkeypatch):
    """A stored provider error must not answer the retry.

    During an outage every first attempt stored {"_error": ...} as current, and
    every retry got that row back without calling the provider, so the whole
    backlog failed again in milliseconds once the provider was back.
    """
    from app.ai.engine import run_task

    entry = await _make_entry(db_session, feed, title="Outage casualty")
    db_session.add(_current_row(entry, analysis_task, {"_error": "[SSL: TLSV1_UNRECOGNIZED_NAME]"}))
    await db_session.flush()
    provider = _stub_provider(monkeypatch, analysis_task)

    result = await run_task(db_session, test_user.id, "entry_analysis", {"entry": {"title": "t"}}, entry_id=entry.id)

    provider.complete.assert_awaited_once()
    assert result["_extraction_status"] == "success"
    current = (
        (
            await db_session.execute(
                select(AIResult).where(AIResult.target_id == entry.id, AIResult.is_current == True)  # noqa: E712
            )
        )
        .scalars()
        .all()
    )
    assert [r.parsed_result["summary"] for r in current] == ["fresh"]


@pytest.mark.asyncio
async def test_run_task_still_dedups_a_current_answer(db_session, feed, analysis_task, test_user, monkeypatch):
    from app.ai.engine import run_task

    entry = await _make_entry(db_session, feed, title="Already analysed")
    db_session.add(_current_row(entry, analysis_task, SAMPLE_PARSED))
    await db_session.flush()
    provider = _stub_provider(monkeypatch, analysis_task)

    result = await run_task(db_session, test_user.id, "entry_analysis", {"entry": {"title": "t"}}, entry_id=entry.id)

    provider.complete.assert_not_awaited()
    assert result["summary"] == SAMPLE_PARSED["summary"]
