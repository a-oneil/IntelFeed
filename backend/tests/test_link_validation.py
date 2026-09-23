"""Tests for the entity-link AI validator."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.workers.link_validation_tasks import (
    LinkRow,
    _batched_timeout,
    _build_prompt_variables,
    _validate_decisions,
    batched_schema,
    build_batched_prompt,
    restore_from_log,
    select_paragraphs_for_links,
    split_batched_response,
)

# --------------------------------------------------------- paragraph slicer


def _entry(title: str = "T", summary: str = "S", content: str | None = None) -> Entry:
    e = Entry()
    e.title = title
    e.summary = summary
    e.content_text = content
    e.language = "en"
    return e


def test_paragraph_slicer_always_includes_title_and_summary():
    """Title (idx 0) and summary (idx 1) carry framing — always include them."""
    content = "\n\n".join(f"Para {i} content." for i in range(2, 10))
    rendered = select_paragraphs_for_links(
        title="My article title",
        summary="A short summary.",
        content_text=content,
        paragraph_indices=[5],
        max_chars=10_000,
    )
    assert "My article title" in rendered
    assert "A short summary." in rendered
    assert "Para 5 content." in rendered
    # ±1 expansion
    assert "Para 4 content." in rendered
    assert "Para 6 content." in rendered


def test_paragraph_slicer_inserts_gap_markers():
    """Discontinuity is shown via [...] marker."""
    content = "\n\n".join(f"Para {i}." for i in range(2, 12))
    rendered = select_paragraphs_for_links(
        title="title",
        summary="summary",
        content_text=content,
        paragraph_indices=[3, 8],
        max_chars=10_000,
    )
    assert "[...]" in rendered, f"Expected gap marker in:\n{rendered}"


def test_paragraph_slicer_deduplicates_overlapping_windows():
    """Adjacent matches with overlapping ±1 windows shouldn't insert gaps."""
    content = "\n\n".join(f"Para {i}." for i in range(2, 12))
    rendered = select_paragraphs_for_links(
        title="t",
        summary="s",
        content_text=content,
        paragraph_indices=[3, 4],
        max_chars=10_000,
    )
    # Should have Para 2,3,4,5 all without a gap marker between them.
    assert "[...]" not in rendered or rendered.count("[...]") <= 1


def test_paragraph_slicer_respects_hard_cap():
    """Hard cap on rendered chars — shouldn't blow up the prompt."""
    huge_content = "\n\n".join("X" * 500 for _ in range(20))
    rendered = select_paragraphs_for_links(
        title="t",
        summary="s",
        content_text=huge_content,
        paragraph_indices=list(range(2, 20)),
        max_chars=300,
    )
    assert len(rendered) <= 350, f"Got {len(rendered)} chars (cap ~300+slack)"


def test_paragraph_slicer_handles_empty_indices():
    """No matches → just title + summary."""
    rendered = select_paragraphs_for_links(
        title="title",
        summary="summary",
        content_text="body para",
        paragraph_indices=[],
        max_chars=10_000,
    )
    assert "title" in rendered
    assert "summary" in rendered


def test_paragraph_slicer_handles_no_content():
    """Missing content body shouldn't crash."""
    rendered = select_paragraphs_for_links(
        title="title",
        summary=None,
        content_text=None,
        paragraph_indices=[5],
        max_chars=10_000,
    )
    assert "title" in rendered


# ----------------------------------------------------- response validator


def _link(key: str = "threat_actor:11111111-1111-1111-1111-111111111111") -> LinkRow:
    type_, eid = key.split(":")
    return LinkRow(
        entity_key=key,
        entity_type=type_,
        entity_id=uuid.UUID(eid),
        name="Test Entity",
        matched_names=["Test"],
        confidence="medium",
        source="auto_link",
        paragraph_indices=[3],
        extracted_at=datetime.now(UTC),
    )


def test_validator_accepts_well_formed():
    link = _link()
    result = {
        "_extraction_status": "success",
        "validations": [{"entity_key": link.entity_key, "decision": "REMOVE", "reason": "off-topic"}],
    }
    decisions = _validate_decisions(result, [link])
    assert decisions is not None
    assert len(decisions) == 1
    assert decisions[0]["decision"] == "REMOVE"


def test_validator_rejects_unknown_entity_keys():
    """If Claude invents an entity_key not in input, treat whole response as bad."""
    link = _link()
    result = {
        "_extraction_status": "success",
        "validations": [
            {"entity_key": "threat_actor:99999999-9999-9999-9999-999999999999", "decision": "REMOVE", "reason": "x"},
        ],
    }
    assert _validate_decisions(result, [link]) is None


def test_validator_defaults_missing_to_keep():
    """If a decision is omitted, default to KEEP rather than removing."""
    a = _link("threat_actor:11111111-1111-1111-1111-111111111111")
    b = _link("malware:22222222-2222-2222-2222-222222222222")
    result = {
        "_extraction_status": "success",
        "validations": [{"entity_key": a.entity_key, "decision": "REMOVE", "reason": "x"}],
    }
    decisions = _validate_decisions(result, [a, b])
    assert decisions is not None
    keys_decisions = {d["link"].entity_key: d["decision"] for d in decisions}
    assert keys_decisions[a.entity_key] == "REMOVE"
    assert keys_decisions[b.entity_key] == "KEEP"


def test_validator_rejects_duplicates():
    link = _link()
    result = {
        "_extraction_status": "success",
        "validations": [
            {"entity_key": link.entity_key, "decision": "REMOVE", "reason": "x"},
            {"entity_key": link.entity_key, "decision": "KEEP", "reason": "y"},
        ],
    }
    assert _validate_decisions(result, [link]) is None


def test_validator_rejects_bad_decision_value():
    """Anything other than KEEP/REMOVE gets dropped silently — that key reads as missing → KEEP."""
    link = _link()
    result = {
        "_extraction_status": "success",
        "validations": [{"entity_key": link.entity_key, "decision": "MAYBE", "reason": "x"}],
    }
    decisions = _validate_decisions(result, [link])
    assert decisions is not None
    assert decisions[0]["decision"] == "KEEP"


def test_validator_rejects_non_list_validations():
    assert _validate_decisions({"validations": "not a list"}, [_link()]) is None


def test_validator_rejects_empty_dict():
    assert _validate_decisions({}, [_link()]) is None


# ----------------------------------------------------- prompt variables


def test_build_prompt_variables_smoke():
    e = Entry()
    e.id = uuid.uuid4()
    e.title = "Test article"
    e.summary = "A summary."
    e.content_text = "Para1.\n\nPara2 mentions Storm.\n\nPara3.\n\nPara4."
    e.language = "en"
    e.published_at = datetime(2026, 5, 1, tzinfo=UTC)
    link = _link()
    link.paragraph_indices = [2]
    variables = _build_prompt_variables(
        entry=e,
        feed_name="Test Feed",
        links=[link],
        max_chars=10_000,
    )
    assert variables["entry_title"] == "Test article"
    assert variables["entry_feed_name"] == "Test Feed"
    assert variables["entry_language"] == "en"
    assert "Storm" in variables["entry_paragraphs"]
    assert variables["linked_entities"][0]["entity_key"] == link.entity_key


# ------------------------------------------------------- integration: restore


@pytest_asyncio.fixture
async def feed_and_entry(db_session: AsyncSession):
    feed = Feed(
        title="Test Feed",
        url="https://example.com/feed.xml",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id,
        title="Storm chasers find new evidence",
        content_text="A heavy storm hit the region today.",
        summary="Storm chasing in Kansas.",
    )
    db_session.add(entry)
    await db_session.flush()
    return feed, entry


@pytest.mark.asyncio
async def test_restore_recreates_junction_and_bumps_article_count(db_session: AsyncSession, feed_and_entry):
    """Restore from a 'removed' log row should re-create the junction and increment article_count."""
    _, entry = feed_and_entry
    actor = ThreatActor(name="Storm-0501", aliases=["Storm"], article_count=5)
    db_session.add(actor)
    await db_session.flush()

    log = EntityLinkValidationLog(
        entry_id=entry.id,
        entity_type="threat_actor",
        entity_id=actor.id,
        entity_name_snapshot=actor.name,
        action="removed",
        reason="weather article",
        original_source="auto_link",
        original_confidence="medium",
        original_matched_names=["Storm"],
        original_paragraph_indices=[0, 1],
        original_extracted_at=datetime.now(UTC) - timedelta(days=1),
    )
    db_session.add(log)
    await db_session.flush()

    ok, msg = await restore_from_log(db_session, log.id)
    assert ok, msg
    await db_session.commit()

    # Junction re-created
    j_result = await db_session.execute(
        select(EntryThreatActor).where(
            EntryThreatActor.entry_id == entry.id,
            EntryThreatActor.threat_actor_id == actor.id,
        )
    )
    j = j_result.scalar_one_or_none()
    assert j is not None
    assert j.source == "auto_link"
    assert j.confidence == "medium"
    assert j.matched_names == ["Storm"]

    # article_count went up
    refreshed = await db_session.get(ThreatActor, actor.id)
    assert refreshed.article_count == 6

    # An audit 'restored' row exists
    audit = await db_session.execute(
        select(EntityLinkValidationLog).where(
            EntityLinkValidationLog.entry_id == entry.id,
            EntityLinkValidationLog.action == "restored",
        )
    )
    assert audit.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_restore_refuses_shadow_rows(db_session: AsyncSession, feed_and_entry):
    """Only 'removed' rows can be restored — 'shadow_remove' rows are not real removals."""
    _, entry = feed_and_entry
    actor = ThreatActor(name="x", article_count=1)
    db_session.add(actor)
    await db_session.flush()
    log = EntityLinkValidationLog(
        entry_id=entry.id,
        entity_type="threat_actor",
        entity_id=actor.id,
        entity_name_snapshot="x",
        action="shadow_remove",
        reason="r",
    )
    db_session.add(log)
    await db_session.flush()

    ok, msg = await restore_from_log(db_session, log.id)
    assert not ok
    assert "shadow_remove" in msg


@pytest.mark.asyncio
async def test_restore_refuses_duplicate(db_session: AsyncSession, feed_and_entry):
    """If the junction already exists, restore should refuse."""
    _, entry = feed_and_entry
    actor = ThreatActor(name="dup", article_count=1)
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntryThreatActor(
            entry_id=entry.id,
            threat_actor_id=actor.id,
            source="auto_link",
            confidence="medium",
        )
    )
    log = EntityLinkValidationLog(
        entry_id=entry.id,
        entity_type="threat_actor",
        entity_id=actor.id,
        entity_name_snapshot="dup",
        action="removed",
        reason="r",
        original_source="auto_link",
    )
    db_session.add(log)
    await db_session.flush()
    ok, msg = await restore_from_log(db_session, log.id)
    assert not ok
    assert "already exists" in msg


# --------------------------------------------------------- batched helpers


def test_build_batched_prompt_marks_each_entry_with_uuid():
    """Envelope must delimit per-entry sections with UUID markers."""
    eid1 = uuid.uuid4()
    eid2 = uuid.uuid4()
    rendered = build_batched_prompt([(eid1, "FIRST ENTRY PROMPT"), (eid2, "SECOND ENTRY PROMPT")])
    assert f"=== ENTRY {eid1} START ===" in rendered
    assert f"=== ENTRY {eid1} END ===" in rendered
    assert f"=== ENTRY {eid2} START ===" in rendered
    assert f"=== ENTRY {eid2} END ===" in rendered
    assert "FIRST ENTRY PROMPT" in rendered
    assert "SECOND ENTRY PROMPT" in rendered
    # Envelope tells the model to produce one combined object with `entries[]`.
    assert "entries" in rendered.lower()


def test_build_batched_prompt_preserves_input_order():
    """The envelope explicitly asks for items in input order; markers should reflect that."""
    eid1 = uuid.uuid4()
    eid2 = uuid.uuid4()
    eid3 = uuid.uuid4()
    rendered = build_batched_prompt([(eid1, "A"), (eid2, "B"), (eid3, "C")])
    pos1 = rendered.index(str(eid1))
    pos2 = rendered.index(str(eid2))
    pos3 = rendered.index(str(eid3))
    assert pos1 < pos2 < pos3


def test_batched_schema_wraps_validations_in_entries_envelope():
    """The wrapped schema must require entries[] of {entry_id, validations}."""
    single = {
        "type": "object",
        "required": ["validations"],
        "properties": {
            "validations": {"type": "array", "items": {"type": "object"}},
        },
    }
    wrapped = batched_schema(single)
    assert wrapped is not None
    assert wrapped["properties"]["entries"]["type"] == "array"
    item_schema = wrapped["properties"]["entries"]["items"]
    assert set(item_schema["required"]) == {"entry_id", "validations"}
    assert item_schema["properties"]["validations"] == single["properties"]["validations"]
    assert wrapped["additionalProperties"] is False
    assert item_schema["additionalProperties"] is False


def test_batched_schema_returns_none_when_validations_missing():
    """Schema without a `validations` property can't be wrapped — fall back to unstructured."""
    assert batched_schema(None) is None
    assert batched_schema({}) is None
    assert batched_schema({"type": "object", "properties": {"foo": {}}}) is None


def test_split_batched_response_routes_entries_by_id():
    """Per-entry validations should land under the corresponding entry_id key."""
    eid1 = uuid.uuid4()
    eid2 = uuid.uuid4()
    parsed = {
        "entries": [
            {
                "entry_id": str(eid1),
                "validations": [
                    {"entity_key": "threat_actor:x", "decision": "KEEP", "reason": "r"},
                ],
            },
            {"entry_id": str(eid2), "validations": []},
        ]
    }
    out = split_batched_response(parsed, [(eid1, ""), (eid2, "")])
    assert out is not None
    assert str(eid1) in out and str(eid2) in out
    assert len(out[str(eid1)]) == 1
    assert out[str(eid2)] == []


def test_split_batched_response_falls_back_to_unbatched_single_entry():
    """When batch_size=1 some models return the un-batched shape; tolerate it."""
    eid = uuid.uuid4()
    parsed = {"validations": [{"entity_key": "threat_actor:x", "decision": "REMOVE", "reason": "r"}]}
    out = split_batched_response(parsed, [(eid, "rendered")])
    assert out is not None
    assert str(eid) in out
    assert out[str(eid)][0]["decision"] == "REMOVE"


def test_split_batched_response_tolerates_missing_entries_in_batch():
    """If the model omits an entry, it should be absent from the routed map (caller defaults to ai_bad_shape)."""
    eid1 = uuid.uuid4()
    eid2 = uuid.uuid4()
    parsed = {"entries": [{"entry_id": str(eid1), "validations": []}]}
    out = split_batched_response(parsed, [(eid1, ""), (eid2, "")])
    assert out is not None
    assert str(eid1) in out
    assert str(eid2) not in out  # caller will fall through to ai_bad_shape


def test_split_batched_response_returns_none_for_bad_shapes():
    """A malformed response with no entries[] AND not the single-entry shape is unusable."""
    assert split_batched_response(None, [(uuid.uuid4(), "")]) is None
    assert split_batched_response("not a dict", [(uuid.uuid4(), "")]) is None
    assert split_batched_response({"foo": "bar"}, [(uuid.uuid4(), ""), (uuid.uuid4(), "")]) is None


def test_batched_timeout_scales_with_batch_size():
    """Larger batches get proportionally more time, capped at 600s."""
    # batch_size=1: just the model default
    assert _batched_timeout("sonnet", 1) == 180.0
    assert _batched_timeout("haiku", 1) == 90.0
    # batch_size=10: 180 * (1 + 0.5*9) = 990 → clamped to 600
    assert _batched_timeout("sonnet", 10) == 600.0
    # Mid-range: batch_size=3 → 180 * (1 + 1.0) = 360
    assert _batched_timeout("sonnet", 3) == 360.0
    # Unknown model gets the fallback (180), still scales
    assert _batched_timeout("unknown-model", 1) == 180.0
