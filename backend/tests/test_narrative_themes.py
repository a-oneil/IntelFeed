"""Narrative themes: reading the day briefing's own grouping back out of its
markdown (app/intelligence/narrative_themes.py) and the promotion gate that
uses it (app/intelligence/correlation.py::_passes_theme_floor)."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.narrative_themes import (
    parse_briefing,
    record_briefing_themes,
    spans_multiple_themes,
    theme_cohorts,
)
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.narrative_theme import SECTION_NOTABLE, SECTION_THEME, NarrativeBriefing, NarrativeThemeMember


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
            published_at=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
        )
        db.add(e)
        entries.append(e)
    await db.flush()
    return entries


def _briefing(ids: list[uuid.UUID]) -> str:
    """A briefing in the shape the daily_summary prompt mandates."""
    return f"""## TL;DR
Edge devices and ransomware dominated. See [an overview](/?entry={ids[0]}).

## Key Developments

### Edge-device exploitation widens
Two vendors shipped emergency patches ([one](/?entry={ids[0]}), [two](/?entry={ids[1]})).
A third advisory landed late: [advisory](https://vendor.example/advisory).

### Ransomware affiliate churn
Affiliates moved between programs ([report](/?entry={ids[2]})).

## Notable Individual Items
- **[A one-off](/?entry={ids[3]})** — did not fit a theme.

## Worth a Closer Look
[The deep one](/?entry={ids[1]}) repays a full read.
"""


def test_parse_pulls_themes_and_buckets():
    ids = [uuid.uuid4() for _ in range(4)]
    citations = parse_briefing(_briefing(ids))
    by_entry: dict[uuid.UUID, set[tuple[str, str]]] = {}
    for entry_id, theme, section in citations:
        by_entry.setdefault(entry_id, set()).add((theme, section))

    assert ("Edge-device exploitation widens", SECTION_THEME) in by_entry[ids[0]]
    assert ("Ransomware affiliate churn", SECTION_THEME) in by_entry[ids[2]]
    # The leftover bucket is recorded, but with no theme — the briefing read the
    # day and declined to group it.
    assert ("", SECTION_NOTABLE) in by_entry[ids[3]]
    # An article cited under a theme *and* in a later section keeps both rows.
    assert ("Edge-device exploitation widens", SECTION_THEME) in by_entry[ids[1]]


def test_parse_ignores_external_links_and_repeats():
    ids = [uuid.uuid4() for _ in range(4)]
    citations = parse_briefing(_briefing(ids))
    # Only in-app reader links carry an entry id; the vendor advisory does not.
    assert len(citations) == len({(c[0], c[1]) for c in citations})
    assert all(isinstance(c[0], uuid.UUID) for c in citations)


def test_parse_of_empty_or_headingless_text_is_empty():
    assert parse_briefing("") == []
    assert parse_briefing("no links here at all") == []


@pytest.mark.asyncio
async def test_record_stores_citations_and_bookkeeping(db_session: AsyncSession):
    entries = await _mk_entries(db_session, 4)
    ids = [e.id for e in entries]

    result = await record_briefing_themes(db_session, "2026-09-18", _briefing(ids))
    assert result["status"] == "ok"
    assert result["themes"] == 2

    brief = (
        await db_session.execute(select(NarrativeBriefing).where(NarrativeBriefing.day_key == "2026-09-18"))
    ).scalar_one()
    assert brief.cited_entry_count == 4

    rows = (
        (await db_session.execute(select(NarrativeThemeMember).where(NarrativeThemeMember.day_key == "2026-09-18")))
        .scalars()
        .all()
    )
    assert {r.theme for r in rows if r.theme} == {
        "Edge-device exploitation widens",
        "Ransomware affiliate churn",
    }


@pytest.mark.asyncio
async def test_reparsing_a_day_does_not_duplicate(db_session: AsyncSession):
    entries = await _mk_entries(db_session, 4)
    ids = [e.id for e in entries]
    await record_briefing_themes(db_session, "2026-09-18", _briefing(ids))
    first = len(
        (await db_session.execute(select(NarrativeThemeMember).where(NarrativeThemeMember.day_key == "2026-09-18")))
        .scalars()
        .all()
    )
    await record_briefing_themes(db_session, "2026-09-18", _briefing(ids))
    second = len(
        (await db_session.execute(select(NarrativeThemeMember).where(NarrativeThemeMember.day_key == "2026-09-18")))
        .scalars()
        .all()
    )
    assert first == second


@pytest.mark.asyncio
async def test_citations_of_unknown_entries_are_dropped(db_session: AsyncSession):
    """A briefing outlives the articles retention prunes."""
    entries = await _mk_entries(db_session, 2)
    ids = [entries[0].id, entries[1].id, uuid.uuid4(), uuid.uuid4()]
    result = await record_briefing_themes(db_session, "2026-09-17", _briefing(ids))
    assert result["dropped"] > 0
    rows = (
        (await db_session.execute(select(NarrativeThemeMember).where(NarrativeThemeMember.day_key == "2026-09-17")))
        .scalars()
        .all()
    )
    assert {r.entry_id for r in rows} <= {entries[0].id, entries[1].id}


@pytest.mark.asyncio
async def test_cohorts_exclude_the_leftover_bucket(db_session: AsyncSession):
    entries = await _mk_entries(db_session, 4)
    ids = [e.id for e in entries]
    await record_briefing_themes(db_session, "2026-09-18", _briefing(ids))

    cohorts = await theme_cohorts(db_session, ids)
    # ids[3] was only ever cited under "Notable Individual Items".
    assert ids[3] not in cohorts
    assert cohorts[ids[0]] == {"2026-09-18|Edge-device exploitation widens"}


@pytest.mark.asyncio
async def test_span_says_no_for_one_wave_and_yes_across_themes(db_session: AsyncSession):
    entries = await _mk_entries(db_session, 4)
    ids = [e.id for e in entries]
    await record_briefing_themes(db_session, "2026-09-18", _briefing(ids))

    # Both articles sit under the same heading on the same day: one reporting
    # wave told twice, which is exactly what the gate exists to catch.
    assert await spans_multiple_themes(db_session, [ids[0], ids[1]]) is False
    # Different headings — independent assertions.
    assert await spans_multiple_themes(db_session, [ids[0], ids[2]]) is True


@pytest.mark.asyncio
async def test_span_has_no_opinion_without_coverage(db_session: AsyncSession):
    """Missing data must read as 'no opinion', never as a failure — otherwise
    switching the gate on would freeze every promotion until themes exist."""
    entries = await _mk_entries(db_session, 2)
    assert await spans_multiple_themes(db_session, [e.id for e in entries]) is None
    assert await spans_multiple_themes(db_session, []) is None


@pytest.mark.asyncio
async def test_theme_floor_degrades_open(db_session: AsyncSession, monkeypatch):
    from app.intelligence import correlation

    entries = await _mk_entries(db_session, 2)
    ids = [e.id for e in entries]

    # Gate off: always passes.
    monkeypatch.setattr("app.intelligence.narrative_themes.theme_gating_enabled", lambda: False)
    assert await correlation._passes_theme_floor(db_session, ids) is True

    # Gate on but nothing parsed: still passes.
    monkeypatch.setattr("app.intelligence.narrative_themes.theme_gating_enabled", lambda: True)
    assert await correlation._passes_theme_floor(db_session, ids) is True


@pytest.mark.asyncio
async def test_theme_floor_blocks_a_single_wave(db_session: AsyncSession, monkeypatch):
    from app.intelligence import correlation

    entries = await _mk_entries(db_session, 4)
    ids = [e.id for e in entries]
    await record_briefing_themes(db_session, "2026-09-18", _briefing(ids))

    monkeypatch.setattr("app.intelligence.narrative_themes.theme_gating_enabled", lambda: True)
    assert await correlation._passes_theme_floor(db_session, [ids[0], ids[1]]) is False
    assert await correlation._passes_theme_floor(db_session, [ids[0], ids[2]]) is True


def test_narrative_settings_are_registered():
    """settings.get() on an unregistered key silently returns None, which would
    make both knobs dead code."""
    from app.config import settings
    from app.services.system_settings import _ENGINE_SECTION_GROUPS, CONFIGURABLE_KEYS

    for key, expected in (("narrative_themes_enabled", True), ("narrative_theme_gating", False)):
        assert CONFIGURABLE_KEYS.get(key) is bool, f"{key} missing from CONFIGURABLE_KEYS"
        assert key in _ENGINE_SECTION_GROUPS, f"{key} missing a settings group"
        assert getattr(settings, key) is expected
