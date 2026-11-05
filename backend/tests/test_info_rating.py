"""Information credibility (the 1-6 half of an Admiralty grade), rated per article.

The AI scores the article alone (2-6); another independent outlet in the same
story thread lifts a 2 or 3 to 1; an analyst's rating beats both.
"""

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.entry import Entry
from app.models.feed import Feed
from app.models.story_thread import StoryThread, StoryThreadEntry
from app.search.query_planner import _info_rating_clause
from app.services.info_rating import (
    normalize_ai_rating,
    set_analyst_rating,
    store_ai_rating,
    sync_corroboration,
)


def test_normalize_cleans_the_ai_payload():
    assert normalize_ai_rating({"score": 3, "access": "Secondhand", "rationale": " relays a vendor blog "}) == {
        "score": 3,
        "access": "secondhand",
        "rationale": "relays a vendor blog",
    }
    # The model can't see other sources, so a 1 from it has no basis.
    assert normalize_ai_rating({"score": 1, "access": "firsthand"})["score"] == 2
    assert normalize_ai_rating({"score": 2, "access": "telepathy"})["access"] == "unclear"
    assert normalize_ai_rating({"score": 9}) is None
    assert normalize_ai_rating({"score": "high"}) is None
    assert normalize_ai_rating(None) is None


def test_info_search_clause_parses_ranges():
    def sql(value: str) -> str:
        return str(_info_rating_clause(Entry.info_rating, value).compile(compile_kwargs={"literal_binds": True}))

    assert sql("2") == "entries.info_rating = 2"
    assert sql("<=2") == "entries.info_rating <= 2"
    assert "entries.info_rating >= 1" in sql("1..3") and "entries.info_rating <= 3" in sql("1..3")
    assert sql("*") == "entries.info_rating IS NOT NULL"
    assert sql("junk") == "false"


@pytest_asyncio.fixture
async def feeds(db_session) -> list[Feed]:
    rows = [Feed(title=f"Outlet {i}", url=f"https://outlet{i}.example/feed", feed_type="rss") for i in range(3)]
    for row in rows:
        db_session.add(row)
    await db_session.flush()
    return rows


async def _entry(db_session, feed: Feed) -> Entry:
    entry = Entry(feed_id=feed.id, title="Story", guid=f"g-{uuid.uuid4()}", published_at=datetime.now(UTC))
    db_session.add(entry)
    await db_session.flush()
    return entry


async def _thread(db_session, members: list[tuple[Entry, str, str, uuid.UUID | None]]) -> None:
    """members: (entry, role, source_key, duplicate_of)."""
    thread = StoryThread(slug=f"t-{uuid.uuid4()}", title="Story")
    db_session.add(thread)
    await db_session.flush()
    for entry, role, source_key, duplicate_of in members:
        db_session.add(
            StoryThreadEntry(
                thread_id=thread.id,
                entry_id=entry.id,
                role=role,
                source_key=source_key,
                duplicate_of_entry_id=duplicate_of,
            )
        )
    await db_session.flush()


async def _rating(db_session, entry: Entry) -> tuple:
    row = (
        await db_session.execute(
            select(Entry.info_rating, Entry.info_rating_ai, Entry.info_rating_by, Entry.info_rating_note).where(
                Entry.id == entry.id
            )
        )
    ).one()
    return tuple(row)


@pytest.mark.asyncio
async def test_single_source_keeps_the_ai_score(db_session, feeds):
    entry = await _entry(db_session, feeds[0])
    await store_ai_rating(db_session, entry.id, {"score": 2, "access": "firsthand", "rationale": "own IR data"})
    assert await _rating(db_session, entry) == (2, 2, "ai", "own IR data")


@pytest.mark.asyncio
async def test_another_outlet_in_the_thread_confirms(db_session, feeds):
    a, b = await _entry(db_session, feeds[0]), await _entry(db_session, feeds[1])
    await _thread(db_session, [(a, "origin", "outlet0.example", None), (b, "beat", "outlet1.example", None)])
    await store_ai_rating(db_session, a.id, {"score": 3, "access": "secondhand", "rationale": ""})
    assert (await _rating(db_session, a))[:2] == (1, 3)


@pytest.mark.asyncio
async def test_copies_and_same_outlet_do_not_confirm(db_session, feeds):
    original, copy, sibling = [await _entry(db_session, f) for f in feeds]
    await _thread(
        db_session,
        [
            (original, "origin", "outlet0.example", None),
            # A rewrite of the original is the same report again.
            (copy, "echo", "outlet1.example", original.id),
            # Same outlet, another article: not independent.
            (sibling, "beat", "outlet0.example", None),
        ],
    )
    await store_ai_rating(db_session, original.id, {"score": 2, "access": "firsthand", "rationale": ""})
    assert (await _rating(db_session, original))[0] == 2
    # The copy can't be confirmed by the article it copies either.
    await store_ai_rating(db_session, copy.id, {"score": 2, "access": "secondhand", "rationale": ""})
    assert (await _rating(db_session, copy))[0] == 2


@pytest.mark.asyncio
async def test_doubtful_articles_neither_get_nor_give_confirmation(db_session, feeds):
    a, b = await _entry(db_session, feeds[0]), await _entry(db_session, feeds[1])
    await _thread(db_session, [(a, "origin", "outlet0.example", None), (b, "beat", "outlet1.example", None)])
    await store_ai_rating(db_session, b.id, {"score": 4, "access": "unclear", "rationale": "actor's own boast"})
    await store_ai_rating(db_session, a.id, {"score": 2, "access": "firsthand", "rationale": ""})
    assert (await _rating(db_session, a))[0] == 2  # b is doubtful, so it confirms nothing
    assert (await _rating(db_session, b))[0] == 4  # repetition doesn't lift a 4


@pytest.mark.asyncio
async def test_confirmation_follows_thread_changes(db_session, feeds):
    a, b = await _entry(db_session, feeds[0]), await _entry(db_session, feeds[1])
    await store_ai_rating(db_session, a.id, {"score": 2, "access": "firsthand", "rationale": ""})
    assert (await _rating(db_session, a))[0] == 2
    # A later sweep threads a second outlet onto the story.
    await _thread(db_session, [(a, "origin", "outlet0.example", None), (b, "beat", "outlet1.example", None)])
    assert await sync_corroboration(db_session) >= 1
    assert (await _rating(db_session, a))[0] == 1


@pytest.mark.asyncio
async def test_analyst_rating_wins_and_reset_returns_to_ai(db_session, feeds):
    a, b = await _entry(db_session, feeds[0]), await _entry(db_session, feeds[1])
    await _thread(db_session, [(a, "origin", "outlet0.example", None), (b, "beat", "outlet1.example", None)])
    await store_ai_rating(db_session, a.id, {"score": 2, "access": "firsthand", "rationale": "ai says"})

    await set_analyst_rating(db_session, a.id, 5, "contradicted by vendor", "analyst1")
    rating, ai, by, note = await _rating(db_session, a)
    assert (rating, ai, by) == (5, 2, "analyst")
    assert note.startswith("contradicted by vendor (analyst1, ")

    # Neither a re-analysis nor a sweep moves an analyst's rating.
    await store_ai_rating(db_session, a.id, {"score": 3, "access": "firsthand", "rationale": "new ai"})
    await sync_corroboration(db_session)
    assert (await _rating(db_session, a))[:3] == (5, 3, "analyst")

    await set_analyst_rating(db_session, a.id, None, None, "analyst1")
    assert (await _rating(db_session, a))[:3] == (1, 3, "ai")


@pytest.mark.asyncio
async def test_info_rating_endpoint(client, auth_headers, db_session, feeds):
    entry = await _entry(db_session, feeds[0])
    resp = await client.put(f"/api/entries/{entry.id}/info-rating", json={"rating": 3}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["info_rating"] == 3 and resp.json()["info_rating_by"] == "analyst"

    detail = (await client.get(f"/api/entries/{entry.id}", headers=auth_headers)).json()
    assert detail["info_rating"] == 3 and detail["info_rating_by"] == "analyst"

    assert (
        await client.put(f"/api/entries/{entry.id}/info-rating", json={"rating": 7}, headers=auth_headers)
    ).status_code == 400
    resp = await client.put(f"/api/entries/{entry.id}/info-rating", json={"rating": None}, headers=auth_headers)
    assert resp.json()["info_rating"] is None and resp.json()["info_rating_by"] is None
