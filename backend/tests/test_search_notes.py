"""Notes in cross-entity search.

Analyst notes live in two tables — `notes` (on an entry, or standalone) and
`entity_notes` (on an actor, CVE, ...) — and global search returns both under
one `note` type. These assert the shape the search page relies on to route a
result: which table it came from, and what it hangs off.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.correlation import search_all_entities
from app.models.entity_note import EntityNote
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.note import Note
from app.models.threat_actor import ThreatActor
from app.models.user import User
from app.search.note_results import note_snippet


@pytest.mark.asyncio
async def test_standalone_note_matches_on_title_and_body(db_session: AsyncSession, test_user: User):
    db_session.add(
        Note(
            created_by=test_user.id,
            title="Zylophant maintenance log",
            content_markdown="Torque spec was 42 Nm and the filter is purple.",
        )
    )
    await db_session.flush()

    by_title = await search_all_entities(db_session, "zylophant")
    assert [r["type"] for r in by_title] == ["note"]
    assert by_title[0]["note_source"] == "note"
    assert by_title[0]["entry_id"] is None
    assert by_title[0]["match_field"] == "title"
    assert by_title[0]["match_kind"] == "direct"

    # A body hit is a mention, not an identity match — the same distinction the
    # facet rail's "Matched on" group draws for every other entity.
    by_body = await search_all_entities(db_session, "torque")
    assert by_body[0]["match_field"] == "content"
    assert by_body[0]["match_kind"] == "mention"
    assert "Torque spec" in by_body[0]["description"]


@pytest.mark.asyncio
async def test_entry_note_carries_its_article(db_session: AsyncSession, test_user: User):
    feed = Feed(title="Security Blog", url="https://example.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, title="Quarterly ransomware review", guid="guid-note-1")
    db_session.add(entry)
    await db_session.flush()
    db_session.add(
        Note(
            created_by=test_user.id,
            entry_id=entry.id,
            title="Follow up on the zylophant claim",
            content_markdown="Unverified.",
        )
    )
    await db_session.flush()

    results = await search_all_entities(db_session, "zylophant")
    assert len(results) == 1
    assert results[0]["note_source"] == "note"
    assert results[0]["entry_id"] == str(entry.id)
    assert results[0]["entry_title"] == "Quarterly ransomware review"


@pytest.mark.asyncio
async def test_entity_note_resolves_its_subject(db_session: AsyncSession, test_user: User):
    actor = ThreatActor(name="Qilin")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntityNote(
            entity_type="threat_actor",
            entity_id=actor.id,
            user_id=test_user.id,
            content="Quixotrope tradecraft observed in this wave.",
            note_type="analysis",
        )
    )
    await db_session.flush()

    results = await search_all_entities(db_session, "quixotrope")
    assert len(results) == 1
    note = results[0]
    assert note["type"] == "note"
    assert note["note_source"] == "entity_note"
    assert note["entity_type"] == "threat_actor"
    assert note["entity_id"] == str(actor.id)
    assert note["entity_name"] == "Qilin"
    # Untitled entity notes borrow their subject, so the row still has a name.
    assert note["title"] == "Note on Qilin"


@pytest.mark.asyncio
async def test_notes_are_excluded_when_types_are_filtered(db_session: AsyncSession, test_user: User):
    db_session.add(
        Note(created_by=test_user.id, title="Zylophant log", content_markdown="x"),
    )
    actor = ThreatActor(name="Zylophant Group")
    db_session.add(actor)
    await db_session.flush()

    results = await search_all_entities(db_session, "zylophant", entity_types=["threat_actor"])
    assert [r["type"] for r in results] == ["threat_actor"]


def test_snippet_flattens_html_and_markdown_to_prose():
    """Note bodies hold pasted HTML as often as markdown; neither renders in a row."""
    raw = (
        "Intro sentence.</p><p>---</p><p># FortiBleed &mdash; Full Report</p>"
        "<p>**TLP:CLEAR** status: **Active** see [the advisory](https://x) and snake_case</p>"
    )
    snippet = note_snippet(raw, "fortibleed")
    assert "<p>" not in snippet
    assert "**" not in snippet
    assert "&mdash;" not in snippet
    # Block tags become spaces, so sentences don't fuse across them.
    assert "Intro sentence. " in snippet
    assert "FortiBleed \u2014 Full Report" in snippet
    # A link keeps its text and loses its URL; a bare underscore is not markup.
    assert "the advisory" in snippet and "https://x" not in snippet
    assert "snake_case" in snippet


@pytest.mark.asyncio
async def test_note_field_spans_both_tables(db_session: AsyncSession, test_user: User):
    """`note:` is one field over two tables — it must reach into both."""
    from app.search.entity_builder import execute_entity_queries
    from app.search.query_parser import parse_query
    from app.search.query_planner import build_execution_plan

    db_session.add(Note(created_by=test_user.id, title="Zylophant log", content_markdown="x"))
    actor = ThreatActor(name="Qilin")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntityNote(
            entity_type="threat_actor",
            entity_id=actor.id,
            user_id=test_user.id,
            content="Zylophant tradecraft.",
            note_type="analysis",
        )
    )
    await db_session.flush()

    plan = build_execution_plan(parse_query("note:zylophant"))
    results, _ = await execute_entity_queries(db_session, plan.entity_nodes, limit=50)
    assert {r["note_source"] for r in results} == {"note", "entity_note"}


@pytest.mark.asyncio
async def test_note_property_fields_exclude_the_wrong_table(db_session: AsyncSession, test_user: User):
    """A field that cannot apply to a table excludes it, rather than matching all of it."""
    from app.search.entity_builder import execute_entity_queries
    from app.search.query_parser import parse_query
    from app.search.query_planner import build_execution_plan

    db_session.add(Note(created_by=test_user.id, title="Pinned thought", content_markdown="zylophant", is_pinned=True))
    actor = ThreatActor(name="Qilin")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(
        EntityNote(
            entity_type="threat_actor",
            entity_id=actor.id,
            user_id=test_user.id,
            content="zylophant analysis body",
            note_type="analysis",
        )
    )
    await db_session.flush()

    async def run(query: str) -> list[dict]:
        plan = build_execution_plan(parse_query(query))
        results, _ = await execute_entity_queries(db_session, plan.entity_nodes, limit=50)
        return results

    # note_type exists only on entity notes, so plain notes must not slip through.
    typed = await run("note.type:analysis")
    assert [r["note_source"] for r in typed] == ["entity_note"]

    # Pinning exists only on plain notes.
    pinned = await run("note.pinned:true")
    assert [r["note_source"] for r in pinned] == ["note"]

    # Negation still reads correctly: a plain note is not an analysis note, so
    # it survives the exclusion the entity note is caught by. Paired with a
    # positive term because the planner drops a query that is *only* a negated
    # entity filter — true for every entity type, not just notes.
    both = await run("note:zylophant")
    assert sorted(r["note_source"] for r in both) == ["entity_note", "note"]
    not_analysis = await run("note:zylophant NOT note.type:analysis")
    assert [r["note_source"] for r in not_analysis] == ["note"]


@pytest.mark.asyncio
async def test_note_about_entry_returns_the_article_too(db_session: AsyncSession, test_user: User):
    """A note on an article carries that article, so `note:` narrows the entry stream."""
    from app.search.entity_builder import execute_entity_queries
    from app.search.query_parser import parse_query
    from app.search.query_planner import build_execution_plan

    feed = Feed(title="Security Blog", url="https://example.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, title="Quarterly ransomware review", guid="guid-note-2")
    db_session.add(entry)
    await db_session.flush()
    db_session.add(Note(created_by=test_user.id, entry_id=entry.id, title="Baselining", content_markdown="x"))
    db_session.add(Note(created_by=test_user.id, title="Standalone", content_markdown="x"))
    await db_session.flush()

    plan = build_execution_plan(parse_query("note.about:entry"))
    results, entry_ids = await execute_entity_queries(db_session, plan.entity_nodes, limit=50)
    assert [r["title"] for r in results] == ["Baselining"]
    assert entry_ids == {str(entry.id)}
