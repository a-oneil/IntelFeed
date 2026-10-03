"""The shared intake query path: a query-language string in, entry ids out.

Used by the campaign saved-search sweep and by campaign ``query`` sources, and
it has to agree with ``/api/search`` — a standing source that silently matches
nothing looks exactly like a source whose subject went quiet.

The regression these pin: the earlier version planned the query and went
straight to Meilisearch, so an entity filter (``threat_actor:``, ``malware:``, ``cve:``)
contributed no ids and the plan was then refused by its own guard. The most
natural intake query there is — "every article about this actor" — synced zero.
"""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.feed import Feed
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.search.entry_query import search_entry_ids


@pytest_asyncio.fixture
async def feed(db_session: AsyncSession) -> Feed:
    f = Feed(title="Query Feed", url="https://query.example.com/feed", feed_type="rss")
    db_session.add(f)
    await db_session.flush()
    return f


async def _entry(db_session: AsyncSession, feed: Feed, guid: str) -> Entry:
    e = Entry(feed_id=feed.id, title=f"Article {guid}", guid=guid, published_at=datetime(2026, 3, 1, tzinfo=UTC))
    db_session.add(e)
    await db_session.flush()
    return e


async def test_an_entity_filter_resolves_without_the_index(db_session: AsyncSession, feed: Feed):
    """`threat_actor:"X"` is answered from the junction table, not Meilisearch — so it
    works even with the index unavailable, and it is not refused for having no
    text to search."""
    actor = ThreatActor(name="Query Actor", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    linked = [await _entry(db_session, feed, f"ent-{i}") for i in range(3)]
    for e in linked:
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    await _entry(db_session, feed, "unlinked")
    await db_session.flush()

    with patch("app.search.meili_builder.execute_entry_search") as meili:
        total, ids = await search_entry_ids('threat_actor:"Query Actor"', db_session)

    meili.assert_not_called()
    assert total == 3
    assert set(ids) == {str(e.id) for e in linked}


async def test_filters_of_one_type_narrow_the_entity_not_the_article(db_session: AsyncSession, feed: Feed):
    """Conditions in one entity group AND against the *entity* row.

    So `malware:"A" AND malware.type:ransomware` means "a family called A that
    is ransomware" — not "an article about A that also mentions ransomware".
    Worth pinning because the reading is easy to get backwards, and a standing
    source built on the wrong reading claims the wrong set forever.
    """
    ransom = MalwareFamily(name="Narrow Family", aliases=[], malware_type="ransomware")
    stealer = MalwareFamily(name="Other Family", aliases=[], malware_type="stealer")
    db_session.add_all([ransom, stealer])
    await db_session.flush()

    wanted = await _entry(db_session, feed, "narrow-hit")
    other = await _entry(db_session, feed, "narrow-miss")
    db_session.add_all(
        [
            EntryMalware(entry_id=wanted.id, malware_family_id=ransom.id),
            EntryMalware(entry_id=other.id, malware_family_id=stealer.id),
        ]
    )
    await db_session.flush()

    total, ids = await search_entry_ids('malware:"Narrow Family" AND malware.type:ransomware', db_session)
    assert (total, ids) == (1, [str(wanted.id)])

    # And two names in one group describe one family, which cannot have both.
    assert await search_entry_ids('malware:"Narrow Family" AND malware:"Other Family"', db_session) == (0, [])


async def test_filters_of_two_types_union_the_way_the_search_endpoint_does(db_session: AsyncSession, feed: Feed):
    """Pinned as-is, not as it reads: `execute_entity_queries` unions across
    entity-type groups, so `threat_actor:X AND malware:Y` answers with either.
    That is a quirk of /api/search, not of intake — the point of this helper is
    that a campaign query and a typed search return the same set, so it is
    mirrored rather than quietly corrected here.
    """
    actor = ThreatActor(name="Union Actor", aliases=[], country="Unknown")
    family = MalwareFamily(name="Union Malware", aliases=[])
    db_session.add_all([actor, family])
    await db_session.flush()

    actor_only = await _entry(db_session, feed, "union-actor")
    malware_only = await _entry(db_session, feed, "union-malware")
    db_session.add_all(
        [
            EntryThreatActor(entry_id=actor_only.id, threat_actor_id=actor.id),
            EntryMalware(entry_id=malware_only.id, malware_family_id=family.id),
        ]
    )
    await db_session.flush()

    total, ids = await search_entry_ids('threat_actor:"Union Actor" AND malware:"Union Malware"', db_session)
    assert total == 2
    assert set(ids) == {str(actor_only.id), str(malware_only.id)}


async def test_an_entity_that_matches_nothing_is_empty_not_unconstrained(db_session: AsyncSession, feed: Feed):
    """The dangerous failure: dropping the constraint and taking everything."""
    await _entry(db_session, feed, "bystander")
    await db_session.flush()

    assert await search_entry_ids('threat_actor:"No Such Actor Anywhere"', db_session) == (0, [])


async def test_an_entity_filter_with_a_text_term_still_asks_the_index(db_session: AsyncSession, feed: Feed):
    """The text half is Meilisearch's job; the entity half narrows it."""
    actor = ThreatActor(name="Mixed Actor", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    linked = await _entry(db_session, feed, "mixed")
    db_session.add(EntryThreatActor(entry_id=linked.id, threat_actor_id=actor.id))
    await db_session.flush()

    fake = {"hits": [{"id": str(linked.id)}], "estimatedTotalHits": 1}
    with patch("app.search.meili_builder.execute_entry_search", return_value=fake) as meili:
        total, ids = await search_entry_ids('threat_actor:"Mixed Actor" AND ransomware', db_session)

    assert (total, ids) == (1, [str(linked.id)])
    constraint = meili.call_args.args[1]
    assert constraint == [str(linked.id)]


async def test_a_constraint_too_large_for_the_index_is_the_answer_itself(db_session: AsyncSession, feed: Feed):
    """``execute_entry_search`` keeps the first 500 ids of a constraint and drops
    the rest, so past that the index cannot be asked at all. Answering from the
    constraint is right; handing it over and losing the tail is not."""
    actor = ThreatActor(name="Prolific Actor", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    linked = [await _entry(db_session, feed, f"big-{i}") for i in range(3)]
    for e in linked:
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    await db_session.flush()

    with (
        patch("app.search.entry_query.MEILI_ID_FILTER_CAP", 1),
        patch("app.search.meili_builder.execute_entry_search") as meili,
    ):
        total, ids = await search_entry_ids('threat_actor:"Prolific Actor" AND ransomware', db_session)

    meili.assert_not_called()
    assert total == 3
    assert set(ids) == {str(e.id) for e in linked}


async def test_a_query_that_does_not_parse_is_empty_rather_than_raising(db_session: AsyncSession):
    """A standing source must not take its campaign down with it."""
    assert await search_entry_ids("ransomware AND", db_session) == (0, [])


async def test_an_empty_query_claims_nothing(db_session: AsyncSession, feed: Feed):
    """ "Everything" is not a source. An empty string used to be a plan with
    entry intent and no filter, which the index would answer with the whole
    corpus."""
    await _entry(db_session, feed, "everything")
    await db_session.flush()

    with patch("app.search.meili_builder.execute_entry_search", return_value={"hits": []}):
        total, _ = await search_entry_ids("", db_session)
    assert total == 0


async def test_the_limit_bounds_what_one_source_can_claim(db_session: AsyncSession, feed: Feed):
    actor = ThreatActor(name="Capped Actor", aliases=[], country="Unknown")
    db_session.add(actor)
    await db_session.flush()
    for i in range(4):
        e = await _entry(db_session, feed, f"cap-{i}")
        db_session.add(EntryThreatActor(entry_id=e.id, threat_actor_id=actor.id))
    await db_session.flush()

    total, ids = await search_entry_ids('threat_actor:"Capped Actor"', db_session, limit=2)
    assert (total, len(ids)) == (2, 2)
