"""Same-feed URL dedup at ingest, and the merge that collapses stored copies.

CrowdStrike's RSS gives each post a fresh random ``?p=`` guid on every fetch
while its <link> stays put, so the guid check never matched and every fetch
stored another copy (5,031 rows for ~129 URLs in prod).
"""

import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.feed import Feed
from app.models.intel_report import IntelReport
from app.models.note import Note
from app.models.story_thread import StoryThread, StoryThreadEntry
from app.models.tag import EntryTag, Tag
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.services.dedup import item_key, normalize_url
from app.services.entry_merge import batch_by_keeper, merge_entries, plan_same_url_merges

# ── URL normalisation ────────────────────────────────────


def test_normalize_url_drops_tracking_and_fragment_only():
    assert (
        normalize_url("HTTP://WWW.Example.com:80/blog/post/?utm_source=rss&utm_medium=x&fbclid=1&gclid=2#comments")
        == "https://www.example.com/blog/post"
    )
    assert normalize_url("https://example.com/post?mc_cid=a&mc_eid=b") == "https://example.com/post"
    # Medium's per-feed tracking tag
    assert normalize_url("https://medium.com/p/abc?source=rss----123") == "https://medium.com/p/abc"


def test_normalize_url_keeps_content_identifying_params():
    # A WordPress ?p= link IS the post; it must never be dropped.
    assert normalize_url("https://www.crowdstrike.com/?p=612853") == "https://www.crowdstrike.com/?p=612853"
    assert normalize_url("https://www.crowdstrike.com/?p=612853") != normalize_url("https://www.crowdstrike.com/?p=1")
    assert normalize_url("https://youtube.com/watch?v=abc&utm_source=x") == "https://youtube.com/watch?v=abc"
    assert normalize_url("https://x.com/a?b=2&a=1") == normalize_url("https://x.com/a?a=1&b=2")
    assert normalize_url("https://x.com/a?source=newsletter") == "https://x.com/a?source=newsletter"


def test_normalize_url_rejects_non_web():
    assert normalize_url(None) is None
    assert normalize_url("") is None
    assert normalize_url("/relative/path") is None
    assert normalize_url("javascript:alert(1)") is None


def test_item_key_separates_podcast_episodes_sharing_a_url():
    url = "https://thecyberwire.com/podcasts/career-notes/98/notes"
    a = item_key(url, "Jon DiMaggio: Two roads diverged.", "https://cdn.example/CYBW1.mp3?updated=1")
    b = item_key(url, "Amanda Fennell: There's a cyber warrior", "https://cdn.example/CYBW2.mp3?updated=1")
    rerun = item_key(url, "Jon DiMaggio: Two roads diverged.", "https://cdn.example/CYBW1.mp3?updated=2")
    assert a != b
    assert a == rerun


# ── Ingest ───────────────────────────────────────────────

POST_URL = "https://www.crowdstrike.com/en-us/blog/why-organizations-secure-ai-agents/"


def _rss(*items: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Blog</title>'
        "<link>https://www.crowdstrike.com/en-us/blog/</link>" + "".join(items) + "</channel></rss>"
    )


def _item(guid: str, title: str = "Why Organizations Secure AI Agents", link: str = POST_URL, body: str = "") -> str:
    return (
        f"<item><title>{title}</title><link>{link}</link>"
        f"<description><![CDATA[{body}]]></description>"
        "<pubDate>Thu, 23 Oct 2026 00:00:00 -0500</pubDate>"
        f'<guid isPermaLink="false">{guid}</guid></item>'
    )


@contextlib.asynccontextmanager
async def _session_on(db: AsyncSession):
    yield db


async def _fetch(db_session: AsyncSession, feed: Feed, body: str, monkeypatch) -> None:
    from app.workers import feed_tasks

    response = MagicMock()
    response.status_code = 200
    response.text = body
    response.headers = {"content-type": "application/rss+xml"}
    client = AsyncMock()
    client.get.return_value = response
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    monkeypatch.setattr(feed_tasks, "_get_worker_session", lambda: _session_on(db_session))
    monkeypatch.setattr(db_session, "commit", db_session.flush)
    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
        patch("app.workers.feed_tasks._extract_full_text", new_callable=AsyncMock, return_value=(None, None)),
        patch("app.workers.feed_tasks._fetch_og_image", new_callable=AsyncMock, return_value=None),
        patch("app.services.meilisearch_client.index_entry") as index_entry,
        patch("app.workers.feed_tasks.dispatch_entry_pipeline"),
        patch("app.workers.automation_tasks.run_entry_automations"),
        patch("app.api.events.broadcast_event"),
    ):
        await feed_tasks._fetch_feed(str(feed.id))
    return index_entry


async def _rows(db: AsyncSession, feed: Feed) -> list[Entry]:
    db.expunge_all()
    return list((await db.execute(select(Entry).where(Entry.feed_id == feed.id))).scalars().all())


@pytest.fixture
async def rss_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="CrowdStrike", url=f"https://{uuid.uuid4().hex}.example.com/feed/", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest.mark.asyncio
async def test_guid_that_changes_every_fetch_inserts_once(db_session, rss_feed, monkeypatch):
    # The teaser differs between fetches, so the cross-feed content hash can't
    # catch the copy either; only the link identifies it.
    await _fetch(
        db_session, rss_feed, _rss(_item("https://www.crowdstrike.com/?p=612853", body="Teaser one")), monkeypatch
    )
    await _fetch(
        db_session, rss_feed, _rss(_item("https://www.crowdstrike.com/?p=188523", body="Teaser two")), monkeypatch
    )
    await _fetch(
        db_session,
        rss_feed,
        _rss(_item("https://www.crowdstrike.com/?p=762655", link=POST_URL + "?utm_source=rss#top", body="Teaser 3")),
        monkeypatch,
    )

    rows = await _rows(db_session, rss_feed)
    assert len(rows) == 1
    assert rows[0].guid == "https://www.crowdstrike.com/?p=612853"
    # A stub never overwrites the stored row (it may hold extracted full text).
    assert rows[0].content_text == "Teaser one"


@pytest.mark.asyncio
async def test_changed_content_updates_the_existing_row(db_session, rss_feed, monkeypatch):
    first = "Original paragraph. " * 40
    second = "Revised paragraph with an added IOC section. " * 20
    await _fetch(db_session, rss_feed, _rss(_item("g-1", body=first)), monkeypatch)
    index_entry = await _fetch(db_session, rss_feed, _rss(_item("g-2", body=second)), monkeypatch)

    rows = await _rows(db_session, rss_feed)
    assert len(rows) == 1
    assert "Revised paragraph" in rows[0].content_text
    assert rows[0].guid == "g-1"
    index_entry.assert_called_once()
    assert index_entry.call_args.kwargs["entry_id"] == rows[0].id


@pytest.mark.asyncio
async def test_distinct_items_sharing_a_link_still_insert(db_session, rss_feed, monkeypatch):
    shared = "https://thecyberwire.com/podcasts/career-notes/98/notes"
    await _fetch(
        db_session,
        rss_feed,
        _rss(
            _item("a", title="Jon DiMaggio: Two roads diverged.", link=shared, body="one"),
            _item("b", title="Amanda Fennell: a cyber warrior", link=shared, body="two"),
        ),
        monkeypatch,
    )
    await _fetch(db_session, rss_feed, _rss(_item("c", title="Something else", link=shared, body="x")), monkeypatch)
    assert len(await _rows(db_session, rss_feed)) == 3


# ── Merge ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_merge_moves_references_onto_the_earliest_copy(db_session: AsyncSession, rss_feed, test_user):
    t0 = datetime(2026, 3, 1, tzinfo=UTC)
    keeper, dupe_a, dupe_b = (
        Entry(
            feed_id=rss_feed.id,
            guid=f"https://www.crowdstrike.com/?p={n}",
            url=POST_URL + suffix,
            title="Why Organizations Secure AI Agents ",
            created_at=t0 + timedelta(hours=i),
        )
        for i, (n, suffix) in enumerate([(1, ""), (2, "?utm_source=rss"), (3, "#x")])
    )
    other = Entry(feed_id=rss_feed.id, guid="other", url=POST_URL + "other/", title="Other", created_at=t0)
    db_session.add_all([keeper, dupe_a, dupe_b, other])
    await db_session.flush()

    tag_shared = Tag(name=f"t-{uuid.uuid4().hex[:8]}", is_global=True)
    tag_dupe = Tag(name=f"t-{uuid.uuid4().hex[:8]}", is_global=True)
    actor = ThreatActor(name=f"Actor {uuid.uuid4().hex[:8]}", article_count=3)
    thread = StoryThread(slug=f"s-{uuid.uuid4().hex[:8]}", title="Story", entry_count=1)
    db_session.add_all([tag_shared, tag_dupe, actor, thread])
    await db_session.flush()
    db_session.add_all(
        [
            EntryTag(entry_id=keeper.id, tag_id=tag_shared.id),
            EntryTag(entry_id=dupe_a.id, tag_id=tag_shared.id),
            EntryTag(entry_id=dupe_b.id, tag_id=tag_dupe.id),
            EntryThreatActor(entry_id=keeper.id, threat_actor_id=actor.id),
            EntryThreatActor(entry_id=dupe_a.id, threat_actor_id=actor.id),
            EntryThreatActor(entry_id=dupe_b.id, threat_actor_id=actor.id),
            Note(entry_id=dupe_a.id, title="note on a copy", created_by=test_user.id),
            UserEntryState(user_id=test_user.id, entry_id=keeper.id, is_read=False),
            UserEntryState(user_id=test_user.id, entry_id=dupe_a.id, is_read=True),
            UserEntryState(user_id=test_user.id, entry_id=dupe_b.id, is_starred=True),
            StoryThreadEntry(thread_id=thread.id, entry_id=dupe_b.id),
            IntelReport(
                title="r",
                template_type="custom",
                entry_ids=[dupe_a.id, keeper.id, dupe_b.id, other.id],
                created_by=test_user.id,
            ),
        ]
    )
    await db_session.flush()

    plan = await plan_same_url_merges(db_session, rss_feed.id)
    assert plan.mapping == {dupe_a.id: keeper.id, dupe_b.id: keeper.id}

    stats = await merge_entries(db_session, plan.mapping)
    assert stats["entries.deleted"] == 2
    db_session.expunge_all()

    remaining = {e.id for e in await _rows(db_session, rss_feed)}
    assert remaining == {keeper.id, other.id}

    tags = (await db_session.execute(select(EntryTag.tag_id).where(EntryTag.entry_id == keeper.id))).scalars().all()
    assert sorted(tags) == sorted([tag_shared.id, tag_dupe.id])

    links = await db_session.scalar(select(func.count()).where(EntryThreatActor.threat_actor_id == actor.id))
    assert links == 1
    # two colliding links dropped, each had bumped the count once
    assert await db_session.scalar(select(ThreatActor.article_count).where(ThreatActor.id == actor.id)) == 1

    note = (await db_session.execute(select(Note).where(Note.title == "note on a copy"))).scalar_one()
    assert note.entry_id == keeper.id

    state = (
        (await db_session.execute(select(UserEntryState).where(UserEntryState.user_id == test_user.id))).scalars().all()
    )
    assert len(state) == 1
    assert state[0].entry_id == keeper.id and state[0].is_read and state[0].is_starred

    member = (
        await db_session.execute(select(StoryThreadEntry).where(StoryThreadEntry.thread_id == thread.id))
    ).scalar_one()
    assert member.entry_id == keeper.id

    report = (await db_session.execute(select(IntelReport).where(IntelReport.title == "r"))).scalar_one()
    assert report.entry_ids == [keeper.id, other.id]


@pytest.mark.asyncio
async def test_plan_keeps_podcast_episodes_that_share_a_url(db_session: AsyncSession, rss_feed):
    from app.models.entry_media import EntryMedia

    shared = "https://thecyberwire.com/podcasts/career-notes/98/notes"
    t0 = datetime(2026, 3, 1, tzinfo=UTC)
    rows = [
        ("Jon DiMaggio: Two roads diverged.", "CYBW1.mp3?updated=1"),
        ("Amanda Fennell: a cyber warrior", "CYBW2.mp3?updated=1"),
        ("Jon DiMaggio: Two roads diverged.", "CYBW1.mp3?updated=2"),  # re-air: same title + audio
        ("Jon DiMaggio: Two roads diverged.", "CYBW9.mp3"),  # same title, different audio
    ]
    entries = []
    for i, (title, audio) in enumerate(rows):
        e = Entry(feed_id=rss_feed.id, guid=f"ep-{i}", url=shared, title=title, created_at=t0 + timedelta(days=i))
        db_session.add(e)
        await db_session.flush()
        db_session.add(EntryMedia(entry_id=e.id, media_type="audio", url=f"https://cdn.example/{audio}"))
        entries.append(e)
    await db_session.flush()

    plan = await plan_same_url_merges(db_session, rss_feed.id, ignore_title=True)
    assert plan.mapping == {entries[2].id: entries[0].id}
    assert plan.rows_sharing_url_not_merged == 4


def test_batch_by_keeper_never_splits_a_keeper():
    mapping = {f"a{i}": "A" for i in range(3)} | {f"b{i}": "B" for i in range(4)} | {"c0": "C"}
    batches = list(batch_by_keeper(mapping, 4))
    assert [sorted(set(b.values())) for b in batches] == [["A"], ["B"], ["C"]]
    assert sum(len(b) for b in batches) == len(mapping)
