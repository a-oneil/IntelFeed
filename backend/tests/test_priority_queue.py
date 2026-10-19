"""The Priority Queue endpoint: what the ranked reading queue is made of.

The queue is entries and story threads in one ordered list, so these tests are
mostly about the seam between them — where a thread row lands, which entries it
swallows on the way, and whether paging through the queue ever shows the same
story twice.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

from app.intelligence.signals import scale_score
from app.models.entry import Entry
from app.models.entry_state import UserEntryState
from app.models.story_thread import StoryThread, StoryThreadEntry

NOW = datetime.now(UTC)

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def surfaced(monkeypatch):
    """Signal engine surfacing on with a known threshold — the queue's premise."""
    from app.config import settings as env_settings

    monkeypatch.setattr(env_settings, "signal_engine_surface", True)

    async def fixed_threshold():
        return 1.5, True

    async def fixed_cutoffs(db=None):
        return IDENTITY_CUTOFFS

    monkeypatch.setattr("app.intelligence.signals.get_radar_threshold", fixed_threshold)
    monkeypatch.setattr("app.intelligence.signals.get_scale_cutoffs", fixed_cutoffs)


# Cutoffs at 1..10 make the 0–10 scale read back the raw sum between 1 and 10,
# so the queue's raw-unit ranking is visible in its scores.
IDENTITY_CUTOFFS = [float(i) for i in range(1, 11)]


async def make_entry(db_session, feed, *, title: str, score: float, published: datetime | None = None) -> Entry:
    """``score`` is the raw signal sum; the 0–10 score is derived the way scoring does."""
    entry = Entry(
        feed_id=feed.id,
        title=title,
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://example.test/{uuid.uuid4()}",
        summary=title,
        content_text="x" * 400,
        published_at=published or NOW,
        priority_raw=score,
        priority_score=scale_score(score, IDENTITY_CUTOFFS),
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


async def make_thread(db_session, *, title: str, members: list[Entry], source_count: int, echoes: int = 0):
    thread = StoryThread(
        slug=f"slug-{uuid.uuid4().hex[:10]}",
        title=title,
        status="open",
        entry_count=len(members),
        source_count=source_count,
        echo_count=echoes,
        first_seen=NOW - timedelta(days=1),
        last_seen=NOW,
    )
    db_session.add(thread)
    await db_session.flush()
    for i, entry in enumerate(members):
        db_session.add(
            StoryThreadEntry(
                thread_id=thread.id,
                entry_id=entry.id,
                role="echo" if i < echoes else "beat",
                added_at=NOW,
            )
        )
    await db_session.flush()
    return thread


async def mark_read(db_session, user, entry: Entry) -> None:
    db_session.add(UserEntryState(user_id=user.id, entry_id=entry.id, is_read=True))
    await db_session.flush()


@pytest_asyncio.fixture
async def subscribed_feed(db_session, test_user, test_feed):
    """test_feed, visible to test_user whether or not subscriptions are enabled."""
    from app.services.feed_visibility import subscriptions_enabled

    if await subscriptions_enabled(db_session):
        from app.models.feed import FeedSubscription

        db_session.add(FeedSubscription(feed_id=test_feed.id, user_id=test_user.id))
        await db_session.flush()
    return test_feed


def kinds(body: dict) -> list[str]:
    return [row["kind"] for row in body["items"]]


def titles(body: dict) -> list[str]:
    return [(row["thread"] or row["entry"])["title"] for row in body["items"]]


class TestQueueShape:
    async def test_entries_only_when_no_threads(self, client, auth_headers, db_session, subscribed_feed):
        await make_entry(db_session, subscribed_feed, title="Loud", score=9.0)
        await make_entry(db_session, subscribed_feed, title="Quiet", score=2.0)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue", headers=auth_headers)).json()

        assert kinds(body) == ["entry", "entry"]
        assert titles(body) == ["Loud", "Quiet"]
        assert body["radar_threshold"] == 1.5

    async def test_entries_below_the_threshold_stay_out(self, client, auth_headers, db_session, subscribed_feed):
        await make_entry(db_session, subscribed_feed, title="Surfaced", score=4.0)
        await make_entry(db_session, subscribed_feed, title="Noise", score=0.4)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue", headers=auth_headers)).json()

        assert titles(body) == ["Surfaced"]

    async def test_read_entries_excluded_unless_asked_for(
        self, client, auth_headers, db_session, test_user, subscribed_feed
    ):
        loud = await make_entry(db_session, subscribed_feed, title="Loud", score=9.0)
        await make_entry(db_session, subscribed_feed, title="Fresh", score=5.0)
        await mark_read(db_session, test_user, loud)
        await db_session.commit()

        assert titles((await client.get("/api/entries/priority-queue", headers=auth_headers)).json()) == ["Fresh"]

        body = (await client.get("/api/entries/priority-queue?unread_only=false", headers=auth_headers)).json()
        assert titles(body) == ["Loud", "Fresh"]


class TestThreadFolding:
    async def test_thread_row_replaces_its_members(self, client, auth_headers, db_session, subscribed_feed):
        members = [await make_entry(db_session, subscribed_feed, title=f"Beat {i}", score=5.0 - i) for i in range(3)]
        await make_thread(db_session, title="One story", members=members, source_count=3)
        await make_entry(db_session, subscribed_feed, title="Unrelated", score=4.5)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue", headers=auth_headers)).json()

        # The thread stands for its three articles; none of them appear alone.
        assert kinds(body) == ["thread", "entry"]
        assert titles(body) == ["One story", "Unrelated"]
        row = body["items"][0]
        assert sorted(row["absorbed_entry_ids"]) == sorted(str(m.id) for m in members)

    async def test_threads_and_entries_share_one_ranking(self, client, auth_headers, db_session, subscribed_feed):
        await make_entry(db_session, subscribed_feed, title="High", score=8.0)
        members = [await make_entry(db_session, subscribed_feed, title="Beat", score=6.0)]
        await make_thread(db_session, title="Story", members=members, source_count=3)
        await make_entry(db_session, subscribed_feed, title="Low", score=4.0)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue", headers=auth_headers)).json()

        # One list, highest score first — the story sits between the articles it
        # outscores and the one that outscores it, not in a block of its own.
        assert titles(body) == ["High", "Story", "Low"]
        assert [r["score"] for r in body["items"]] == pytest.approx([8.0, 6.0, 4.0])

    async def test_coverage_does_not_lift_a_story_above_a_higher_scored_article(
        self, client, auth_headers, db_session, subscribed_feed
    ):
        members = [await make_entry(db_session, subscribed_feed, title="Beat", score=5.0)]
        await make_thread(db_session, title="Everyone covered it", members=members, source_count=12)
        await make_entry(db_session, subscribed_feed, title="Lone article", score=7.0)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue", headers=auth_headers)).json()

        # Twelve outlets don't add to the row's score: it ranks on its 5.0 beat.
        assert titles(body) == ["Lone article", "Everyone covered it"]
        assert body["items"][1]["score"] == pytest.approx(5.0)

    async def test_fully_read_thread_does_not_appear(
        self, client, auth_headers, db_session, test_user, subscribed_feed
    ):
        members = [await make_entry(db_session, subscribed_feed, title="Beat", score=9.0)]
        await make_thread(db_session, title="Finished story", members=members, source_count=5)
        await mark_read(db_session, test_user, members[0])
        await make_entry(db_session, subscribed_feed, title="Still unread", score=2.0)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue", headers=auth_headers)).json()

        assert titles(body) == ["Still unread"]

    async def test_thread_ranks_on_its_best_unread_beat_not_an_echo(
        self, client, auth_headers, db_session, subscribed_feed
    ):
        echo = await make_entry(db_session, subscribed_feed, title="Echo", score=9.0)
        beat = await make_entry(db_session, subscribed_feed, title="Beat", score=3.0)
        await make_thread(db_session, title="Story", members=[echo, beat], source_count=1, echoes=1)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue", headers=auth_headers)).json()

        # The echo's 9.0 is a reprint, not a beat — the row ranks on the 3.0.
        assert body["items"][0]["score"] == pytest.approx(3.0)

    async def test_with_threads_false_returns_the_members(self, client, auth_headers, db_session, subscribed_feed):
        members = [await make_entry(db_session, subscribed_feed, title=f"Beat {i}", score=5.0 - i) for i in range(3)]
        await make_thread(db_session, title="One story", members=members, source_count=3)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue?with_threads=false", headers=auth_headers)).json()

        assert kinds(body) == ["entry"] * 3
        assert titles(body) == ["Beat 0", "Beat 1", "Beat 2"]

    async def test_excluded_thread_releases_its_members(self, client, auth_headers, db_session, subscribed_feed):
        members = [await make_entry(db_session, subscribed_feed, title="Beat", score=5.0)]
        thread = await make_thread(db_session, title="Dismissed", members=members, source_count=3)
        await db_session.commit()

        body = (
            await client.get(f"/api/entries/priority-queue?exclude_thread_ids={thread.id}", headers=auth_headers)
        ).json()

        assert titles(body) == ["Beat"]


class TestPaging:
    async def test_pages_never_repeat_a_thread_and_stay_ranked(self, client, auth_headers, db_session, subscribed_feed):
        for i in range(12):
            await make_entry(db_session, subscribed_feed, title=f"Article {i}", score=20.0 - i)
        for i in range(4):
            member = await make_entry(db_session, subscribed_feed, title=f"Thread beat {i}", score=15.0 - i * 3)
            await make_thread(db_session, title=f"Story {i}", members=[member], source_count=2)
        await db_session.commit()

        seen: list[tuple[str, str]] = []
        scores: list[float] = []
        cursor = None
        for _ in range(10):
            url = "/api/entries/priority-queue?limit=3" + (f"&cursor={cursor}" if cursor else "")
            body = (await client.get(url, headers=auth_headers)).json()
            for row in body["items"]:
                node = row["thread"] or row["entry"]
                seen.append((row["kind"], node["id"]))
                scores.append(row["score"])
            cursor = body["next_cursor"]
            if not cursor:
                break

        assert cursor is None, "queue never terminated"
        assert len(seen) == len(set(seen)), "a row was served on two pages"
        assert sum(1 for kind, _ in seen if kind == "thread") == 4
        assert sum(1 for kind, _ in seen if kind == "entry") == 12
        assert scores == sorted(scores, reverse=True), "queue is not globally ranked"

    async def test_threads_below_the_last_entry_are_flushed_on_the_final_page(
        self, client, auth_headers, db_session, subscribed_feed
    ):
        await make_entry(db_session, subscribed_feed, title="First", score=9.0)
        await make_entry(db_session, subscribed_feed, title="Second", score=8.0)
        member = await make_entry(db_session, subscribed_feed, title="Beat", score=1.5)
        await make_thread(db_session, title="Late story", members=[member], source_count=1)
        await db_session.commit()

        # The thread outranks nothing on this page, so it waits rather than
        # taking a position the next page would contradict.
        body = (await client.get("/api/entries/priority-queue?limit=1", headers=auth_headers)).json()
        assert titles(body) == ["First"]
        assert body["has_more"] is True

        # Last page of entries: nothing is left for it to outrank, so it lands.
        body = (
            await client.get(f"/api/entries/priority-queue?limit=1&cursor={body['next_cursor']}", headers=auth_headers)
        ).json()
        assert titles(body) == ["Second", "Late story"]
        assert body["has_more"] is False

    async def test_echo_only_unread_thread_does_not_enter_queue(
        self, client, auth_headers, db_session, test_user, subscribed_feed
    ):
        echo = await make_entry(db_session, subscribed_feed, title="Echo", score=9.0)
        beat = await make_entry(db_session, subscribed_feed, title="Beat", score=6.0)
        await make_thread(db_session, title="Echo-only left", members=[echo, beat], source_count=2, echoes=1)
        await mark_read(db_session, test_user, beat)
        await make_entry(db_session, subscribed_feed, title="Standalone", score=3.0)
        await db_session.commit()

        body = (await client.get("/api/entries/priority-queue", headers=auth_headers)).json()
        assert titles(body) == ["Standalone"]

        count_body = (await client.get("/api/entries/priority-unread-count", headers=auth_headers)).json()
        assert count_body["unread_count"] == 1

    async def test_priority_unread_count_folds_threads_and_dedups(
        self, client, auth_headers, db_session, subscribed_feed
    ):
        members = [await make_entry(db_session, subscribed_feed, title=f"Beat {i}", score=6.0 - i) for i in range(3)]
        await make_thread(db_session, title="Folded story", members=members, source_count=3)
        await make_entry(db_session, subscribed_feed, title="Standalone", score=4.0)
        await db_session.commit()

        count_body = (await client.get("/api/entries/priority-unread-count", headers=auth_headers)).json()
        # 1 folded story thread + 1 standalone entry = 2 rows in the queue.
        assert count_body["unread_count"] == 2

    async def test_rejects_a_malformed_cursor(self, client, auth_headers):
        resp = await client.get("/api/entries/priority-queue?cursor=not-base64", headers=auth_headers)
        assert resp.status_code == 400
