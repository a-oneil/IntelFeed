"""Story threads: what gets folded into one story, and what deliberately does not.

The thresholds here are the ones tuned against the live corpus (see
app/intelligence/story_threads.py) — every test that hardcodes a cosine builds
its vectors to sit a known distance apart rather than asserting on a magic
number, so a threshold change fails the test that owns it rather than all of them.
"""

import math
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import text

from app.intelligence.story_threads import (
    SAME_SOURCE_LIMIT,
    _candidate_entries,
    ambient_entities,
    assign_entries,
    merge_overlapping,
    prune_threads,
    refresh_thread,
    similar_entries,
    slugify,
    thread_title,
)
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.vector_types import to_literal
from app.services import embeddings, thread_narrative
from app.services.embeddings import build_text
from app.services.thread_narrative import _ai_beats, clean_body, ensure_spine, heuristic_beats

NOW = datetime.now(UTC)
DIM = 768


def unit(*, similarity: float, axis: int = 1) -> list[float]:
    """A 768-d unit vector whose cosine to e1 is exactly ``similarity``.

    Each vector leans into its own axis, so two of them made with similarities
    s1 and s2 (on different axes) sit at s1*s2 to each other. That makes every
    pairwise distance in these tests something the test states outright rather
    than something it stumbles into — which matters, because the whole feature
    is a set of thresholds.
    """
    vec = [0.0] * DIM
    vec[0] = similarity
    vec[axis] = math.sqrt(max(0.0, 1.0 - similarity * similarity))
    return vec


@pytest_asyncio.fixture
async def feeds(db_session) -> list[Feed]:
    rows = [Feed(title=f"Outlet {i}", url=f"https://outlet{i}.example/feed", feed_type="rss") for i in range(4)]
    db_session.addAll = None  # guard against accidental bulk helper use
    for row in rows:
        db_session.add(row)
    await db_session.flush()
    return rows


async def make_entry(
    db_session,
    feed: Feed,
    *,
    title: str,
    similarity_to_base: float = 1.0,
    axis: int = 1,
    published: datetime | None = None,
    body: str = "x" * 800,
    host: str | None = None,
) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title=title,
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://{host or f'outlet-{uuid.uuid4().hex[:6]}.example'}/{uuid.uuid4()}",
        content_text=body,
        summary=title,
        published_at=published or NOW,
    )
    db_session.add(entry)
    await db_session.flush()
    await db_session.execute(
        text(
            "INSERT INTO entry_embeddings (entry_id, embedding, model, content_hash) "
            "VALUES (:e, (:v)::halfvec, 'test', :h)"
        ),
        {
            "e": entry.id,
            "v": to_literal(unit(similarity=similarity_to_base, axis=axis)),
            "h": uuid.uuid4().hex,
        },
    )
    return entry


async def thread_rows(db_session) -> list[dict]:
    rows = await db_session.execute(
        text("SELECT id, title, entry_count, source_count, echo_count FROM story_threads ORDER BY entry_count DESC")
    )
    return [dict(r) for r in rows.mappings().all()]


class TestSeeding:
    async def test_three_articles_from_three_outlets_become_a_thread(self, db_session, feeds):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )

        stats = await assign_entries(db_session, limit=50)

        assert stats["seeded"] == 1
        rows = await thread_rows(db_session)
        assert len(rows) == 1
        assert rows[0]["entry_count"] == 3
        assert rows[0]["source_count"] == 3

    async def test_one_outlet_publishing_three_times_is_not_a_thread(self, db_session, feeds):
        """A publisher's own series clears every similarity bar there is."""
        for i in range(4):
            await make_entry(
                db_session,
                feeds[0],
                title=f"Advisory {i}: package update",
                similarity_to_base=1.0 if i == 0 else 0.95,
                axis=i + 1,
                host="advisories.example",
            )

        stats = await assign_entries(db_session, limit=50)

        assert stats["seeded"] == 0
        assert await thread_rows(db_session) == []

    async def test_unrelated_articles_do_not_thread(self, db_session, feeds):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Unrelated story {i}",
                similarity_to_base=1.0 if i == 0 else 0.5,  # nowhere near the bar
                axis=i + 1,
                host=f"outlet{i}.example",
            )

        stats = await assign_entries(db_session, limit=50)

        assert stats["seeded"] == 0

    async def test_bulletin_rows_are_never_threaded(self, db_session, feeds):
        """Below the body-length floor an entry is a database row, not an article."""
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"kubernetes: CVSS (Max): 9.{i}",
                similarity_to_base=1.0 if i == 0 else 0.99,
                axis=i + 1,
                body="CVSS (Max): 9.8",
                host=f"outlet{i}.example",
            )

        stats = await assign_entries(db_session, limit=50)

        assert stats["considered"] == 0
        assert stats["seeded"] == 0


class TestJoiningAndEchoes:
    async def test_later_article_joins_the_story_it_continues(self, db_session, feeds):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)

        # A follow-up two days later: close to the story, not a copy of it, and
        # sharing the actor — which is what earns it the lower join bar.
        actor = ThreatActor(name="Qilin")
        db_session.add(actor)
        await db_session.flush()
        for entry_id in (await db_session.execute(text("SELECT entry_id FROM story_thread_entries"))).scalars().all():
            db_session.add(EntryThreatActor(entry_id=entry_id, threat_actor_id=actor.id))
        follow_up = await make_entry(
            db_session,
            feeds[3],
            title="Qilin hospital attack: NHS confirms data theft",
            similarity_to_base=0.87,
            axis=6,
            published=NOW + timedelta(days=2),
            host="outlet3.example",
        )
        db_session.add(EntryThreatActor(entry_id=follow_up.id, threat_actor_id=actor.id))
        await db_session.flush()
        await refresh_thread(db_session, (await db_session.execute(text("SELECT id FROM story_threads"))).scalar_one())
        stats = await assign_entries(db_session, limit=50)

        assert stats["joined"] == 1
        rows = await thread_rows(db_session)
        assert rows[0]["entry_count"] == 4

    async def test_near_identical_re_report_is_folded_as_an_echo(self, db_session, feeds):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)

        await make_entry(
            db_session,
            feeds[3],
            title="Qilin hits hospital chain (syndicated)",
            similarity_to_base=0.995,
            axis=7,
            published=NOW + timedelta(hours=6),
            host="aggregator.example",
        )
        stats = await assign_entries(db_session, limit=50)

        assert stats["echoed"] == 1
        rows = await thread_rows(db_session)
        assert rows[0]["echo_count"] == 1
        role = await db_session.execute(
            text("SELECT role, duplicate_of_entry_id FROM story_thread_entries WHERE role = 'echo'")
        )
        echo = role.mappings().one()
        assert echo["duplicate_of_entry_id"] is not None

    async def test_an_article_three_weeks_later_starts_its_own_story(self, db_session, feeds):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                published=NOW - timedelta(days=18),
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)

        await make_entry(
            db_session,
            feeds[3],
            title="Qilin returns to healthcare",
            similarity_to_base=0.97,
            axis=7,
            published=NOW,
            host="outlet3.example",
        )
        stats = await assign_entries(db_session, limit=50)

        assert stats["joined"] == 0


class TestMerging:
    async def test_two_threads_about_one_story_merge(self, db_session, feeds):
        # Two seeds far enough apart in the fanout to cluster separately, but
        # whose centroids land within the merge bar once both exist.
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Magento zero-day {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)
        await db_session.execute(
            text("UPDATE story_threads SET centroid = (:v)::halfvec"),
            {"v": to_literal(unit(similarity=1.0))},
        )
        await db_session.execute(
            text(
                "INSERT INTO story_threads (id, slug, title, status, centroid, entry_count, source_count, "
                "echo_count, first_seen, last_seen) "
                "VALUES (:id, 'other', 'StyleSmuggler Magento zero-day', 'open', (:v)::halfvec, 2, 2, 0, "
                ":first, :last)"
            ),
            {
                "id": uuid.uuid4(),
                "v": to_literal(unit(similarity=0.99, axis=5)),
                "first": NOW,
                "last": NOW,
            },
        )

        merged = await merge_overlapping(db_session)

        assert merged == 1
        rows = await thread_rows(db_session)
        assert len(rows) == 1
        origins = await db_session.execute(text("SELECT COUNT(*) FROM story_thread_entries WHERE role = 'origin'"))
        assert origins.scalar() == 1


class TestAmbientEntities:
    async def test_an_entity_on_most_of_the_window_is_not_identity(self, db_session, feeds):
        actor = ThreatActor(name="Linux")
        db_session.add(actor)
        await db_session.flush()
        for i in range(10):
            entry = await make_entry(db_session, feeds[i % 3], title=f"Story {i}", similarity_to_base=0.9, axis=i + 1)
            db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id))
        await db_session.flush()

        # min_window lowered for the fixture: the rule itself is "more than 2% of
        # the window", and the production floor (200 articles) exists so a young
        # install doesn't strip every entity it has.
        ambient = await ambient_entities(db_session, NOW - timedelta(days=21), min_window=5)
        assert ("threat_actor", str(actor.id)) in ambient

        assert await ambient_entities(db_session, NOW - timedelta(days=21)) == set()


class TestSpine:
    def test_beats_group_by_day_with_a_first_and_a_peak(self):
        day1 = NOW - timedelta(days=2)
        day2 = NOW - timedelta(days=1)
        members = [
            {
                "entry_id": uuid.uuid4(),
                "role": "origin",
                "title": "Broke",
                "summary": None,
                "published_at": day1,
                "priority_raw": 1.0,
            },
            {
                "entry_id": uuid.uuid4(),
                "role": "beat",
                "title": "Wave A",
                "summary": None,
                "published_at": day2,
                "priority_raw": 2.0,
            },
            {
                "entry_id": uuid.uuid4(),
                "role": "beat",
                "title": "Wave B",
                "summary": None,
                "published_at": day2,
                "priority_raw": 5.0,
            },
            {
                "entry_id": uuid.uuid4(),
                "role": "echo",
                "title": "Re-report",
                "summary": None,
                "published_at": day2,
                "priority_raw": 0.0,
            },
        ]

        beats = heuristic_beats(members)

        assert [b["kind"] for b in beats] == ["first_disclosure", "peak"]
        assert beats[1]["headline"] == "Wave B"  # highest-scoring article of the day leads, not the first listed
        assert beats[1]["collapsed_count"] == 1  # the echo is counted, not listed

    def test_markup_and_tracking_blobs_never_reach_a_beat_body(self):
        assert clean_body("<p>Volexity <b>detected</b> a campaign.</p>") == "Volexity detected a campaign."
        assert clean_body("Read more: https://news.google.com/rss/" + "A" * 300) is None
        assert clean_body("") is None

    def test_written_beats_map_back_onto_real_articles(self):
        """The model answers with article indexes; nothing else may be trusted."""
        members = [
            {
                "entry_id": uuid.uuid4(),
                "role": "beat",
                "title": f"Article {i}",
                "summary": None,
                "published_at": NOW - timedelta(days=3 - i),
                "priority_raw": 0.0,
            }
            for i in range(3)
        ]
        payload = {
            "beats": [
                {"kind": "first_disclosure", "headline": "It broke", "body": "b", "entry_indexes": [1]},
                {"kind": "not_a_kind", "headline": "Then this", "entry_indexes": [2, 3]},
                {"kind": "peak", "headline": "", "entry_indexes": [2]},  # no headline: dropped
                {"kind": "update", "headline": "Out of range", "entry_indexes": [99]},
            ]
        }

        beats = _ai_beats(payload, members)

        assert [b["headline"] for b in beats] == ["It broke", "Then this", "Out of range"]
        assert beats[0]["lead_entry_id"] == members[0]["entry_id"]
        assert beats[1]["kind"] == "update"  # unknown kinds fall back rather than reaching the UI
        assert beats[1]["entry_ids"] == [str(members[1]["entry_id"]), str(members[2]["entry_id"])]
        assert beats[2]["entry_ids"] == []  # an index the prompt never offered cites nothing
        assert all(b["is_ai"] for b in beats)

    async def test_a_thread_gets_a_spine_without_any_ai(self, db_session, feeds):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                published=NOW - timedelta(days=i),
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)
        thread_id = (await db_session.execute(text("SELECT id FROM story_threads"))).scalar_one()

        result = await ensure_spine(db_session, thread_id, allow_ai=False)

        assert result["status"] == "heuristic"
        beats = await db_session.execute(
            text("SELECT kind, is_ai FROM story_thread_beats WHERE thread_id = :t ORDER BY position"),
            {"t": thread_id},
        )
        rows = beats.mappings().all()
        assert rows
        assert rows[0]["kind"] == "first_disclosure"
        assert all(r["is_ai"] is False for r in rows)


class TestSimilarEntries:
    async def test_nearest_neighbours_come_back_in_order(self, db_session, feeds):
        anchor = await make_entry(db_session, feeds[0], title="Anchor", similarity_to_base=1.0)
        near = await make_entry(db_session, feeds[1], title="Near", similarity_to_base=0.95, axis=2)
        # Both clear SIMILAR_FLOOR; anything under it is dropped, which is what
        # TestSimilarEntriesGuards covers.
        far = await make_entry(db_session, feeds[2], title="Far", similarity_to_base=0.8, axis=3)

        rows = await similar_entries(db_session, anchor.id, limit=5)

        assert [r["entry_id"] for r in rows] == [near.id, far.id]
        assert rows[0]["similarity"] > rows[1]["similarity"]
        assert anchor.id not in [r["entry_id"] for r in rows]


class TestTitles:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (
                "BlueMoon Exploit Kit Chains Recent Chrome, Windows Zero-Days - SecurityWeek",
                "BlueMoon Exploit Kit Chains Recent Chrome, Windows Zero-Days",
            ),
            ("Qilin hits hospitals | The Record", "Qilin hits hospitals | The Record"),  # too short to trim
            ("Short - X", "Short - X"),
            ("", "Untitled story"),
        ],
    )
    def test_outlet_suffix_comes_off_the_story_name(self, raw, expected):
        assert thread_title(raw) == expected


class TestSlugs:
    @pytest.mark.parametrize(
        ("title", "expected"),
        [
            ("Shai-Hulud npm worm", "shai-hulud-npm-worm"),
            ("  CVE-2026-1234: RCE!  ", "cve-2026-1234-rce"),
            ("", "thread"),
        ],
    )
    def test_slugify(self, title, expected):
        assert slugify(title) == expected


class TestThreadsApi:
    async def test_list_and_detail(self, client, db_session, feeds, auth_headers):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)
        thread_id = (await db_session.execute(text("SELECT id FROM story_threads"))).scalar_one()
        await ensure_spine(db_session, thread_id, allow_ai=False)
        await db_session.commit()

        listing = await client.get("/api/threads", headers=auth_headers)
        assert listing.status_code == 200
        payload = listing.json()
        assert payload["total"] == 1
        row = payload["threads"][0]
        assert row["entry_count"] == 3
        assert row["source_count"] == 3
        assert len(row["entry_ids"]) == 3

        detail = await client.get(f"/api/threads/{row['slug']}", headers=auth_headers)
        assert detail.status_code == 200
        body = detail.json()
        assert body["beats"]
        assert len(body["members"]) == 3
        assert body["thread_yield"]["echoes_folded"] == 0
        assert {m["role"] for m in body["members"]} == {"origin", "beat"}

    async def test_titles_can_be_searched_for_a_picker(self, client, db_session, feeds, auth_headers):
        """A picker needs one *named* story, not the recent ones — following one
        onto a campaign starts from its title."""
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)
        await db_session.commit()

        # No q is the unfiltered listing it has always been.
        unfiltered = await client.get("/api/threads", headers=auth_headers)
        assert unfiltered.json()["total"] == 1
        title = unfiltered.json()["threads"][0]["title"]

        word = title.split()[0]
        hit = await client.get("/api/threads", params={"q": word.lower()}, headers=auth_headers)
        assert hit.status_code == 200
        assert hit.json()["total"] == 1

        miss = await client.get("/api/threads", params={"q": "nothing like this"}, headers=auth_headers)
        assert miss.json()["threads"] == []

    async def test_unknown_slug_is_a_404(self, client, auth_headers):
        resp = await client.get("/api/threads/no-such-story", headers=auth_headers)
        assert resp.status_code == 404

    async def test_a_thread_that_no_longer_exists_is_a_404_not_a_500(self, client, auth_headers):
        """Threads are merged and pruned, so a stale tab addressing one is routine."""
        ghost = uuid.uuid4()

        assert (await client.post(f"/api/threads/{ghost}/open", headers=auth_headers)).status_code == 404

    async def test_detail_names_the_entry_that_carries_the_score(self, client, db_session, feeds, auth_headers):
        """The rank and the article reported alongside it have to be the same one."""
        entries = [
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                published=NOW - timedelta(days=2 - i),
                host=f"outlet{i}.example",
            )
            for i in range(3)
        ]
        await assign_entries(db_session, limit=50)
        # The loudest article is the last one published, so publication order
        # and score order disagree — which is the whole bug.
        loudest = {"e": entries[-1].id}
        await db_session.execute(
            text("UPDATE entries SET priority_score = 9.5, priority_raw = 4.0 WHERE id = :e"), loudest
        )
        await db_session.execute(
            text("UPDATE entries SET priority_score = 1.0, priority_raw = 0.1 WHERE id <> :e"), loudest
        )
        slug = (await db_session.execute(text("SELECT slug FROM story_threads"))).scalar_one()
        await db_session.commit()

        body = (await client.get(f"/api/threads/{slug}", headers=auth_headers)).json()

        assert body["top_score"] == 9.5
        assert body["top_entry_id"] == str(entries[-1].id)

    async def test_opening_a_thread_clears_what_counts_as_new(self, client, db_session, feeds, auth_headers):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)
        thread_id = (await db_session.execute(text("SELECT id FROM story_threads"))).scalar_one()
        await db_session.commit()

        assert (await client.post(f"/api/threads/{thread_id}/open", headers=auth_headers)).status_code == 200

        listing = await client.get("/api/threads", headers=auth_headers)
        assert listing.json()["total"] == 1
        # Opening stamped the thread, so nothing counts as new any more.
        assert listing.json()["threads"][0]["new_since_opened"] == 0


class TestCandidateSelection:
    """What the sweeper looks at, and in what order."""

    async def test_never_checked_entries_are_never_crowded_out_by_re_checks(self, db_session, feeds):
        """The failure this ordering exists to prevent.

        Everything inside the gap window is re-offered on every pass, so once
        that set outgrows the batch limit a plain oldest-first ordering spends
        the whole budget re-examining the same articles and never reaches
        today's — which is the only part of the window the queue is about.
        """
        for i in range(4):
            entry = await make_entry(
                db_session,
                feeds[0],
                title=f"Older article {i}",
                published=NOW - timedelta(days=2),
                host=f"outlet{i}.example",
            )
            await db_session.execute(
                text("UPDATE entry_embeddings SET threaded_checked_at = now() WHERE entry_id = :e"),
                {"e": entry.id},
            )
        fresh = await make_entry(db_session, feeds[1], title="Published an hour ago", host="new.example")

        # A budget smaller than the re-offered set: the newcomer still has to be in it.
        candidates = await _candidate_entries(db_session, NOW - timedelta(days=21), 2, 400, 5)

        assert fresh.id in [c["id"] for c in candidates]

    async def test_advisory_rows_are_never_threaded(self, db_session, feeds):
        """Long enough to clear the body floor, still not coverage of anything."""
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"RHSA-2026:6330{i}: Important: {['libtiff', 'buildah', '389-ds'][i]} security update",
                similarity_to_base=1.0 if i == 0 else 0.97,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await make_entry(db_session, feeds[3], title="openssl: CVSS (Max): 7.5", host="auscert.example")

        stats = await assign_entries(db_session, limit=50)

        assert stats["considered"] == 0
        assert stats["seeded"] == 0


class TestSourceDominance:
    async def test_one_outlet_cannot_keep_adding_itself_as_echoes(self, db_session, feeds):
        """The exemption that let six unrelated Red Hat errata become one story."""
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"PaperCut exploited in the wild {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)

        # The origin's own outlet files three more, each a near-copy of the last.
        for i in range(3):
            await make_entry(
                db_session,
                feeds[0],
                title=f"PaperCut advisory follow-up {i}",
                similarity_to_base=0.99,
                axis=1,
                published=NOW + timedelta(hours=i + 1),
                host="outlet0.example",
            )
            await assign_entries(db_session, limit=50)

        from_origin = (
            await db_session.execute(
                text("SELECT COUNT(*) FROM story_thread_entries WHERE source_key = 'outlet0.example'")
            )
        ).scalar_one()
        assert from_origin <= SAME_SOURCE_LIMIT


class TestRoundups:
    """A recurring catalogue is a format, not a story."""

    async def _entities(self, db_session, entry, names: list[str]) -> None:
        for name in names:
            actor = (
                await db_session.execute(text("SELECT id FROM threat_actors WHERE name = :n"), {"n": name})
            ).scalar_one_or_none()
            if actor is None:
                row = ThreatActor(name=name)
                db_session.add(row)
                await db_session.flush()
                actor = row.id
            db_session.add(EntryThreatActor(entry_id=entry.id, threat_actor_id=actor))
        await db_session.flush()

    async def test_entity_dense_but_disjoint_articles_do_not_seed(self, db_session, feeds):
        for i in range(3):
            entry = await make_entry(
                db_session,
                feeds[i],
                title=f"CISA adds five flaws to KEV ({i})",
                similarity_to_base=1.0 if i == 0 else 0.95,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
            # Each instalment catalogues different things — nothing recurs.
            await self._entities(db_session, entry, [f"Group-{i}-{n}" for n in range(5)])

        stats = await assign_entries(db_session, limit=50)

        assert stats["seeded"] == 0

    async def test_entity_dense_articles_about_one_subject_still_seed(self, db_session, feeds):
        """The control: density alone must not block a real story."""
        for i in range(3):
            entry = await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hospital campaign {i}",
                similarity_to_base=1.0 if i == 0 else 0.95,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
            await self._entities(db_session, entry, ["Qilin", "Agenda", f"Side-{i}-a", f"Side-{i}-b", f"Side-{i}-c"])

        stats = await assign_entries(db_session, limit=50)

        assert stats["seeded"] == 1


class TestPruning:
    async def test_a_thread_whose_articles_aged_out_is_removed(self, db_session, feeds):
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)

        # Feed retention deletes entries; membership cascades, the thread does not.
        doomed = (await db_session.execute(text("SELECT entry_id FROM story_thread_entries LIMIT 2"))).scalars().all()
        await db_session.execute(text("DELETE FROM entries WHERE id = ANY(:ids)"), {"ids": list(doomed)})

        stats = await prune_threads(db_session, since=datetime.now(UTC))

        assert stats["pruned"] == 1
        assert await thread_rows(db_session) == []

    async def test_counts_are_reconciled_when_one_article_disappears(self, db_session, feeds):
        for i in range(4):
            await make_entry(
                db_session,
                feeds[i % len(feeds)],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)
        thread_id = (await db_session.execute(text("SELECT id FROM story_threads"))).scalar_one()
        await ensure_spine(db_session, thread_id, allow_ai=False)

        gone = (await db_session.execute(text("SELECT entry_id FROM story_thread_entries LIMIT 1"))).scalar_one()
        await db_session.execute(text("DELETE FROM entries WHERE id = :e"), {"e": gone})

        stats = await prune_threads(db_session, since=datetime.now(UTC))

        assert stats["reconciled"] == 1
        row = (
            (
                await db_session.execute(
                    text("SELECT entry_count, narrative_hash FROM story_threads WHERE id = :t"), {"t": thread_id}
                )
            )
            .mappings()
            .one()
        )
        assert row["entry_count"] == 3
        # The spine describes a member set that no longer exists as described.
        assert row["narrative_hash"] is None


class TestNarrationHandover:
    """The heuristic spine is a floor, never a ceiling."""

    async def _seed(self, db_session, feeds) -> uuid.UUID:
        for i in range(3):
            await make_entry(
                db_session,
                feeds[i],
                title=f"Qilin hits hospital chain {i}",
                similarity_to_base=1.0 if i == 0 else 0.87,
                axis=i + 1,
                published=NOW - timedelta(days=i),
                host=f"outlet{i}.example",
            )
        await assign_entries(db_session, limit=50)
        return (await db_session.execute(text("SELECT id FROM story_threads"))).scalar_one()

    async def test_a_heuristic_spine_does_not_count_as_narrated(self, db_session, feeds):
        thread_id = await self._seed(db_session, feeds)

        await ensure_spine(db_session, thread_id, allow_ai=False)

        narrated_at = (
            await db_session.execute(text("SELECT narrated_at FROM story_threads WHERE id = :t"), {"t": thread_id})
        ).scalar_one()
        assert narrated_at is None  # the reader shows "not yet written" off this

    async def test_the_ai_pass_still_upgrades_a_thread_that_never_changed(self, db_session, feeds, monkeypatch):
        """The hash the sweeper stamps must not lock the model out."""
        thread_id = await self._seed(db_session, feeds)
        await ensure_spine(db_session, thread_id, allow_ai=False)

        async def fake_task(db, tid, title, members):
            return {
                "title": "Qilin hospital campaign",
                "summary": "Qilin claims a hospital chain.",
                "beats": [{"kind": "first_disclosure", "headline": "Qilin claims the breach", "entry_indexes": [1]}],
            }

        monkeypatch.setattr(thread_narrative, "_run_spine_task", fake_task)
        result = await ensure_spine(db_session, thread_id, allow_ai=True)

        assert result["status"] == "narrated"
        row = (
            (
                await db_session.execute(
                    text("SELECT title, narrated_at FROM story_threads WHERE id = :t"), {"t": thread_id}
                )
            )
            .mappings()
            .one()
        )
        assert row["title"] == "Qilin hospital campaign"
        assert row["narrated_at"] is not None

    async def test_a_failed_model_call_leaves_the_thread_up_for_retry(self, db_session, feeds, monkeypatch):
        thread_id = await self._seed(db_session, feeds)

        async def failed_task(db, tid, title, members):
            return None

        monkeypatch.setattr(thread_narrative, "_run_spine_task", failed_task)
        first = await ensure_spine(db_session, thread_id, allow_ai=True)
        second = await ensure_spine(db_session, thread_id, allow_ai=True)

        assert first["status"] == "heuristic"
        # Tomorrow night has to try again rather than call this thread done.
        assert second["status"] != "cached"


class TestEmbeddingText:
    def test_a_thin_summary_loses_to_the_article(self):
        """70% of the corpus ships a teaser; embedding it throws the article away."""
        text_out = build_text("Qilin hits hospital chain", "Read more", "The ransomware group Qilin " + "x" * 900)
        assert "Read more" not in text_out
        assert text_out.startswith("Qilin hits hospital chain")
        assert "The ransomware group Qilin" in text_out

    def test_a_substantive_summary_is_preferred(self):
        summary = "Qilin claimed responsibility for the intrusion. " * 8
        text_out = build_text("Qilin hits hospital chain", summary, "Navigation junk " * 200)
        assert "Navigation junk" not in text_out

    def test_an_entry_with_only_a_short_summary_still_embeds(self):
        assert build_text("A headline", "Short one.", None) == "A headline\n\nShort one."

    async def test_the_verify_pass_rotates_through_the_corpus(self, db_session, feeds):
        first = await make_entry(db_session, feeds[0], title="One", host="a.example")
        second = await make_entry(db_session, feeds[1], title="Two", host="b.example")
        await db_session.execute(text("UPDATE entry_embeddings SET model = 'test'"))

        batch = await embeddings.verify_entries(db_session, "test", 1)
        await embeddings.mark_verified(db_session, [batch[0]["id"]])
        following = await embeddings.verify_entries(db_session, "test", 1)

        assert {first.id, second.id} == {batch[0]["id"], following[0]["id"]}


class TestSimilarEntriesGuards:
    async def test_distant_neighbours_are_not_offered_as_similar(self, db_session, feeds):
        anchor = await make_entry(db_session, feeds[0], title="Qilin hits hospital chain", host="a.example")
        await make_entry(
            db_session, feeds[1], title="Unrelated conference keynote", similarity_to_base=0.4, axis=2, host="b.example"
        )

        assert await similar_entries(db_session, anchor.id, limit=5) == []

    async def test_syndicated_copies_are_excluded(self, db_session, feeds):
        anchor = await make_entry(db_session, feeds[0], title="Qilin hits hospital chain", host="a.example")
        copy = await make_entry(
            db_session, feeds[1], title="Qilin hits hospital chain", similarity_to_base=0.999, axis=2, host="b.example"
        )

        neighbours = await similar_entries(db_session, anchor.id, limit=5, exclude_ids=[copy.id])

        assert neighbours == []
