import contextlib
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.models.user import User


@pytest.mark.asyncio
async def test_list_feeds_empty(client: AsyncClient, auth_headers: dict):
    response = await client.get("/api/feeds", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["has_more"] is False


@pytest.mark.asyncio
async def test_create_feed(client: AsyncClient, auth_headers: dict):
    mock_result = SimpleNamespace(
        title="Test Blog",
        url="https://example.com/feed.xml",
        feed_type="rss",
        description="A test blog feed",
    )

    with (
        patch("app.api.feeds.discover_feed", return_value=mock_result) as mock_discover,
        patch("app.workers.feed_tasks.fetch_feed.delay") as mock_fetch,
    ):
        response = await client.post(
            "/api/feeds",
            json={"url": "https://example.com/feed.xml"},
            headers=auth_headers,
        )

    assert response.status_code == 201
    data = response.json()
    # The response is a flat FeedResponse; it used to be a subscription
    # wrapper with the feed nested under a "feed" key.
    assert data["title"] == "Test Blog"
    assert data["url"] == "https://example.com/feed.xml"
    assert data["feed_type"] == "rss"
    assert data["description"] == "A test blog feed"
    assert data["unread_count"] == 0
    assert data["is_muted"] is False

    mock_discover.assert_called_once_with("https://example.com/feed.xml")
    mock_fetch.assert_called_once()


@pytest.mark.asyncio
async def test_create_feed_duplicate(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    # Create a feed directly in the DB
    feed = Feed(
        title="Existing Feed",
        url="https://existing.com/feed.xml",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    # Attempt to add again -- discover_feed won't be called because the
    # Feed URL already exists in the DB, but we still need to mock fetch_feed.delay
    # since the code path checks for existing feed first.
    with patch("app.workers.feed_tasks.fetch_feed.delay"):
        response = await client.post(
            "/api/feeds",
            json={"url": "https://existing.com/feed.xml"},
            headers=auth_headers,
        )

    assert response.status_code == 409
    data = response.json()
    assert data["error"]["code"] == "conflict"


@pytest.mark.asyncio
async def test_get_feed(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    feed = Feed(
        title="My Feed",
        url="https://myfeed.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.get(f"/api/feeds/{feed.id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "My Feed"
    assert data["url"] == "https://myfeed.com/rss"


@pytest.mark.asyncio
async def test_get_feed_not_found(client: AsyncClient, auth_headers: dict):
    import uuid as _uuid

    fake_id = _uuid.uuid4()
    response = await client.get(f"/api/feeds/{fake_id}", headers=auth_headers)
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "not_found"


@pytest.mark.asyncio
async def test_delete_feed(client: AsyncClient, admin_headers: dict, test_user: User, db_session: AsyncSession):
    feed = Feed(
        title="To Delete",
        url="https://delete.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.delete(f"/api/feeds/{feed.id}", headers=admin_headers)
    assert response.status_code == 204

    # Verify feed is no longer in the list
    response = await client.get("/api/feeds", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["total"] == 0


@pytest.mark.asyncio
async def test_delete_feed_requires_admin(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """Feed deletion is admin-only; a regular user gets 403 and the feed survives."""
    feed = Feed(
        title="Protected",
        url="https://protected.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.delete(f"/api/feeds/{feed.id}", headers=auth_headers)
    assert response.status_code == 403

    response = await client.get("/api/feeds", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["total"] == 1


@pytest.mark.asyncio
async def test_failing_feeds(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    healthy = Feed(title="Healthy", url="https://ok.com/rss", feed_type="rss", error_count=0)
    below_threshold = Feed(title="Flaky", url="https://flaky.com/rss", feed_type="rss", error_count=3)
    failing = Feed(
        title="Broken",
        url="https://broken.com/rss",
        feed_type="rss",
        error_count=10,
        last_error="HTTP 403",
    )
    failing_high_value = Feed(
        title="CISA KEV",
        url="https://cisa.gov/feed.xml",
        feed_type="rss",
        error_count=6,
        last_error="HTTP 403",
        reliability_rating="A",
    )
    inactive = Feed(title="Disabled", url="https://off.com/rss", feed_type="rss", error_count=99, is_active=False)
    for f in (healthy, below_threshold, failing, failing_high_value, inactive):
        db_session.add(f)
    await db_session.flush()

    response = await client.get("/api/feeds/health/failing", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["threshold"] == 5
    assert data["total"] == 2
    assert data["high_value_count"] == 1
    # High-value feeds sort first, then by error count
    assert [f["title"] for f in data["feeds"]] == ["CISA KEV", "Broken"]
    assert data["feeds"][0]["is_high_value"] is True
    assert data["feeds"][1]["last_error"] == "HTTP 403"

    # Custom threshold picks up the flaky feed too
    response = await client.get("/api/feeds/health/failing?threshold=3", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["total"] == 3


@pytest.mark.asyncio
async def test_refresh_feed(client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession):
    feed = Feed(
        title="Refresh Me",
        url="https://refresh.com/rss",
        feed_type="rss",
    )
    db_session.add(feed)
    await db_session.flush()

    with patch("app.workers.feed_tasks.fetch_feed.delay") as mock_fetch:
        response = await client.post(f"/api/feeds/{feed.id}/refresh", headers=auth_headers)

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Feed refresh queued"
    mock_fetch.assert_called_once_with(str(feed.id))


@pytest.mark.asyncio
async def test_feed_health_includes_reliability(
    client: AsyncClient, auth_headers: dict, test_user: User, db_session: AsyncSession
):
    """Feed health rows carry the reliability rating for the UI badge."""
    from datetime import UTC, datetime, timedelta

    stale_rated = Feed(
        title="Stale Rated",
        url="https://stale-rated.com/rss",
        feed_type="rss",
        reliability_rating="B",
        last_fetched_at=datetime.now(UTC) - timedelta(days=30),
    )
    unrated = Feed(title="Unrated Off", url="https://off2.com/rss", feed_type="rss", is_active=False)
    db_session.add_all([stale_rated, unrated])
    await db_session.flush()

    response = await client.get("/api/feeds/health", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    stale_row = next(f for f in data["stale_feeds"] if f["id"] == str(stale_rated.id))
    assert stale_row["reliability_rating"] == "B"
    disabled_row = next(f for f in data["disabled_feeds"] if f["id"] == str(unrated.id))
    assert disabled_row["reliability_rating"] is None


@pytest.mark.asyncio
async def test_update_feed_type_accepts_every_registered_adapter(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """Every type the adapter registry serves is a legal target for a type change.

    The allowlist used to be a hand-written copy that had drifted: it rejected
    github_repo / github_releases / github_advisories / nvd / mastodon, all of
    which the edit modal offers, and accepted `github`, which has no adapter.
    """
    from app.adapters import known_feed_types

    feed = Feed(title="Retype", url="https://retype.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    for feed_type in sorted(known_feed_types()):
        response = await client.put(
            f"/api/feeds/{feed.id}",
            json={"feed_type": feed_type},
            headers=admin_headers,
        )
        assert response.status_code == 200, f"{feed_type}: {response.text}"
        assert response.json()["feed_type"] == feed_type


@pytest.mark.asyncio
async def test_update_feed_type_rejects_an_adapterless_type(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """`github` has no adapter — get_adapter() would silently fall back to RSS."""
    feed = Feed(title="Bad Retype", url="https://bad-retype.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"feed_type": "github"},
        headers=admin_headers,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_feed_type"


@pytest.mark.asyncio
async def test_one_feed_value_returns_a_single_ranked_row(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession
):
    """The modal's Overview pane reads one row, ranked against the active set."""
    scored = Feed(title="Scored", url="https://scored.example.com/rss", feed_type="rss")
    other = Feed(title="Other", url="https://other.example.com/rss", feed_type="rss")
    db_session.add_all([scored, other])
    await db_session.flush()

    response = await client.get(f"/api/feeds/{scored.id}/value", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["scored"] is True
    assert data["feed_id"] == str(scored.id)
    assert data["tier"] in {"S", "A", "B", "C", "D"}
    assert data["of"] >= 2
    assert 1 <= data["rank"] <= data["of"]
    for key in ("articles", "unique_entities", "entity_introductions", "correlation_events", "detection_rules"):
        assert isinstance(data[key], int)


@pytest.mark.asyncio
async def test_one_feed_value_scores_a_paused_feed(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    """A paused feed is outside the active set but still has a history to show."""
    paused = Feed(title="Paused", url="https://paused.example.com/rss", feed_type="rss", is_active=False)
    db_session.add(paused)
    await db_session.flush()

    response = await client.get(f"/api/feeds/{paused.id}/value", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["scored"] is True


@pytest.mark.asyncio
async def test_one_feed_value_not_found(client: AsyncClient, auth_headers: dict):
    import uuid as _uuid

    response = await client.get(f"/api/feeds/{_uuid.uuid4()}/value", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_feed_can_clear_category_and_retention(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """An explicit null means "uncategorized" / "keep forever", not "unchanged"."""
    from app.models.category import Category

    category = Category(name="News")
    db_session.add(category)
    await db_session.flush()

    feed = Feed(
        title="Clearable",
        url="https://clearable.example.com/rss",
        feed_type="rss",
        category_id=category.id,
        retention_days=90,
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"category_id": None, "retention_days": None},
        headers=admin_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["category_id"] is None
    assert data["retention_days"] is None


@pytest.mark.asyncio
async def test_update_feed_omitted_fields_stay_untouched(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """The flip side: a key the caller never sent must not be cleared."""
    from app.models.category import Category

    category = Category(name="Vendor research")
    db_session.add(category)
    await db_session.flush()

    feed = Feed(
        title="Untouched",
        url="https://untouched.example.com/rss",
        feed_type="rss",
        category_id=category.id,
        retention_days=90,
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"custom_title": "Renamed"},
        headers=admin_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["custom_title"] == "Renamed"
    assert data["category_id"] == str(category.id)
    assert data["retention_days"] == 90


@pytest.mark.asyncio
async def test_non_admin_cannot_clear_retention_with_an_explicit_null(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession
):
    """Retention is infrastructure — an explicit null is still an admin write."""
    feed = Feed(
        title="Guarded",
        url="https://guarded.example.com/rss",
        feed_type="rss",
        retention_days=90,
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"retention_days": None},
        headers=auth_headers,
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


@pytest.mark.asyncio
async def test_ai_analysis_can_be_disabled_without_disabling_autolinking(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """The gap this field closes: quieting the AI used to mean mode="none"."""
    feed = Feed(
        title="Noisy",
        url="https://noisy.example.com/rss",
        feed_type="rss",
        intel_extraction_mode="selective",
    )
    db_session.add(feed)
    await db_session.flush()
    assert feed.ai_analysis_enabled is True

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"ai_analysis_enabled": False},
        headers=admin_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ai_analysis_enabled"] is False
    # Autolinking is untouched — that is the whole point.
    assert data["intel_extraction_mode"] == "selective"


@pytest.mark.asyncio
async def test_ai_analysis_toggle_is_admin_only(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = Feed(title="Guard", url="https://guard-ai.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"ai_analysis_enabled": False},
        headers=auth_headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_analysis_is_not_queued_for_a_feed_with_ai_off(db_session: AsyncSession, monkeypatch):
    """The switch has to actually stop the enqueue, not just store a bool."""
    from app.config import settings as env_settings
    from app.models.entry import Entry
    from app.services.entry_analysis import enqueue_entry_analysis

    monkeypatch.setattr(env_settings, "ai_one_pass_enabled", True)

    feed = Feed(
        title="AI off",
        url="https://ai-off.example.com/rss",
        feed_type="rss",
        ai_analysis_enabled=False,
    )
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(feed_id=feed.id, title="Something", url="https://ai-off.example.com/a", guid="ai-off-1")
    db_session.add(entry)
    await db_session.flush()

    assert await enqueue_entry_analysis(db_session, entry.id) is None


@pytest.mark.asyncio
async def test_feed_pipeline_reports_legacy_while_the_engine_is_off(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession
):
    """With no plan engine, the Feed booleans are authoritative — say so."""
    feed = Feed(title="Plain", url="https://plain.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    response = await client.get(f"/api/feeds/{feed.id}/pipeline", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["engine_enabled"] is False
    assert set(data["decided_by"].values()) == {"legacy"}
    assert "autolink" in data["stages"]


@pytest.mark.asyncio
async def test_feed_pipeline_names_the_scope_that_overrode_a_stage(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, monkeypatch
):
    """Feed scope beats global, and the pane needs to be told which won."""
    from app.config import settings as env_settings
    from app.models.pipeline_plan import PipelinePlan

    monkeypatch.setattr(env_settings, "pipeline_engine_enabled", True)

    feed = Feed(title="Planned", url="https://planned.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    db_session.add_all(
        [
            PipelinePlan(name="global", scope_type="global", scope_id=None, stages={"autolink": {"enabled": False}}),
            PipelinePlan(name="feed", scope_type="feed", scope_id=feed.id, stages={"autolink": {"enabled": True}}),
        ]
    )
    await db_session.flush()

    response = await client.get(f"/api/feeds/{feed.id}/pipeline", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["engine_enabled"] is True
    assert data["decided_by"]["autolink"] == "feed"
    assert data["stages"]["autolink"]["enabled"] is True
    # A stage no plan touched still reads from the Feed booleans.
    assert data["decided_by"]["score"] == "legacy"


@contextlib.asynccontextmanager
async def _worker_session_on(db: AsyncSession):
    """Hand the task the test's own session so it sees uncommitted fixtures.

    `_extract_entry_intel` opens its own worker session, which cannot see the
    test transaction — without this the task simply logs "Entry not found" and
    returns zeroes, which would make a "nothing was extracted" assertion pass
    for entirely the wrong reason.
    """
    yield db


async def _run_extract(db_session: AsyncSession, monkeypatch, feed: Feed, text: str) -> dict:
    from app.models.entry import Entry
    from app.workers import intel_feed_tasks

    db_session.add(feed)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id,
        title="Advisory",
        url=f"https://{uuid.uuid4().hex}.example.com/a",
        guid=uuid.uuid4().hex,
        content_text=text,
    )
    db_session.add(entry)
    await db_session.flush()

    monkeypatch.setattr(intel_feed_tasks, "_get_worker_session", lambda: _worker_session_on(db_session))
    # The real commit would end the test transaction.
    monkeypatch.setattr(db_session, "commit", db_session.flush)
    return await intel_feed_tasks._extract_entry_intel(str(entry.id))


@pytest.mark.asyncio
async def test_regex_pass_is_skipped_when_only_rule_extraction_is_on(db_session: AsyncSession, monkeypatch):
    """The NVD/CVE pass has to honour its own flag.

    Both halves of `extract_entry_intel_task` share one dispatch gate
    (`auto_extract_on_ingest or extract_detection_rules`), and the regex half
    used not to re-check its own flag — so turning "look up CVEs in NVD" off did
    nothing at all as long as rule extraction was on.
    """
    feed = Feed(
        title="Rules only",
        url="https://rules-only.example.com/rss",
        feed_type="rss",
        auto_extract_on_ingest=False,
        extract_detection_rules=True,
    )
    stats = await _run_extract(db_session, monkeypatch, feed, "Patch CVE-2026-10101 now. See also T1059.")
    assert stats["ttps"] == 0
    assert stats["cves"] == 0


@pytest.mark.asyncio
async def test_regex_pass_runs_when_its_own_flag_is_on(db_session: AsyncSession, monkeypatch):
    """The companion to the test above — otherwise it could pass vacuously."""
    from app.models.ttp import TTP

    db_session.add(TTP(technique_id="T1059", technique_name="Command and Scripting Interpreter"))
    await db_session.flush()

    feed = Feed(
        title="Regex on",
        url="https://regex-on.example.com/rss",
        feed_type="rss",
        auto_extract_on_ingest=True,
        extract_detection_rules=False,
    )
    stats = await _run_extract(db_session, monkeypatch, feed, "Patch CVE-2026-10102 now. See also T1059.")
    assert stats["ttps"] >= 1


@pytest.mark.asyncio
async def test_extended_feed_types_track_the_adapter_registry():
    """A second hand-written feed-type set is a second thing that can drift."""
    from app.adapters import _EXTENDED_ADAPTERS
    from app.api.feeds import _EXTENDED_FEED_TYPES

    assert set(_EXTENDED_FEED_TYPES) == set(_EXTENDED_ADAPTERS)


@pytest.mark.asyncio
async def test_bulk_category_update_stamps_the_review_date(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """Rating a whole category used to leave every feed reading "never assessed".

    The single-feed PUT stamped `last_reviewed_at` on any assessment change and
    the bulk path did not, so the Overview pane contradicted what you had just
    done.
    """
    from app.models.category import Category

    category = Category(name="Bulk assessed")
    db_session.add(category)
    await db_session.flush()

    feeds = [
        Feed(
            title=f"Bulk {i}",
            url=f"https://bulk-{i}.example.com/rss",
            feed_type="rss",
            category_id=category.id,
        )
        for i in range(2)
    ]
    db_session.add_all(feeds)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/category/{category.id}/bulk-update",
        json={"reliability_rating": "B", "timeliness_rating": "good", "relevance_rating": "high"},
        headers=admin_headers,
    )
    assert response.status_code == 200

    for feed in feeds:
        await db_session.refresh(feed)
        assert feed.reliability_rating == "B"
        assert feed.timeliness_rating == "good"
        assert feed.relevance_rating == "high"
        assert feed.last_reviewed_at is not None


@pytest.mark.asyncio
async def test_bulk_category_update_leaves_unsent_fields_alone(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """ "Leave as they are" is the default on every control — it must mean it."""
    from app.models.category import Category

    category = Category(name="Bulk untouched")
    db_session.add(category)
    await db_session.flush()

    feed = Feed(
        title="Untouched",
        url="https://bulk-untouched.example.com/rss",
        feed_type="rss",
        category_id=category.id,
        fetch_interval_minutes=360,
        reliability_rating="A",
        extract_tools=False,
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/category/{category.id}/bulk-update",
        json={"ai_analysis_enabled": False},
        headers=admin_headers,
    )
    assert response.status_code == 200

    await db_session.refresh(feed)
    assert feed.ai_analysis_enabled is False
    assert feed.fetch_interval_minutes == 360
    assert feed.reliability_rating == "A"
    assert feed.extract_tools is False
    # Nothing in the assessment block changed, so the review date stays unset.
    assert feed.last_reviewed_at is None


@pytest.mark.asyncio
async def test_bulk_category_update_cannot_overwrite_analyst_notes(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """One textarea replacing the notes on every feed in a category, with no
    undo, is not a thing this endpoint should be able to do. Per-feed notes are
    edited per feed."""
    from app.models.category import Category

    category = Category(name="Notes guarded")
    db_session.add(category)
    await db_session.flush()

    feed = Feed(
        title="Has notes",
        url="https://notes-guarded.example.com/rss",
        feed_type="rss",
        category_id=category.id,
        analyst_notes="Hard-won context about this source.",
    )
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/category/{category.id}/bulk-update",
        json={"analyst_notes": "wiped", "reliability_rating": "C"},
        headers=admin_headers,
    )
    assert response.status_code == 200

    await db_session.refresh(feed)
    assert feed.analyst_notes == "Hard-won context about this source."
    # The rest of the request still applied.
    assert feed.reliability_rating == "C"


@pytest.mark.asyncio
async def test_single_feed_update_still_writes_analyst_notes(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    """The companion guard: dropping it from the bulk body must not drop it here."""
    feed = Feed(title="Notes ok", url="https://notes-ok.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"analyst_notes": "Fast on ransomware."},
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.json()["analyst_notes"] == "Fast on ransomware."
