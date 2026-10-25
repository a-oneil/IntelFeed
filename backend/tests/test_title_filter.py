"""The per-feed exclude-title filter: parsing, validation, ingest and preview."""

import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import ParsedEntry, ParsedFeedMeta
from app.core.exceptions import AppError
from app.models.entry import Entry
from app.models.feed import Feed
from app.services.title_filter import (
    matching_pattern,
    normalize_patterns,
    parse_patterns,
    partition_by_title,
)

# ---------- the phrase list ----------


def test_matching_is_case_insensitive_substring():
    patterns = parse_patterns("ISC Stormcast For\nChromium CVE-")
    assert matching_pattern("ISC Stormcast For Friday, October 24th, 2025", patterns) == "isc stormcast for"
    assert matching_pattern("chromium cve-2025-1234 Use after free", patterns) == "chromium cve-"
    assert matching_pattern("Another Stormcast-free diary", patterns) is None


def test_whitespace_runs_count_as_one_space():
    assert matching_pattern("ISC  Stormcast\tFor Monday", parse_patterns("isc stormcast for"))


def test_text_is_not_a_regex():
    # A dot is a dot: "v1.2" must not match "v1x2".
    assert matching_pattern("Release v1x2", parse_patterns("v1.2")) is None
    assert matching_pattern("Release v1.2", parse_patterns("v1.2"))


def test_no_patterns_or_non_text_means_no_filter():
    assert parse_patterns(None) == []
    assert parse_patterns(MagicMock()) == []
    kept, dropped = partition_by_title([MagicMock(title="x")], None)
    assert len(kept) == 1 and dropped == []


def test_normalize_trims_dedupes_and_keeps_display_case():
    assert normalize_patterns("  ISC Stormcast For \n\nisc stormcast for\nChromium CVE-\n") == (
        "ISC Stormcast For\nChromium CVE-"
    )
    assert normalize_patterns("  \n ") is None
    assert normalize_patterns(None) is None


@pytest.mark.parametrize("bad", ["ab", "x" * 201, "\n".join(f"phrase {i}" for i in range(51))])
def test_normalize_rejects_lines_that_would_misbehave(bad):
    with pytest.raises(AppError) as exc:
        normalize_patterns(bad)
    assert exc.value.status_code == 422


# ---------- ingest ----------

_RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>ISC</title>
<item><title>ISC Stormcast For Friday, October 24th, 2025</title><link>https://isc.example/1</link>
<guid>g-1</guid><description>stub</description></item>
<item><title>Analyzing a phishing kit</title><link>https://isc.example/2</link>
<guid>g-2</guid><description>real diary</description></item>
</channel></rss>"""


@pytest.mark.asyncio
async def test_rss_fetch_never_saves_an_excluded_title():
    feed = MagicMock(spec=Feed)
    feed.id = uuid.uuid4()
    feed.url = "https://isc.example/rss"
    feed.is_active = True
    feed.etag = None
    feed.last_modified = None
    feed.last_fetched_at = None
    feed.error_count = 0
    feed.last_error = None
    feed.title = "ISC"
    feed.description = None
    feed.site_url = None
    feed.feed_type = "rss"
    feed.adapter_config = {}
    feed.exclude_title_patterns = "ISC Stormcast For"

    session = AsyncMock()
    calls = 0

    async def execute(stmt):
        nonlocal calls
        calls += 1
        result = MagicMock()
        result.scalar_one_or_none.return_value = feed if calls == 1 else None
        result.all.return_value = []
        return result

    session.execute = AsyncMock(side_effect=execute)
    session.add = MagicMock()
    nested = AsyncMock()
    session.begin_nested = MagicMock(return_value=nested)
    factory = AsyncMock()
    factory.__aenter__.return_value = session

    response = MagicMock(status_code=200, text=_RSS, headers={})
    client = AsyncMock()
    client.get.return_value = response
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("app.workers.feed_tasks._get_worker_session", return_value=factory),
        patch("httpx.AsyncClient", return_value=client),
        patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
        patch("app.workers.feed_tasks._extract_full_text", new_callable=AsyncMock, return_value=(None, None)),
        patch("app.workers.feed_tasks._fetch_og_image", new_callable=AsyncMock, return_value=None),
        patch("app.services.meilisearch_client.index_entry") as index,
    ):
        from app.workers.feed_tasks import _fetch_feed

        await _fetch_feed(str(feed.id))

    saved = [c.args[0] for c in session.add.call_args_list if isinstance(c.args[0], Entry)]
    assert [e.title for e in saved] == ["Analyzing a phishing kit"]
    index.assert_called_once()
    assert index.call_args.kwargs["title"] == "Analyzing a phishing kit"


@pytest.mark.asyncio
async def test_extended_adapter_fetch_applies_the_same_filter():
    from app.workers import feed_tasks

    def parsed(guid, title):
        return ParsedEntry(
            guid=guid,
            url=f"https://msrc.example/{guid}",
            title=title,
            content_html="<p>body</p>",
            published_at=datetime(2026, 10, 1, tzinfo=UTC),
        )

    adapter = MagicMock()
    adapter.fetch_entries = AsyncMock(
        return_value=(
            ParsedFeedMeta(title="MSRC"),
            [parsed("a", "Chromium CVE-2026-1111 Heap overflow"), parsed("b", "CVE-2026-2222 Windows SMB")],
        )
    )
    feed = MagicMock()
    feed.id = "feed-msrc"
    feed.feed_type = "nvd"
    feed.adapter_config = {}
    feed.last_fetched_at = None
    feed.title = "MSRC"
    feed.exclude_title_patterns = "chromium cve-"

    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()

    with (
        patch("app.adapters.get_extended_adapter", return_value=adapter),
        patch("app.services.system_settings._ensure_cache", new=AsyncMock()),
        patch("app.services.meilisearch_client.index_entry"),
        patch.object(feed_tasks, "_create_entry_media", new=AsyncMock()),
        patch.object(feed_tasks, "_apply_post_ingest_links", new=AsyncMock()),
        patch.object(feed_tasks, "dispatch_entry_pipeline"),
        patch("app.workers.automation_tasks.run_entry_automations"),
    ):
        await feed_tasks._fetch_extended_feed(db, feed)

    saved = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], Entry)]
    assert [e.title for e in saved] == ["CVE-2026-2222 Windows SMB"]


# ---------- API ----------


@pytest.mark.asyncio
async def test_update_stores_the_normalized_list(client: AsyncClient, admin_headers: dict, db_session: AsyncSession):
    feed = Feed(title="ISC", url="https://tf-store.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/{feed.id}",
        json={"exclude_title_patterns": " ISC Stormcast For \n\n"},
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.json()["exclude_title_patterns"] == "ISC Stormcast For"

    response = await client.put(f"/api/feeds/{feed.id}", json={"exclude_title_patterns": ""}, headers=admin_headers)
    assert response.json()["exclude_title_patterns"] is None


@pytest.mark.asyncio
async def test_update_rejects_a_bad_line(client: AsyncClient, admin_headers: dict, db_session: AsyncSession):
    feed = Feed(title="ISC", url="https://tf-bad.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(f"/api/feeds/{feed.id}", json={"exclude_title_patterns": "a"}, headers=admin_headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_title_filter"


@pytest.mark.asyncio
async def test_title_filter_is_admin_only(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = Feed(title="ISC", url="https://tf-guard.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    response = await client.put(
        f"/api/feeds/{feed.id}", json={"exclude_title_patterns": "Stormcast"}, headers=auth_headers
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_preview_counts_recent_titles(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    feed = Feed(title="ISC", url="https://tf-preview.example.com/rss", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    now = datetime.now(UTC)
    titles = ["ISC Stormcast For Monday", "ISC Stormcast For Tuesday", "A real diary"]
    for i, title in enumerate(titles):
        db_session.add(
            Entry(
                feed_id=feed.id,
                guid=f"tf-{i}",
                title=title,
                url=f"https://tf-preview.example.com/{i}",
                published_at=now - timedelta(hours=i),
            )
        )
    await db_session.flush()

    response = await client.post(
        f"/api/feeds/{feed.id}/title-filter/preview",
        json={"exclude_title_patterns": "isc stormcast for"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json() == {
        "checked": 3,
        "dropped": 2,
        "examples": ["ISC Stormcast For Monday", "ISC Stormcast For Tuesday"],
    }

    response = await client.post(
        f"/api/feeds/{feed.id}/title-filter/preview",
        json={"exclude_title_patterns": "x"},
        headers=auth_headers,
    )
    assert response.status_code == 422


# ---------- OPML ----------


def test_opml_round_trips_the_list():
    from app.api.opml import feed_outline_attrs, parse_extension_attrs
    from app.feed_packs import INTELFEED_NS

    feed = Feed(
        title="MSRC",
        url="https://msrc.example/rss",
        feed_type="rss",
        fetch_interval_minutes=30,
        intel_extraction_mode="selective",
        ai_analysis_enabled=True,
        extract_tools=True,
        extract_detection_rules=False,
        auto_extract_on_ingest=False,
        exclude_title_patterns="Chromium CVE-\nISC Stormcast For",
    )
    attrs = {
        (f"{{{INTELFEED_NS}}}{k.removeprefix('intelfeed:')}" if k.startswith("intelfeed:") else k): v
        for k, v in feed_outline_attrs(feed).items()
    }
    outline = ET.Element("outline", attrs)
    assert parse_extension_attrs(outline)["exclude_title_patterns"] == "Chromium CVE-\nISC Stormcast For"
