"""Tests for the Bluesky adapter."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.adapters.bluesky import (
    BlueskyAdapter,
    _bsky_post_url,
    _parse_iso,
    _rkey_from_uri,
    _stable_guid,
)

# ---------- helpers ----------


def _author_feed_response(posts: list[dict], cursor: str | None = None) -> dict:
    return {"feed": [{"post": p} for p in posts], "cursor": cursor}


def _make_post(
    cid: str = "bafyrei000",
    handle: str = "alice.bsky.social",
    did: str = "did:plc:abc",
    rkey: str = "3kabc",
    text: str = "Hello world",
    facets: list[dict] | None = None,
    created_at: str = "2026-04-30T12:00:00.000Z",
    embed: dict | None = None,
    reason: dict | None = None,
    record_extras: dict | None = None,
) -> dict:
    record = {
        "$type": "app.bsky.feed.post",
        "text": text,
        "createdAt": created_at,
    }
    if facets is not None:
        record["facets"] = facets
    if record_extras:
        record.update(record_extras)
    post = {
        "uri": f"at://{did}/app.bsky.feed.post/{rkey}",
        "cid": cid,
        "author": {
            "did": did,
            "handle": handle,
            "displayName": handle.split(".")[0].title(),
        },
        "record": record,
        "replyCount": 0,
        "repostCount": 5,
        "likeCount": 22,
        "indexedAt": "2026-04-30T12:00:01.000Z",
    }
    if embed is not None:
        post["embed"] = embed
    if reason is not None:
        return {"post": post, "reason": reason}
    return {"post": post}


# ---------- pure helpers ----------


def test_stable_guid_is_deterministic():
    g1 = _stable_guid("bafyrei000")
    g2 = _stable_guid("bafyrei000")
    assert g1 == g2
    assert len(g1) == 32
    assert _stable_guid("other") != g1


def test_rkey_from_uri():
    assert _rkey_from_uri("at://did:plc:abc/app.bsky.feed.post/3kabc") == "3kabc"
    assert _rkey_from_uri("") == ""


def test_bsky_post_url():
    assert (
        _bsky_post_url("alice.bsky.social", "at://did:plc:abc/app.bsky.feed.post/3kabc")
        == "https://bsky.app/profile/alice.bsky.social/post/3kabc"
    )
    assert _bsky_post_url("", "at://x/y/z") == ""


def test_parse_iso_handles_z_suffix():
    dt = _parse_iso("2026-04-30T12:00:00.000Z")
    assert dt is not None
    assert dt.year == 2026 and dt.tzinfo is not None
    assert _parse_iso(None) is None
    assert _parse_iso("not-a-date") is None


# ---------- _post_to_entry ----------


def test_post_to_entry_basic():
    adapter = BlueskyAdapter()
    raw = _make_post(text="Patch your FortiGate today.\nMore info coming.")
    entry = adapter._post_to_entry(raw)
    assert entry is not None
    assert entry.guid == _stable_guid("bafyrei000")
    assert entry.url == "https://bsky.app/profile/alice.bsky.social/post/3kabc"
    assert entry.title.startswith("Patch your FortiGate today.")
    assert entry.author and "alice.bsky.social" in entry.author
    assert entry.metadata["source"] == "bluesky"
    assert entry.metadata["like_count"] == 22
    assert "Patch your FortiGate" in (entry.content_html or "")
    assert entry.published_at is not None
    assert entry.media is None


def test_post_to_entry_skips_when_no_cid():
    adapter = BlueskyAdapter()
    raw = {"post": {"author": {"handle": "x"}, "record": {"text": "hi"}}}
    assert adapter._post_to_entry(raw) is None


# ---------- facet rendering ----------


def test_render_facets_link_mention_and_tag():
    adapter = BlueskyAdapter()
    text = "See #APT29 from @alice.bsky.social https://example.com"
    # Compute byte indices
    b = text.encode("utf-8")
    tag_start = b.index(b"#APT29")
    tag_end = tag_start + len(b"#APT29")
    mention_start = b.index(b"@alice.bsky.social")
    mention_end = mention_start + len(b"@alice.bsky.social")
    link_start = b.index(b"https://example.com")
    link_end = link_start + len(b"https://example.com")
    facets = [
        {
            "index": {"byteStart": tag_start, "byteEnd": tag_end},
            "features": [{"$type": "app.bsky.richtext.facet#tag", "tag": "APT29"}],
        },
        {
            "index": {"byteStart": mention_start, "byteEnd": mention_end},
            "features": [{"$type": "app.bsky.richtext.facet#mention", "did": "did:plc:abc"}],
        },
        {
            "index": {"byteStart": link_start, "byteEnd": link_end},
            "features": [{"$type": "app.bsky.richtext.facet#link", "uri": "https://example.com"}],
        },
    ]
    html = adapter._render_facets(text, facets)
    assert "#APT29" in html
    assert "hashtag/APT29" in html
    assert "@alice.bsky.social" in html
    assert "profile/alice.bsky.social" in html
    assert 'href="https://example.com"' in html


def test_render_facets_html_escapes_text():
    adapter = BlueskyAdapter()
    text = "<script>alert(1)</script>"
    html = adapter._render_facets(text, [])
    assert "<script" not in html
    assert "&lt;script&gt;" in html


def test_extract_tags_from_facets():
    adapter = BlueskyAdapter()
    facets = [
        {"features": [{"$type": "app.bsky.richtext.facet#tag", "tag": "infosec"}]},
        {"features": [{"$type": "app.bsky.richtext.facet#tag", "tag": "ransomware"}]},
        {"features": [{"$type": "app.bsky.richtext.facet#link", "uri": "https://x"}]},
    ]
    assert adapter._extract_tags(facets) == ["infosec", "ransomware"]


# ---------- embed handling ----------


def test_render_image_embed_picks_first_inlines_extras():
    adapter = BlueskyAdapter()
    embed = {
        "$type": "app.bsky.embed.images#view",
        "images": [
            {"thumb": "https://t/1", "fullsize": "https://f/1", "alt": "first"},
            {"thumb": "https://t/2", "fullsize": "https://f/2", "alt": "second"},
        ],
    }
    html, primary = adapter._render_embed(embed)
    assert primary is not None
    assert primary.url == "https://f/1"
    assert primary.thumbnail_url == "https://t/1"
    assert primary.media_type == "image"
    assert "https://f/2" in html  # extras inlined


def test_render_external_embed():
    adapter = BlueskyAdapter()
    embed = {
        "$type": "app.bsky.embed.external#view",
        "external": {
            "uri": "https://example.com/article",
            "title": "Story",
            "description": "Read this",
            "thumb": "https://t/thumb",
        },
    }
    html, primary = adapter._render_embed(embed)
    assert primary is None
    assert "bsky-external" in html
    assert "https://example.com/article" in html
    assert "Story" in html


def test_render_record_embed():
    adapter = BlueskyAdapter()
    embed = {
        "$type": "app.bsky.embed.record#view",
        "record": {
            "uri": "at://did:plc:xyz/app.bsky.feed.post/3kdef",
            "author": {"handle": "bob.bsky.social"},
            "value": {"text": "Quoted post body"},
        },
    }
    html, primary = adapter._render_embed(embed)
    assert primary is None
    assert "bsky-quote" in html
    assert "@bob.bsky.social" in html
    assert "Quoted post body" in html


def test_render_unknown_embed_type_degrades_gracefully():
    adapter = BlueskyAdapter()
    html, primary = adapter._render_embed({"$type": "app.bsky.embed.something#view"})
    assert html == ""
    assert primary is None


def test_render_video_embed():
    adapter = BlueskyAdapter()
    embed = {
        "$type": "app.bsky.embed.video#view",
        "playlist": "https://video/master.m3u8",
        "thumbnail": "https://t/thumb",
    }
    html, primary = adapter._render_embed(embed)
    assert primary is not None
    assert primary.media_type == "video"
    assert primary.url == "https://video/master.m3u8"


# ---------- mocked HTTP fetches ----------


@pytest.mark.asyncio
async def test_fetch_author_mode_end_to_end():
    adapter = BlueskyAdapter()
    p1 = _make_post(cid="bafyrei001", text="post 1")
    p2 = _make_post(cid="bafyrei002", text="post 2")
    response_data = _author_feed_response([p1["post"], p2["post"]])

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: response_data
    mock_response.text = ""

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        meta, entries = await adapter.fetch_entries({"mode": "author", "handle": "alice.bsky.social"}, since=None)
        assert "alice.bsky.social" in meta.title
        assert len(entries) == 2
        assert entries[0].metadata["source"] == "bluesky"
        # Adapter should publish the newest CID into _adapter_state for the worker.
        assert meta.extra.get("_adapter_state", {}).get("last_seen_cid") == "bafyrei001"


@pytest.mark.asyncio
async def test_fetch_author_skips_reposts_by_default():
    adapter = BlueskyAdapter()
    repost = _make_post(cid="bafyrei001", reason={"$type": "app.bsky.feed.defs#reasonRepost"})
    own = _make_post(cid="bafyrei002")
    response_data = {"feed": [repost, own]}

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: response_data
    mock_response.text = ""

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _, entries = await adapter.fetch_entries({"mode": "author", "handle": "alice.bsky.social"}, since=None)
        assert len(entries) == 1
        assert entries[0].metadata["cid"] == "bafyrei002"


@pytest.mark.asyncio
async def test_fetch_feed_uri_mode():
    adapter = BlueskyAdapter()
    response_data = _author_feed_response([_make_post(cid="bafyrei100")["post"]])
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: response_data
    mock_response.text = ""

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        meta, entries = await adapter.fetch_entries(
            {
                "mode": "feed",
                "feed_uri": "at://did:plc:xyz/app.bsky.feed.generator/whats-hot",
            },
            since=None,
        )
        assert len(entries) == 1
        assert "whats-hot" in meta.title


@pytest.mark.asyncio
async def test_fetch_search_mode():
    adapter = BlueskyAdapter()
    p = _make_post(cid="bafyrei200", text="ransomware news")["post"]
    # searchPosts returns flat post objects under 'posts'
    response_data = {"posts": [p]}
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: response_data
    mock_response.text = ""

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        meta, entries = await adapter.fetch_entries({"mode": "search", "query": "ransomware"}, since=None)
        assert len(entries) == 1
        assert "ransomware" in meta.title


@pytest.mark.asyncio
async def test_rate_limit_returns_empty_without_raising():
    adapter = BlueskyAdapter()
    mock_response = AsyncMock()
    mock_response.status_code = 429
    mock_response.json = lambda: {}
    mock_response.text = "rate limited"

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        meta, entries = await adapter.fetch_entries({"mode": "author", "handle": "alice.bsky.social"}, since=None)
        assert entries == []
        assert "rate limited" in (meta.description or "").lower()


@pytest.mark.asyncio
async def test_last_seen_cid_short_circuits_pagination():
    adapter = BlueskyAdapter()
    p1 = _make_post(cid="bafyrei001")["post"]
    p2 = _make_post(cid="bafyrei002")["post"]
    p_seen = _make_post(cid="bafyrei_old")["post"]
    page1 = {"feed": [{"post": p1}, {"post": p2}, {"post": p_seen}], "cursor": "next"}

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: page1
    mock_response.text = ""

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        meta, entries = await adapter.fetch_entries(
            {
                "mode": "author",
                "handle": "alice.bsky.social",
                "last_seen_cid": "bafyrei_old",
            },
            since=None,
        )
        assert {e.metadata["cid"] for e in entries} == {"bafyrei001", "bafyrei002"}


@pytest.mark.asyncio
async def test_since_filter_skips_older_posts():
    adapter = BlueskyAdapter()
    new_post = _make_post(cid="bafyrei001", created_at="2026-04-30T12:00:00.000Z")["post"]
    old_post = _make_post(cid="bafyrei002", created_at="2024-01-01T00:00:00.000Z")["post"]
    response = {"feed": [{"post": new_post}, {"post": old_post}]}

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: response
    mock_response.text = ""

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _, entries = await adapter.fetch_entries(
            {"mode": "author", "handle": "alice.bsky.social"},
            since=datetime(2025, 1, 1, tzinfo=UTC),
        )
        assert len(entries) == 1
        assert entries[0].metadata["cid"] == "bafyrei001"


def test_get_feed_meta_for_each_mode():
    adapter = BlueskyAdapter()
    m = adapter.get_feed_meta({"mode": "author", "handle": "x.bsky.social"})
    assert "x.bsky.social" in m.title
    m = adapter.get_feed_meta({"mode": "feed", "feed_uri": "at://x/y/z"})
    assert "at://x/y/z" in m.title
    m = adapter.get_feed_meta({"mode": "search", "query": "ransomware"})
    assert "ransomware" in m.title


# ---------- autolinker round-trip ----------


def test_facet_text_survives_html_to_text():
    """Hashtag and mention text must survive html_to_text so the autolinker still sees them."""
    from app.services.sanitizer import html_to_text

    adapter = BlueskyAdapter()
    text = "Tracking #APT29 attacks via @malwaretech.bsky.social with CVE-2024-3400"
    b = text.encode("utf-8")
    tag_start = b.index(b"#APT29")
    facets = [
        {
            "index": {"byteStart": tag_start, "byteEnd": tag_start + len(b"#APT29")},
            "features": [{"$type": "app.bsky.richtext.facet#tag", "tag": "APT29"}],
        }
    ]
    html = adapter._render_facets(text, facets)
    plain = html_to_text(html)
    assert "#APT29" in plain
    assert "@malwaretech.bsky.social" in plain
    assert "CVE-2024-3400" in plain


# ---------- adapter registry ----------


def test_bluesky_in_registry():
    from app.adapters import get_extended_adapter, is_extended_feed_type

    assert get_extended_adapter("bluesky") is not None
    assert is_extended_feed_type("bluesky") is True


# ---------- two-page paginated fetch ----------


@pytest.mark.asyncio
async def test_two_page_pagination_follows_cursor():
    """Author mode should follow the cursor across pages until max_per_poll is hit."""
    adapter = BlueskyAdapter()
    page1 = {
        "feed": [{"post": _make_post(cid=f"bafyrei{i:03d}")["post"]} for i in range(50)],
        "cursor": "page2",
    }
    page2 = {
        "feed": [{"post": _make_post(cid=f"bafyrei{i:03d}")["post"]} for i in range(50, 60)],
        "cursor": None,
    }

    calls: list[dict] = []

    async def mock_get(self, url, **kwargs):  # noqa: ARG001
        params = kwargs.get("params") or {}
        calls.append(dict(params))
        resp = AsyncMock()
        resp.status_code = 200
        resp.text = ""
        if params.get("cursor") == "page2":
            resp.json = lambda: page2
        else:
            resp.json = lambda: page1
        return resp

    with patch.object(httpx.AsyncClient, "get", new=mock_get):
        _, entries = await adapter.fetch_entries(
            {"mode": "author", "handle": "alice.bsky.social", "max_per_poll": 60},
            since=None,
        )
        assert len(entries) == 60
        assert len(calls) == 2
        assert calls[1].get("cursor") == "page2"


# ---------- auth path: createSession then getAuthorFeed ----------


@pytest.mark.asyncio
async def test_auth_path_create_session_then_fetch(monkeypatch):
    """When identifier+app_password are set, the adapter should POST createSession first
    and use the access JWT in the Authorization header on the subsequent getAuthorFeed call."""
    from app.adapters import bluesky as bsky_module

    bsky_module._session_cache_local.clear()

    async def fake_read(_feed_id):
        return None

    async def fake_write(*_args, **_kwargs):
        return None

    async def fake_invalidate(*_args, **_kwargs):
        return None

    monkeypatch.setattr(bsky_module, "_read_session", fake_read)
    monkeypatch.setattr(bsky_module, "_write_session", fake_write)
    monkeypatch.setattr(bsky_module, "_invalidate_session", fake_invalidate)
    monkeypatch.setattr(bsky_module, "decrypt_value", lambda v: v)

    captured_headers: dict[str, str] = {}

    async def fake_post(self, url, **kwargs):  # noqa: ARG001
        resp = AsyncMock()
        resp.status_code = 200
        resp.json = lambda: {"accessJwt": "fake.jwt", "refreshJwt": "fake.refresh"}
        resp.text = ""
        return resp

    async def fake_get(self, url, **kwargs):  # noqa: ARG001
        # AsyncClient instance carries the headers we constructed in fetch_entries
        captured_headers.update(dict(getattr(self, "headers", {}) or {}))
        post = _make_post(cid="bafyrei_auth")["post"]
        resp = AsyncMock()
        resp.status_code = 200
        resp.json = lambda: {"feed": [{"post": post}]}
        resp.text = ""
        return resp

    with patch.object(httpx.AsyncClient, "post", new=fake_post), patch.object(httpx.AsyncClient, "get", new=fake_get):
        adapter = BlueskyAdapter()
        _, entries = await adapter.fetch_entries(
            {
                "mode": "author",
                "handle": "alice.bsky.social",
                "identifier": "me.bsky.social",
                "app_password": "abcd-efgh-ijkl-mnop",
                "_feed_id": "feed-uuid-1",
            },
            since=None,
        )
        assert len(entries) == 1
        # Authorization header should have been set on the AsyncClient that fetched posts
        auth = captured_headers.get("Authorization") or captured_headers.get("authorization")
        assert auth == "Bearer fake.jwt"


# ---------- _apply_post_ingest_links author_entity attribution ----------


@pytest.mark.asyncio
async def test_apply_post_ingest_links_threat_actor():
    from unittest.mock import MagicMock

    from app.workers.feed_tasks import _apply_post_ingest_links

    db = MagicMock()
    db.execute = AsyncMock()
    feed = MagicMock(id="feed-1")
    entry = MagicMock(id="entry-1")
    parsed = MagicMock()

    config = {
        "author_entity": {
            "type": "threat_actor",
            "id": "00000000-0000-0000-0000-000000000001",
        }
    }
    await _apply_post_ingest_links(db, feed, entry, parsed, config)
    assert db.execute.await_count == 1


@pytest.mark.asyncio
async def test_apply_post_ingest_links_vendor():
    from unittest.mock import MagicMock

    from app.workers.feed_tasks import _apply_post_ingest_links

    db = MagicMock()
    db.execute = AsyncMock()
    feed = MagicMock(id="feed-1")
    entry = MagicMock(id="entry-1")
    parsed = MagicMock()

    config = {
        "author_entity": {
            "type": "vendor",
            "id": "00000000-0000-0000-0000-000000000002",
        }
    }
    await _apply_post_ingest_links(db, feed, entry, parsed, config)
    assert db.execute.await_count == 1


@pytest.mark.asyncio
async def test_apply_post_ingest_links_product():
    from unittest.mock import MagicMock

    from app.workers.feed_tasks import _apply_post_ingest_links

    db = MagicMock()
    db.execute = AsyncMock()
    feed = MagicMock(id="feed-1")
    entry = MagicMock(id="entry-1")
    parsed = MagicMock()

    config = {
        "author_entity": {
            "type": "product",
            "id": "00000000-0000-0000-0000-000000000003",
        }
    }
    await _apply_post_ingest_links(db, feed, entry, parsed, config)
    assert db.execute.await_count == 1


@pytest.mark.asyncio
async def test_apply_post_ingest_links_no_attribution_is_noop():
    from unittest.mock import MagicMock

    from app.workers.feed_tasks import _apply_post_ingest_links

    db = MagicMock()
    db.execute = AsyncMock()
    feed = MagicMock(id="feed-1")
    entry = MagicMock(id="entry-1")
    parsed = MagicMock()

    await _apply_post_ingest_links(db, feed, entry, parsed, {})
    assert db.execute.await_count == 0


@pytest.mark.asyncio
async def test_apply_post_ingest_links_invalid_type_is_noop():
    from unittest.mock import MagicMock

    from app.workers.feed_tasks import _apply_post_ingest_links

    db = MagicMock()
    db.execute = AsyncMock()
    feed = MagicMock(id="feed-1")
    entry = MagicMock(id="entry-1")
    parsed = MagicMock()

    config = {"author_entity": {"type": "unknown", "id": "00000000-0000-0000-0000-000000000004"}}
    await _apply_post_ingest_links(db, feed, entry, parsed, config)
    assert db.execute.await_count == 0
