"""Feed fetch health: the curl_cffi fallback for bot walls and which client is
remembered, the failure backoff, why a feed was paused, and the reachable-but-
empty flag."""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.feed import Feed
from app.services.feed_fetch_health import (
    EMPTY_UNHEALTHY_DAYS,
    FETCH_HEALTH_KEY,
    health_warning,
    note_items,
    pause_reason,
)
from app.workers.feed_tasks import DUE_FEEDS_SQL, _auto_pause_dead_feeds

RSS_ONE_ITEM = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>CISA</title><link>https://www.cisa.gov</link>
<item><title>Advisory AA26-001A</title><link>https://www.cisa.gov/aa26-001a</link>
<guid>https://www.cisa.gov/aa26-001a</guid><description>Advisory text.</description>
<pubDate>Mon, 05 Oct 2026 12:00:00 GMT</pubDate></item>
</channel></rss>"""

RSS_EMPTY = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Empty</title><link>https://e.example</link></channel></rss>"""


def _feed(**kw) -> Feed:
    defaults = dict(
        title="CISA Cybersecurity Advisories",
        url="https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
        feed_type="rss",
        is_active=True,
        etag='"etag-1"',
        last_modified="Mon, 05 Oct 2026 00:00:00 GMT",
        error_count=0,
        adapter_config={},
    )
    defaults.update(kw)
    feed = Feed(**defaults)
    feed.id = uuid.uuid4()
    return feed


def _response(status: int, body: str = "", url: str | None = None, content_type: str = "application/rss+xml"):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {"content-type": content_type}
    r.url = url or ""
    return r


def _session_for(feed: Feed):
    calls = {"n": 0}

    async def execute(_stmt):
        calls["n"] += 1
        result = MagicMock()
        result.scalar_one_or_none.return_value = feed if calls["n"] == 1 else None
        result.all.return_value = []
        return result

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=execute)
    db.add = MagicMock()
    nested = AsyncMock()
    db.begin_nested = MagicMock(return_value=nested)
    ctx = AsyncMock()
    ctx.__aenter__.return_value = db
    ctx.__aexit__.return_value = None
    return ctx, db


def _httpx_client(*responses):
    client = AsyncMock()
    client.get.side_effect = list(responses)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


async def _run_fetch(feed: Feed, httpx_client, curl):
    ctx, db = _session_for(feed)
    with (
        patch("app.workers.feed_tasks._get_worker_session", return_value=ctx),
        patch("httpx.AsyncClient", return_value=httpx_client),
        patch("app.workers.feed_tasks.safe_curl_get", curl),
        patch("app.services.rate_limiter.acquire_rate_limit", new_callable=AsyncMock, return_value=True),
        patch("app.workers.feed_tasks._resolve_user_agent", new_callable=AsyncMock, return_value="Mozilla/5.0 X"),
        patch("app.workers.feed_tasks._extract_full_text", new_callable=AsyncMock, return_value=(None, None)),
        patch("app.workers.feed_tasks._fetch_og_image", new_callable=AsyncMock, return_value=None),
        patch("app.workers.feed_tasks._maybe_create_feed_error_event", new_callable=AsyncMock),
        patch("app.workers.feed_tasks.dispatch_entry_pipeline"),
        patch("app.workers.automation_tasks.run_entry_automations"),
        patch("app.api.events.broadcast_event"),
        patch("app.services.meilisearch_client.index_entry"),
        patch("app.pipeline.plans.resolve_feed_plan", new_callable=AsyncMock, return_value=None),
    ):
        from app.workers.feed_tasks import _fetch_feed

        await _fetch_feed(str(feed.id))
    return db


def _client_memory(feed: Feed):
    return (feed.adapter_config or {}).get(FETCH_HEALTH_KEY, {}).get("client")


# --- 403 -> curl_cffi --------------------------------------------------------


@pytest.mark.asyncio
async def test_403_retries_through_curl_cffi_and_remembers_it():
    feed = _feed()
    client = _httpx_client(_response(403, "<html>Access Denied</html>", content_type="text/html"))
    curl = AsyncMock(return_value=_response(200, RSS_ONE_ITEM, url=feed.url))

    db = await _run_fetch(feed, client, curl)

    curl.assert_awaited_once()
    args, kwargs = curl.call_args
    assert args[0] == feed.url
    assert kwargs["impersonate"] == "chrome"
    assert kwargs["timeout"] == 30.0
    sent = kwargs["headers"]
    assert sent["If-None-Match"] == '"etag-1"'
    assert sent["If-Modified-Since"] == "Mon, 05 Oct 2026 00:00:00 GMT"
    assert "User-Agent" not in sent, "impersonation supplies a UA that matches its TLS fingerprint"

    assert feed.error_count == 0 and feed.last_error is None
    assert _client_memory(feed) == "curl_cffi"
    added = [c.args[0] for c in db.add.call_args_list]
    assert any(getattr(a, "title", None) == "Advisory AA26-001A" for a in added if a is not feed)


@pytest.mark.asyncio
async def test_remembered_client_is_used_first():
    feed = _feed(adapter_config={FETCH_HEALTH_KEY: {"client": "curl_cffi"}})
    client = _httpx_client()
    curl = AsyncMock(return_value=_response(304))

    await _run_fetch(feed, client, curl)

    curl.assert_awaited_once()
    client.get.assert_not_awaited()
    assert _client_memory(feed) == "curl_cffi"
    assert feed.error_count == 0


@pytest.mark.asyncio
async def test_remembered_curl_falls_back_to_httpx_and_forgets():
    feed = _feed(adapter_config={FETCH_HEALTH_KEY: {"client": "curl_cffi"}, "keep": 1})
    client = _httpx_client(_response(304))
    curl = AsyncMock(side_effect=RuntimeError("curl: (35) TLS connect error"))

    await _run_fetch(feed, client, curl)

    client.get.assert_awaited_once()
    assert _client_memory(feed) is None
    assert feed.adapter_config == {"keep": 1}
    assert feed.error_count == 0


@pytest.mark.asyncio
async def test_remembered_curl_blocked_falls_back_to_httpx():
    feed = _feed(adapter_config={FETCH_HEALTH_KEY: {"client": "curl_cffi"}})
    client = _httpx_client(_response(304))
    curl = AsyncMock(return_value=_response(403, "denied"))

    await _run_fetch(feed, client, curl)

    assert _client_memory(feed) is None
    assert feed.error_count == 0


@pytest.mark.asyncio
async def test_both_clients_blocked_records_the_403():
    feed = _feed()
    client = _httpx_client(_response(403, "denied"))
    curl = AsyncMock(return_value=_response(403, "denied"))

    await _run_fetch(feed, client, curl)

    assert feed.error_count == 1 and feed.last_error == "HTTP 403"
    assert _client_memory(feed) is None


@pytest.mark.asyncio
async def test_dropped_connection_retries_through_curl_cffi_and_remembers_it():
    """SiteGround's anti-bot hangs up on Python's TLS handshake instead of
    answering 403, so the bot-wall check never saw a status. Cyber Security
    News, HACKMAGEDDON and Sekoia failed this way for 12 days on prod."""
    feed = _feed()
    client = _httpx_client(httpx.RemoteProtocolError("Server disconnected without sending a response."))
    curl = AsyncMock(return_value=_response(200, RSS_ONE_ITEM, url=feed.url))

    await _run_fetch(feed, client, curl)

    curl.assert_awaited_once()
    assert feed.error_count == 0 and feed.last_error is None
    assert _client_memory(feed) == "curl_cffi"


@pytest.mark.asyncio
async def test_host_down_does_not_try_curl():
    feed = _feed()
    curl = AsyncMock(return_value=_response(304))

    await _run_fetch(feed, _httpx_client(httpx.ConnectTimeout("timed out")), curl)

    curl.assert_not_awaited()
    assert feed.error_count == 1


@pytest.mark.asyncio
async def test_dropped_connection_keeps_the_httpx_error_when_curl_fails_too():
    feed = _feed()
    client = _httpx_client(httpx.RemoteProtocolError("Server disconnected without sending a response."))
    curl = AsyncMock(side_effect=RuntimeError("curl: (28) Operation timed out"))

    await _run_fetch(feed, client, curl)

    curl.assert_awaited_once()
    assert feed.error_count == 1
    assert "Server disconnected" in (feed.last_error or "")
    assert _client_memory(feed) is None


@pytest.mark.asyncio
async def test_plain_503_does_not_try_curl_but_a_challenge_page_does():
    feed = _feed()
    curl = AsyncMock(return_value=_response(304))
    await _run_fetch(feed, _httpx_client(_response(503, "Service Unavailable")), curl)
    curl.assert_not_awaited()
    assert feed.last_error == "HTTP 503"

    feed = _feed()
    curl = AsyncMock(return_value=_response(304))
    challenge = "<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/x'></script>"
    await _run_fetch(feed, _httpx_client(_response(503, challenge, content_type="text/html")), curl)
    curl.assert_awaited_once()
    assert feed.error_count == 0
    assert _client_memory(feed) == "curl_cffi"


# --- reachable but empty -----------------------------------------------------


@pytest.mark.asyncio
async def test_redirect_to_a_page_with_no_items_is_flagged():
    feed = _feed(url="https://www.mandiant.com/resources/blog/rss.xml")
    landing = "https://cloud.google.com/security/mandiant-services"
    client = _httpx_client(_response(200, RSS_EMPTY, url=landing, content_type="application/xml"))

    await _run_fetch(feed, client, AsyncMock())

    warning = health_warning(feed)
    assert warning and warning["kind"] == "redirected_no_items"
    assert warning["redirected_to"] == landing


def test_empty_feed_is_flagged_only_after_the_grace_period_and_cleared_by_items():
    feed = _feed()
    note_items(feed, 0, final_url=feed.url)
    assert health_warning(feed) is None, "a feed empty since this morning is not yet unhealthy"

    cfg = dict(feed.adapter_config)
    cfg[FETCH_HEALTH_KEY] = dict(cfg[FETCH_HEALTH_KEY])
    old = (datetime.now(UTC) - timedelta(days=EMPTY_UNHEALTHY_DAYS + 1)).isoformat()
    cfg[FETCH_HEALTH_KEY]["empty"] = {**cfg[FETCH_HEALTH_KEY]["empty"], "since": old}
    feed.adapter_config = cfg

    note_items(feed, 0, final_url=feed.url)
    warning = health_warning(feed)
    assert warning and warning["kind"] == "no_items" and warning["days"] >= EMPTY_UNHEALTHY_DAYS
    assert warning["since"] == old, "the streak start must not move"

    note_items(feed, 5, final_url=feed.url)
    assert health_warning(feed) is None
    assert FETCH_HEALTH_KEY not in feed.adapter_config


def test_same_url_with_www_or_trailing_slash_is_not_a_redirect():
    feed = _feed(url="https://example.com/feed/")
    note_items(feed, 0, final_url="https://www.example.com/feed")
    assert feed.adapter_config[FETCH_HEALTH_KEY]["empty"]["redirected_to"] is None


# --- auto-pause and backoff ----------------------------------------------------


@pytest.mark.asyncio
async def test_auto_pause_records_why(db_session: AsyncSession):
    since = datetime.now(UTC) - timedelta(days=31)
    blocked = Feed(
        title="ICS Advisories",
        url="https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
        feed_type="rss",
        error_count=35,
        last_error="HTTP 403",
        error_since=since,
        adapter_config={"other": True},
    )
    off = Feed(title="Off by hand", url="https://off.example/rss", feed_type="rss", is_active=False)
    db_session.add_all([blocked, off])
    await db_session.flush()

    assert await _auto_pause_dead_feeds(db_session, 30) == 1
    await db_session.refresh(blocked)

    reason = pause_reason(blocked)
    assert reason["reason"] == "http_4xx"
    assert reason["status"] == 403 and reason["last_error"] == "HTTP 403"
    assert reason["failures"] == 35 and reason["days"] == 31
    assert reason["client"] == "httpx" and reason["paused_at"]
    assert blocked.adapter_config["other"] is True
    assert pause_reason(off) is None, "a feed a person switched off has no pause reason"


def test_pause_reason_for_feeds_paused_before_the_snapshot_existed():
    since = datetime.now(UTC) - timedelta(days=40)
    feed = _feed(
        is_active=False,
        auto_paused_at=since + timedelta(days=30),
        last_error="HTTP 403",
        error_since=since,
        error_count=5660,
    )
    reason = pause_reason(feed)
    assert reason["status"] == 403 and reason["failures"] == 5660 and reason["days"] == 30


@pytest.mark.asyncio
async def test_poller_backs_off_while_a_feed_keeps_failing(db_session: AsyncSession):
    now = datetime.now(UTC)

    def mk(name, minutes_ago, errors, interval=10):
        return Feed(
            title=name,
            url=f"https://{name}.example/rss",
            feed_type="rss",
            fetch_interval_minutes=interval,
            last_fetched_at=now - timedelta(minutes=minutes_ago),
            error_count=errors,
        )

    feeds = {
        "healthy": mk("healthy", 11, 0),  # due: 11 > 10
        "one_fail": mk("one_fail", 11, 1),  # backoff 20 min: not due
        "one_fail_due": mk("one_fail_due", 21, 1),  # due
        "long_streak": mk("long_streak", 600, 50),  # capped at 640 (10*64): not due
        "long_streak_due": mk("long_streak_due", 641, 50),  # due
        "capped_day": mk("capped_day", 1441, 50, interval=60),  # 60*64 capped to 1440: due
        "long_interval": mk("long_interval", 2000, 9, interval=2880),  # never below its own interval
    }
    db_session.add_all(feeds.values())
    await db_session.flush()

    rows = await db_session.execute(text(DUE_FEEDS_SQL), {"per_user": False})
    due = {r[0] for r in rows.all()}
    names = {name for name, f in feeds.items() if f.id in due}
    assert names == {"healthy", "one_fail_due", "long_streak_due", "capped_day"}


# --- API ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_exposes_pause_reason_and_protects_fetch_health(client, admin_headers, db_session: AsyncSession):
    since = datetime.now(UTC) - timedelta(days=31)
    feed = Feed(
        title="Oracle Security Alerts",
        url="https://www.oracle.com/rss-otn-sec.xml",
        feed_type="rss",
        is_active=False,
        auto_paused_at=datetime.now(UTC),
        error_count=40,
        last_error="HTTP 403",
        error_since=since,
        adapter_config={FETCH_HEALTH_KEY: {"client": "curl_cffi"}},
    )
    db_session.add(feed)
    await db_session.commit()

    resp = await client.get(f"/api/feeds/{feed.id}", headers=admin_headers)
    if resp.status_code == 200:
        body = resp.json()
        assert body["pause_reason"]["status"] == 403
        assert body["auto_paused_at"]

    health = (await client.get("/api/feeds/health", headers=admin_headers)).json()
    dead = {f["id"]: f for f in health["dead_feeds"]}
    assert dead[str(feed.id)]["pause_reason"]["last_error"] == "HTTP 403"

    # A stale copy of fetch_health echoed back by a client must not win.
    resp = await client.put(
        f"/api/feeds/{feed.id}",
        json={"adapter_config": {FETCH_HEALTH_KEY: {"client": "httpx"}, "note": "x"}},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(feed)
    assert feed.adapter_config[FETCH_HEALTH_KEY]["client"] == "curl_cffi"
    assert feed.adapter_config["note"] == "x"

    resp = await client.post(f"/api/feeds/{feed.id}/resume", headers=admin_headers)
    assert resp.status_code == 200
    await db_session.refresh(feed)
    assert feed.is_active and feed.auto_paused_at is None
    assert "paused" not in feed.adapter_config.get(FETCH_HEALTH_KEY, {})
    assert feed.adapter_config[FETCH_HEALTH_KEY]["client"] == "curl_cffi", "client memory survives a resume"


@pytest.mark.asyncio
async def test_health_endpoint_lists_empty_feeds(client, admin_headers, db_session: AsyncSession):
    feed = Feed(
        title="Mandiant",
        url="https://www.mandiant.com/resources/blog/rss.xml",
        feed_type="rss",
        last_fetched_at=datetime.now(UTC),
        error_count=0,
        adapter_config={},
    )
    note_items(feed, 0, final_url="https://cloud.google.com/security/mandiant-services")
    db_session.add(feed)
    await db_session.commit()

    health = (await client.get("/api/feeds/health", headers=admin_headers)).json()
    assert health["summary"]["empty"] == 1
    (row,) = health["empty_feeds"]
    assert row["id"] == str(feed.id)
    assert row["health_warning"]["kind"] == "redirected_no_items"
    assert httpx.URL(row["health_warning"]["redirected_to"]).host == "cloud.google.com"
