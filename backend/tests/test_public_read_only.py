"""Public read-only mode (issue #136): who may reach what, and what visitors see.

The route walk below is the guard that keeps the mode safe as the API grows:
every route that a visitor can reach, and every route with no login at all,
is listed here by hand. A new route that takes ``get_viewer`` or skips auth
fails ``test_every_open_route_is_classified`` until someone decides it belongs.
"""

import re
import uuid

import pytest
import pytest_asyncio
from fastapi.routing import APIRoute
from httpx import AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.main import app
from app.models.entry import Entry
from app.models.feed import Feed
from app.services.public_view import HIDDEN_WIDGET_TYPES, scrub_for_visitor

#: Routes a visitor may read while the switch is on (they take ``get_viewer``).
VISITOR_ROUTES = frozenset(
    """
    GET /api/analytics/overview
    GET /api/analytics/trending/{entity_type}
    GET /api/analytics/velocity
    GET /api/attack/layer
    GET /api/attack/matrix
    GET /api/attack/techniques
    GET /api/categories
    GET /api/countries
    GET /api/countries/{country_id}
    GET /api/countries/{country_id}/profile
    GET /api/cves
    GET /api/cves/trending
    GET /api/cves/{cve_id}
    GET /api/cves/{cve_id}/affected
    GET /api/cves/{cve_id}/weaknesses
    GET /api/cwes
    GET /api/cwes/rollup
    GET /api/cwes/{cwe_id}
    GET /api/cwes/{cwe_id}/affected-cves
    GET /api/cwes/{cwe_id}/family
    GET /api/cwes/{cwe_id}/vendors
    GET /api/dashboards
    GET /api/dashboards/{dashboard_id}
    GET /api/documentation
    GET /api/documentation/{slug:path}
    GET /api/engine/entities/{entity_type}/{entity_id}/whats-new
    GET /api/entities/{entity_type}/{entity_id}/attack-layer
    GET /api/entities/{entity_type}/{entity_id}/attack-techniques
    GET /api/entities/{entity_type}/context-columns
    POST /api/entities/{entity_type}/context-values
    GET /api/entities/{entity_type}/{entity_id}/context
    GET /api/entities/{entity_type}/{entity_id}/glance
    GET /api/entities/{entity_type}/{entity_id}/entries-window
    GET /api/entities/{entity_type}/{entity_id}/mentions-timeseries
    GET /api/entities/{entity_type}/{entity_id}/provenance
    GET /api/entities/{entity_type}/{entity_id}/story-threads
    GET /api/entities/{entity_type}/{entity_id}/target-sectors
    GET /api/entities/{entity_type}/{entity_id}/top-entries
    GET /api/entity-links
    GET /api/entity-relationships
    GET /api/entity-relationships/by-entity/{entity_type}/{entity_id}
    POST /api/entity-relationships/signals/{entity_type}
    GET /api/entries
    GET /api/entries/calendar
    GET /api/entries/count
    GET /api/entries/day-entities
    GET /api/entries/day-intel
    GET /api/entries/map
    GET /api/entries/priority-queue
    GET /api/entries/priority-unread-count
    GET /api/entries/{entry_id}
    GET /api/entries/{entry_id}/article-metadata
    GET /api/entries/{entry_id}/countries
    GET /api/entries/{entry_id}/cves
    GET /api/entries/{entry_id}/cwes
    GET /api/entries/{entry_id}/kill-chain
    GET /api/entries/{entry_id}/malware
    GET /api/entries/{entry_id}/mitigations
    GET /api/entries/{entry_id}/products
    GET /api/entries/{entry_id}/sectors
    GET /api/entries/{entry_id}/similar
    GET /api/entries/{entry_id}/threat-actors
    GET /api/entries/{entry_id}/tools
    GET /api/entries/{entry_id}/ttps
    GET /api/entries/{entry_id}/ttps/navigator
    GET /api/entries/{entry_id}/urls
    GET /api/entries/{entry_id}/vendors
    GET /api/feeds
    GET /api/feeds/{feed_id}
    GET /api/feeds/{feed_id}/entries
    GET /api/glossary
    GET /api/glossary/categories
    GET /api/glossary/counts
    GET /api/glossary/{term_id}/entries
    GET /api/intelligence/entry-graph/{entry_id}
    GET /api/intelligence/events/grouped
    GET /api/intelligence/graph/{entity_type}/{entity_id}
    GET /api/intelligence/pivot/{entity_type}/{entity_id}
    GET /api/intelligence/temporal-clusters
    GET /api/intelligence/timeline/{entity_type}/{entity_id}
    GET /api/malware
    GET /api/malware/{malware_id}
    GET /api/mitigations
    GET /api/mitigations/{mitigation_id}
    GET /api/products
    GET /api/products/{product_id}
    GET /api/products/{product_id}/affected-cves
    GET /api/products/{product_id}/weaknesses
    GET /api/proxy/image
    GET /api/regions
    GET /api/sectors
    GET /api/sectors/{sector_ref}
    GET /api/sectors/{sector_ref}/profile
    GET /api/tags
    GET /api/tags/entries/{entry_id}
    GET /api/themes
    GET /api/themes/{theme_id}
    GET /api/threads
    GET /api/threads/{slug}
    GET /api/threat-actors
    GET /api/threat-actors/{actor_id}
    GET /api/tools
    GET /api/tools/{tool_id:uuid}
    GET /api/ttps
    GET /api/ttps/by-technique/{technique_id}
    GET /api/ttps/{ttp_id}/mitigations
    GET /api/ttps/{ttp_id}/related-techniques
    GET /api/vendors
    GET /api/vendors/{vendor_id}
    GET /api/vendors/{vendor_id}/affected-cves
    GET /api/vendors/{vendor_id}/products
    GET /api/vendors/{vendor_id}/weaknesses
    GET /api/widgets/actor-activity
    GET /api/widgets/attack-heatmap
    GET /api/widgets/correlation-events
    GET /api/widgets/cve-severity
    GET /api/widgets/feed-activity
    GET /api/widgets/hot-correlations
    GET /api/widgets/kev-deadlines
    GET /api/widgets/kev-matches
    GET /api/widgets/new-actors
    GET /api/widgets/new-cves
    GET /api/widgets/overview
    GET /api/widgets/stats
    GET /api/widgets/targeted-countries
    GET /api/widgets/threat-timeline
    GET /api/widgets/top-tags
    GET /api/widgets/trending-cves
    GET /api/widgets/trending-products
    GET /api/widgets/trending-vendors
    GET /api/widgets/triage-flow
    GET /api/widgets/triage-queue-stats
    GET /api/widgets/under-reported
    GET /api/widgets/weekly-recap
    POST /api/entries/intel-counts
    POST /api/autolink/scan
    POST /api/entries/resolve-names
    POST /api/glossary/detect
    POST /api/intelligence/resolve-names
    GET /api/tts/existing
    """.split("\n")
) - {""}
VISITOR_ROUTES = frozenset(r.strip() for r in VISITOR_ROUTES) - {""}

#: Routes with no login at all — each has its own audience and its own check.
OWN_AUTH_ROUTES = frozenset(
    {
        "GET /docs",
        "GET /redoc",
        "GET /api/auth/registration-status",
        "POST /api/auth/login",
        "POST /api/auth/logout",
        "POST /api/auth/refresh",
        "POST /api/auth/register",
        "GET /api/documentation/assets/{path:path}",
        "GET /api/events",
        "GET /api/health",
        "GET /api/version",
        "GET /api/ingest-files/{file_id}",
        "GET /api/intelligence/feed",
        "GET /metrics",
        "GET /api/public/rss/{token}.xml",
        "GET /api/public/rss/{token}/categories",
        "GET /api/public/rss/{token}/category/{slug}.xml",
        "GET /api/publish/edl/{filename}",
        "GET /api/publish/lookup/{filename}",
        "GET /api/taxii2/",
        "GET /api/taxii2/api/",
        "GET /api/taxii2/api/collections/",
        "GET /api/taxii2/api/collections/{collection_id}/",
        "GET /api/taxii2/api/collections/{collection_id}/objects/",
        "GET /api/shared/copilot/{token}",
        "GET /api/shared/{token}",
        "GET /api/shared/{token}/og",
        "GET /api/shared/{token}/tts/file/{cache_key}.mp3",
        "POST /api/shared/{token}/ask-agent",
        "POST /api/shared/{token}/run-ai-task",
        "POST /api/shared/{token}/tts/prepare",
        "GET /api/telegram-media/{channel_id}/{filename}",
        "GET /api/themes/default",
        "GET /api/themes/default.css",
        "GET /api/themes/schema",
        "GET /api/tts/file/{cache_key}.mp3",
    }
)

_AUTH_DEPS = {"get_current_user", "get_admin_user", "get_current_user_from_query", "get_tool_caller", "get_viewer"}


def _dep_names(dependant, acc: set[str]) -> set[str]:
    for d in dependant.dependencies:
        if d.call is not None:
            acc.add(getattr(d.call, "__name__", ""))
        _dep_names(d, acc)
    return acc


def _routes() -> list[tuple[str, APIRoute, set[str]]]:
    # FastAPI 0.153+ keeps each included router as one nested entry in
    # app.routes; iter_route_contexts flattens them with their full paths.
    try:
        from fastapi.routing import iter_route_contexts
    except ImportError:  # older FastAPI: app.routes is already flat
        contexts = app.routes
    else:
        contexts = list(iter_route_contexts(app.routes))
    out = []
    for r in contexts:
        if isinstance(getattr(r, "original_route", r), APIRoute):
            deps = _dep_names(r.dependant, set())
            for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
                out.append((f"{m} {r.path}", r, deps))
    return out


@pytest.fixture
def public_mode(monkeypatch):
    """Turn the switch on (env default; the test DB has no override row)."""
    monkeypatch.setattr(settings, "public_read_only_enabled", True)


@pytest.fixture
def fresh_rate_limits(monkeypatch):
    """Give this test's anonymous requests a client identity of their own.

    Rate-limit windows live in the shared dev Redis for up to an hour, and the
    test client's addresses repeat across runs and across parallel workers;
    a fresh identity starts every bucket empty without touching anyone else's.
    """
    from app.core import rate_limit

    own = f"ip:test-{uuid.uuid4()}"
    original = rate_limit._get_identity
    monkeypatch.setattr(
        rate_limit, "_get_identity", lambda request: own if (ident := original(request)).startswith("ip:") else ident
    )


@pytest_asyncio.fixture
async def shown_entry(db_session: AsyncSession, test_entry: Entry, test_feed: Feed) -> Entry:
    """The test entry, in a feed an admin has marked visible to visitors."""
    test_feed.visible_to_visitors = True
    await db_session.flush()
    return test_entry


# ── Classification ───────────────────────────────────────────────────


def test_every_open_route_is_classified():
    """A route a visitor can reach, or one with no login, must be listed above."""
    visitor, no_auth = set(), set()
    for key, _route, deps in _routes():
        if "get_viewer" in deps:
            visitor.add(key)
        elif not deps & _AUTH_DEPS:
            no_auth.add(key)
    assert visitor == VISITOR_ROUTES, {
        "unlisted visitor routes": sorted(visitor - VISITOR_ROUTES),
        "listed but not visitor": sorted(VISITOR_ROUTES - visitor),
    }
    assert no_auth == OWN_AUTH_ROUTES, {
        "unlisted unauthenticated routes": sorted(no_auth - OWN_AUTH_ROUTES),
        "listed but authenticated": sorted(OWN_AUTH_ROUTES - no_auth),
    }


def test_visitor_routes_about_one_article_check_it_is_visible():
    """A route keyed by an entry id reads junction rows the visitor filter
    never sees; get_entry_viewer 404s an entry from a hidden feed first."""
    unguarded = sorted(
        key
        for key, _route, deps in _routes()
        if key in VISITOR_ROUTES and "{entry_id}" in key and "get_entry_viewer" not in deps
    )
    assert unguarded == []


def test_visitor_routes_are_reads_or_reviewed_posts():
    from app.core.public_access import ANONYMOUS_READ_POST_TEMPLATES, ANONYMOUS_READ_POSTS

    writes = {k for k in VISITOR_ROUTES if not k.startswith("GET ")}
    assert writes == {f"POST {p}" for p in ANONYMOUS_READ_POSTS | set(ANONYMOUS_READ_POST_TEMPLATES)}


@pytest.mark.asyncio
async def test_relationship_signals_open_to_visitors_with_a_larger_cap(client: AsyncClient, public_mode):
    url = "/api/entity-relationships/signals/threat_actor"
    page = [str(uuid.uuid4()) for _ in range(300)]
    assert (await client.post(url, json={"ids": page})).status_code == 200
    # Past the 1000 ids the route reads, the body is refused before it is parsed.
    too_many = [str(uuid.uuid4()) for _ in range(1400)]
    assert (await client.post(url, json={"ids": too_many})).status_code == 413
    # Any other path under it is still a write and still locked.
    assert (await client.post(url + "/extra", json={"ids": page})).status_code == 401


def test_openapi_keeps_the_real_login_check():
    route = next(r for k, r, _ in _routes() if k == "GET /openapi.json")
    assert "get_current_user" in _dep_names(route.dependant, set())


# ── Walking every visitor route ──────────────────────────────────────

_PARAM_VALUES = {
    "entity_type": "threat_actor",
    "slug": "no-such-thread",
    "technique_id": "T1059",
    "sector_ref": "healthcare",
    "cve_id": "CVE-2024-1234",
    "cwe_id": "CWE-79",
}


def _fill(path: str, overrides: dict[str, str]) -> str:
    def value(m: re.Match) -> str:
        name = m.group(1).split(":")[0]
        return overrides.get(name) or _PARAM_VALUES.get(name, str(uuid.uuid4()))

    return re.sub(r"\{([^}]+)\}", value, path)


@pytest.fixture
def no_rate_limit(monkeypatch):
    """The walks send ~140 requests from one address; they test access, not the budget."""
    from app.core import rate_limit

    monkeypatch.setattr(rate_limit, "_get_limits", lambda *a, **kw: None)


async def _walk(client: AsyncClient, **overrides: str) -> dict[str, int]:
    statuses = {}
    for key in sorted(VISITOR_ROUTES):
        method, path = key.split(" ", 1)
        url = _fill(path, overrides)
        if path == "/api/proxy/image":
            url += "?url=https://example.com/a.png"
        if path == "/api/tts/existing":
            url += f"?source=entry&id={uuid.uuid4()}"
        if method == "GET":
            resp = await client.get(url)
        else:
            resp = await client.post(url, json={"entry_ids": [], "names": [], "text": "x"})
        statuses[key] = resp.status_code
    return statuses


@pytest.mark.asyncio
async def test_switch_off_every_visitor_route_still_needs_a_login(client: AsyncClient, no_rate_limit):
    statuses = await _walk(client)
    assert {k: s for k, s in statuses.items() if s != 401} == {}


@pytest.mark.asyncio
async def test_switch_on_visitor_routes_answer_without_writes_or_background_work(
    client: AsyncClient, db_session: AsyncSession, public_mode, monkeypatch, shown_entry, no_rate_limit
):
    dispatched = []
    from celery.app.task import Task

    monkeypatch.setattr(Task, "apply_async", lambda self, *a, **kw: dispatched.append(self.name))
    writes = []

    def _no_writes(session, flush_context, instances):
        if session.new or session.dirty or session.deleted:
            writes.append((list(session.new), list(session.dirty), list(session.deleted)))

    event.listen(db_session.sync_session, "before_flush", _no_writes)
    try:
        statuses = await _walk(client, entry_id=str(shown_entry.id))
    finally:
        event.remove(db_session.sync_session, "before_flush", _no_writes)

    assert {k: s for k, s in statuses.items() if s in (401, 403, 429) or s >= 500} == {}
    assert dispatched == []
    assert writes == []


@pytest.mark.asyncio
async def test_switch_on_locked_routes_stay_locked(client: AsyncClient, public_mode):
    for url in (
        "/api/search?q=x",
        "/api/notes",
        "/api/observables",
        "/api/campaigns",
        "/api/detection-rules",
        "/api/intel-reports",
        "/api/requirements",
        "/api/ransomware/victims",
        "/api/ai/results/entry/00000000-0000-0000-0000-000000000000",
        "/api/entries/daily-summary",
        "/api/system-settings",
        "/api/feeds/health",
        "/api/telegram/mentions",
        "/api/saved-searches",
        "/openapi.json",
    ):
        resp = await client.get(url)
        assert resp.status_code in (401, 404, 405), (url, resp.status_code)
        assert resp.status_code != 200


@pytest.mark.asyncio
async def test_switch_on_every_anonymous_write_is_refused(client: AsyncClient, public_mode, test_entry):
    for method, url in (
        ("POST", "/api/feeds"),
        ("POST", "/api/entries/mark-all-read"),
        ("POST", f"/api/entries/{test_entry.id}/translate"),
        ("POST", "/api/entries/daily-summary"),
        ("POST", "/api/tts/prepare"),
        ("POST", "/api/threads/00000000-0000-0000-0000-000000000000/open"),
        ("PUT", "/api/auth/me"),
        ("DELETE", f"/api/feeds/{uuid.uuid4()}"),
        ("PATCH", "/api/onboarding/status"),
        ("POST", "/api/search/advanced"),
    ):
        resp = await client.request(method, url, json={})
        assert resp.status_code == 401, (method, url, resp.status_code)


@pytest.mark.asyncio
async def test_read_posts_are_size_limited(client: AsyncClient, public_mode):
    resp = await client.post("/api/entries/intel-counts", content=b"x" * 20_000)
    assert resp.status_code == 413


# ── What a visitor sees ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_registration_status_reports_the_switch(client: AsyncClient, monkeypatch):
    assert (await client.get("/api/auth/registration-status")).json()["public_read_only_enabled"] is False
    monkeypatch.setattr(settings, "public_read_only_enabled", True)
    assert (await client.get("/api/auth/registration-status")).json()["public_read_only_enabled"] is True


@pytest.mark.asyncio
async def test_visitor_sees_feed_names_only(client: AsyncClient, public_mode, db_session: AsyncSession):
    feed = Feed(
        title="Vendor research",
        url="https://secret.example/feed.xml?key=abc",
        feed_type="rss",
        last_error="401 from upstream",
        error_count=3,
        analyst_notes="internal",
        visible_to_visitors=True,
    )
    db_session.add(feed)
    await db_session.flush()

    items = (await client.get("/api/feeds")).json()["items"]
    row = next(i for i in items if i["id"] == str(feed.id))
    assert row["title"] == "Vendor research"
    assert row["url"] == "" and row["last_error"] is None and row["error_count"] == 0
    assert row["analyst_notes"] is None
    detail = (await client.get(f"/api/feeds/{feed.id}")).json()
    assert "secret.example" not in str(detail)


@pytest.mark.asyncio
async def test_manual_uploads_are_invisible_to_visitors(
    client: AsyncClient, public_mode, db_session: AsyncSession, auth_headers
):
    # Hidden even if someone flags it.
    manual = Feed(title="Manual Uploads", url="manual://uploads", feed_type="manual", visible_to_visitors=True)
    db_session.add(manual)
    await db_session.flush()
    doc = Entry(feed_id=manual.id, title="Private upload", guid="up-1", url="https://x.example/up")
    db_session.add(doc)
    await db_session.flush()

    assert (await client.get(f"/api/entries/{doc.id}")).status_code == 404
    assert str(doc.id) not in (await client.get("/api/entries")).text
    assert str(manual.id) not in (await client.get("/api/feeds")).text
    # A signed-in reader still sees it.
    assert (await client.get(f"/api/entries/{doc.id}", headers=auth_headers)).status_code == 200


@pytest.mark.asyncio
async def test_visitor_entry_has_no_personal_state(client: AsyncClient, public_mode, shown_entry):
    data = (await client.get(f"/api/entries/{shown_entry.id}")).json()
    assert data["is_read"] is False and data["is_starred"] is False and data["is_bookmarked"] is False
    assert data.get("exposure") is None


@pytest.mark.asyncio
async def test_visitor_gets_the_trimmed_builtin_dashboards(client: AsyncClient, public_mode):
    boards = (await client.get("/api/dashboards")).json()["items"]
    assert [b["name"] for b in boards] == ["__triage__/Triage", "__triage__/Intel", "__triage__/CVE"]
    types = {w["widget_type"] for b in boards for w in b["widgets"]}
    assert types and not types & HIDDEN_WIDGET_TYPES
    one = (await client.get(f"/api/dashboards/{boards[1]['id']}")).json()
    assert one["name"] == "__triage__/Intel"


def test_visitor_boards_have_no_holes():
    """Hidden widgets leave no empty columns: nothing overlaps, every widget
    starts at the left edge or right after a neighbour, and none sits beside
    free space it could have widened into."""
    from app.services.public_view import _GRID_COLS, visitor_dashboards

    for board in visitor_dashboards():
        cells: dict[tuple[int, int], str] = {}
        for w in board.widgets:
            assert w.position_x + w.width <= _GRID_COLS
            for x in range(w.position_x, w.position_x + w.width):
                for y in range(w.position_y, w.position_y + w.height):
                    assert (x, y) not in cells, (board.name, w.widget_type, cells.get((x, y)))
                    cells[(x, y)] = w.widget_type
        for w in board.widgets:
            if w.position_x > 0:
                assert (w.position_x - 1, w.position_y) in cells, (board.name, w.widget_type)
            right = w.position_x + w.width
            if right < _GRID_COLS:
                assert any((right, y) in cells for y in range(w.position_y, w.position_y + w.height)), (
                    board.name,
                    w.widget_type,
                )


@pytest.mark.asyncio
async def test_api_responses_are_private_and_unindexed(client: AsyncClient, public_mode):
    resp = await client.get("/api/feeds")
    assert resp.headers["cache-control"] == "private, no-store"
    assert "noindex" in resp.headers["x-robots-tag"]


@pytest.mark.asyncio
async def test_image_proxy_refuses_arbitrary_urls_for_visitors(client: AsyncClient, public_mode, monkeypatch):
    monkeypatch.setattr(settings, "image_proxy_enabled", True)
    resp = await client.get("/api/proxy/image", params={"url": "https://example.com/not-in-any-article.png"})
    assert resp.status_code == 404


def test_scrub_drops_users_and_hidden_areas():
    payload = {
        "name": "APT29",
        "author": "Article byline",
        "claims": [{"value": "Russia", "analyst": "alice"}],
        "rule_count": 4,
        "pir_matches": [{"id": "p1"}],
        "notes": 2,
        "detection_opportunity": "actionable_gap",
        "source_campaigns": ["c1"],
        "coverage_summary": {"covered": 3},
        "has_rules": True,
        "graph": {
            "nodes": [{"id": "a", "type": "threat_actor"}, {"id": "c", "type": "campaign"}],
            "edges": [{"source": "a", "target": "c"}, {"source": "a", "target": "a"}],
        },
    }
    out = scrub_for_visitor(payload)
    assert out["author"] == "Article byline"
    assert out["claims"] == [{"value": "Russia"}]
    # Hidden lists and counts keep their shape, emptied, so a page reading
    # campaigns.length still renders; hidden objects are dropped.
    assert out["rule_count"] == 0 and out["source_campaigns"] == [] and out["pir_matches"] == []
    assert out["notes"] == 0 and out["has_rules"] is False
    assert "coverage_summary" not in out
    assert "detection_opportunity" not in out
    assert out["graph"]["nodes"] == [{"id": "a", "type": "threat_actor"}]
    assert out["graph"]["edges"] == [{"source": "a", "target": "a"}]


# --- Anonymous rate limits ---------------------------------------------------


def test_anonymous_buckets():
    from app.core.rate_limit import (
        ANON_ARTICLE_LIMITS,
        ANON_HEAVY_LIMITS,
        ANON_LIMITS,
        INDICATOR_FEED_LIMIT,
        _get_limits,
    )

    entry = f"/api/entries/{uuid.uuid4()}"
    assert _get_limits(entry, anonymous=True) == ("anon_article", ANON_ARTICLE_LIMITS)
    assert _get_limits(f"{entry}/ttps", anonymous=True) == ("anon", ANON_LIMITS)
    assert _get_limits("/api/entries", anonymous=True) == ("anon", ANON_LIMITS)
    assert _get_limits("/api/intelligence/graph/x", anonymous=True) == ("anon_heavy", ANON_HEAVY_LIMITS)
    assert _get_limits("/api/taxii2/api/collections/", anonymous=True) == (
        "indicator_feeds",
        (INDICATOR_FEED_LIMIT,),
    )
    assert _get_limits("/api/publish/edl/x.txt", anonymous=True)[0] == "indicator_feeds"
    # Signed-in reads stay unlimited.
    assert _get_limits(entry, anonymous=False) is None
    # Every anonymous bucket has a burst window and an hourly cap.
    for windows in (ANON_LIMITS, ANON_ARTICLE_LIMITS, ANON_HEAVY_LIMITS):
        assert [w for _, w in windows] == [60, 3600]


@pytest.mark.asyncio
async def test_anonymous_article_budget_refuses_then_recovers(
    client: AsyncClient, public_mode, shown_entry, auth_headers, monkeypatch, fresh_rate_limits
):
    from app.core import rate_limit

    monkeypatch.setitem(rate_limit._BUCKET_WINDOWS, "anon_article", ((2, 60), (3, 3600)))
    url = f"/api/entries/{shown_entry.id}"

    first = await client.get(url)
    assert first.status_code == 200
    assert first.headers["X-RateLimit-Remaining"] == "1"
    assert (await client.get(url)).status_code == 200

    refused = await client.get(url)
    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "rate_limited"
    assert 1 <= int(refused.headers["Retry-After"]) <= 61

    # The rest of the app is a separate budget, and a refused request isn't
    # counted against the next one.
    assert (await client.get(f"{url}/ttps")).status_code == 200
    assert (await client.get(url)).status_code == 429
    # Signed in, the same address is not limited.
    assert (await client.get(url, headers=auth_headers)).status_code == 200


@pytest.mark.asyncio
async def test_anonymous_hourly_cap_outlasts_the_minute(
    client: AsyncClient, public_mode, shown_entry, monkeypatch, fresh_rate_limits
):
    from app.core import rate_limit

    monkeypatch.setitem(rate_limit._BUCKET_WINDOWS, "anon_article", ((50, 60), (2, 3600)))
    url = f"/api/entries/{shown_entry.id}"
    assert (await client.get(url)).status_code == 200
    assert (await client.get(url)).status_code == 200
    refused = await client.get(url)
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) > 3000


# --- Which feeds visitors see ------------------------------------------------


@pytest.mark.asyncio
async def test_feeds_are_hidden_from_visitors_until_an_admin_shows_them(
    client: AsyncClient, public_mode, db_session: AsyncSession, test_entry: Entry, test_feed: Feed, auth_headers
):
    entry_id, feed_id = test_entry.id, test_feed.id
    url = f"/api/entries/{entry_id}"
    # A request starts with an empty session; the tests share one, so clear
    # it or db.get() answers from the fixtures already loaded in it.
    db_session.expunge_all()
    assert (await client.get(url)).status_code == 404
    assert str(entry_id) not in (await client.get("/api/entries")).text
    assert str(feed_id) not in (await client.get("/api/feeds")).text
    assert (await client.get(f"/api/feeds/{feed_id}")).status_code == 404
    # Signed in, nothing changes.
    assert (await client.get(url, headers=auth_headers)).status_code == 200

    feed = await db_session.get(Feed, feed_id)
    feed.visible_to_visitors = True
    await db_session.flush()
    db_session.expunge_all()
    assert (await client.get(url)).status_code == 200
    assert str(feed_id) in (await client.get("/api/feeds")).text


@pytest.mark.asyncio
async def test_only_an_admin_can_show_a_feed_to_visitors(
    client: AsyncClient, test_feed: Feed, auth_headers, admin_headers
):
    url = f"/api/feeds/{test_feed.id}"
    refused = await client.put(url, json={"visible_to_visitors": True}, headers=auth_headers)
    assert refused.status_code == 403
    assert "visible_to_visitors" in refused.json()["error"]["message"]

    ok = await client.put(url, json={"visible_to_visitors": True}, headers=admin_headers)
    assert ok.status_code == 200
    assert ok.json()["visible_to_visitors"] is True
    # Other edits leave it alone.
    again = await client.put(url, json={"custom_title": "Renamed"}, headers=admin_headers)
    assert again.json()["visible_to_visitors"] is True


@pytest.mark.asyncio
async def test_visitors_see_only_folders_holding_a_visible_feed(
    client: AsyncClient, public_mode, db_session: AsyncSession, test_user, auth_headers
):
    from app.models.category import Category

    parent = Category(created_by=test_user.id, name="Research", position=0)
    empty = Category(created_by=test_user.id, name="Empty folder", position=1)
    private = Category(created_by=test_user.id, name="Private folder", position=2)
    db_session.add_all([parent, empty, private])
    await db_session.flush()
    child = Category(
        created_by=test_user.id,
        name="Vendors",
        parent_id=parent.id,
        position=0,
        feed_defaults={"ai_analysis_enabled": False},
    )
    db_session.add(child)
    await db_session.flush()
    db_session.add_all(
        [
            Feed(
                title="Shown",
                url="https://a.example/feed",
                feed_type="rss",
                category_id=child.id,
                visible_to_visitors=True,
            ),
            Feed(title="Hidden", url="https://b.example/feed", feed_type="rss", category_id=private.id),
        ]
    )
    await db_session.flush()

    tree = (await client.get("/api/categories")).json()
    assert [c["name"] for c in tree] == ["Research"]
    assert [c["name"] for c in tree[0]["children"]] == ["Vendors"]
    assert tree[0]["children"][0]["feed_count"] == 1
    assert tree[0]["children"][0]["feed_defaults"] == {}

    signed_in = (await client.get("/api/categories", headers=auth_headers)).json()
    assert {c["name"] for c in signed_in} >= {"Research", "Empty folder", "Private folder"}


# --- Authorization headers that carry no token ------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["Bearer ", "Bearer", "bearer  ", "Basic abc", "Token x"])
async def test_a_header_without_a_token_is_refused_not_treated_as_a_visitor(
    client: AsyncClient, public_mode, header, no_rate_limit
):
    """A header the bearer parse can't read must not skip the write lock and
    scrubbing as a signed-in caller would, then reach the route as a visitor."""
    for url in ("/api/widgets/overview?days=7", "/api/feeds", "/api/ttps?limit=3"):
        resp = await client.get(url, headers={"Authorization": header})
        assert resp.status_code == 401, (header, url, resp.status_code)
    resp = await client.post("/api/autolink/scan", json={"text": "x" * 20_000}, headers={"Authorization": header})
    assert resp.status_code in (401, 413), (header, resp.status_code)


@pytest.mark.asyncio
async def test_a_lowercase_bearer_scheme_is_a_signed_in_caller(client: AsyncClient, public_mode, auth_headers):
    token = auth_headers["Authorization"].split(" ", 1)[1]
    resp = await client.get("/api/widgets/overview?days=7", headers={"Authorization": f"bearer {token}"})
    assert resp.status_code == 200
    assert "X-RateLimit-Limit" not in resp.headers  # signed-in reads are not limited


@pytest.mark.asyncio
async def test_parallel_requests_cannot_overrun_the_window(
    client: AsyncClient, public_mode, shown_entry, monkeypatch, fresh_rate_limits
):
    import asyncio

    from app.core import rate_limit

    monkeypatch.setitem(rate_limit._BUCKET_WINDOWS, "anon_article", ((3, 60), (100, 3600)))
    url = f"/api/entries/{shown_entry.id}"
    statuses = [r.status_code for r in await asyncio.gather(*(client.get(url) for _ in range(12)))]
    assert statuses.count(200) == 3, statuses
    assert statuses.count(429) == 9


# --- Canary: nothing from a hidden feed reaches a visitor ---------------------
#
# The ORM filter only sees ORM queries that name Entry. Raw SQL, junction-only
# queries, Redis caches and the search index all sit outside it, and every one
# of those has leaked before. This seeds one article in a hidden feed, marked
# everywhere it can be (title, URL, text, an actor known only from it, a
# thread built from it, a beat, an event, a claim quote) and walks every
# visitor route, first signed in so caches fill, then as a visitor. No visitor
# response may carry a marker or the hidden ids.

_CANARY = "CANARYZQX"


@pytest_asyncio.fixture
async def canary(db_session: AsyncSession):
    from datetime import UTC, datetime, timedelta

    from app.models.correlation_event import CorrelationEventRecord
    from app.models.entity_field_claim import EntityFieldClaim
    from app.models.entity_relationship import EntityRelationship
    from app.models.malware_family import EntryMalware, MalwareFamily
    from app.models.product import EntryProduct, Product
    from app.models.story_thread import StoryThread, StoryThreadBeat, StoryThreadEntry
    from app.models.threat_actor import EntryThreatActor, ThreatActor
    from app.models.tool import EntryTool, Tool
    from app.models.vendor import EntryVendor, Vendor

    shown_feed = Feed(title="Shown feed", url="https://shown.example/feed", feed_type="rss", visible_to_visitors=True)
    hidden_feed = Feed(title=f"{_CANARY} feed", url=f"https://{_CANARY.lower()}.example/feed", feed_type="rss")
    db_session.add_all([shown_feed, hidden_feed])
    await db_session.flush()
    now = datetime.now(UTC)
    shown = Entry(
        feed_id=shown_feed.id,
        title="A public article about Shared Actor",
        guid="shown-1",
        url="https://shown.example/a",
        content_text="Shared Actor did something.",
        published_at=now,
    )
    hidden = Entry(
        feed_id=hidden_feed.id,
        title=f"{_CANARY} title",
        guid="hidden-1",
        url=f"https://{_CANARY.lower()}.example/a",
        content_text=f"{_CANARY} text about Shared Actor and {_CANARY} Ghost.",
        summary=f"{_CANARY} summary",
        published_at=now,
    )
    # A second hidden article: the seed of a thread that also has a visible member.
    hidden_seed = Entry(
        feed_id=hidden_feed.id,
        title=f"{_CANARY} seed headline",
        guid="hidden-2",
        url=f"https://{_CANARY.lower()}.example/b",
        content_text=f"{_CANARY} seed text",
        published_at=now - timedelta(hours=1),
    )
    db_session.add_all([shown, hidden, hidden_seed])
    await db_session.flush()

    shared = ThreatActor(name="Shared Actor", first_seen_at=now, last_seen_at=now)
    ghost = ThreatActor(name=f"{_CANARY} Ghost", first_seen_at=now, last_seen_at=now)
    # Two actors a visitor sees (on the visible article): the relationships
    # between them and Shared Actor below carry what a visitor must not get.
    partner = ThreatActor(name="Partner Actor", first_seen_at=now, last_seen_at=now)
    rumoured = ThreatActor(name="Rumoured Actor", first_seen_at=now, last_seen_at=now)
    db_session.add_all([shared, ghost, partner, rumoured])
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=shown.id, threat_actor_id=shared.id, matched_names=["Shared Actor"]),
            EntryThreatActor(entry_id=shown.id, threat_actor_id=partner.id, matched_names=["Partner Actor"]),
            EntryThreatActor(entry_id=shown.id, threat_actor_id=rumoured.id, matched_names=["Rumoured Actor"]),
            EntryThreatActor(entry_id=hidden.id, threat_actor_id=shared.id, matched_names=[f"{_CANARY} alias"]),
            EntryThreatActor(entry_id=hidden.id, threat_actor_id=ghost.id, matched_names=[f"{_CANARY} Ghost"]),
        ]
    )
    # Every article-derived type gets a ghost known only from the hidden article.
    ghost_malware = MalwareFamily(name=f"{_CANARY} Ghostware", first_seen_at=now, last_seen_at=now)
    ghost_tool = Tool(name=f"{_CANARY} Ghosttool", first_seen_at=now, last_seen_at=now)
    ghost_vendor = Vendor(name=f"{_CANARY} Ghostvendor", first_seen_at=now, last_seen_at=now)
    db_session.add_all([ghost_malware, ghost_tool, ghost_vendor])
    await db_session.flush()
    ghost_product = Product(
        name=f"{_CANARY} Ghostproduct", vendor_id=ghost_vendor.id, first_seen_at=now, last_seen_at=now
    )
    # A product visitors may see (mentioned in the visible article) whose vendor they may not.
    shown_product = Product(name="Shown Product", vendor_id=ghost_vendor.id, first_seen_at=now, last_seen_at=now)
    db_session.add_all([ghost_product, shown_product])
    await db_session.flush()
    db_session.add_all(
        [
            EntryMalware(entry_id=hidden.id, malware_family_id=ghost_malware.id),
            EntryTool(entry_id=hidden.id, tool_id=ghost_tool.id),
            EntryVendor(entry_id=hidden.id, vendor_id=ghost_vendor.id),
            EntryProduct(entry_id=hidden.id, product_id=ghost_product.id),
            EntryProduct(entry_id=shown.id, product_id=shown_product.id),
        ]
    )
    thread = StoryThread(slug="canary-thread", title=f"{_CANARY} thread", summary=f"{_CANARY} spine", entry_count=1)
    # A thread with a visible and a hidden member: its stored title, summary
    # and entity chips come from the hidden one.
    mixed = StoryThread(
        slug="canary-mixed",
        title=f"{_CANARY} mixed",
        summary=f"{_CANARY} mixed spine",
        entry_count=2,
        key_entities=[
            {"entity_type": "threat_actor", "entity_id": str(ghost.id), "label": f"{_CANARY} Ghost", "count": 1}
        ],
    )
    db_session.add(mixed)
    db_session.add(thread)
    await db_session.flush()
    # Visible ends, but the only evidence is the hidden article: the edge itself goes.
    hidden_edge = EntityRelationship(
        id=uuid.uuid4(),
        source_type="threat_actor",
        source_id=shared.id,
        target_type="threat_actor",
        target_id=rumoured.id,
        relationship_type="related-to",
        confidence="likely",
        source="ai_extracted",
        evidence_entry_ids=[hidden.id],
    )
    db_session.add_all(
        [
            StoryThreadEntry(thread_id=thread.id, entry_id=hidden.id, role="origin"),
            StoryThreadEntry(thread_id=mixed.id, entry_id=hidden_seed.id, role="origin"),
            StoryThreadEntry(thread_id=mixed.id, entry_id=shown.id, role="beat"),
            StoryThreadBeat(
                thread_id=thread.id,
                headline=f"{_CANARY} beat",
                body=f"{_CANARY} beat body",
                lead_entry_id=hidden.id,
                entry_ids=[str(hidden.id)],
            ),
            EntityRelationship(
                source_type="threat_actor",
                source_id=shared.id,
                target_type="threat_actor",
                target_id=ghost.id,
                relationship_type="related-to",
                confidence="likely",
                source="ai_extracted",
                description=f"{_CANARY} relationship",
                evidence_entry_ids=[hidden.id],
            ),
            # Visible ends and visible evidence, but the description is an analyst's.
            EntityRelationship(
                source_type="threat_actor",
                source_id=shared.id,
                target_type="threat_actor",
                target_id=partner.id,
                relationship_type="related-to",
                confidence="likely",
                source="analyst_created",
                description=f"{_CANARY} analyst note",
                evidence_entry_ids=[shown.id],
            ),
            hidden_edge,
            CorrelationEventRecord(
                event_type="co_occurrence",
                entry_id=hidden.id,
                source_entity_type="threat_actor",
                source_entity_id=shared.id,
                source_entity_label="Shared Actor",
                related_entity_type="threat_actor",
                related_entity_id=ghost.id,
                related_entity_label=f"{_CANARY} Ghost",
                context=f"{_CANARY} event",
            ),
            # An allowed type on a visible article, naming the hidden-only actor.
            CorrelationEventRecord(
                event_type="actor_malware_cooccurrence",
                entry_id=shown.id,
                source_entity_type="threat_actor",
                source_entity_id=shared.id,
                source_entity_label="Shared Actor",
                related_entity_type="threat_actor",
                related_entity_id=ghost.id,
                related_entity_label=f"{_CANARY} Ghost",
                context=f"{_CANARY} event on a visible article",
            ),
            EntityFieldClaim(
                entity_type="threat_actor",
                entity_id=shared.id,
                field="aliases",
                value_text=f"{_CANARY} claim",
                source_kind="article",
                entry_id=hidden.id,
                quote=f"{_CANARY} quote",
                claim_key=f"{_CANARY}-claim",
            ),
        ]
    )
    await db_session.flush()
    db_session.expunge_all()
    return {
        "shown": shown.id,
        "hidden": hidden.id,
        "hidden_seed": hidden_seed.id,
        "hidden_feed": hidden_feed.id,
        "shared": shared.id,
        "ghost": ghost.id,
        "ghost_malware": ghost_malware.id,
        "ghost_tool": ghost_tool.id,
        "ghost_vendor": ghost_vendor.id,
        "ghost_product": ghost_product.id,
        "shown_product": shown_product.id,
        "slug": mixed.slug,
        "hidden_edge": hidden_edge.id,
    }


_CANARY_IDS = (
    "hidden",
    "hidden_seed",
    "hidden_feed",
    "ghost",
    "ghost_malware",
    "ghost_tool",
    "ghost_vendor",
    "ghost_product",
    "hidden_edge",
)


def _leaks(body: str, c: dict, url: str) -> list[str]:
    found = [m for m in (_CANARY, _CANARY.lower()) if m in body]
    # An id the visitor put in the URL may come back; any other may not.
    found += [k for k in _CANARY_IDS if str(c[k]) in body and str(c[k]) not in url]
    return found


async def _canary_walk(client: AsyncClient, overrides: dict, headers: dict | None = None) -> dict[str, list[str]]:
    leaks = {}
    for key in sorted(VISITOR_ROUTES):
        method, path = key.split(" ", 1)
        url = _fill(path, overrides)
        if path == "/api/proxy/image":
            url += f"?url=https://{_CANARY.lower()}.example/x.png"
        if path == "/api/tts/existing":
            url += f"?source=entry&id={overrides.get('entry_id')}"
        if method == "GET":
            resp = await client.get(url, headers=headers)
        else:
            body = {"entry_ids": [overrides.get("entry_id")], "ids": [overrides.get("entity_id")], "names": []}
            resp = await client.post(url, json={**body, "text": "Shared Actor"}, headers=headers)
        if headers is None and (found := _leaks(resp.text, overrides["_canary"], url)):
            leaks[f"{key} -> {url}"] = found
    return leaks


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "focus,entity_type",
    [
        ("shared", "threat_actor"),
        ("ghost", "threat_actor"),
        ("ghost_malware", "malware"),
        ("ghost_tool", "tool"),
        ("ghost_vendor", "vendor"),
        ("ghost_product", "product"),
        ("shown_product", "product"),
    ],
)
async def test_nothing_from_a_hidden_feed_reaches_a_visitor(
    client: AsyncClient, public_mode, canary, auth_headers, no_rate_limit, focus, entity_type
):
    from app.services.redis_client import get_redis

    r = await get_redis()
    # Tests share the dev Redis: clear only this run's entities' pivots and graphs.
    for entity in ("shared", *_CANARY_IDS[3:], "shown_product"):
        keys = [k async for k in r.scan_iter(match=f"intelfeed:corr:*:{canary[entity]}*")]
        if keys:
            await r.delete(*keys)

    focus_id = str(canary[focus])
    overrides = {
        "entity_type": entity_type,
        "entity_id": focus_id,
        "id": focus_id,
        f"{ {'threat_actor': 'actor', 'malware': 'malware'}.get(entity_type, entity_type) }_id": focus_id,
        "feed_id": str(canary["hidden_feed"]),
        "entry_id": str(canary["hidden"]),
        "slug": canary["slug"],
        "_canary": canary,
    }
    await _canary_walk(client, overrides, headers=auth_headers)  # fills caches the way an analyst would
    leaks = await _canary_walk(client, overrides)
    # The article and entity routes are also walked from the visible article,
    # whose neighbours, threads and counts include the hidden one.
    leaks |= await _canary_walk(client, {**overrides, "entry_id": str(canary["shown"])})
    assert leaks == {}, "\n".join(f"{k}: {v}" for k, v in sorted(leaks.items()))


# --- Paths the canary walk can't see -------------------------------------------


@pytest.mark.asyncio
async def test_image_proxy_serves_a_visitor_only_what_a_visible_article_shows(
    client: AsyncClient, public_mode, canary, db_session: AsyncSession, monkeypatch
):
    from app.api import proxy
    from app.services.sanitizer import sanitize_html

    monkeypatch.setattr(settings, "image_proxy_enabled", True)
    shown_img, hidden_img = "https://shown.example/pic.png?a=1&b=2", f"https://{_CANARY.lower()}.example/pic.png"
    link = "https://shown.example/page"
    shown = await db_session.get(Entry, canary["shown"])
    shown.content_html = sanitize_html(f'<p><img src="{shown_img}"><a href="{link}">x</a></p>')
    hidden = await db_session.get(Entry, canary["hidden"])
    hidden.content_html = sanitize_html(f'<p><img src="{hidden_img}"></p>')
    await db_session.flush()
    db_session.expunge_all()

    # Both already cached (an analyst read both articles), and fetching is stubbed.
    monkeypatch.setattr(proxy, "_read_cache", lambda url: (b"\x89PNG" + b"0" * 200, "image/png"))
    get = client.get
    assert (await get("/api/proxy/image", params={"url": shown_img, "entry": str(canary["shown"])})).status_code == 200
    # The cache does not answer for an image only a hidden article shows...
    resp = await get("/api/proxy/image", params={"url": hidden_img, "entry": str(canary["hidden"])})
    assert resp.status_code == 404
    # ...nor without an article, nor for a link that isn't an image.
    assert (await get("/api/proxy/image", params={"url": shown_img})).status_code == 404
    assert (await get("/api/proxy/image", params={"url": link, "entry": str(canary["shown"])})).status_code == 404


@pytest.mark.asyncio
async def test_visitors_see_only_global_tags_on_visible_articles(
    client: AsyncClient, public_mode, canary, db_session: AsyncSession, test_user
):
    from app.models.tag import EntryTag, Tag

    public = Tag(name="public-tag", is_global=True, created_by=test_user.id)
    hidden_only = Tag(name=f"{_CANARY}-tag", is_global=True, created_by=test_user.id)
    personal = Tag(name="my-private-tag", is_global=False, created_by=test_user.id)
    db_session.add_all([public, hidden_only, personal])
    await db_session.flush()
    db_session.add_all(
        [
            EntryTag(entry_id=canary["shown"], tag_id=public.id),
            EntryTag(entry_id=canary["hidden"], tag_id=hidden_only.id),
            EntryTag(entry_id=canary["shown"], tag_id=personal.id, user_id=test_user.id),
        ]
    )
    await db_session.flush()
    tags = (await client.get("/api/tags")).json()
    assert [(t["name"], t["entry_count"]) for t in tags] == [("public-tag", 1)]


@pytest.mark.asyncio
async def test_autolink_scan_never_names_a_hidden_entity_or_shrinks_the_vocabulary(
    client: AsyncClient, public_mode, canary
):
    from app.intelligence import autolinker

    autolinker._vocabulary = None  # force the rebuild inside the visitor's request
    resp = await client.post("/api/autolink/scan", json={"text": f"Shared Actor met {_CANARY} Ghost."})
    assert resp.status_code == 200
    names = {m["canonical_name"] for m in resp.json()["matches"]}
    assert "Shared Actor" in names
    assert not any(_CANARY in n for n in names)
    # The rebuild the visitor triggered is the shared one: it still knows the ghost.
    assert any(_CANARY in m["canonical_name"] for m in autolinker.scan_text(f"{_CANARY} Ghost"))


@pytest.mark.asyncio
async def test_attack_matrix_counts_and_cache_are_per_viewer(
    client: AsyncClient, public_mode, canary, db_session: AsyncSession, auth_headers
):
    from app.models.ttp import TTP, EntryTTP
    from app.services.redis_client import get_redis

    ttp = TTP(
        technique_id="T9999",
        technique_name="Canary technique",
        tactic="execution",
        tactics=["execution"],
        matrix_domain="enterprise",
    )
    db_session.add(ttp)
    await db_session.flush()
    ttp.article_count = 2
    db_session.add_all(
        [EntryTTP(entry_id=canary["shown"], ttp_id=ttp.id), EntryTTP(entry_id=canary["hidden"], ttp_id=ttp.id)]
    )
    await db_session.flush()
    r = await get_redis()
    keys = [k async for k in r.scan_iter(match="intelfeed:attack:matrix*")]
    if keys:
        await r.delete(*keys)

    def count(body: dict) -> int:
        cells = [t for col in body["tactics"] for t in col["techniques"] if t["technique_id"] == "T9999"]
        return cells[0]["article_count"] if cells else -1

    analyst = (await client.get("/api/attack/matrix", headers=auth_headers)).json()
    visitor = (await client.get("/api/attack/matrix")).json()
    assert count(analyst) == 2  # the stored rollup, every feed
    assert count(visitor) == 1  # visible articles only, not served the analyst's cached copy


@pytest.mark.asyncio
async def test_refused_visitor_writes_carry_the_private_and_noindex_headers(client: AsyncClient, public_mode):
    resp = await client.post("/api/feeds", json={"url": "https://x.example/feed"})
    assert resp.status_code == 401
    assert resp.headers["cache-control"] == "private, no-store"
    assert "noindex" in resp.headers["x-robots-tag"]


@pytest.mark.asyncio
async def test_private_work_named_in_article_fields_never_reaches_a_visitor(
    client: AsyncClient, public_mode, canary, db_session: AsyncSession, test_user, no_rate_limit
):
    """Signal explanations, AI article metadata and campaign membership name
    private work in values the key scrubber can't see."""
    from app.models.campaign import Campaign, CampaignEntry
    from app.models.entry_signal import EntrySignal

    shown = await db_session.get(Entry, canary["shown"])
    shown.priority_score, shown.priority_raw = 9.5, 5.0
    shown.metadata_ = {"article_intel": {"report_type": f"{_CANARY} report", "victims": [f"{_CANARY} victim"]}}
    campaign = Campaign(name=f"{_CANARY} campaign", created_by=test_user.id)
    db_session.add(campaign)
    await db_session.flush()
    db_session.add_all(
        [
            EntrySignal(entry_id=shown.id, signal_type="pir_match", score=0.9, explanation=f"Matches '{_CANARY} PIR'"),
            EntrySignal(entry_id=shown.id, signal_type="critical_cvss", score=0.8, explanation="CVSS 9.8"),
            CampaignEntry(campaign_id=campaign.id, entry_id=shown.id),
        ]
    )
    await db_session.flush()
    db_session.expunge_all()

    detail = await client.get(f"/api/entries/{shown.id}")
    assert detail.status_code == 200 and _CANARY not in detail.text
    signals = detail.json().get("priority_signals") or []
    assert all(s["explanation"] != f"Matches '{_CANARY} PIR'" for s in signals)
    assert (await client.get(f"/api/entries/{shown.id}/article-metadata")).json() is None
    listing = await client.get("/api/entries", params={"limit": 50})
    assert _CANARY not in listing.text
    # A campaign id finds nothing: membership is private.
    by_campaign = await client.get("/api/entries", params={"campaign_id": str(campaign.id)})
    assert by_campaign.json()["items"] == []
    # A campaign as a pivot source is empty: its articles and name stay private.
    pivot = await client.get(f"/api/intelligence/pivot/campaign/{campaign.id}")
    assert _CANARY not in pivot.text and str(shown.id) not in pivot.text


@pytest.mark.asyncio
async def test_thread_search_does_not_match_a_hidden_headline(client: AsyncClient, public_mode, canary):
    # The mixed thread's stored title is the hidden seed's; a visitor sees and
    # searches the visible member's.
    assert (await client.get("/api/threads", params={"q": _CANARY})).json()["threads"] == []
    hits = (await client.get("/api/threads", params={"q": "public article"})).json()["threads"]
    assert [t["slug"] for t in hits] and all(t["slug"].startswith("t-") for t in hits)
    # The alias opens the thread.
    assert (await client.get(f"/api/threads/{hits[0]['slug']}")).status_code == 200


@pytest.mark.asyncio
async def test_article_less_correlation_events_reach_visitors(
    client: AsyncClient, public_mode, db_session: AsyncSession, no_rate_limit
):
    from app.models.correlation_event import CorrelationEventRecord
    from app.models.cve import CVE

    cve = CVE(cve_id="CVE-2099-0001")
    db_session.add(cve)
    await db_session.flush()
    db_session.add(
        CorrelationEventRecord(
            event_type="kev_addition",
            entry_id=None,
            source_entity_type="cve",
            source_entity_id=cve.id,
            source_entity_label="CVE-2099-0001",
            related_entity_type="cve",
            related_entity_id=cve.id,
            related_entity_label="CVE-2099-0001",
            context="CVE-2099-0001 added to KEV",
        )
    )
    await db_session.flush()
    assert "CVE-2099-0001 added to KEV" in (await client.get("/api/widgets/correlation-events")).text


def test_visitor_pages_are_capped():
    from starlette.requests import Request

    from app.core.public_access import VISITOR_PAGE_CAP, _cap_page_size

    def capped(path: str, query: str) -> str:
        request = Request(
            {"type": "http", "method": "GET", "path": path, "query_string": query.encode(), "headers": []}
        )
        _cap_page_size(request, path)
        return request.scope["query_string"].decode()

    assert capped("/api/entries", "limit=500&feed_id=x") == f"limit={VISITOR_PAGE_CAP}&feed_id=x"
    assert capped("/api/entries", "limit=20") == "limit=20"
    assert capped("/api/feeds/abc/entries", "limit=999") == f"limit={VISITOR_PAGE_CAP}"
    # The sidebar's feed list is names only and keeps its page.
    assert capped("/api/feeds", "limit=1000") == "limit=1000"


@pytest.mark.asyncio
async def test_timeline_relationships_follow_the_visitor_rule(
    client: AsyncClient, public_mode, canary, auth_headers, no_rate_limit
):
    """Rumoured Actor is visible, but its edge to Shared Actor rests on the hidden article alone."""
    url = f"/api/intelligence/timeline/threat_actor/{canary['shared']}"
    analyst = await client.get(url, headers=auth_headers)
    assert "Rumoured Actor" in analyst.text  # the event exists
    visitor = await client.get(url)
    assert visitor.status_code == 200, visitor.text
    assert "Rumoured Actor" not in visitor.text
    assert "Partner Actor" in visitor.text  # an edge with visible evidence stays
