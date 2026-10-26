"""Public read-only mode (issue #136): who may reach what, and what visitors see.

The route walk below is the guard that keeps the mode safe as the API grows:
every route that a visitor can reach, and every route with no login at all,
is listed here by hand. A new route that takes ``get_viewer`` or skips auth
fails ``test_every_open_route_is_classified`` until someone decides it belongs.
"""

import re
import uuid

import pytest
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
    GET /api/enrichment/results
    GET /api/entities/{entity_type}/{entity_id}/attack-layer
    GET /api/entities/{entity_type}/{entity_id}/attack-techniques
    GET /api/entities/{entity_type}/{entity_id}/entries-window
    GET /api/entities/{entity_type}/{entity_id}/mentions-timeseries
    GET /api/entities/{entity_type}/{entity_id}/provenance
    GET /api/entities/{entity_type}/{entity_id}/story-threads
    GET /api/entities/{entity_type}/{entity_id}/target-sectors
    GET /api/entities/{entity_type}/{entity_id}/top-entries
    GET /api/entity-links
    GET /api/entity-relationships
    GET /api/entity-relationships/by-entity/{entity_type}/{entity_id}
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
        "GET /api/automation/templates",
        "GET /api/automation/variable-contexts",
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
    out = []
    for r in app.routes:
        if isinstance(r, APIRoute):
            deps = _dep_names(r.dependant, set())
            for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
                out.append((f"{m} {r.path}", r, deps))
    return out


@pytest.fixture
def public_mode(monkeypatch):
    """Turn the switch on (env default; the test DB has no override row)."""
    monkeypatch.setattr(settings, "public_read_only_enabled", True)


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


def test_visitor_routes_are_reads_or_reviewed_posts():
    from app.core.public_access import ANONYMOUS_READ_POSTS

    writes = {k for k in VISITOR_ROUTES if not k.startswith("GET ")}
    assert writes == {f"POST {p}" for p in ANONYMOUS_READ_POSTS}


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
async def test_switch_off_every_visitor_route_still_needs_a_login(client: AsyncClient):
    statuses = await _walk(client)
    assert {k: s for k, s in statuses.items() if s != 401} == {}


@pytest.mark.asyncio
async def test_switch_on_visitor_routes_answer_without_writes_or_background_work(
    client: AsyncClient, db_session: AsyncSession, public_mode, monkeypatch, test_entry
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
        statuses = await _walk(client, entry_id=str(test_entry.id))
    finally:
        event.remove(db_session.sync_session, "before_flush", _no_writes)

    assert {k: s for k, s in statuses.items() if s in (401, 403) or s >= 500} == {}
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
    manual = Feed(title="Manual Uploads", url="manual://uploads", feed_type="manual")
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
async def test_visitor_entry_has_no_personal_state(client: AsyncClient, public_mode, test_entry):
    data = (await client.get(f"/api/entries/{test_entry.id}")).json()
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
        "graph": {
            "nodes": [{"id": "a", "type": "threat_actor"}, {"id": "c", "type": "campaign"}],
            "edges": [{"source": "a", "target": "c"}, {"source": "a", "target": "a"}],
        },
    }
    out = scrub_for_visitor(payload)
    assert out["author"] == "Article byline"
    assert out["claims"] == [{"value": "Russia"}]
    assert "rule_count" not in out and "source_campaigns" not in out
    assert "pir_matches" not in out and "notes" not in out and "detection_opportunity" not in out
    assert out["graph"]["nodes"] == [{"id": "a", "type": "threat_actor"}]
    assert out["graph"]["edges"] == [{"source": "a", "target": "a"}]
