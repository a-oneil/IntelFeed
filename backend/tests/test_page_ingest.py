"""The browser extension's endpoints: POST /entries/ingest/page, and the lookup, coverage and results reads."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.api import ingest as ingest_api
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.note import Note
from app.models.tag import EntryTag, Tag
from app.services.ingest_parsers import ParsedDocument
from app.services.manual_ingest import create_manual_entry, url_guid

PAGE = """<html><head><title>Akira returns</title>
<meta property="og:image" content="https://example.com/og.png"></head>
<body><nav>Home | About</nav><article><h1>Akira returns</h1>
<p>The Akira ransomware group is exploiting CVE-2024-40766 in SonicWall appliances.</p>
<p onclick="steal()">Second paragraph <a href="javascript:alert(1)">link</a> <a href="/rel">relative</a>.</p>
<script>alert('x')</script><style>body{}</style><iframe src="https://evil.example"></iframe>
</article></body></html>"""


@pytest.fixture
def quiet_pipeline(monkeypatch):
    created = []
    monkeypatch.setattr(ingest_api, "_after_create", lambda entry, source: created.append((entry.id, source)))
    return created


# ── page ingest ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_page_html_is_sanitized_and_marked(
    client: AsyncClient, auth_headers, test_user, db_session, quiet_pipeline
):
    resp = await client.post(
        "/api/entries/ingest/page",
        json={
            "url": "https://example.com/akira#comments",
            "html": PAGE,
            "selection": "  exploiting CVE-2024-40766  ",
            "published_at": "2024-09-10T12:00:00Z",
            "client": "intelfeed-extension/1.0.0",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["created"] is True
    assert body["url"] == "https://example.com/akira"

    entry = await db_session.get(Entry, uuid.UUID(body["id"]))
    html = entry.content_html
    for banned in ("<script", "<style", "<iframe", "onclick", "javascript:"):
        assert banned not in html.lower()
    assert "https://example.com/rel" in html
    assert "SonicWall" in entry.content_text
    assert entry.title == "Akira returns"
    assert entry.published_at == datetime(2024, 9, 10, 12, tzinfo=UTC)
    assert entry.guid == url_guid("https://example.com/akira")
    assert entry.metadata_ == {
        "source": "extension_page",
        "uploaded_by": str(test_user.id),
        "client": "intelfeed-extension/1.0.0",
        "excerpt": "exploiting CVE-2024-40766",
    }
    assert quiet_pipeline == [(entry.id, "page")]


@pytest.mark.asyncio
async def test_html_page_never_fetches_the_url(client: AsyncClient, auth_headers, monkeypatch, quiet_pipeline):
    """A robots-disallowed or intranet URL still ingests when the browser sends the page."""

    async def no_fetch(url):
        raise AssertionError("the server fetched a page the client sent")

    monkeypatch.setattr("app.services.manual_ingest.fetch_url_document", no_fetch)
    resp = await client.post(
        "/api/entries/ingest/page",
        json={"url": "http://wiki.internal/secret-runbook", "html": PAGE},
        headers=auth_headers,
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_second_send_returns_the_existing_entry(
    client: AsyncClient, auth_headers, test_user, db_session, quiet_pipeline
):
    tag = Tag(name=f"t-{uuid.uuid4().hex[:6]}")
    db_session.add(tag)
    await db_session.flush()

    first = await client.post(
        "/api/entries/ingest/page", json={"url": "https://example.com/dup", "html": PAGE}, headers=auth_headers
    )
    second = await client.post(
        "/api/entries/ingest/page",
        json={"url": "https://example.com/dup", "html": PAGE, "tag_ids": [str(tag.id)], "note": "seen on VPN logs"},
        headers=auth_headers,
    )
    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["created"] is False
    assert second.json()["id"] == first.json()["id"]
    assert len(quiet_pipeline) == 1

    entry_id = uuid.UUID(first.json()["id"])
    notes = (await db_session.execute(select(Note).where(Note.entry_id == entry_id))).scalars().all()
    assert [(n.title, n.content_markdown) for n in notes] == [("Akira returns", "seen on VPN logs")]
    # A personal tag: the assignment belongs to the sender.
    rows = (await db_session.execute(select(EntryTag).where(EntryTag.entry_id == entry_id))).scalars().all()
    assert [(r.tag_id, r.user_id) for r in rows] == [(tag.id, test_user.id)]


@pytest.mark.asyncio
async def test_implausible_published_date_is_dropped(client: AsyncClient, auth_headers, db_session, quiet_pipeline):
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    resp = await client.post(
        "/api/entries/ingest/page",
        json={"url": "https://example.com/future", "html": PAGE, "published_at": future},
        headers=auth_headers,
    )
    entry = await db_session.get(Entry, uuid.UUID(resp.json()["id"]))
    assert entry.published_at <= datetime.now(UTC)


@pytest.mark.asyncio
async def test_oversize_and_bad_urls_are_refused(client: AsyncClient, auth_headers, quiet_pipeline):
    big = await client.post(
        "/api/entries/ingest/page",
        json={"url": "https://example.com/big", "html": "x" * 2_000_001},
        headers=auth_headers,
    )
    assert big.status_code == 400  # request validation errors are 400 here
    bad = await client.post(
        "/api/entries/ingest/page", json={"url": "file:///etc/passwd", "html": PAGE}, headers=auth_headers
    )
    assert bad.status_code == 400


@pytest.mark.asyncio
async def test_lookup_finds_polled_and_sent_pages(client: AsyncClient, auth_headers, db_session, quiet_pipeline):
    missing = await client.get(
        "/api/entries/ingest/lookup", params={"url": "https://example.com/x"}, headers=auth_headers
    )
    assert missing.status_code == 404

    feed = Feed(title="Vendor blog", url=f"https://vendor.example/{uuid.uuid4().hex}/feed")
    db_session.add(feed)
    await db_session.flush()
    polled = Entry(feed_id=feed.id, guid="g1", url="https://vendor.example/post", title="Post")
    db_session.add(polled)
    await db_session.flush()

    found = await client.get(
        "/api/entries/ingest/lookup", params={"url": "https://vendor.example/post#top"}, headers=auth_headers
    )
    assert found.status_code == 200
    assert found.json()["id"] == str(polled.id)
    assert found.json()["feed_title"] == "Vendor blog"

    sent = await client.post(
        "/api/entries/ingest/page", json={"url": "https://vendor.example/post", "html": PAGE}, headers=auth_headers
    )
    assert sent.status_code == 200
    assert sent.json()["id"] == str(polled.id)


# ── results after sending, story context ─────────────────────────────


async def _thread_with(db_session, *entries) -> "object":
    from app.models.story_thread import StoryThread, StoryThreadEntry

    thread = StoryThread(
        slug=f"akira-{uuid.uuid4().hex[:6]}", title="Akira hits SonicWall", entry_count=3, source_count=2
    )
    db_session.add(thread)
    await db_session.flush()
    for e in entries:
        db_session.add(StoryThreadEntry(thread_id=thread.id, entry_id=e.id))
    await db_session.flush()
    return thread


@pytest.mark.asyncio
async def test_results_report_findings_state_and_thread(client: AsyncClient, auth_headers, db_session, quiet_pipeline):
    from app.models.cve import CVE, EntryCVE
    from app.models.entry_pipeline_run import EntryPipelineRun
    from app.models.threat_actor import EntryThreatActor, ThreatActor

    sent = await client.post(
        "/api/entries/ingest/page", json={"url": "https://example.com/akira", "html": PAGE}, headers=auth_headers
    )
    entry_id = uuid.UUID(sent.json()["id"])
    url = f"/api/entries/ingest/{entry_id}/results"

    # Nothing has run yet: a new entry waits in the queue.
    first = (await client.get(url, headers=auth_headers)).json()
    assert first["state"] == "processing"
    assert first["actors"] == [] and first["thread"] is None

    actor = ThreatActor(name=f"Akira-{uuid.uuid4().hex[:4]}")
    cve = CVE(cve_id="CVE-2024-40766", cvss_score=9.3)
    db_session.add_all([actor, cve])
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=entry_id, threat_actor_id=actor.id),
            EntryCVE(entry_id=entry_id, cve_id=cve.id),
            EntryPipelineRun(entry_id=entry_id, stage="autolink", status="success"),
        ]
    )
    await db_session.flush()
    entry = await db_session.get(Entry, entry_id)
    thread = await _thread_with(db_session, entry)

    mid = (await client.get(url, headers=auth_headers)).json()
    assert mid["state"] == "processing"
    assert [a["name"] for a in mid["actors"]] == [actor.name]
    assert mid["cves"] == [{"id": str(cve.id), "cve_id": "CVE-2024-40766", "cvss_score": 9.3}]
    assert mid["thread"]["slug"] == thread.slug

    db_session.add(EntryPipelineRun(entry_id=entry_id, stage="score", status="success"))
    await db_session.flush()
    assert (await client.get(url, headers=auth_headers)).json()["state"] == "done"

    # The lookup carries the thread too.
    found = await client.get(
        "/api/entries/ingest/lookup", params={"url": "https://example.com/akira"}, headers=auth_headers
    )
    assert found.json()["thread"] == {
        "slug": thread.slug,
        "title": "Akira hits SonicWall",
        "entry_count": 3,
        "source_count": 2,
    }

    assert (await client.get(f"/api/entries/ingest/{uuid.uuid4()}/results", headers=auth_headers)).status_code == 404


@pytest.mark.asyncio
async def test_coverage_counts_outlets_and_drops_weak_matches(
    client: AsyncClient, auth_headers, db_session, monkeypatch
):
    from app.services import meilisearch_client

    a = Feed(title="Outlet A", url=f"https://a.example/{uuid.uuid4().hex}/feed")
    b = Feed(title="Outlet B", url=f"https://b.example/{uuid.uuid4().hex}/feed")
    db_session.add_all([a, b])
    await db_session.flush()
    now = datetime.now(UTC)
    strong1 = Entry(
        feed_id=a.id,
        guid="c1",
        url="https://a.example/akira-sonicwall",
        title="Akira ransomware exploits SonicWall flaw",
        published_at=now,
    )
    strong2 = Entry(
        feed_id=a.id,
        guid="c2",
        url="https://a.example/akira-sonicwall-2",
        title="Akira exploits SonicWall firewall flaw again",
        published_at=now,
    )
    strong3 = Entry(
        feed_id=b.id,
        guid="c3",
        url="https://b.example/news",
        title="SonicWall flaw exploited by Akira ransomware",
        published_at=now,
    )
    weak = Entry(
        feed_id=b.id, guid="c4", url="https://b.example/other", title="Patch Tuesday roundup", published_at=now
    )
    db_session.add_all([strong1, strong2, strong3, weak])
    await db_session.flush()
    thread = await _thread_with(db_session, strong1, strong3)

    def fake_similar(**kwargs):
        hits = [{"id": str(e.id), "title": e.title} for e in (strong1, strong2, strong3, weak)]
        return {"hits": hits, "query_keywords": ["akira", "ransomware", "exploits", "sonicwall", "flaw"]}

    monkeypatch.setattr(meilisearch_client, "find_similar_entries", fake_similar)
    resp = await client.get(
        "/api/entries/ingest/coverage",
        params={"title": "Akira ransomware exploits SonicWall flaw", "url": "https://a.example/akira-sonicwall"},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The page's own URL is left out; the weak match is dropped; two sites remain.
    assert [e["id"] for e in body["entries"]] == [str(strong2.id), str(strong3.id)]
    assert body["outlet_count"] == 2
    assert body["thread"]["slug"] == thread.slug

    short = await client.get("/api/entries/ingest/coverage", params={"title": "Akira"}, headers=auth_headers)
    assert short.json() == {"outlet_count": 0, "entries": [], "thread": None}


@pytest.mark.asyncio
async def test_results_state_unknown_for_old_entries_and_errored_on_a_failed_stage(
    client: AsyncClient, auth_headers, db_session, test_entry
):
    from app.models.entry_pipeline_run import EntryPipelineRun

    test_entry.created_at = datetime.now(UTC) - timedelta(hours=2)
    await db_session.flush()
    url = f"/api/entries/ingest/{test_entry.id}/results"
    assert (await client.get(url, headers=auth_headers)).json()["state"] == "unknown"

    db_session.add(EntryPipelineRun(entry_id=test_entry.id, stage="autolink", status="error"))
    await db_session.flush()
    assert (await client.get(url, headers=auth_headers)).json()["state"] == "errored"


# ── other paths through the page endpoint ────────────────────────────


@pytest.mark.asyncio
async def test_page_without_html_fetches_the_url(
    client: AsyncClient, auth_headers, db_session, monkeypatch, quiet_pipeline
):
    fetched = []

    async def fake_fetch(url):
        fetched.append(url)
        return ParsedDocument(
            text="Fetched body about Akira.", html="<p>Fetched body about Akira.</p>", title="Fetched"
        )

    monkeypatch.setattr("app.services.manual_ingest.fetch_url_document", fake_fetch)
    resp = await client.post(
        "/api/entries/ingest/page", json={"url": "https://example.com/fetch-me#x"}, headers=auth_headers
    )
    assert resp.status_code == 201, resp.text
    assert fetched == ["https://example.com/fetch-me"]
    entry = await db_session.get(Entry, uuid.UUID(resp.json()["id"]))
    assert entry.title == "Fetched"
    assert entry.metadata_["source"] == "url_ingest"


@pytest.mark.asyncio
async def test_page_with_no_readable_text_is_a_422(client: AsyncClient, auth_headers, quiet_pipeline):
    resp = await client.post(
        "/api/entries/ingest/page",
        json={"url": "https://example.com/empty", "html": "<html><body><script>x()</script></body></html>"},
        headers=auth_headers,
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "extraction_failed"


@pytest.mark.asyncio
async def test_page_whose_guid_exists_under_another_url_returns_that_entry(
    client: AsyncClient, auth_headers, db_session, quiet_pipeline
):
    """The URL lookup misses (the stored URL kept its fragment), but the GUID is taken: the existing entry wins."""
    existing = await create_manual_entry(
        db_session,
        guid=url_guid("https://example.com/race"),
        title="Earlier copy",
        html="<p>x</p>",
        text="x",
        url="https://example.com/race#kept",
    )
    resp = await client.post(
        "/api/entries/ingest/page", json={"url": "https://example.com/race", "html": PAGE}, headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["created"] is False
    assert resp.json()["id"] == str(existing.id)
    assert quiet_pipeline == []


@pytest.mark.asyncio
async def test_reads_hide_entries_from_feeds_the_user_does_not_follow(
    client: AsyncClient, auth_headers, db_session, monkeypatch
):
    """With per-user subscriptions on, lookup, results and coverage never show an unfollowed feed's entry."""
    from app.config import settings as env_settings
    from app.services import meilisearch_client

    monkeypatch.setattr(env_settings, "per_user_subscriptions_enabled", True)
    feed = Feed(title="Unfollowed", url=f"https://hidden.example/{uuid.uuid4().hex}/feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id,
        guid="h1",
        url="https://hidden.example/akira",
        title="Akira ransomware exploits SonicWall flaw",
        published_at=datetime.now(UTC),
    )
    db_session.add(entry)
    await db_session.flush()

    lookup = await client.get(
        "/api/entries/ingest/lookup", params={"url": "https://hidden.example/akira"}, headers=auth_headers
    )
    assert lookup.status_code == 404
    results = await client.get(f"/api/entries/ingest/{entry.id}/results", headers=auth_headers)
    assert results.status_code == 404

    def fake_similar(**kwargs):
        return {
            "hits": [{"id": str(entry.id), "title": entry.title}],
            "query_keywords": ["akira", "ransomware", "exploits", "sonicwall", "flaw"],
        }

    monkeypatch.setattr(meilisearch_client, "find_similar_entries", fake_similar)
    coverage = await client.get(
        "/api/entries/ingest/coverage",
        params={"title": "Akira ransomware exploits SonicWall flaw"},
        headers=auth_headers,
    )
    assert coverage.json() == {"outlet_count": 0, "entries": [], "thread": None}
