"""The routes a stranger can reach: what they give away and what they accept.

Each test pins one fix from the pre-publication review of the unauthenticated
and visitor APIs (share links, query-token routes, visitor counts).
"""

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import blacklist_token, create_access_token, decode_token
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.note import Note
from app.models.shared_entry import SharedEntry
from app.models.tag import EntryTag, Tag
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.user import User

pytestmark = pytest.mark.asyncio


@pytest.fixture
def public_mode(monkeypatch):
    monkeypatch.setattr(settings, "public_read_only_enabled", True)


@pytest_asyncio.fixture
async def share(db_session: AsyncSession, test_entry: Entry, test_user: User) -> SharedEntry:
    row = SharedEntry(entry_id=test_entry.id, created_by=test_user.id, is_active=True)
    db_session.add(row)
    await db_session.flush()
    return row


# ── Share links ─────────────────────────────────────────────────────


async def test_a_share_link_shows_only_the_sharers_notes(
    client: AsyncClient, db_session: AsyncSession, share: SharedEntry, test_entry: Entry, test_user, admin_user
):
    db_session.add_all(
        [
            Note(created_by=test_user.id, entry_id=test_entry.id, title="Sharer's note", content_markdown="mine"),
            Note(created_by=admin_user.id, entry_id=test_entry.id, title="Colleague's note", content_markdown="ours"),
        ]
    )
    await db_session.flush()

    resp = await client.get(f"/api/shared/{share.token}")
    assert resp.status_code == 200, resp.text
    assert [n["title"] for n in resp.json()["notes"]] == ["Sharer's note"]


async def test_a_share_link_made_by_a_deleted_user_shows_no_notes(
    client: AsyncClient, db_session: AsyncSession, test_entry: Entry, test_user
):
    db_session.add(Note(created_by=test_user.id, entry_id=test_entry.id, title="A note", content_markdown="x"))
    orphan = SharedEntry(entry_id=test_entry.id, created_by=None, is_active=True)
    db_session.add(orphan)
    await db_session.flush()

    resp = await client.get(f"/api/shared/{orphan.token}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["notes"] == []


async def test_share_audio_serves_only_that_articles_audio(
    client: AsyncClient,
    db_session: AsyncSession,
    share: SharedEntry,
    test_entry: Entry,
    test_feed,
    tmp_path,
    monkeypatch,
):
    from app.models.tts_audio import TTSAudio
    from app.services import tts

    monkeypatch.setattr(settings, "tts_media_dir", str(tmp_path))
    other = Entry(feed_id=test_feed.id, title="Another article", guid="other-1", url="https://example.com/o")
    db_session.add(other)
    await db_session.flush()

    def stored(key: str, ref_id: str) -> TTSAudio:
        path = tts.audio_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"ID3")
        return TTSAudio(cache_key=key, source="entry", ref_id=ref_id, voice="v1", status="ready", byte_size=3)

    own, foreign = "a" * 64, "b" * 64
    db_session.add_all([stored(own, str(test_entry.id)), stored(foreign, str(other.id))])
    await db_session.flush()

    assert (await client.get(f"/api/shared/{share.token}/tts/file/{own}.mp3")).status_code == 200
    assert (await client.get(f"/api/shared/{share.token}/tts/file/{foreign}.mp3")).status_code == 404


# ── Tokens read from ?token= ────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "/api/tts/file/" + "a" * 64 + ".mp3?token={t}",
        "/api/telegram-media/-1001/1.jpg?token={t}",
        "/api/ingest-files/9fd9027b-d93a-4f3d-ad65-8b37b96957ce?token={t}",
        "/api/documentation/assets/missing.png?token={t}",
    ],
)
async def test_a_logged_out_token_stops_working_on_query_token_routes(client: AsyncClient, test_user: User, url):
    token = create_access_token(test_user.id, test_user.role)
    live = await client.get(url.format(t=token))
    assert live.status_code != 401, live.text  # 404/400: past the login check

    payload = decode_token(token)
    await blacklist_token(payload["jti"], datetime.fromtimestamp(payload["exp"], tz=UTC))
    revoked = await client.get(url.format(t=token))
    assert revoked.status_code == 401


async def test_a_logged_out_token_stops_working_on_the_intel_feed(client: AsyncClient, test_user: User):
    token = create_access_token(test_user.id, test_user.role)
    headers = {"Authorization": f"Bearer {token}"}
    assert (await client.get("/api/intelligence/feed", headers=headers)).status_code == 200

    payload = decode_token(token)
    await blacklist_token(payload["jti"], datetime.fromtimestamp(payload["exp"], tz=UTC))
    assert (await client.get("/api/intelligence/feed", headers=headers)).status_code == 401


# ── Login required ──────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/api/automation/templates", "/api/automation/variable-contexts"])
async def test_automation_reference_routes_need_a_login(client: AsyncClient, auth_headers, path):
    assert (await client.get(path)).status_code == 401
    assert (await client.get(path, headers=auth_headers)).status_code == 200


# ── What visitors see ───────────────────────────────────────────────


@pytest_asyncio.fixture
async def visible_and_hidden(db_session: AsyncSession) -> dict:
    """One article a visitor sees, one they don't, and a global tag on both."""
    shown_feed = Feed(title="Shown", url="https://shown.example/f", feed_type="rss", visible_to_visitors=True)
    hidden_feed = Feed(title="Hidden", url="https://hidden.example/f", feed_type="rss")
    db_session.add_all([shown_feed, hidden_feed])
    await db_session.flush()
    shown = Entry(feed_id=shown_feed.id, title="Shown", guid="h-shown", url="https://shown.example/a")
    hidden = Entry(feed_id=hidden_feed.id, title="Hidden", guid="h-hidden", url="https://hidden.example/a")
    tag = Tag(name="hardening-global", is_global=True)
    db_session.add_all([shown, hidden, tag])
    await db_session.flush()
    db_session.add_all([EntryTag(entry_id=shown.id, tag_id=tag.id), EntryTag(entry_id=hidden.id, tag_id=tag.id)])
    await db_session.flush()
    return {"shown": shown, "hidden": hidden, "tag": tag}


async def test_a_visitors_tag_count_on_an_article_covers_visible_articles_only(
    client: AsyncClient, public_mode, visible_and_hidden, auth_headers
):
    shown = visible_and_hidden["shown"]
    visitor = await client.get(f"/api/tags/entries/{shown.id}")
    assert visitor.status_code == 200, visitor.text
    assert [t["entry_count"] for t in visitor.json()] == [1]

    analyst = await client.get(f"/api/tags/entries/{shown.id}", headers=auth_headers)
    assert [t["entry_count"] for t in analyst.json()] == [2]


async def test_visitors_never_see_rejected_relationships(
    client: AsyncClient, db_session: AsyncSession, public_mode, visible_and_hidden, auth_headers
):
    shown = visible_and_hidden["shown"]
    a, b = ThreatActor(name="Hardening A"), ThreatActor(name="Hardening B")
    db_session.add_all([a, b])
    await db_session.flush()
    db_session.add_all(
        [
            EntryThreatActor(entry_id=shown.id, threat_actor_id=a.id, matched_names=["Hardening A"]),
            EntryThreatActor(entry_id=shown.id, threat_actor_id=b.id, matched_names=["Hardening B"]),
            EntityRelationship(
                source_type="threat_actor",
                source_id=a.id,
                target_type="threat_actor",
                target_id=b.id,
                relationship_type="related-to",
                confidence="likely",
                source="analyst_rejected",
            ),
        ]
    )
    await db_session.flush()

    query = f"entity_type=threat_actor&entity_id={a.id}&include_rejected=true&all_confidence=true"
    visitor = await client.get(f"/api/entity-relationships?{query}")
    assert visitor.status_code == 200, visitor.text
    assert visitor.json()["items"] == []
    by_entity = await client.get(f"/api/entity-relationships/by-entity/threat_actor/{a.id}?include_rejected=true")
    assert by_entity.json() == []

    analyst = await client.get(f"/api/entity-relationships?{query}", headers=auth_headers)
    assert len(analyst.json()["items"]) == 1


async def test_evidence_structure_names_threads_as_a_visitor_sees_them(
    db_session: AsyncSession, public_mode, visible_and_hidden
):
    """A thread seeded by a hidden article must not lend a visitor its stored slug or title."""
    from app.core.public_access import set_viewer_anonymous
    from app.intelligence.evidence_structure import _fetch_threads
    from app.intelligence.story_threads import visitor_slug
    from app.models.story_thread import StoryThread, StoryThreadEntry

    shown, hidden = visible_and_hidden["shown"], visible_and_hidden["hidden"]
    thread = StoryThread(slug="hidden-seed-headline", title="Hidden seed headline", entry_count=2)
    db_session.add(thread)
    await db_session.flush()
    db_session.add_all(
        [
            StoryThreadEntry(thread_id=thread.id, entry_id=hidden.id, role="origin"),
            StoryThreadEntry(thread_id=thread.id, entry_id=shown.id, role="beat"),
        ]
    )
    await db_session.flush()

    assert await _fetch_threads(db_session, [shown.id]) == {
        str(shown.id): ("hidden-seed-headline", "Hidden seed headline")
    }
    set_viewer_anonymous(True)
    try:
        assert await _fetch_threads(db_session, [shown.id]) == {str(shown.id): (visitor_slug(thread.id), "Shown")}
    finally:
        set_viewer_anonymous(False)


# ── Abuse limits ────────────────────────────────────────────────────


async def test_glossary_counts_take_the_heavy_anonymous_budget():
    from app.core.rate_limit import ANON_HEAVY_LIMITS, _get_limit

    assert _get_limit("/api/glossary/counts", "GET", anonymous=True) == (*ANON_HEAVY_LIMITS[0], "anon_heavy")


async def test_share_request_sizes_are_bounded():
    from app.api.shared import SharedAskAgentRequest

    req = SharedAskAgentRequest(question="q", history=[{"role": "user", "content": "z" * 9000}] * 25)
    assert len(req.history) == 20
    assert {len(m.content) for m in req.history} == {8000}
