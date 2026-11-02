"""Per-user tag assignments: a tag on an entry belongs to whoever applied it,
unless the tag is global, in which case one shared row serves everyone.

The tag list itself (names, colours, chip flags) stays shared.
"""

import importlib.util
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.tag import EntryTag, Tag
from app.models.user import User
from app.services.entry_tags import (
    MissingOwner,
    assignment_owner,
    ensure_assignment,
    load_entry_tags,
)

# ---- fixtures ----


@pytest_asyncio.fixture
async def scope_entries(db_session: AsyncSession) -> list[Entry]:
    feed = Feed(title="Scope Feed", url="https://example.com/scope-feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entries = [Entry(feed_id=feed.id, title=f"Entry {i}", guid=f"scope-guid-{i}") for i in range(2)]
    db_session.add_all(entries)
    await db_session.flush()
    return entries


@pytest_asyncio.fixture
async def other_user(db_session: AsyncSession) -> User:
    user = User(username="otheranalyst", password_hash=hash_password("otherpassword"), role="user")
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def other_headers(other_user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(other_user.id, other_user.role)}"}


@pytest_asyncio.fixture
async def system_user(db_session: AsyncSession) -> User:
    """The non-loginable service account; never receives a fanned-out assignment."""
    user = User(username="system", password_hash=hash_password("x"), role="system", is_active=False)
    db_session.add(user)
    await db_session.flush()
    return user


async def _make_tag(db: AsyncSession, name: str, *, is_global: bool = False, created_by=None) -> Tag:
    tag = Tag(name=name, created_by=created_by, is_global=is_global)
    db.add(tag)
    await db.flush()
    return tag


async def _rows(db: AsyncSession, tag: Tag | uuid.UUID) -> list[tuple]:
    tag_id = tag if isinstance(tag, uuid.UUID) else tag.id
    result = await db.execute(select(EntryTag.entry_id, EntryTag.user_id).where(EntryTag.tag_id == tag_id))
    return sorted(result.all(), key=lambda r: (str(r[0]), str(r[1])))


async def _names_for(db: AsyncSession, entry: Entry, user_id) -> set[str]:
    tags = (await load_entry_tags(db, [entry.id], user_id)).get(entry.id, [])
    return {t["name"] for t in tags}


# ---- owner rule ----


def test_assignment_owner_follows_tag_scope():
    personal = Tag(name="mine")
    shared = Tag(name="ours", is_global=True)
    uid = "11111111-1111-1111-1111-111111111111"
    assert str(assignment_owner(personal, uid)) == uid
    assert assignment_owner(shared, uid) is None
    assert assignment_owner(shared, None) is None
    with pytest.raises(MissingOwner):
        assignment_owner(personal, None)


# ---- hand tagging through the API ----


@pytest.mark.asyncio
async def test_hand_tag_is_personal(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    entry = scope_entries[0]
    tag = (await client.post("/api/tags", json={"name": "customer-a"}, headers=auth_headers)).json()
    assert tag["is_global"] is False

    resp = await client.post(f"/api/tags/entries/{entry.id}", json={"tag_ids": [tag["id"]]}, headers=auth_headers)
    assert resp.json() == {"added": 1}

    mine = (await client.get(f"/api/tags/entries/{entry.id}", headers=auth_headers)).json()
    assert [t["name"] for t in mine] == ["customer-a"]
    theirs = (await client.get(f"/api/tags/entries/{entry.id}", headers=other_headers)).json()
    assert theirs == []

    # The shared tag list shows the tag to both; the count is each viewer's own.
    counts = {t["name"]: t["entry_count"] for t in (await client.get("/api/tags", headers=auth_headers)).json()}
    assert counts["customer-a"] == 1
    counts = {t["name"]: t["entry_count"] for t in (await client.get("/api/tags", headers=other_headers)).json()}
    assert counts["customer-a"] == 0

    assert await _rows(db_session, uuid.UUID(tag["id"])) == [(entry.id, test_user.id)]


@pytest.mark.asyncio
async def test_global_tag_assignment_is_shared(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    entry = scope_entries[0]
    tag = (await client.post("/api/tags", json={"name": "team-wide", "is_global": True}, headers=auth_headers)).json()
    assert tag["is_global"] is True

    await client.post(f"/api/tags/entries/{entry.id}", json={"tag_ids": [tag["id"]]}, headers=auth_headers)
    # Re-applying by the other user adds nothing: the shared row already exists.
    resp = await client.post(f"/api/tags/entries/{entry.id}", json={"tag_ids": [tag["id"]]}, headers=other_headers)
    assert resp.json() == {"added": 0}

    for headers in (auth_headers, other_headers):
        seen = (await client.get(f"/api/tags/entries/{entry.id}", headers=headers)).json()
        assert [t["name"] for t in seen] == ["team-wide"]

    assert await _rows(db_session, uuid.UUID(tag["id"])) == [(entry.id, None)]
    item = (await load_entry_tags(db_session, [entry.id], other_user.id))[entry.id][0]
    assert item["is_global"] is True and item["personal"] is False


@pytest.mark.asyncio
async def test_bulk_tag_respects_scope(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
):
    personal = await _make_tag(db_session, "mine")
    shared = await _make_tag(db_session, "ours", is_global=True)
    entry_ids = [str(e.id) for e in scope_entries]

    resp = await client.post(
        "/api/tags/entries/bulk-tag",
        json={"entry_ids": entry_ids, "tag_ids": [str(personal.id), str(shared.id)]},
        headers=auth_headers,
    )
    assert resp.json() == {"added": 4}

    assert {r[1] for r in await _rows(db_session, personal)} == {test_user.id}
    assert {r[1] for r in await _rows(db_session, shared)} == {None}
    for entry in scope_entries:
        assert await _names_for(db_session, entry, other_user.id) == {"ours"}
        assert await _names_for(db_session, entry, test_user.id) == {"mine", "ours"}


@pytest.mark.asyncio
async def test_bulk_untag_leaves_other_users_rows(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
):
    tag = await _make_tag(db_session, "mine")
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, tag, test_user.id)
    await ensure_assignment(db_session, entry.id, tag, other_user.id)

    resp = await client.post(
        "/api/tags/entries/bulk-untag",
        json={"entry_ids": [str(entry.id)], "tag_ids": [str(tag.id)]},
        headers=auth_headers,
    )
    assert resp.json() == {"removed": 1}
    assert await _rows(db_session, tag) == [(entry.id, other_user.id)]


# ---- scope toggle ----


@pytest.mark.asyncio
async def test_make_tag_global_collapses_rows(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    tag = await _make_tag(db_session, "customer-a")
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, tag, test_user.id)
    await ensure_assignment(db_session, entry.id, tag, other_user.id)
    await ensure_assignment(db_session, scope_entries[1].id, tag, test_user.id)

    with patch("app.services.meilisearch_client.bulk_update_entry_tags") as push:
        resp = await client.put(f"/api/tags/{tag.id}", json={"is_global": True}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["is_global"] is True
    assert resp.json()["entry_count"] == 2

    assert await _rows(db_session, tag) == sorted(
        [(entry.id, None), (scope_entries[1].id, None)], key=lambda r: (str(r[0]), str(r[1]))
    )
    for headers in (auth_headers, other_headers):
        seen = (await client.get(f"/api/tags/entries/{entry.id}", headers=headers)).json()
        assert [t["name"] for t in seen] == ["customer-a"]

    pushed = push.call_args[0][0]
    assert set(pushed) == {str(entry.id), str(scope_entries[1].id)}
    assert pushed[str(entry.id)] == {"tags": ["customer-a"], "user_tags": []}


@pytest.mark.asyncio
async def test_make_tag_personal_fans_out(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    system_user: User,
    auth_headers: dict,
):
    tag = await _make_tag(db_session, "team-wide", is_global=True)
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, tag, test_user.id)
    assert await _rows(db_session, tag) == [(entry.id, None)]

    with patch("app.services.meilisearch_client.bulk_update_entry_tags") as push:
        resp = await client.put(f"/api/tags/{tag.id}", json={"is_global": False}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["is_global"] is False

    owners = {r[1] for r in await _rows(db_session, tag)}
    assert owners == {test_user.id, other_user.id}  # every human account, never the system user

    pushed = push.call_args[0][0][str(entry.id)]
    assert pushed["tags"] == []
    assert sorted(pushed["user_tags"]) == sorted([f"{test_user.id}:team-wide", f"{other_user.id}:team-wide"])


@pytest.mark.asyncio
async def test_toggle_tolerates_rows_already_in_target_shape(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    auth_headers: dict,
):
    """A shared row left beside a user's own row (a raced rule, or a half-done
    flip) must not make the collapse fail on the unique constraint."""
    tag = await _make_tag(db_session, "customer-a")
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, tag, test_user.id)
    db_session.add(EntryTag(entry_id=entry.id, tag_id=tag.id, user_id=None))
    await db_session.flush()

    with patch("app.services.meilisearch_client.bulk_update_entry_tags"):
        resp = await client.put(f"/api/tags/{tag.id}", json={"is_global": True}, headers=auth_headers)
    assert resp.status_code == 200
    assert await _rows(db_session, tag) == [(entry.id, None)]


# ---- merge ----


@pytest.mark.asyncio
async def test_merge_into_global_target_collapses(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
):
    source = await _make_tag(db_session, "cust-a")
    target = await _make_tag(db_session, "customer-a", is_global=True)
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, source, test_user.id)
    await ensure_assignment(db_session, entry.id, source, other_user.id)

    with patch("app.services.meilisearch_client.bulk_update_entry_tags"):
        resp = await client.post(
            "/api/tags/merge",
            json={"source_ids": [str(source.id)], "target_id": str(target.id)},
            headers=auth_headers,
        )
    assert resp.status_code == 200
    assert await _rows(db_session, target) == [(entry.id, None)]
    assert (await db_session.execute(select(Tag).where(Tag.id == source.id))).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_merge_global_source_into_personal_target_fans_out(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    system_user: User,
    auth_headers: dict,
):
    source = await _make_tag(db_session, "team-wide", is_global=True)
    target = await _make_tag(db_session, "customer-a")
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, source, test_user.id)  # one shared row
    await ensure_assignment(db_session, scope_entries[1].id, target, other_user.id)  # kept as-is

    with patch("app.services.meilisearch_client.bulk_update_entry_tags"):
        resp = await client.post(
            "/api/tags/merge",
            json={"source_ids": [str(source.id)], "target_id": str(target.id)},
            headers=auth_headers,
        )
    assert resp.status_code == 200
    rows = await _rows(db_session, target)
    assert (entry.id, test_user.id) in rows and (entry.id, other_user.id) in rows
    assert (scope_entries[1].id, other_user.id) in rows
    assert all(r[1] is not None for r in rows)
    assert len(rows) == 3


# ---- automation ----


@pytest.mark.asyncio
async def test_add_tags_without_owner_skips_personal_tag(db_session: AsyncSession, scope_entries: list[Entry]):
    from app.automation.actions import execute_action

    entry = scope_entries[0]
    await _make_tag(db_session, "mine")
    await _make_tag(db_session, "ours", is_global=True)

    result = await execute_action(db_session, entry, {"type": "add_tags", "config": {"tags": ["mine"]}}, None)
    assert result["status"] == "skipped"
    assert "no owner" in result["message"]
    assert await _names_for(db_session, entry, None) == set()

    result = await execute_action(db_session, entry, {"type": "add_tags", "config": {"tags": ["ours"]}}, None)
    assert result["tags_added"] == ["ours"]
    assert await _names_for(db_session, entry, None) == {"ours"}


@pytest.mark.asyncio
async def test_add_tags_can_create_a_global_tag(db_session: AsyncSession, scope_entries: list[Entry], test_user: User):
    from app.automation.actions import execute_action

    entry = scope_entries[0]
    spec = {"name": "team-wide", "global": True, "chip": True}
    result = await execute_action(db_session, entry, {"type": "add_tags", "config": {"tags": [spec]}}, test_user.id)
    assert result["tags_added"] == ["team-wide"]

    tag = (await db_session.execute(select(Tag).where(Tag.name == "team-wide"))).scalar_one()
    assert tag.is_global is True and tag.display_as_chip is True
    assert await _rows(db_session, tag) == [(entry.id, None)]


@pytest.mark.asyncio
async def test_copilot_add_tag_is_personal_and_reaches_search(
    db_session: AsyncSession, scope_entries: list[Entry], test_user: User
):
    from app.tools.write import _add_tag

    entry = scope_entries[0]
    with patch("app.services.meilisearch_client.bulk_update_entry_tags") as push:
        result = await _add_tag(db_session, test_user.id, str(entry.id), "from-copilot")
    assert result["created"] is True

    tag = (await db_session.execute(select(Tag).where(Tag.name == "from-copilot"))).scalar_one()
    assert await _rows(db_session, tag) == [(entry.id, test_user.id)]
    pushed = push.call_args[0][0][str(entry.id)]
    assert pushed == {"tags": [], "user_tags": [f"{test_user.id}:from-copilot"]}

    again = await _add_tag(db_session, test_user.id, str(entry.id), "from-copilot")
    assert again["already_tagged"] is True


# ---- search ----


@pytest.mark.asyncio
async def test_search_hit_tags_are_the_viewers(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    """The index's bare `tags` array is rewritten to what the viewer sees, so
    string-only consumers (the Android client) agree with `tag_details`."""
    entry = scope_entries[0]
    tag = await _make_tag(db_session, "customer-a")
    await ensure_assignment(db_session, entry.id, tag, test_user.id)

    def fake_search(**kwargs):
        return {
            "hits": [{"id": str(entry.id), "title": entry.title, "tags": ["stale-global-name"]}],
            "estimatedTotalHits": 1,
            "processingTimeMs": 1,
        }

    with patch("app.api.search.meilisearch_client.search_entries", side_effect=fake_search) as search:
        mine = (await client.get("/api/search?q=entry", headers=auth_headers)).json()["hits"][0]
        theirs = (await client.get("/api/search?q=entry", headers=other_headers)).json()["hits"][0]

    assert search.call_args_list[0].kwargs["viewer_id"] == str(test_user.id)
    assert mine["tags"] == ["customer-a"]
    assert [t["name"] for t in mine["tag_details"]] == ["customer-a"]
    assert theirs["tags"] == [] and theirs["tag_details"] == []


def test_legacy_tags_filter_includes_the_viewers_assignments():
    from unittest.mock import MagicMock

    from app.services import meilisearch_client

    index = MagicMock()
    index.search.return_value = {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}
    with patch("app.services.meilisearch_client._get_client") as get_client:
        get_client.return_value = MagicMock(index=MagicMock(return_value=index))
        meilisearch_client.search_entries(query="", tags=["customer-a"], viewer_id="u-1")
        params = index.search.call_args[0][1]
        assert params["filter"] == '(tags = "customer-a" OR user_tags = "u-1:customer-a")'
        assert params["facets"] == ["feed_type", "tags", "media_type", "user_tags"]

        meilisearch_client.get_facets(query="", viewer_id="u-1")
        assert "user_tags" in index.search.call_args[0][1]["facets"]


# ---- filter strings are built, not interpolated ----


def test_meili_quote_escapes_quotes_and_backslashes():
    from app.search.query_planner import meili_quote, tag_filter_clause

    assert meili_quote("plain") == '"plain"'
    assert meili_quote('a"b') == '"a\\"b"'
    assert meili_quote("a\\b") == '"a\\\\b"'
    # A value trying to close the quote and add its own clause stays one literal.
    hostile = 'x" OR user_tags = "victim:customer-a'
    expected_global = 'tags = "x\\" OR user_tags = \\"victim:customer-a"'
    expected_mine = 'user_tags = "me:x\\" OR user_tags = \\"victim:customer-a"'
    assert tag_filter_clause(hostile, "me") == f"({expected_global} OR {expected_mine})"


def test_wildcard_expansion_quotes_indexed_values():
    from app.search.meili_builder import _resolve_facet_filters
    from app.search.query_planner import PendingFacetFilter

    class Index:
        def search(self, query, params):
            return {"facetDistribution": {"tags": {'odd"name': 1}, "user_tags": {'u-1:odd"mine': 1}}}

    clauses = _resolve_facet_filters(Index(), [PendingFacetFilter("tags", "odd*")], viewer_id="u-1")
    assert clauses == ['(tags = "odd\\"name" OR user_tags = "u-1:odd\\"mine")']


def test_legacy_tags_param_cannot_escape_the_filter():
    from unittest.mock import MagicMock

    from app.services import meilisearch_client

    index = MagicMock()
    index.search.return_value = {"hits": [], "estimatedTotalHits": 0, "processingTimeMs": 0}
    with patch("app.services.meilisearch_client._get_client") as get_client:
        get_client.return_value = MagicMock(index=MagicMock(return_value=index))
        meilisearch_client.search_entries(query="", tags=['x" OR user_tags = "victim:secret'], viewer_id="me")
    flt = index.search.call_args[0][1]["filter"]
    assert 'user_tags = "victim:secret"' not in flt
    assert flt.count("OR") == 3 and flt.startswith('(tags = "x\\" OR')


@pytest.mark.asyncio
async def test_tag_names_cannot_carry_quotes(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, scope_entries
):
    # Request validation errors come back as 400 from the app's handler.
    resp = await client.post("/api/tags", json={"name": 'say "hi"'}, headers=auth_headers)
    assert resp.status_code == 400
    resp = await client.post("/api/tags", json={"name": "back\\slash"}, headers=auth_headers)
    assert resp.status_code == 400

    # Rules and the copilot tool normalise instead of failing.
    from app.automation.actions import execute_action

    result = await execute_action(
        db_session, scope_entries[0], {"type": "add_tags", "config": {"tags": ['cust "a"']}}, None
    )
    assert result["status"] == "skipped"  # no owner — but the name was cleaned first
    assert "cust a" in result["message"]


# ---- the index mirrors visible_to ----


@pytest.mark.asyncio
async def test_index_fields_skip_a_stray_shared_row_on_a_personal_tag(
    db_session: AsyncSession, scope_entries: list[Entry], test_user: User
):
    from app.services.entry_tags import search_tag_fields

    personal = await _make_tag(db_session, "customer-a")
    shared = await _make_tag(db_session, "team-wide", is_global=True)
    entry = scope_entries[0]
    db_session.add_all(
        [
            EntryTag(entry_id=entry.id, tag_id=personal.id, user_id=None),  # stray
            EntryTag(entry_id=entry.id, tag_id=shared.id, user_id=None),
        ]
    )
    await ensure_assignment(db_session, entry.id, personal, test_user.id)
    await db_session.flush()

    fields = await search_tag_fields(db_session, [entry.id])
    assert fields[str(entry.id)] == {"tags": ["team-wide"], "user_tags": [f"{test_user.id}:customer-a"]}


def test_reindexing_an_entry_keeps_its_tag_fields():
    """index_entry is a partial update that leaves `tags`/`user_tags` alone
    unless told otherwise; a transcript append or reconcile must not wipe them."""
    from unittest.mock import MagicMock

    from app.services import meilisearch_client

    index = MagicMock()
    with patch("app.services.meilisearch_client._get_client") as get_client:
        get_client.return_value = MagicMock(index=MagicMock(return_value=index))
        meilisearch_client.index_entry(
            entry_id=uuid.uuid4(),
            feed_id=uuid.uuid4(),
            title="t",
            content_text="body",
            summary=None,
            author=None,
            published_at=None,
            feed_title="f",
            feed_type="rss",
        )
    index.add_documents.assert_not_called()
    (doc,), _ = index.update_documents.call_args[0], index.update_documents.call_args[1]
    assert "tags" not in doc and "user_tags" not in doc


def test_multi_branch_search_folds_the_viewers_facets():
    from unittest.mock import MagicMock

    from app.search.meili_builder import execute_entry_search
    from app.search.query_parser import parse_query
    from app.search.query_planner import build_execution_plan

    class Index:
        def search(self, query, params):
            return {
                "hits": [{"id": query, "user_tags": ["u-1:x"]}],
                "estimatedTotalHits": 1,
                "processingTimeMs": 1,
                "facetDistribution": {"tags": {"team-wide": 1}, "user_tags": {"u-1:customer-a": 1, "u-2:other": 1}},
            }

    plan = build_execution_plan(parse_query("qilin OR lockbit"), viewer_id="u-1")
    assert len(plan.branches) == 2
    with patch("app.services.meilisearch_client._get_client") as get_client:
        get_client.return_value = MagicMock(index=MagicMock(return_value=Index()))
        result = execute_entry_search(plan)
    assert result["facetDistribution"] == {"tags": {"team-wide": 2, "customer-a": 2}}
    assert all("user_tags" not in h for h in result["hits"])


def test_get_facets_drops_other_users_tokens():
    from unittest.mock import MagicMock

    from app.services import meilisearch_client

    index = MagicMock()
    index.search.return_value = {
        "facetDistribution": {"tags": {"team-wide": 3}, "user_tags": {"me:customer-a": 2, "them:secret": 9}}
    }
    with patch("app.services.meilisearch_client._get_client") as get_client:
        get_client.return_value = MagicMock(index=MagicMock(return_value=index))
        facets = meilisearch_client.get_facets(query="", viewer_id="me")
    assert facets == {"tags": {"team-wide": 3, "customer-a": 2}}


# ---- backup ----


@pytest.mark.asyncio
async def test_backup_round_trips_tag_scope_and_presentation(
    client: AsyncClient, db_session: AsyncSession, admin_headers: dict
):
    resp = await client.post(
        "/api/tags",
        json={
            "name": "team-wide",
            "color": "#DC2626",
            "display_as_chip": True,
            "description": "Shared",
            "is_global": True,
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201

    exported = (await client.get("/api/backup/export", headers=admin_headers)).json()
    tag = next(t for t in exported["tags"] if t["name"] == "team-wide")
    assert tag == {
        "name": "team-wide",
        "color": "#DC2626",
        "display_as_chip": True,
        "description": "Shared",
        "is_global": True,
    }

    await db_session.execute(text("DELETE FROM tags"))
    await db_session.flush()
    resp = await client.post("/api/backup/import", json={"tags": [tag]}, headers=admin_headers)
    assert resp.status_code == 200
    restored = (await db_session.execute(select(Tag).where(Tag.name == "team-wide"))).scalar_one()
    assert (restored.is_global, restored.display_as_chip, restored.description) == (True, True, "Shared")


# ---- the harder interleavings ----


@pytest.mark.asyncio
async def test_rename_and_flip_in_one_put(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
):
    tag = await _make_tag(db_session, "cust-a")
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, tag, test_user.id)
    await ensure_assignment(db_session, entry.id, tag, other_user.id)

    with patch("app.services.meilisearch_client.bulk_update_entry_tags") as push:
        resp = await client.put(
            f"/api/tags/{tag.id}", json={"name": "customer-a", "is_global": True}, headers=auth_headers
        )
    assert resp.status_code == 200
    assert (resp.json()["name"], resp.json()["is_global"]) == ("customer-a", True)
    assert await _rows(db_session, tag) == [(entry.id, None)]
    # The index gets the new name, in the shared field.
    assert push.call_args[0][0][str(entry.id)] == {"tags": ["customer-a"], "user_tags": []}


@pytest.mark.asyncio
async def test_two_users_flipping_back_and_forth(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    system_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    tag = await _make_tag(db_session, "customer-a")
    e0, e1 = scope_entries
    await ensure_assignment(db_session, e0.id, tag, test_user.id)
    await ensure_assignment(db_session, e1.id, tag, other_user.id)

    async def counts() -> tuple[int, int]:
        a = next(t for t in (await client.get("/api/tags", headers=auth_headers)).json() if t["id"] == str(tag.id))
        b = next(t for t in (await client.get("/api/tags", headers=other_headers)).json() if t["id"] == str(tag.id))
        return a["entry_count"], b["entry_count"]

    assert await counts() == (1, 1)
    with patch("app.services.meilisearch_client.bulk_update_entry_tags"):
        assert (
            await client.put(f"/api/tags/{tag.id}", json={"is_global": True}, headers=auth_headers)
        ).status_code == 200
        assert await counts() == (2, 2)  # both entries, one shared row each
        assert (
            await client.put(f"/api/tags/{tag.id}", json={"is_global": False}, headers=other_headers)
        ).status_code == 200
        assert await counts() == (2, 2)  # fanned out: each user now owns both
        assert (
            await client.put(f"/api/tags/{tag.id}", json={"is_global": True}, headers=auth_headers)
        ).status_code == 200
    rows = await _rows(db_session, tag)
    assert rows == sorted([(e0.id, None), (e1.id, None)], key=lambda r: (str(r[0]), str(r[1])))


@pytest.mark.asyncio
async def test_delete_tag_with_mixed_rows_clears_the_index(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
):
    tag = await _make_tag(db_session, "customer-a")
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, tag, test_user.id)
    await ensure_assignment(db_session, entry.id, tag, other_user.id)
    db_session.add(EntryTag(entry_id=entry.id, tag_id=tag.id, user_id=None))
    await db_session.flush()

    with patch("app.services.meilisearch_client.bulk_update_entry_tags") as push:
        resp = await client.delete(f"/api/tags/{tag.id}", headers=auth_headers)
    assert resp.status_code == 204
    assert await _rows(db_session, tag) == []
    assert push.call_args[0][0] == {str(entry.id): {"tags": [], "user_tags": []}}


@pytest.mark.asyncio
async def test_copilot_delete_entity_tag_clears_the_index(
    db_session: AsyncSession, scope_entries: list[Entry], test_user: User, other_user: User
):
    from app.tools.delete import _delete_entity

    tag = await _make_tag(db_session, "customer-a")
    entry = scope_entries[0]
    await ensure_assignment(db_session, entry.id, tag, test_user.id)
    await ensure_assignment(db_session, entry.id, tag, other_user.id)

    first = await _delete_entity(db_session, test_user.id, "tag", str(tag.id))
    assert first.get("confirmation_token"), first
    with patch("app.services.meilisearch_client.bulk_update_entry_tags") as push:
        done = await _delete_entity(db_session, test_user.id, "tag", str(tag.id), first["confirmation_token"])
    assert done["status"] == "deleted"
    assert await _rows(db_session, tag) == []
    assert push.call_args[0][0] == {str(entry.id): {"tags": [], "user_tags": []}}


@pytest.mark.asyncio
async def test_global_tag_can_be_removed_by_anyone(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    other_headers: dict,
):
    """A global tag's shared row is everyone's: another user, or another
    user's rule, can take it off the entry."""
    from app.automation.actions import execute_action

    tag = await _make_tag(db_session, "team-wide", is_global=True)
    e0, e1 = scope_entries
    await ensure_assignment(db_session, e0.id, tag, test_user.id)
    await ensure_assignment(db_session, e1.id, tag, test_user.id)

    resp = await client.delete(f"/api/tags/entries/{e0.id}/{tag.id}", headers=other_headers)
    assert resp.status_code == 204

    result = await execute_action(
        db_session, e1, {"type": "remove_tags", "config": {"tags": ["team-wide"]}}, other_user.id
    )
    assert result["tags_removed"] == ["team-wide"]
    assert await _rows(db_session, tag) == []


@pytest.mark.asyncio
async def test_run_now_refuses_an_ownerless_rule(client: AsyncClient, db_session: AsyncSession, admin_headers: dict):
    from app.models.automation_rule import AutomationRule

    rule = AutomationRule(
        created_by=None,
        name="Orphan",
        trigger_type="on_manual",
        conditions={},
        actions=[{"type": "add_tags", "config": {"tags": ["orphan-tag"]}}],
    )
    db_session.add(rule)
    await db_session.flush()

    resp = await client.post(f"/api/automation/rules/{rule.id}/run", headers=admin_headers)
    assert resp.status_code == 400
    assert "no owner" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_personal_flag_when_shared_and_own_rows_coexist(
    db_session: AsyncSession, scope_entries: list[Entry], test_user: User
):
    """Mid-flip a global tag can briefly have both a shared row and a user's
    own row; the shared one decides the label."""
    tag = await _make_tag(db_session, "team-wide", is_global=True)
    entry = scope_entries[0]
    db_session.add_all(
        [
            EntryTag(entry_id=entry.id, tag_id=tag.id, user_id=None),
            EntryTag(entry_id=entry.id, tag_id=tag.id, user_id=test_user.id),
        ]
    )
    await db_session.flush()
    items = (await load_entry_tags(db_session, [entry.id], test_user.id))[entry.id]
    assert [(t["name"], t["personal"]) for t in items] == [("team-wide", False)]


@pytest.mark.asyncio
async def test_stray_shared_row_on_a_personal_tag_is_invisible(
    db_session: AsyncSession, scope_entries: list[Entry], test_user: User, other_user: User
):
    """A NULL-owner row that outlives a flip to personal must not publish the
    tag to everyone; it is simply not shown."""
    tag = await _make_tag(db_session, "customer-a")
    entry = scope_entries[0]
    db_session.add(EntryTag(entry_id=entry.id, tag_id=tag.id, user_id=None))
    await db_session.flush()
    assert await _names_for(db_session, entry, test_user.id) == set()
    assert await _names_for(db_session, entry, other_user.id) == set()
    assert await _names_for(db_session, entry, None) == set()


@pytest.mark.asyncio
async def test_export_and_top_tags_do_not_leak_across_users(
    client: AsyncClient,
    db_session: AsyncSession,
    scope_entries: list[Entry],
    test_user: User,
    other_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    from datetime import UTC, datetime

    tag = await _make_tag(db_session, "customer-a")
    entry = scope_entries[0]
    entry.published_at = datetime.now(UTC)
    await ensure_assignment(db_session, entry.id, tag, test_user.id)
    await db_session.flush()

    mine = (await client.get(f"/api/export/entries/{entry.id}", headers=auth_headers)).text
    theirs = (await client.get(f"/api/export/entries/{entry.id}", headers=other_headers)).text
    assert "customer-a" in mine
    assert "customer-a" not in theirs

    mine = (await client.get("/api/widgets/top-tags", headers=auth_headers)).json()
    theirs = (await client.get("/api/widgets/top-tags", headers=other_headers)).json()
    names = lambda payload: {t["name"] for t in (payload["tags"] if isinstance(payload, dict) else payload)}  # noqa: E731
    assert "customer-a" in names(mine)
    assert "customer-a" not in names(theirs)


# ---- migration SQL ----


def _migration_module():
    path = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "y6q8s0u2w4y6_per_user_tags.py"
    spec = importlib.util.spec_from_file_location("per_user_tags_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_migration_copies_shared_rows_to_each_human_user(
    db_session: AsyncSession, scope_entries: list[Entry], test_user: User, other_user: User, system_user: User
):
    """The upgrade's statements, run against a seeded schema: one shared row
    becomes one personal row per human account, and the shared row goes."""
    mig = _migration_module()
    tag = await _make_tag(db_session, "legacy")
    entry = scope_entries[0]
    db_session.add(EntryTag(entry_id=entry.id, tag_id=tag.id, user_id=None))
    # A user who already holds their own row (an x5p7r9t1v3x5 chip stamp) is left alone.
    db_session.add(EntryTag(entry_id=entry.id, tag_id=tag.id, user_id=test_user.id))
    await db_session.flush()

    await db_session.execute(text(mig.COPY_SHARED_TO_EACH_USER))
    await db_session.execute(text(mig.DELETE_SHARED_ROWS))

    assert {r[1] for r in await _rows(db_session, tag)} == {test_user.id, other_user.id}

    # And the downgrade collapses them back to one shared row.
    await db_session.execute(text(mig.COLLAPSE_TO_SHARED))
    await db_session.execute(text(mig.DELETE_PERSONAL_ROWS))
    assert await _rows(db_session, tag) == [(entry.id, None)]
