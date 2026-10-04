"""User-defined chips: promotable tags, rule-authored presentation, and
per-user chip stamps (issue #23)."""

from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.tag import EntryTag, Tag
from app.models.user import User
from app.search.query_parser import parse_query
from app.search.query_planner import build_execution_plan


@pytest_asyncio.fixture
async def chip_entry(db_session: AsyncSession) -> Entry:
    feed = Feed(title="Chip Feed", url="https://example.com/chip-feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, title="OT exposure at Customer A", guid="chip-guid-1")
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest_asyncio.fixture
async def other_user(db_session: AsyncSession) -> User:
    user = User(username="otheranalyst", password_hash=hash_password("otherpassword"), role="user")
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def other_headers(other_user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(other_user.id, other_user.role)}"}


async def _add_tags(db: AsyncSession, entry: Entry, tags: list, user_id):
    from app.automation.actions import execute_action

    return await execute_action(db, entry, {"type": "add_tags", "config": {"tags": tags}}, user_id)


async def _entry_tags(client: AsyncClient, headers: dict, entry: Entry) -> list[dict]:
    resp = await client.get(f"/api/entries?feed_id={entry.feed_id}", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    return next(i for i in items if i["id"] == str(entry.id))["tags"]


# ---- Rule authoring ----


@pytest.mark.asyncio
async def test_add_tags_creates_chip_with_presentation(db_session: AsyncSession, chip_entry: Entry, test_user: User):
    spec = {"name": "customer-a", "color": "#DC2626", "description": "Customer A exposure", "chip": True}
    result = await _add_tags(db_session, chip_entry, [spec], test_user.id)

    assert result["status"] == "success"
    assert result["tags_added"] == ["customer-a"]
    tag = (await db_session.execute(select(Tag).where(Tag.name == "customer-a"))).scalar_one()
    assert tag.color == "#DC2626"
    assert tag.description == "Customer A exposure"
    assert tag.display_as_chip is True


@pytest.mark.asyncio
async def test_add_tags_never_restyles_existing_tag(db_session: AsyncSession, chip_entry: Entry, test_user: User):
    db_session.add(Tag(name="ot-relevant", color="#2563EB", description="Original"))
    await db_session.flush()

    spec = {"name": "ot-relevant", "color": "#16A34A", "description": "Overwritten?", "chip": True}
    await _add_tags(db_session, chip_entry, [spec], test_user.id)

    tag = (await db_session.execute(select(Tag).where(Tag.name == "ot-relevant"))).scalar_one()
    assert tag.color == "#2563EB"
    assert tag.description == "Original"
    assert tag.display_as_chip is False


@pytest.mark.asyncio
async def test_add_tags_name_only_config_still_works(db_session: AsyncSession, chip_entry: Entry, test_user: User):
    result = await _add_tags(db_session, chip_entry, ["plain-label"], test_user.id)

    assert result["tags_added"] == ["plain-label"]
    tag = (await db_session.execute(select(Tag).where(Tag.name == "plain-label"))).scalar_one()
    assert tag.color == "#6B7280"
    assert tag.display_as_chip is False
    row = (await db_session.execute(select(EntryTag).where(EntryTag.tag_id == tag.id))).scalar_one()
    assert row.user_id is None  # plain tags stay shared


@pytest.mark.asyncio
async def test_add_tags_rejects_bad_color(db_session: AsyncSession, chip_entry: Entry, test_user: User):
    await _add_tags(db_session, chip_entry, [{"name": "bad-color", "color": "red", "chip": True}], test_user.id)
    tag = (await db_session.execute(select(Tag).where(Tag.name == "bad-color"))).scalar_one()
    assert tag.color == "#6B7280"


# ---- Per-user stamps ----


@pytest.mark.asyncio
async def test_chip_stamp_is_personal(
    client: AsyncClient,
    db_session: AsyncSession,
    chip_entry: Entry,
    test_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    await _add_tags(db_session, chip_entry, [{"name": "customer-a", "chip": True}, "shared-label"], test_user.id)

    mine = {t["name"]: t for t in await _entry_tags(client, auth_headers, chip_entry)}
    assert mine["customer-a"]["display_as_chip"] is True
    assert mine["customer-a"]["personal"] is True
    assert mine["shared-label"]["personal"] is False

    theirs = {t["name"] for t in await _entry_tags(client, other_headers, chip_entry)}
    assert theirs == {"shared-label"}


@pytest.mark.asyncio
async def test_two_users_can_stamp_the_same_chip(
    db_session: AsyncSession, chip_entry: Entry, test_user: User, other_user: User
):
    await _add_tags(db_session, chip_entry, [{"name": "customer-a", "chip": True}], test_user.id)
    result = await _add_tags(db_session, chip_entry, ["customer-a"], other_user.id)

    assert result["tags_added"] == ["customer-a"]
    rows = (await db_session.execute(select(EntryTag.user_id).where(EntryTag.entry_id == chip_entry.id))).all()
    assert {r[0] for r in rows} == {test_user.id, other_user.id}


@pytest.mark.asyncio
async def test_remove_from_card_only_removes_my_stamp(
    client: AsyncClient,
    db_session: AsyncSession,
    chip_entry: Entry,
    test_user: User,
    other_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    await _add_tags(db_session, chip_entry, [{"name": "customer-a", "chip": True}], test_user.id)
    await _add_tags(db_session, chip_entry, ["customer-a"], other_user.id)
    tag = (await db_session.execute(select(Tag).where(Tag.name == "customer-a"))).scalar_one()

    resp = await client.delete(f"/api/tags/entries/{chip_entry.id}/{tag.id}", headers=auth_headers)
    assert resp.status_code == 204

    assert await _entry_tags(client, auth_headers, chip_entry) == []
    assert [t["name"] for t in await _entry_tags(client, other_headers, chip_entry)] == ["customer-a"]

    # Nothing left that this user can see → 404, not someone else's row.
    resp = await client.delete(f"/api/tags/entries/{chip_entry.id}/{tag.id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_tag_counts_are_per_viewer(
    client: AsyncClient,
    db_session: AsyncSession,
    chip_entry: Entry,
    test_user: User,
    auth_headers: dict,
    other_headers: dict,
):
    await _add_tags(db_session, chip_entry, [{"name": "customer-a", "chip": True}], test_user.id)

    mine = {t["name"]: t for t in (await client.get("/api/tags", headers=auth_headers)).json()}
    theirs = {t["name"]: t for t in (await client.get("/api/tags", headers=other_headers)).json()}
    assert mine["customer-a"]["entry_count"] == 1
    assert theirs["customer-a"]["entry_count"] == 0


@pytest.mark.asyncio
async def test_tag_matches_sees_the_rule_owners_chips(
    db_session: AsyncSession, chip_entry: Entry, test_user: User, other_user: User
):
    from app.automation.conditions import evaluate_conditions

    await _add_tags(db_session, chip_entry, [{"name": "customer-a", "chip": True}], test_user.id)

    cond = {"type": "tag_matches", "config": {"tags": ["customer-a"]}}
    assert await evaluate_conditions(db_session, chip_entry, cond, user_id=test_user.id) is True
    assert await evaluate_conditions(db_session, chip_entry, cond, user_id=other_user.id) is False


@pytest.mark.asyncio
async def test_remove_tags_action_leaves_other_users_stamps(
    db_session: AsyncSession, chip_entry: Entry, test_user: User, other_user: User
):
    from app.automation.actions import execute_action

    await _add_tags(db_session, chip_entry, [{"name": "customer-a", "chip": True}], test_user.id)
    await _add_tags(db_session, chip_entry, ["customer-a"], other_user.id)

    action = {"type": "remove_tags", "config": {"tags": ["customer-a"]}}
    result = await execute_action(db_session, chip_entry, action, test_user.id)
    assert result["tags_removed"] == ["customer-a"]

    rows = (await db_session.execute(select(EntryTag.user_id).where(EntryTag.entry_id == chip_entry.id))).all()
    assert [r[0] for r in rows] == [other_user.id]


# ---- Tag API ----


@pytest.mark.asyncio
async def test_promote_and_describe_tag(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    tag = Tag(name="needs-review")
    db_session.add(tag)
    await db_session.flush()

    resp = await client.put(
        f"/api/tags/{tag.id}",
        json={"display_as_chip": True, "description": "Analyst should look"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["display_as_chip"] is True
    assert resp.json()["description"] == "Analyst should look"

    resp = await client.put(f"/api/tags/{tag.id}", json={"description": ""}, headers=auth_headers)
    assert resp.json()["description"] is None
    assert resp.json()["display_as_chip"] is True


@pytest.mark.asyncio
async def test_merge_keeps_stamps_personal(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, chip_entry: Entry, test_user: User
):
    await _add_tags(db_session, chip_entry, [{"name": "cust-a", "chip": True}], test_user.id)
    target = Tag(name="customer-a", display_as_chip=True)
    db_session.add(target)
    await db_session.flush()
    source = (await db_session.execute(select(Tag).where(Tag.name == "cust-a"))).scalar_one()

    resp = await client.post(
        "/api/tags/merge", json={"source_ids": [str(source.id)], "target_id": str(target.id)}, headers=auth_headers
    )
    assert resp.status_code == 200

    row = (await db_session.execute(select(EntryTag).where(EntryTag.entry_id == chip_entry.id))).scalar_one()
    assert row.tag_id == target.id
    assert row.user_id == test_user.id


# ---- Search ----


@pytest.mark.asyncio
async def test_automation_tags_reach_search_index(db_session: AsyncSession, chip_entry: Entry, test_user: User):
    """Regression: tags applied by a rule are pushed to Meilisearch, shared
    names in `tags` and personal stamps in `user_tags`."""
    with patch("app.services.meilisearch_client.bulk_update_entry_tags") as push:
        await _add_tags(db_session, chip_entry, [{"name": "customer-a", "chip": True}, "shared-label"], test_user.id)

    pushed = push.call_args[0][0][str(chip_entry.id)]
    assert pushed["tags"] == ["shared-label"]
    assert pushed["user_tags"] == [f"{test_user.id}:customer-a"]


def test_tag_filter_includes_the_viewers_stamps():
    plan = build_execution_plan(parse_query('tag:"customer-a"'), viewer_id="u-1")
    assert plan.meili_filters == ['(tags = "customer-a" OR user_tags = "u-1:customer-a")']


def test_tag_filter_without_viewer_is_shared_only():
    plan = build_execution_plan(parse_query('tag:"customer-a"'))
    assert plan.meili_filters == ['tags = "customer-a"']


def test_negated_tag_filter_covers_the_viewers_stamps():
    plan = build_execution_plan(parse_query('NOT tag:"customer-a"'), viewer_id="u-1")
    assert plan.meili_filters == ['NOT (tags = "customer-a" OR user_tags = "u-1:customer-a")']


def test_hits_never_carry_user_tags():
    from app.services.meilisearch_client import strip_private_fields

    result = strip_private_fields({"hits": [{"id": "e1", "tags": ["x"], "user_tags": ["someone:y"]}]})
    assert result["hits"] == [{"id": "e1", "tags": ["x"]}]


@pytest.mark.asyncio
async def test_entry_detail_carries_tags(
    client: AsyncClient, db_session: AsyncSession, chip_entry: Entry, test_user: User, auth_headers: dict
):
    await _add_tags(db_session, chip_entry, [{"name": "customer-a", "chip": True}], test_user.id)

    resp = await client.get(f"/api/entries/{chip_entry.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert [(t["name"], t["display_as_chip"]) for t in resp.json()["tags"]] == [("customer-a", True)]
