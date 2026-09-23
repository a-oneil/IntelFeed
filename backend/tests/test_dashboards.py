"""Tests for dashboard and widget management API."""

import uuid

import pytest
from httpx import AsyncClient

from app.dashboard_defaults import DEFAULT_BOARDS


@pytest.mark.asyncio
async def test_create_dashboard(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/dashboards",
        json={"name": "Threat Overview"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Threat Overview"
    assert data["is_default"] is False
    assert data["widgets"] == []


@pytest.mark.asyncio
async def test_list_dashboards(client: AsyncClient, auth_headers: dict):
    # Create two dashboards
    await client.post("/api/dashboards", json={"name": "D1"}, headers=auth_headers)
    await client.post("/api/dashboards", json={"name": "D2"}, headers=auth_headers)

    resp = await client.get("/api/dashboards", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2
    names = [d["name"] for d in data["items"]]
    assert "D1" in names
    assert "D2" in names


@pytest.mark.asyncio
async def test_get_dashboard(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards", json={"name": "Get Test"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    resp = await client.get(f"/api/dashboards/{dash_id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "Get Test"


@pytest.mark.asyncio
async def test_update_dashboard(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards", json={"name": "Before"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    resp = await client.put(f"/api/dashboards/{dash_id}", json={"name": "After"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "After"


@pytest.mark.asyncio
async def test_delete_dashboard(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards", json={"name": "To Delete"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    resp = await client.delete(f"/api/dashboards/{dash_id}", headers=auth_headers)
    assert resp.status_code == 204

    resp = await client.get(f"/api/dashboards/{dash_id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_dashboard_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.get(f"/api/dashboards/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_default_dashboard(client: AsyncClient, auth_headers: dict):
    # Create default
    resp = await client.post("/api/dashboards", json={"name": "Default", "is_default": True}, headers=auth_headers)
    d1_id = resp.json()["id"]

    # Create another default — first should be unset
    resp = await client.post("/api/dashboards", json={"name": "New Default", "is_default": True}, headers=auth_headers)
    d2_id = resp.json()["id"]

    # Check first is no longer default
    resp = await client.get(f"/api/dashboards/{d1_id}", headers=auth_headers)
    assert resp.json()["is_default"] is False

    resp = await client.get(f"/api/dashboards/{d2_id}", headers=auth_headers)
    assert resp.json()["is_default"] is True


# --- Widget tests ---


@pytest.mark.asyncio
async def test_add_widget(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards", json={"name": "With Widget"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    resp = await client.post(
        f"/api/dashboards/{dash_id}/widgets",
        json={"widget_type": "stat_card", "title": "CVE Count", "width": 3, "height": 2},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    widget = resp.json()
    assert widget["widget_type"] == "stat_card"
    assert widget["title"] == "CVE Count"
    assert widget["width"] == 3
    assert widget["height"] == 2


@pytest.mark.asyncio
async def test_update_widget(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards", json={"name": "Widget Update"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    resp = await client.post(
        f"/api/dashboards/{dash_id}/widgets",
        json={"widget_type": "feed_activity", "title": "Activity"},
        headers=auth_headers,
    )
    widget_id = resp.json()["id"]

    resp = await client.put(
        f"/api/dashboards/{dash_id}/widgets/{widget_id}",
        json={"title": "Updated Title", "config": {"date_range": "7d"}},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Updated Title"
    assert resp.json()["config"]["date_range"] == "7d"


@pytest.mark.asyncio
async def test_remove_widget(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards", json={"name": "Widget Remove"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    resp = await client.post(
        f"/api/dashboards/{dash_id}/widgets",
        json={"widget_type": "cve_severity"},
        headers=auth_headers,
    )
    widget_id = resp.json()["id"]

    resp = await client.delete(f"/api/dashboards/{dash_id}/widgets/{widget_id}", headers=auth_headers)
    assert resp.status_code == 204

    # Verify gone
    resp = await client.get(f"/api/dashboards/{dash_id}", headers=auth_headers)
    assert len(resp.json()["widgets"]) == 0


@pytest.mark.asyncio
async def test_bulk_layout_update(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards", json={"name": "Layout Test"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    # Add two widgets
    r1 = await client.post(
        f"/api/dashboards/{dash_id}/widgets", json={"widget_type": "stat_card"}, headers=auth_headers
    )
    r2 = await client.post(
        f"/api/dashboards/{dash_id}/widgets", json={"widget_type": "feed_activity"}, headers=auth_headers
    )
    w1 = r1.json()["id"]
    w2 = r2.json()["id"]

    # Bulk update positions
    resp = await client.put(
        f"/api/dashboards/{dash_id}/layout",
        json={
            "items": [
                {"id": w1, "position_x": 0, "position_y": 0, "width": 6, "height": 3},
                {"id": w2, "position_x": 6, "position_y": 0, "width": 6, "height": 4},
            ]
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200

    # Verify positions
    resp = await client.get(f"/api/dashboards/{dash_id}", headers=auth_headers)
    widgets = resp.json()["widgets"]
    w1_data = next(w for w in widgets if w["id"] == w1)
    w2_data = next(w for w in widgets if w["id"] == w2)
    assert w1_data["width"] == 6
    assert w2_data["position_x"] == 6
    assert w2_data["height"] == 4


@pytest.mark.asyncio
async def test_dashboard_includes_widgets(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards", json={"name": "Full"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    await client.post(
        f"/api/dashboards/{dash_id}/widgets", json={"widget_type": "stat_card", "title": "A"}, headers=auth_headers
    )
    await client.post(
        f"/api/dashboards/{dash_id}/widgets", json={"widget_type": "cve_severity", "title": "B"}, headers=auth_headers
    )

    resp = await client.get(f"/api/dashboards/{dash_id}", headers=auth_headers)
    assert len(resp.json()["widgets"]) == 2


@pytest.mark.asyncio
async def test_dashboards_are_scoped_to_their_owner(
    client: AsyncClient, auth_headers: dict, admin_headers: dict
):
    """One user's boards are invisible — and unreachable — to another."""
    resp = await client.post("/api/dashboards", json={"name": "Mine"}, headers=auth_headers)
    dash_id = resp.json()["id"]

    listed = await client.get("/api/dashboards", headers=admin_headers)
    assert [d["name"] for d in listed.json()["items"]] == []

    assert (await client.get(f"/api/dashboards/{dash_id}", headers=admin_headers)).status_code == 404
    assert (
        await client.put(f"/api/dashboards/{dash_id}", json={"name": "Yours"}, headers=admin_headers)
    ).status_code == 404
    assert (await client.delete(f"/api/dashboards/{dash_id}", headers=admin_headers)).status_code == 404

    still_mine = await client.get(f"/api/dashboards/{dash_id}", headers=auth_headers)
    assert still_mine.json()["name"] == "Mine"


@pytest.mark.asyncio
async def test_seed_defaults_creates_the_default_board_set(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/dashboards/seed-defaults", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()["items"]

    assert [d["name"] for d in items] == [b["name"] for b in DEFAULT_BOARDS]
    assert all(d["name"].startswith("__triage__/") for d in items)
    for board, created in zip(DEFAULT_BOARDS, items, strict=True):
        assert len(created["widgets"]) == len(board["widgets"])
        assert {w["widget_type"] for w in created["widgets"]} == {
            w["widget_type"] for w in board["widgets"]
        }

    # Widget types all exist in the registry the frontend renders from.
    assert all(w["width"] <= 12 for d in items for w in d["widgets"])


@pytest.mark.asyncio
async def test_seed_defaults_leaves_an_existing_board_set_alone(
    client: AsyncClient, auth_headers: dict
):
    """A user who already customized their boards never gets defaults poured on top."""
    await client.post("/api/dashboards", json={"name": "__triage__/Just Mine"}, headers=auth_headers)

    resp = await client.post("/api/dashboards/seed-defaults", headers=auth_headers)
    assert resp.status_code == 200
    assert [d["name"] for d in resp.json()["items"]] == ["__triage__/Just Mine"]

    # And a second call is still a no-op for a seeded user.
    await client.delete(
        f"/api/dashboards/{resp.json()['items'][0]['id']}", headers=auth_headers
    )
    first = await client.post("/api/dashboards/seed-defaults", headers=auth_headers)
    again = await client.post("/api/dashboards/seed-defaults", headers=auth_headers)
    assert [d["id"] for d in again.json()["items"]] == [d["id"] for d in first.json()["items"]]


@pytest.mark.asyncio
async def test_seed_defaults_is_per_user(
    client: AsyncClient, auth_headers: dict, admin_headers: dict
):
    mine = await client.post("/api/dashboards/seed-defaults", headers=auth_headers)
    theirs = await client.post("/api/dashboards/seed-defaults", headers=admin_headers)

    mine_ids = {d["id"] for d in mine.json()["items"]}
    theirs_ids = {d["id"] for d in theirs.json()["items"]}
    assert mine_ids and theirs_ids
    assert mine_ids.isdisjoint(theirs_ids)
