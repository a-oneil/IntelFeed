"""Tests for the Entity Profiles API (BE-16)."""

import uuid

import pytest
from httpx import AsyncClient

BASE = "/api/entities"


# ── Threat Actor ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_threat_actor(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        f"{BASE}/threat-actors",
        json={
            "name": "Fancy Bear",
            "aliases": ["APT28", "Sofacy"],
            "description": "Russian GRU unit",
            "country": "Russia",
            "motivation": "espionage",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Fancy Bear"
    assert "APT28" in data["aliases"]
    assert data["country"] == "Russia"
    assert data["motivation"] == "espionage"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_threat_actor_upsert(client: AsyncClient, auth_headers: dict):
    """Creating the same actor name (case-insensitive) returns the existing entity."""
    body = {"name": "Lazarus Group", "description": "DPRK threat actor"}
    resp1 = await client.post(f"{BASE}/threat-actors", json=body, headers=auth_headers)
    assert resp1.status_code == 201
    id1 = resp1.json()["id"]

    body2 = {"name": "lazarus group", "description": "Updated description"}
    resp2 = await client.post(f"{BASE}/threat-actors", json=body2, headers=auth_headers)
    assert resp2.status_code == 201
    assert resp2.json()["id"] == id1
    assert resp2.json()["description"] == "Updated description"


@pytest.mark.asyncio
async def test_create_threat_actor_dedupes_by_alias(client: AsyncClient, auth_headers: dict):
    """Creating an actor by a name that is an *alias* of an existing profile must
    resolve to that profile, not spawn a duplicate (regression: post-merge aliases
    live in the aliases array, not the name column)."""
    resp1 = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Cozy Bear", "aliases": ["APT29", "The Dukes"]},
        headers=auth_headers,
    )
    assert resp1.status_code == 201
    id1 = resp1.json()["id"]

    # Reference the same actor by one of its aliases (different case for good measure)
    resp2 = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "apt29", "description": "Seen again under alias"},
        headers=auth_headers,
    )
    assert resp2.status_code == 201
    assert resp2.json()["id"] == id1, "alias reference should not create a duplicate actor"


@pytest.mark.asyncio
async def test_create_malware_dedupes_by_alias(client: AsyncClient, auth_headers: dict):
    """Malware lookup must also match the aliases array, not just the canonical name."""
    resp1 = await client.post(
        f"{BASE}/malware",
        json={"name": "Emotet", "aliases": ["Geodo", "Heodo"]},
        headers=auth_headers,
    )
    assert resp1.status_code == 201
    id1 = resp1.json()["id"]

    resp2 = await client.post(
        f"{BASE}/malware",
        json={"name": "Heodo"},
        headers=auth_headers,
    )
    assert resp2.status_code == 201
    assert resp2.json()["id"] == id1, "alias reference should not create a duplicate family"


@pytest.mark.asyncio
async def test_create_threat_actor_linked_to_entry(client: AsyncClient, auth_headers: dict, test_entry):
    resp = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Linked Actor", "entry_id": str(test_entry.id)},
        headers=auth_headers,
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_update_threat_actor(client: AsyncClient, auth_headers: dict):
    create = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Update Target Actor"},
        headers=auth_headers,
    )
    actor_id = create.json()["id"]

    resp = await client.put(
        f"{BASE}/threat-actors/{actor_id}",
        json={
            "name": "Renamed Actor",
            "aliases": ["alias1"],
            "description": "new desc",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Renamed Actor"
    assert data["aliases"] == ["alias1"]
    assert data["description"] == "new desc"


@pytest.mark.asyncio
async def test_update_threat_actor_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = str(uuid.uuid4())
    resp = await client.put(
        f"{BASE}/threat-actors/{fake_id}",
        json={"name": "nope"},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_threat_actor(client: AsyncClient, auth_headers: dict):
    create = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Delete Me Actor"},
        headers=auth_headers,
    )
    actor_id = create.json()["id"]

    resp = await client.delete(f"{BASE}/threat-actors/{actor_id}", headers=auth_headers)
    assert resp.status_code == 204

    # Verify gone
    resp2 = await client.put(
        f"{BASE}/threat-actors/{actor_id}",
        json={"name": "should fail"},
        headers=auth_headers,
    )
    assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_delete_threat_actor_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = str(uuid.uuid4())
    resp = await client.delete(f"{BASE}/threat-actors/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404


# ── TTP ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_ttp(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        f"{BASE}/ttps",
        json={
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "execution",
            "description": "Adversaries may abuse PowerShell",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["technique_id"] == "T1059.001"
    assert data["technique_name"] == "PowerShell"
    assert data["tactic"] == "execution"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_ttp_upsert(client: AsyncClient, auth_headers: dict):
    """Creating the same technique_id returns the existing TTP."""
    body = {"technique_id": "T1071", "technique_name": "Application Layer Protocol"}
    resp1 = await client.post(f"{BASE}/ttps", json=body, headers=auth_headers)
    assert resp1.status_code == 201
    id1 = resp1.json()["id"]

    body2 = {"technique_id": "t1071", "technique_name": "Updated Name", "tactic": "command-and-control"}
    resp2 = await client.post(f"{BASE}/ttps", json=body2, headers=auth_headers)
    assert resp2.status_code == 201
    assert resp2.json()["id"] == id1
    assert resp2.json()["technique_name"] == "Updated Name"


@pytest.mark.asyncio
async def test_delete_ttp_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = str(uuid.uuid4())
    resp = await client.delete(f"{BASE}/ttps/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404


# ── CVE ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_cve(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        f"{BASE}/cves",
        json={
            "cve_id": "CVE-2024-12345",
            "description": "Critical RCE vulnerability",
            "severity": "CRITICAL",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["cve_id"] == "CVE-2024-12345"
    assert data["description"] == "Critical RCE vulnerability"
    assert data["severity"] == "CRITICAL"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_cve_upsert(client: AsyncClient, auth_headers: dict):
    """Creating the same CVE ID (case-insensitive) returns the existing entity."""
    body = {"cve_id": "CVE-2024-99999", "severity": "HIGH"}
    resp1 = await client.post(f"{BASE}/cves", json=body, headers=auth_headers)
    assert resp1.status_code == 201
    id1 = resp1.json()["id"]

    body2 = {"cve_id": "CVE-2024-99999", "description": "Added later", "severity": "CRITICAL"}
    resp2 = await client.post(f"{BASE}/cves", json=body2, headers=auth_headers)
    assert resp2.status_code == 201
    assert resp2.json()["id"] == id1
    assert resp2.json()["severity"] == "CRITICAL"
    assert resp2.json()["description"] == "Added later"


@pytest.mark.asyncio
async def test_delete_cve_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = str(uuid.uuid4())
    resp = await client.delete(f"{BASE}/cves/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404


# ── Auth requirements ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_threat_actor_requires_auth(client: AsyncClient):
    resp = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Unauthorized Actor"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_threat_actor_requires_auth(client: AsyncClient):
    fake_id = str(uuid.uuid4())
    resp = await client.delete(f"{BASE}/threat-actors/{fake_id}")
    assert resp.status_code == 401


# ── Rescan ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rescan_entity_queues_backlink(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Rescan Test Actor"},
        headers=auth_headers,
    )
    entity_id = create_resp.json()["id"]

    resp = await client.post(f"{BASE}/threat_actor/{entity_id}/rescan", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["queued"] is True
    assert data["entity_type"] == "threat_actor"
    assert data["entity_id"] == entity_id


@pytest.mark.asyncio
async def test_rescan_entity_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = str(uuid.uuid4())
    resp = await client.post(f"{BASE}/threat_actor/{fake_id}/rescan", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_rescan_entity_rejects_unknown_type(client: AsyncClient, auth_headers: dict):
    fake_id = str(uuid.uuid4())
    resp = await client.post(f"{BASE}/not_a_real_type/{fake_id}/rescan", headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_rescan_entity_requires_auth(client: AsyncClient):
    fake_id = str(uuid.uuid4())
    resp = await client.post(f"{BASE}/threat_actor/{fake_id}/rescan")
    assert resp.status_code == 401


# ── Alias adds trigger the same retro match scan as entity creation ──


@pytest.fixture
def queued_backlinks(monkeypatch):
    """Capture link_new_entity_to_entries dispatches instead of hitting Celery."""
    from app.workers import intel_feed_tasks

    calls: list[dict] = []
    monkeypatch.setattr(
        intel_feed_tasks.link_new_entity_to_entries,
        "apply_async",
        lambda *a, **kw: calls.append(kw.get("kwargs", {})),
    )
    return calls


@pytest.mark.asyncio
async def test_adding_alias_queues_retro_scan(client: AsyncClient, auth_headers: dict, queued_backlinks: list):
    create = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Retro Alias Actor", "aliases": ["Alpha"]},
        headers=auth_headers,
    )
    actor_id = create.json()["id"]
    queued_backlinks.clear()

    resp = await client.put(
        f"{BASE}/threat-actors/{actor_id}",
        json={"aliases": ["Alpha", "Beta"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert queued_backlinks == [{"entity_type": "threat_actor", "entity_id": actor_id}]


@pytest.mark.asyncio
async def test_adding_tool_alias_queues_retro_scan(client: AsyncClient, auth_headers: dict, queued_backlinks: list):
    create = await client.post(
        f"{BASE}/tools",
        json={"name": "Retro Alias Tool"},
        headers=auth_headers,
    )
    tool_id = create.json()["id"]
    queued_backlinks.clear()

    resp = await client.put(
        f"{BASE}/tools/{tool_id}",
        json={"aliases": ["RatBag"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert queued_backlinks == [{"entity_type": "tool", "entity_id": tool_id}]


@pytest.mark.asyncio
async def test_non_alias_update_does_not_queue_retro_scan(
    client: AsyncClient, auth_headers: dict, queued_backlinks: list
):
    create = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Quiet Actor", "aliases": ["Gamma"]},
        headers=auth_headers,
    )
    actor_id = create.json()["id"]
    queued_backlinks.clear()

    # Description-only edit, and a re-cased alias — neither widens the match surface.
    resp = await client.put(
        f"{BASE}/threat-actors/{actor_id}",
        json={"description": "updated", "aliases": ["GAMMA"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert queued_backlinks == []


@pytest.mark.asyncio
async def test_removing_alias_does_not_queue_retro_scan(
    client: AsyncClient, auth_headers: dict, queued_backlinks: list
):
    create = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Shrinking Actor", "aliases": ["Delta", "Epsilon"]},
        headers=auth_headers,
    )
    actor_id = create.json()["id"]
    queued_backlinks.clear()

    resp = await client.put(
        f"{BASE}/threat-actors/{actor_id}",
        json={"aliases": ["Delta"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert queued_backlinks == []


@pytest.mark.asyncio
async def test_merge_queues_retro_scan_for_keeper(client: AsyncClient, admin_headers: dict, queued_backlinks: list):
    keeper = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Keeper Actor"},
        headers=admin_headers,
    )
    keeper_id = keeper.json()["id"]
    dupe = await client.post(
        f"{BASE}/threat-actors",
        json={"name": "Duplicate Actor", "aliases": ["DupeAlias"]},
        headers=admin_headers,
    )
    dupe_id = dupe.json()["id"]
    queued_backlinks.clear()

    resp = await client.post(
        f"{BASE}/threat_actor/merge",
        json={"keeper_id": keeper_id, "merge_ids": [dupe_id]},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    # The keeper absorbed "Duplicate Actor" + "DupeAlias" — both are new match surface.
    assert queued_backlinks == [{"entity_type": "threat_actor", "entity_id": keeper_id}]
