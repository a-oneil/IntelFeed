"""Tests for the Intelligence API (/api/ intelligence endpoints)."""

import uuid

import pytest
from httpx import AsyncClient

from app.models.entry import Entry
from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP

# ── TTP Endpoints ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_ttps(client: AsyncClient, auth_headers: dict, test_ttp: TTP):
    resp = await client.get("/api/ttps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(t["technique_id"] == "T1566.001" for t in data["items"])


@pytest.mark.asyncio
async def test_list_ttps_unauthenticated(client: AsyncClient, test_ttp: TTP):
    resp = await client.get("/api/ttps")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_ttp_by_technique_id(client: AsyncClient, auth_headers: dict, test_ttp: TTP):
    resp = await client.get(f"/api/ttps/by-technique/{test_ttp.technique_id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["technique_name"] == "Spearphishing Attachment"
    assert data["tactic"] == "initial-access"


# ── Threat Actor Endpoints ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_threat_actors(client: AsyncClient, auth_headers: dict, test_threat_actor: ThreatActor):
    resp = await client.get("/api/threat-actors", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(a["name"] == "APT29" for a in data["items"])


@pytest.mark.asyncio
async def test_get_threat_actor_by_id(client: AsyncClient, auth_headers: dict, test_threat_actor: ThreatActor):
    resp = await client.get(f"/api/threat-actors/{test_threat_actor.id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "APT29"
    assert "Cozy Bear" in data["aliases"]


@pytest.mark.asyncio
async def test_get_threat_actor_not_found(client: AsyncClient, auth_headers: dict):
    fake_id = uuid.uuid4()
    resp = await client.get(f"/api/threat-actors/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404


# ── Detection Rule Endpoints ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_detection_rules_empty(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/detection-rules", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_create_detection_rule(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    payload = {
        "title": "Detect Suspicious PowerShell",
        "rule_content": (
            "title: Suspicious PowerShell\nstatus: test\nlogsource:\n  product: windows\ndetection:\n  selection:\n"
            '    CommandLine|contains: "Invoke-Expression"\n  condition: selection'
        ),
        "rule_type": "sigma",
        "severity": "high",
        "entry_id": str(test_entry.id),
    }
    resp = await client.post("/api/detection-rules", json=payload, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Detect Suspicious PowerShell"
    assert data["rule_type"] == "sigma"
    assert data["severity"] == "high"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_and_get_detection_rule(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    payload = {
        "title": "Detect Mimikatz",
        "rule_content": "rule mimikatz { condition: true }",
        "rule_type": "yara",
        "severity": "critical",
    }
    create_resp = await client.post("/api/detection-rules", json=payload, headers=auth_headers)
    assert create_resp.status_code == 201
    rule_id = create_resp.json()["id"]

    get_resp = await client.get(f"/api/detection-rules/{rule_id}", headers=auth_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["title"] == "Detect Mimikatz"


@pytest.mark.asyncio
async def test_create_detection_rule_unauthenticated(client: AsyncClient):
    payload = {
        "title": "Test Rule",
        "rule_content": "test",
        "rule_type": "sigma",
        "severity": "low",
    }
    resp = await client.post("/api/detection-rules", json=payload)
    assert resp.status_code == 401


# ── Entry CVE Endpoints ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_entry_cves_empty(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    resp = await client.get(f"/api/entries/{test_entry.id}/cves", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


# ── Link / Unlink Entity ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_link_entity_invalid_type(
    client: AsyncClient,
    auth_headers: dict,
    test_entry: Entry,
):
    payload = {"entity_type": "invalid", "entity_id": str(uuid.uuid4())}
    resp = await client.post(
        f"/api/entries/{test_entry.id}/link-entity",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 400


# ── Batch Intel Counts ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_batch_intel_counts(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    payload = [str(test_entry.id)]
    resp = await client.post("/api/entries/intel-counts", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    # Entries with zero intel are omitted from the result
    assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_batch_intel_counts_empty_list(client: AsyncClient, auth_headers: dict):
    resp = await client.post("/api/entries/intel-counts", json=[], headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_batch_intel_counts_unauthenticated(client: AsyncClient):
    resp = await client.post("/api/entries/intel-counts", json=[str(uuid.uuid4())])
    assert resp.status_code == 401
