"""Tests for detection rule CRUD API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_detection_rule(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "sigma",
            "title": "Test SIGMA Rule",
            "description": "Detects test activity",
            "rule_content": (
                "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n"
                "  condition: selection"
            ),
            "severity": "high",
            "tags": ["T1059"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["rule_type"] == "sigma"
    assert data["title"] == "Test SIGMA Rule"
    assert data["severity"] == "high"
    assert "T1059" in data["tags"]


@pytest.mark.asyncio
async def test_list_detection_rules(client: AsyncClient, auth_headers: dict):
    # Create a rule first
    await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "splunk_spl",
            "title": "Splunk Rule",
            "rule_content": "index=main | stats count",
        },
        headers=auth_headers,
    )

    resp = await client.get("/api/detection-rules", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


@pytest.mark.asyncio
async def test_update_detection_rule(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "kql",
            "title": "Original Title",
            "rule_content": "SecurityEvent | where EventID == 4625",
        },
        headers=auth_headers,
    )
    rule_id = create_resp.json()["id"]

    resp = await client.put(
        f"/api/detection-rules/{rule_id}",
        json={"title": "Updated Title", "severity": "critical"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Updated Title"
    assert resp.json()["severity"] == "critical"


@pytest.mark.asyncio
async def test_delete_detection_rule(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "sigma",
            "title": "To Delete",
            "rule_content": "title: Delete Me",
        },
        headers=auth_headers,
    )
    rule_id = create_resp.json()["id"]

    resp = await client.delete(f"/api/detection-rules/{rule_id}", headers=auth_headers)
    assert resp.status_code == 204

    resp = await client.get(f"/api/detection-rules/{rule_id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_filter_rules_by_type(client: AsyncClient, auth_headers: dict):
    await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "SIGMA 1", "rule_content": "..."},
        headers=auth_headers,
    )
    await client.post(
        "/api/detection-rules",
        json={"rule_type": "kql", "title": "KQL 1", "rule_content": "..."},
        headers=auth_headers,
    )

    resp = await client.get("/api/detection-rules?rule_type=sigma", headers=auth_headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["rule_type"] == "sigma"


@pytest.mark.asyncio
async def test_create_snort_suricata_rule(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "snort_suricata",
            "title": "Suricata C2 Detection",
            "rule_content": 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 Beacon"; sid:1000001; rev:1;)',
            "severity": "high",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["rule_type"] == "snort_suricata"


@pytest.mark.asyncio
async def test_create_yara_rule(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "yara",
            "title": "YARA Malware Detection",
            "rule_content": 'rule test_malware { strings: $a = "malware" condition: $a }',
            "severity": "critical",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["rule_type"] == "yara"


@pytest.mark.asyncio
async def test_response_includes_new_fields(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "sigma",
            "title": "Full Field Test",
            "rule_content": (
                "title: test\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel"
            ),
            "is_draft": True,
            "data_sources": ["process_creation", "file_creation"],
            "mitre_tactics": ["execution"],
            "notes": "Test note",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["is_draft"] is True
    assert "process_creation" in data["data_sources"]
    assert "execution" in data["mitre_tactics"]
    assert data["notes"] == "Test note"
    assert "source_entries" in data
    assert "source_actors" in data
    assert "source_campaigns" in data


@pytest.mark.asyncio
async def test_update_creates_version(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "sigma",
            "title": "Version Test",
            "rule_content": (
                "title: v1\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel"
            ),
        },
        headers=auth_headers,
    )
    rule_id = create_resp.json()["id"]

    # Update rule_content
    await client.put(
        f"/api/detection-rules/{rule_id}",
        json={
            "rule_content": (
                "title: v2\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 2\n  condition: sel"
            ),
            "change_description": "Changed EventID to 2",
        },
        headers=auth_headers,
    )

    # Verify version was created
    versions_resp = await client.get(f"/api/detection-rules/{rule_id}/versions", headers=auth_headers)
    assert versions_resp.status_code == 200
    versions = versions_resp.json()
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1
    assert "v1" in versions[0]["rule_content"]
    assert versions[0]["change_description"] == "Changed EventID to 2"


@pytest.mark.asyncio
async def test_list_versions(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "kql",
            "title": "Multi Version",
            "rule_content": "SecurityEvent | where EventID == 1",
        },
        headers=auth_headers,
    )
    rule_id = create_resp.json()["id"]

    # Two content updates
    await client.put(
        f"/api/detection-rules/{rule_id}",
        json={"rule_content": "SecurityEvent | where EventID == 2"},
        headers=auth_headers,
    )
    await client.put(
        f"/api/detection-rules/{rule_id}",
        json={"rule_content": "SecurityEvent | where EventID == 3"},
        headers=auth_headers,
    )

    versions_resp = await client.get(f"/api/detection-rules/{rule_id}/versions", headers=auth_headers)
    assert versions_resp.status_code == 200
    versions = versions_resp.json()
    assert len(versions) == 2
    # Should be ordered desc by version_number
    assert versions[0]["version_number"] > versions[1]["version_number"]


@pytest.mark.asyncio
async def test_rollback_version(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "splunk_spl",
            "title": "Rollback Test",
            "rule_content": "index=main original",
        },
        headers=auth_headers,
    )
    rule_id = create_resp.json()["id"]

    # Update to new content
    await client.put(
        f"/api/detection-rules/{rule_id}",
        json={"rule_content": "index=main updated"},
        headers=auth_headers,
    )

    # Get version id of the snapshot (original content)
    versions_resp = await client.get(f"/api/detection-rules/{rule_id}/versions", headers=auth_headers)
    version_id = versions_resp.json()[0]["id"]

    # Rollback
    rollback_resp = await client.post(
        f"/api/detection-rules/{rule_id}/versions/{version_id}/rollback",
        headers=auth_headers,
    )
    assert rollback_resp.status_code == 200
    assert "original" in rollback_resp.json()["rule_content"]


@pytest.mark.asyncio
async def test_status_toggle(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "sigma",
            "title": "Status Test",
            "rule_content": "title: test",
        },
        headers=auth_headers,
    )
    rule_id = create_resp.json()["id"]
    assert create_resp.json()["is_draft"] is True

    # Publish
    resp = await client.patch(
        f"/api/detection-rules/{rule_id}/status",
        json={"is_draft": False},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["is_draft"] is False

    # Unpublish
    resp = await client.patch(
        f"/api/detection-rules/{rule_id}/status",
        json={"is_draft": True},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["is_draft"] is True


@pytest.mark.asyncio
async def test_filter_by_draft_status(client: AsyncClient, auth_headers: dict):
    # Create draft
    await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Draft Rule", "rule_content": "...", "is_draft": True},
        headers=auth_headers,
    )
    # Create published
    await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Published Rule", "rule_content": "...", "is_draft": False},
        headers=auth_headers,
    )

    drafts = await client.get("/api/detection-rules?is_draft=true", headers=auth_headers)
    assert drafts.status_code == 200
    for item in drafts.json()["items"]:
        assert item["is_draft"] is True

    published = await client.get("/api/detection-rules?is_draft=false", headers=auth_headers)
    assert published.status_code == 200
    for item in published.json()["items"]:
        assert item["is_draft"] is False


@pytest.mark.asyncio
async def test_validate_minimal_body(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/detection-rules/validate",
        json={
            "rule_type": "sigma",
            "rule_content": (
                "title: Test\nstatus: test\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n"
                "  condition: sel"
            ),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "valid" in resp.json()


@pytest.mark.asyncio
async def test_validate_snort_suricata(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/detection-rules/validate",
        json={
            "rule_type": "snort_suricata",
            "rule_content": 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; rev:1;)',
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


@pytest.mark.asyncio
async def test_validate_yara(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/detection-rules/validate",
        json={
            "rule_type": "yara",
            "rule_content": 'rule test { strings: $a = "test" condition: $a }',
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


@pytest.mark.asyncio
async def test_bulk_publish(client: AsyncClient, auth_headers: dict):
    r1 = await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Bulk 1", "rule_content": "..."},
        headers=auth_headers,
    )
    r2 = await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Bulk 2", "rule_content": "..."},
        headers=auth_headers,
    )

    resp = await client.post(
        "/api/detection-rules/bulk-update",
        json={"rule_ids": [r1.json()["id"], r2.json()["id"]], "is_draft": False},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] == 2

    # Verify they're published
    check = await client.get(f"/api/detection-rules/{r1.json()['id']}", headers=auth_headers)
    assert check.json()["is_draft"] is False


@pytest.mark.asyncio
async def test_bulk_add_tags(client: AsyncClient, auth_headers: dict):
    r1 = await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Tag Test", "rule_content": "...", "tags": ["existing"]},
        headers=auth_headers,
    )

    resp = await client.post(
        "/api/detection-rules/bulk-update",
        json={"rule_ids": [r1.json()["id"]], "tags_add": ["new_tag"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200

    check = await client.get(f"/api/detection-rules/{r1.json()['id']}", headers=auth_headers)
    assert "existing" in check.json()["tags"]
    assert "new_tag" in check.json()["tags"]


@pytest.mark.asyncio
async def test_bulk_delete(client: AsyncClient, auth_headers: dict, admin_headers: dict):
    r1 = await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Delete 1", "rule_content": "..."},
        headers=auth_headers,
    )
    r2 = await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Delete 2", "rule_content": "..."},
        headers=auth_headers,
    )

    resp = await client.post(
        "/api/detection-rules/bulk-delete",
        json={"rule_ids": [r1.json()["id"], r2.json()["id"]]},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2

    check = await client.get(f"/api/detection-rules/{r1.json()['id']}", headers=auth_headers)
    assert check.status_code == 404


@pytest.mark.asyncio
async def test_bulk_delete_requires_admin(client: AsyncClient, auth_headers: dict):
    """Bulk-delete and delete-all are admin-only; single-rule CRUD stays open."""
    r1 = await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Survivor", "rule_content": "..."},
        headers=auth_headers,
    )

    resp = await client.post(
        "/api/detection-rules/bulk-delete",
        json={"rule_ids": [r1.json()["id"]]},
        headers=auth_headers,
    )
    assert resp.status_code == 403

    resp = await client.delete("/api/intelligence/detection-rules", headers=auth_headers)
    assert resp.status_code == 403

    check = await client.get(f"/api/detection-rules/{r1.json()['id']}", headers=auth_headers)
    assert check.status_code == 200


@pytest.mark.asyncio
async def test_export_yaml(client: AsyncClient, auth_headers: dict):
    await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Export 1", "rule_content": "title: export1"},
        headers=auth_headers,
    )
    resp = await client.get("/api/detection-rules/export?format=yaml", headers=auth_headers)
    assert resp.status_code == 200
    assert "export1" in resp.text


@pytest.mark.asyncio
async def test_export_zip(client: AsyncClient, auth_headers: dict):
    await client.post(
        "/api/detection-rules",
        json={"rule_type": "sigma", "title": "Export Zip", "rule_content": "title: ziptest"},
        headers=auth_headers,
    )
    resp = await client.get("/api/detection-rules/export?format=zip", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"


@pytest.mark.asyncio
async def test_feasibility_full_coverage(client: AsyncClient, auth_headers: dict):
    # Create a telemetry source with log types
    await client.post(
        "/api/telemetry-sources",
        json={
            "name": "Sysmon",
            "category": "endpoint",
            "log_types": ["process_creation", "file_creation"],
            "enabled": True,
        },
        headers=auth_headers,
    )

    resp = await client.post(
        "/api/telemetry-sources/check-feasibility",
        json={"data_sources": ["process_creation"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "process_creation" in data["feasible"]
    assert len(data["missing"]) == 0
    assert data["coverage_pct"] == 1.0


@pytest.mark.asyncio
async def test_feasibility_partial_coverage(client: AsyncClient, auth_headers: dict):
    await client.post(
        "/api/telemetry-sources",
        json={
            "name": "Firewall",
            "category": "network",
            "log_types": ["firewall_log"],
            "enabled": True,
        },
        headers=auth_headers,
    )

    resp = await client.post(
        "/api/telemetry-sources/check-feasibility",
        json={"data_sources": ["firewall_log", "dns_query"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["coverage_pct"] == 0.5
    assert len(data["feasible"]) == 1
    assert len(data["missing"]) == 1


@pytest.mark.asyncio
async def test_feasibility_no_telemetry(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/telemetry-sources/check-feasibility",
        json={"data_sources": ["process_creation"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["coverage_pct"] == 0.0


@pytest.mark.asyncio
async def test_taxonomy_returns_structure(client: AsyncClient, auth_headers: dict):
    resp = await client.get("/api/telemetry-sources/taxonomy", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "endpoint" in data
    assert "network" in data
    assert "process_creation" in data["endpoint"]
