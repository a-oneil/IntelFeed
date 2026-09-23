"""Tests for DE-5/DE-7 endpoints: provenance, needing-review, diff, telemetry-gaps, detection summaries."""

import uuid

import pytest
from httpx import AsyncClient

# ── Helpers ──────────────────────────────────────────────────────────────────


async def _create_rule(client: AsyncClient, headers: dict, **overrides) -> dict:
    payload = {
        "rule_type": "sigma",
        "title": "Test Rule",
        "rule_content": (
            "title: test\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel"
        ),
        **overrides,
    }
    resp = await client.post("/api/detection-rules", json=payload, headers=headers)
    assert resp.status_code == 201
    return resp.json()


# ── Provenance ───────────────────────────────────────────────────────────────


class TestProvenance:
    @pytest.mark.asyncio
    async def test_provenance_returns_structure(self, client: AsyncClient, auth_headers: dict):
        rule = await _create_rule(client, auth_headers, title="Provenance Rule")
        resp = await client.get(f"/api/detection-rules/{rule['id']}/provenance", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule"]["id"] == rule["id"]
        assert "entries" in data
        assert "ttps" in data
        assert "threat_actors" in data
        assert "malware" in data

        # Upstream attribution, added when rules were reframed as research
        # material that has to cite where it came from.
        for key in ("source_repo", "source_author", "license", "references", "upstream_updated_at"):
            assert key in data["rule"]

    @pytest.mark.asyncio
    async def test_provenance_rule_not_found(self, client: AsyncClient, auth_headers: dict):
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/api/detection-rules/{fake_id}/provenance", headers=auth_headers)
        assert resp.status_code == 404


# ── Needing Review ───────────────────────────────────────────────────────────


class TestNeedingReview:
    @pytest.mark.asyncio
    async def test_needing_review_returns_list(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/detection-rules/needing-review", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)

    @pytest.mark.asyncio
    async def test_needing_review_respects_limit(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/detection-rules/needing-review?limit=5", headers=auth_headers)
        assert resp.status_code == 200
        assert len(resp.json()["items"]) <= 5


# ── Version Diff ─────────────────────────────────────────────────────────────


class TestVersionDiff:
    @pytest.mark.asyncio
    async def test_diff_version_vs_current(self, client: AsyncClient, auth_headers: dict):
        rule = await _create_rule(client, auth_headers, title="Diff Test")
        rule_id = rule["id"]

        # Update to create version 1
        await client.put(
            f"/api/detection-rules/{rule_id}",
            json={
                "rule_content": (
                    "title: v2\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 2\n  condition: sel"
                )
            },
            headers=auth_headers,
        )

        resp = await client.get(f"/api/detection-rules/{rule_id}/diff?v1=1", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == rule_id
        assert data["from_version"] == 1
        assert data["to_version"] == "current"
        assert data["has_changes"] is True
        assert "diff" in data

    @pytest.mark.asyncio
    async def test_diff_two_versions(self, client: AsyncClient, auth_headers: dict):
        rule = await _create_rule(client, auth_headers, title="Diff Two Versions")
        rule_id = rule["id"]

        # Create version 1
        await client.put(
            f"/api/detection-rules/{rule_id}",
            json={"rule_content": "title: v2"},
            headers=auth_headers,
        )
        # Create version 2
        await client.put(
            f"/api/detection-rules/{rule_id}",
            json={"rule_content": "title: v3"},
            headers=auth_headers,
        )

        resp = await client.get(f"/api/detection-rules/{rule_id}/diff?v1=1&v2=2", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["from_version"] == 1
        assert data["to_version"] == 2
        assert data["has_changes"] is True

    @pytest.mark.asyncio
    async def test_diff_version_not_found(self, client: AsyncClient, auth_headers: dict):
        rule = await _create_rule(client, auth_headers, title="Diff Missing Version")
        resp = await client.get(f"/api/detection-rules/{rule['id']}/diff?v1=999", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_diff_rule_not_found(self, client: AsyncClient, auth_headers: dict):
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/api/detection-rules/{fake_id}/diff?v1=1", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_diff_no_changes(self, client: AsyncClient, auth_headers: dict):
        """When comparing a version to a current rule with identical content, no changes."""
        rule = await _create_rule(client, auth_headers, title="No Change Diff", rule_content="title: same")
        rule_id = rule["id"]

        # Update content to create version 1 (snapshot of "title: same")
        await client.put(
            f"/api/detection-rules/{rule_id}",
            json={"rule_content": "title: changed"},
            headers=auth_headers,
        )

        # Rollback to version 1 (which has "title: same") — creates version 2 (snapshot of "title: changed")
        versions_resp = await client.get(f"/api/detection-rules/{rule_id}/versions", headers=auth_headers)
        version_id = versions_resp.json()[0]["id"]
        await client.post(
            f"/api/detection-rules/{rule_id}/versions/{version_id}/rollback",
            headers=auth_headers,
        )

        # Now: version 1 = "title: same", current = "title: same"
        # Diff v1 vs current should show no changes
        resp = await client.get(f"/api/detection-rules/{rule_id}/diff?v1=1", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["has_changes"] is False


# ── Telemetry Gaps ───────────────────────────────────────────────────────────


class TestTelemetryGaps:
    @pytest.mark.asyncio
    async def test_gaps_empty_when_no_rules(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/telemetry-sources/telemetry-gaps", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "rules_with_gaps" in data
        assert "most_needed_sources" in data

    @pytest.mark.asyncio
    async def test_gaps_detects_missing_sources(self, client: AsyncClient, auth_headers: dict):
        # Create a rule that requires a specific data source
        await _create_rule(
            client,
            auth_headers,
            title="Gap Rule",
            data_sources=["dns_query", "process_creation"],
        )

        resp = await client.get("/api/telemetry-sources/telemetry-gaps", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        # Without any telemetry sources, all data_sources should be missing
        assert len(data["rules_with_gaps"]) >= 1

    @pytest.mark.asyncio
    async def test_gaps_resolved_with_telemetry(self, client: AsyncClient, auth_headers: dict):
        # Create rule needing process_creation
        await _create_rule(
            client,
            auth_headers,
            title="Covered Rule",
            data_sources=["process_creation"],
        )

        # Add telemetry source covering it
        await client.post(
            "/api/telemetry-sources",
            json={
                "name": "Sysmon",
                "category": "endpoint",
                "log_types": ["process_creation"],
                "enabled": True,
            },
            headers=auth_headers,
        )

        resp = await client.get("/api/telemetry-sources/telemetry-gaps", headers=auth_headers)
        assert resp.status_code == 200
        # The rule's process_creation should now be covered
        gap_rules = resp.json()["rules_with_gaps"]
        if gap_rules:
            for gr in gap_rules:
                assert "process_creation" not in gr["missing_sources"]


# ── Detection Summary CRUD ───────────────────────────────────────────────────


class TestDetectionSummaryCRUD:
    @pytest.mark.asyncio
    async def test_list_summaries_empty(self, client: AsyncClient, auth_headers: dict):
        resp = await client.get("/api/intelligence/detection-summaries", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_get_summary_not_found(self, client: AsyncClient, auth_headers: dict):
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/api/intelligence/detection-summaries/{fake_id}", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_summary_not_found(self, client: AsyncClient, auth_headers: dict):
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/intelligence/detection-summaries/{fake_id}", headers=auth_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_create_summary_no_ai_returns_400(self, client: AsyncClient, auth_headers: dict):
        """Creating a summary without AI configured should return 400."""
        resp = await client.post(
            "/api/intelligence/detection-summaries",
            json={
                "entry_ids": [str(uuid.uuid4())],
                "title": "Test Summary",
            },
            headers=auth_headers,
        )
        # Should return 400 because no AI task assignment / no valid entries
        assert resp.status_code == 400
