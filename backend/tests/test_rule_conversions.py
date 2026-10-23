"""Format conversions as sibling rules.

A conversion used to live in ``metadata.rule_conversions`` on its parent, which
made it invisible to /detection-rules/search, unversioned, unexportable on its
own and deleted with the parent. ``detection_rules.derived_from`` makes it a
row. These tests pin the properties that were previously missing, plus the
on-write coverage resolution that both paths now trigger.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select

from app import entity_types
from app.models.detection_rule import DetectionRule
from app.models.detection_rule_version import DetectionRuleVersion
from app.models.rule_coverage import RuleCoverage

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def parent_rule(db_session, test_user) -> DetectionRule:
    rule = DetectionRule(
        created_by=test_user.id,
        rule_type="sigma",
        title="LockBit Shadow Copy Deletion",
        description="Detects vssadmin shadow copy deletion",
        rule_content="title: LockBit Shadow Copy Deletion\ndetection:\n  condition: selection\n",
        severity="high",
        tags=["ransomware"],
        source_ttps=["T1490"],
        source_cves=["CVE-2026-1731"],
        mitre_tactics=["impact"],
        license="DRL-1.1",
        is_draft=False,
    )
    db_session.add(rule)
    await db_session.flush()
    return rule


@pytest_asyncio.fixture
async def fake_converter(db_session, monkeypatch):
    """Stand in for the AI provider so the convert endpoint is testable offline.

    All three providers read ``is_active = false`` in dev, so nothing AI-backed
    runs locally without this. The task and provider are real rows because a
    conversion is ledgered in ai_results, which points at both.
    """
    from app.models.ai_provider import AIProvider
    from app.models.ai_task import AITask

    task = AITask(name="detection_rules", display_name="Detection Rules", default_prompt_template="{{ entry }}")
    provider_model = AIProvider(name="Test Provider", provider_type="ollama", base_url="http://ollama.test")
    db_session.add_all([task, provider_model])
    await db_session.flush()
    # A real site assignment, so the lookup finds the task the way a deployed
    # instance would; only the provider call is faked.
    from app.models.ai_task_assignment import AITaskAssignment

    db_session.add(AITaskAssignment(task_id=task.id, provider_id=provider_model.id, model_name="test-model"))
    await db_session.flush()

    def _install(content: str = 'process where process.name == "vssadmin.exe"\n'):
        response = MagicMock()
        response.content = content
        response.model = "test-model"
        response.tokens_input = 100
        response.tokens_output = 50
        response.latency_ms = 5
        response.cost_usd = None

        provider = MagicMock()
        provider.complete = AsyncMock(return_value=response)

        import app.ai.engine as engine

        monkeypatch.setattr(engine, "_get_provider_instance", lambda pm, **kw: provider)
        monkeypatch.setattr(engine, "_estimate_cost", lambda *a, **kw: 0.0012)
        return provider

    return _install


async def _convert(client, headers, rule_id, target_type="elastic_ql"):
    return await client.post(
        f"/api/detection-rules/{rule_id}/convert",
        json={"target_type": target_type},
        headers=headers,
    )


# ── conversions become rows ──────────────────────────────────────────


async def test_convert_creates_a_sibling_rule(db_session, client, auth_headers, parent_rule, fake_converter):
    fake_converter()
    resp = await _convert(client, auth_headers, parent_rule.id)
    assert resp.status_code == 200, resp.text
    payload = resp.json()

    sibling = (
        await db_session.execute(select(DetectionRule).where(DetectionRule.derived_from == parent_rule.id))
    ).scalar_one()

    assert payload["rule_id"] == str(sibling.id)
    assert sibling.rule_type == "elastic_ql"
    assert sibling.rule_content == payload["converted_content"]
    # A machine translation is a draft until a human reads it, whatever the
    # parent's status.
    assert sibling.is_draft is True
    assert sibling.title == "LockBit Shadow Copy Deletion (Elastic QL)"
    # The old response keys still answer the old question.
    assert payload["source_type"] == "sigma"
    assert payload["target_type"] == "elastic_ql"
    assert payload["tokens_used"] == 150


async def test_sibling_inherits_the_parents_entity_mappings(
    db_session, client, auth_headers, parent_rule, fake_converter
):
    """Without these the sibling resolves to nothing and reads as unattributed."""
    fake_converter()
    await _convert(client, auth_headers, parent_rule.id)

    sibling = (
        await db_session.execute(select(DetectionRule).where(DetectionRule.derived_from == parent_rule.id))
    ).scalar_one()
    assert sibling.source_ttps == ["T1490"]
    assert sibling.source_cves == ["CVE-2026-1731"]
    assert sibling.license == "DRL-1.1"
    assert sibling.metadata_["conversion"]["converted_from"] == str(parent_rule.id)
    assert sibling.metadata_["conversion"]["source_type"] == "sigma"


async def test_sibling_resolves_into_rule_coverage(db_session, client, auth_headers, parent_rule, fake_converter):
    fake_converter()
    await _convert(client, auth_headers, parent_rule.id)

    sibling = (
        await db_session.execute(select(DetectionRule).where(DetectionRule.derived_from == parent_rule.id))
    ).scalar_one()
    rows = (await db_session.execute(select(RuleCoverage).where(RuleCoverage.rule_id == sibling.id))).scalars().all()
    assert {(r.entity_type, r.entity_key) for r in rows} == {
        (entity_types.TTP, "T1490"),
        (entity_types.CVE, "CVE-2026-1731"),
    }


async def test_reconverting_updates_the_sibling_and_versions_it(
    db_session, client, auth_headers, parent_rule, fake_converter
):
    """Re-running a conversion must not pile up near-identical library rows."""
    fake_converter("first body\n")
    await _convert(client, auth_headers, parent_rule.id)
    fake_converter("second body\n")
    await _convert(client, auth_headers, parent_rule.id)

    siblings = (
        (await db_session.execute(select(DetectionRule).where(DetectionRule.derived_from == parent_rule.id)))
        .scalars()
        .all()
    )
    assert len(siblings) == 1
    assert siblings[0].rule_content == "second body"

    versions = (
        (await db_session.execute(select(DetectionRuleVersion).where(DetectionRuleVersion.rule_id == siblings[0].id)))
        .scalars()
        .all()
    )
    assert [v.rule_content for v in versions] == ["first body"]


async def test_converting_to_a_second_format_adds_a_second_sibling(
    db_session, client, auth_headers, parent_rule, fake_converter
):
    fake_converter("elastic body\n")
    await _convert(client, auth_headers, parent_rule.id, "elastic_ql")
    fake_converter("kql body\n")
    await _convert(client, auth_headers, parent_rule.id, "kql")

    siblings = (
        (await db_session.execute(select(DetectionRule).where(DetectionRule.derived_from == parent_rule.id)))
        .scalars()
        .all()
    )
    assert {s.rule_type for s in siblings} == {"elastic_ql", "kql"}


async def test_conversions_endpoint_lists_siblings(client, auth_headers, parent_rule, fake_converter):
    fake_converter()
    await _convert(client, auth_headers, parent_rule.id)

    resp = await client.get(f"/api/detection-rules/{parent_rule.id}/conversions", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["rule_type"] == "elastic_ql"
    assert items[0]["derived_from"] == str(parent_rule.id)


async def test_conversions_endpoint_is_empty_for_an_unconverted_rule(client, auth_headers, parent_rule):
    resp = await client.get(f"/api/detection-rules/{parent_rule.id}/conversions", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_sibling_survives_its_parent(db_session, client, auth_headers, parent_rule, fake_converter):
    """The blob was deleted with the parent; a row is only detached from it."""
    fake_converter()
    await _convert(client, auth_headers, parent_rule.id)

    resp = await client.delete(f"/api/detection-rules/{parent_rule.id}", headers=auth_headers)
    assert resp.status_code == 204
    # ON DELETE SET NULL runs in the database; the session still holds the row
    # as it was read.
    db_session.expire_all()

    sibling = (
        await db_session.execute(select(DetectionRule).where(DetectionRule.rule_type == "elastic_ql"))
    ).scalar_one()
    assert sibling.derived_from is None


async def test_convert_rejects_the_same_type(client, auth_headers, parent_rule, fake_converter):
    fake_converter()
    resp = await _convert(client, auth_headers, parent_rule.id, "sigma")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "same_type"


async def test_convert_404s_for_an_unknown_rule(client, auth_headers, fake_converter):
    fake_converter()
    resp = await _convert(client, auth_headers, uuid.uuid4())
    assert resp.status_code == 404


# ── on-write coverage resolution ─────────────────────────────────────


async def test_creating_a_rule_resolves_coverage_immediately(db_session, client, auth_headers):
    resp = await client.post(
        "/api/detection-rules",
        json={
            "rule_type": "sigma",
            "title": "Shadow copy deletion",
            "rule_content": "title: x\ntags:\n  - attack.t1490\ndetection:\n  condition: selection\n",
            "source_cves": ["CVE-2026-4242"],
            "source_ttps": ["T1490"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    rule_id = uuid.UUID(resp.json()["id"])

    rows = (await db_session.execute(select(RuleCoverage).where(RuleCoverage.rule_id == rule_id))).scalars().all()
    resolved = {(r.entity_type, r.entity_key) for r in rows}
    assert (entity_types.TTP, "T1490") in resolved
    # source_cves was accepted by the create schema and then dropped on the
    # floor, so an advisory-derived rule resolved to no CVE at all.
    assert (entity_types.CVE, "CVE-2026-4242") in resolved


async def test_updating_a_rules_tags_re_resolves_coverage(db_session, client, auth_headers, parent_rule):
    resp = await client.put(
        f"/api/detection-rules/{parent_rule.id}",
        json={"source_ttps": ["T1486"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text

    rows = (
        (
            await db_session.execute(
                select(RuleCoverage).where(
                    RuleCoverage.rule_id == parent_rule.id, RuleCoverage.entity_type == entity_types.TTP
                )
            )
        )
        .scalars()
        .all()
    )
    # The old technique row is gone, not merely joined by a new one.
    assert {r.entity_key for r in rows} == {"T1486"}


async def test_a_resolver_failure_does_not_fail_the_save(client, auth_headers):
    """Coverage is derived data — losing a save over it would be a worse trade."""
    with patch("app.services.rule_coverage.resolve_rule", side_effect=RuntimeError("vocab down")):
        resp = await client.post(
            "/api/detection-rules",
            json={"rule_type": "sigma", "title": "Still saves", "rule_content": "title: x\n"},
            headers=auth_headers,
        )
    assert resp.status_code == 201


async def test_extend_creates_a_draft_child_with_lineage(db_session, client, auth_headers, parent_rule):
    """Extend = a derived_from draft in the same format, mappings carried.

    Unlike conversions, each call makes a NEW child: two analysts extending the
    same upstream are doing two different jobs.
    """
    resp = await client.post(f"/api/detection-rules/{parent_rule.id}/extend", headers=auth_headers)
    assert resp.status_code == 201
    body = resp.json()
    assert body["derived_from"] == str(parent_rule.id)
    assert body["rule_type"] == parent_rule.rule_type
    assert body["is_draft"] is True
    assert body["title"] == f"{parent_rule.title} (extended)"
    assert body["source_ttps"] == ["T1490"]

    # The child resolves into rule_coverage on the spot — it counts on the
    # board the moment it exists.
    rows = (
        (await db_session.execute(select(RuleCoverage).where(RuleCoverage.rule_id == uuid.UUID(body["id"]))))
        .scalars()
        .all()
    )
    assert {(r.entity_type, r.entity_key) for r in rows} >= {(entity_types.TTP, "T1490")}

    second = await client.post(f"/api/detection-rules/{parent_rule.id}/extend", headers=auth_headers)
    assert second.status_code == 201
    assert second.json()["id"] != body["id"]


async def test_extend_404s_for_an_unknown_rule(client, auth_headers):
    resp = await client.post(f"/api/detection-rules/{uuid.uuid4()}/extend", headers=auth_headers)
    assert resp.status_code == 404


# ── a failed conversion is still a request ──────────────────────────


async def test_failed_conversion_is_ledgered(db_session, client, auth_headers, parent_rule, fake_converter, test_user):
    from app.models.ai_result import AIResult

    provider = fake_converter()
    provider.complete = AsyncMock(side_effect=RuntimeError("provider down"))

    resp = await _convert(client, auth_headers, parent_rule.id)

    assert resp.status_code == 502
    rows = (await db_session.execute(select(AIResult).where(AIResult.target_id == parent_rule.id))).scalars().all()
    assert len(rows) == 1
    assert rows[0].caller_kind == "user"
    assert rows[0].user_id == test_user.id
    assert rows[0].parsed_result["_error"] == "provider down"
    # Nothing was converted: no sibling rule appeared.
    siblings = (
        (await db_session.execute(select(DetectionRule).where(DetectionRule.derived_from == parent_rule.id)))
        .scalars()
        .all()
    )
    assert siblings == []
