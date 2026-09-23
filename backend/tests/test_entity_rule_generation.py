"""Tests for entity-scoped detection rule generation.

POST /intelligence/entities/{entity_type}/{entity_id}/generate-rules wraps the
entry-scoped AI flow with entity context (facts + recent linked articles).
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP

AI_RESULT = {
    "rules": [
        {
            "title": "Detect Suspicious Activity",
            "description": "Detects the described behavior",
            "rule_content": "title: Detect Suspicious Activity\ndetection:\n  condition: selection",
            "severity": "high",
        }
    ]
}


@pytest_asyncio.fixture
async def actor_with_context(db_session: AsyncSession):
    """Actor linked to one entry that also carries a TTP and a CVE."""
    feed = Feed(title="Blog", url="https://example.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(
        feed_id=feed.id,
        title="APT29 exploits CVE-2024-1111",
        content_text="APT29 used T1059 PowerShell to exploit CVE-2024-1111.",
        published_at=datetime(2026, 5, 1, tzinfo=UTC),
        guid="guid-actor-1",
    )
    actor = ThreatActor(name="APT29", aliases=["Cozy Bear"], country="Russia", motivation="espionage")
    ttp = TTP(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="execution")
    cve = CVE(cve_id="CVE-2024-1111", severity="critical")
    db_session.add_all([entry, actor, ttp, cve])
    await db_session.flush()

    db_session.add_all(
        [
            EntryThreatActor(entry_id=entry.id, threat_actor_id=actor.id, confidence="high"),
            EntryTTP(entry_id=entry.id, ttp_id=ttp.id, confidence="high"),
            EntryCVE(entry_id=entry.id, cve_id=cve.id),
        ]
    )
    await db_session.flush()
    return {"entry": entry, "actor": actor, "ttp": ttp, "cve": cve}


async def test_generate_rules_for_actor(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, actor_with_context
):
    actor = actor_with_context["actor"]
    entry = actor_with_context["entry"]

    with patch("app.intelligence.detection.run_task", new_callable=AsyncMock, return_value=AI_RESULT) as mock_run:
        resp = await client.post(
            f"/api/intelligence/entities/threat_actor/{actor.id}/generate-rules",
            json={"rule_types": ["sigma"]},
            headers=auth_headers,
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["title"] == "Detect Suspicious Activity"
    assert data[0]["rule_type"] == "sigma"

    # The AI prompt got entity facts + article context, keyed to the entity.
    call = mock_run.call_args.kwargs
    assert call["target_id"] == actor.id
    assert call["variables"]["entry"]["title"] == "Detection engineering request: APT29"
    assert "APT29" in call["variables"]["entry"]["content_text"]
    assert "Recent reporting" in call["variables"]["entry"]["content_text"]
    assert call["variables"]["ttps"][0]["technique_id"] == "T1059"

    # Persisted rule carries entity provenance and pivots back to the actor.
    rule = (await db_session.execute(select(DetectionRule))).scalar_one()
    assert rule.entry_id == entry.id
    assert actor.id in rule.source_actors
    assert rule.source_ttps == ["T1059"]
    assert rule.source_cves == ["CVE-2024-1111"]


async def test_generate_rules_for_cve_without_entries(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession
):
    cve = CVE(cve_id="CVE-2025-9999", severity="high", description="Remote code execution")
    db_session.add(cve)
    await db_session.flush()

    with patch("app.intelligence.detection.run_task", new_callable=AsyncMock, return_value=AI_RESULT) as mock_run:
        resp = await client.post(
            f"/api/intelligence/entities/cve/{cve.id}/generate-rules",
            json={"rule_types": ["sigma"]},
            headers=auth_headers,
        )

    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert "CVE-2025-9999" in mock_run.call_args.kwargs["variables"]["entry"]["content_text"]

    rule = (await db_session.execute(select(DetectionRule))).scalar_one()
    assert rule.entry_id is None
    assert rule.source_cves == ["CVE-2025-9999"]


async def test_generate_rules_unsupported_entity_type(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        f"/api/intelligence/entities/vendor/{uuid.uuid4()}/generate-rules",
        json={"rule_types": ["sigma"]},
        headers=auth_headers,
    )
    assert resp.status_code == 400


async def test_generate_rules_entity_not_found(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        f"/api/intelligence/entities/ttp/{uuid.uuid4()}/generate-rules",
        json={"rule_types": ["sigma"]},
        headers=auth_headers,
    )
    assert resp.status_code == 404
