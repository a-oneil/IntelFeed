"""API tests for /api/autolink/scan — the arbitrary-text entity scanner.

The scan powers inline entity links in profile assessments and notes. Each
match must carry the full entity payload (same shape as the entry-entity
endpoints) so hover popovers show the same descriptions, facts and links as
the reader — not just a bare name card.
"""

import pytest

from app.intelligence.autolinker import refresh_vocabulary
from app.models.cve import CVE
from app.models.threat_actor import ThreatActor


@pytest.mark.asyncio
async def test_scan_match_carries_full_entity_payload(client, db_session, auth_headers):
    actor = ThreatActor(
        name="Scanline Bear",
        aliases=["SL-Bear"],
        description="A test actor used to verify scan payloads.",
        motivation="espionage",
    )
    db_session.add(actor)
    await db_session.commit()
    await refresh_vocabulary(db_session)

    resp = await client.post(
        "/api/autolink/scan",
        json={"text": "Researchers attribute the campaign to Scanline Bear."},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    matches = resp.json()["matches"]
    match = next(m for m in matches if m["entity_type"] == "threat_actor")
    assert match["entity_id"] == str(actor.id)
    entity = match["entity"]
    assert entity is not None
    assert entity["description"] == "A test actor used to verify scan payloads."
    assert entity["motivation"] == "espionage"
    assert entity["aliases"] == ["SL-Bear"]


@pytest.mark.asyncio
async def test_scan_cve_payload_includes_meta(client, db_session, auth_headers):
    cve = CVE(cve_id="CVE-2024-99999", description="Test flaw in a test product.", severity="HIGH")
    db_session.add(cve)
    await db_session.commit()
    # CVEs match by regex, but scan_text still needs a built vocabulary.
    await refresh_vocabulary(db_session)

    resp = await client.post(
        "/api/autolink/scan",
        json={"text": "Exploitation of CVE-2024-99999 continues in the wild."},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    matches = resp.json()["matches"]
    match = next(m for m in matches if m["entity_type"] == "cve")
    assert match["entity_id"] == str(cve.id)
    entity = match["entity"]
    assert entity is not None
    assert entity["description"] == "Test flaw in a test product."
    assert entity["severity"] == "HIGH"
    assert entity["article_count"] == 0
    assert entity["is_kev"] is False
