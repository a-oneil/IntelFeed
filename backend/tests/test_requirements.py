"""Tests for Intelligence Requirements API."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.intelligence.requirement_matching import check_requirement_expiry, match_entry_against_requirements
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.intelligence_requirement import IntelligenceRequirement
from app.models.user import User


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    user = User(
        username="req_testuser",
        password_hash=hash_password("testpassword"),
        role="user",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def auth_headers(test_user: User) -> dict:
    token = create_access_token(test_user.id, test_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def test_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Test Feed", url="https://test-req.example.com/feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def test_entry(db_session: AsyncSession, test_feed: Feed) -> Entry:
    entry = Entry(
        feed_id=test_feed.id,
        title="APT28 Targets Healthcare with Ransomware",
        guid="test-req-entry-1",
        content_text="The threat actor APT28 has been observed deploying ransomware against healthcare organizations.",
        summary="APT28 ransomware campaign targeting healthcare",
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


async def test_create_requirement(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Track ransomware targeting healthcare",
            "description": "Monitor for ransomware groups targeting healthcare sector",
            "priority": "critical",
            "category": "operational",
            "keywords": ["ransomware", "healthcare", "hospital"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["title"] == "Track ransomware targeting healthcare"
    assert data["priority"] == "critical"
    assert data["status"] == "active"
    assert data["match_count"] == 0


async def test_list_requirements(client: AsyncClient, auth_headers: dict):
    # Create two
    await client.post(
        "/api/requirements",
        json={
            "title": "Req 1",
            "priority": "high",
        },
        headers=auth_headers,
    )
    await client.post(
        "/api/requirements",
        json={
            "title": "Req 2",
            "priority": "medium",
        },
        headers=auth_headers,
    )

    resp = await client.get("/api/requirements", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2

    # Filter by priority
    resp = await client.get("/api/requirements?priority=high", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert all(r["priority"] == "high" for r in data["items"])


async def test_get_requirement_detail(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Detail test",
            "priority": "low",
        },
        headers=auth_headers,
    )
    req_id = resp.json()["id"]

    resp = await client.get(f"/api/requirements/{req_id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["title"] == "Detail test"


async def test_update_requirement(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Original",
            "priority": "medium",
        },
        headers=auth_headers,
    )
    req_id = resp.json()["id"]

    resp = await client.patch(
        f"/api/requirements/{req_id}",
        json={
            "title": "Updated",
            "priority": "high",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Updated"
    assert resp.json()["priority"] == "high"


async def test_delete_requirement(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/requirements",
        json={
            "title": "To delete",
            "priority": "low",
        },
        headers=auth_headers,
    )
    req_id = resp.json()["id"]

    resp = await client.delete(f"/api/requirements/{req_id}", headers=auth_headers)
    assert resp.status_code == 204

    resp = await client.get(f"/api/requirements/{req_id}", headers=auth_headers)
    assert resp.status_code == 404


async def test_manual_match(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Manual match test",
            "priority": "medium",
        },
        headers=auth_headers,
    )
    req_id = resp.json()["id"]

    resp = await client.post(
        f"/api/requirements/{req_id}/match",
        json={
            "entry_id": str(test_entry.id),
            "relevance": "high",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201

    # Verify match appears in list
    resp = await client.get(f"/api/requirements/{req_id}/matches", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["match_type"] == "manual"
    assert data["items"][0]["entry_title"] == test_entry.title


async def test_remove_match(client: AsyncClient, auth_headers: dict, test_entry: Entry):
    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Remove match test",
            "priority": "medium",
        },
        headers=auth_headers,
    )
    req_id = resp.json()["id"]

    await client.post(
        f"/api/requirements/{req_id}/match",
        json={
            "entry_id": str(test_entry.id),
        },
        headers=auth_headers,
    )

    resp = await client.delete(f"/api/requirements/{req_id}/matches/{test_entry.id}", headers=auth_headers)
    assert resp.status_code == 204


async def test_coverage_summary(client: AsyncClient, auth_headers: dict):
    await client.post(
        "/api/requirements",
        json={
            "title": "Active req",
            "priority": "critical",
            "status": "active",
        },
        headers=auth_headers,
    )
    await client.post(
        "/api/requirements",
        json={
            "title": "Draft req",
            "priority": "low",
            "status": "draft",
        },
        headers=auth_headers,
    )

    resp = await client.get("/api/requirements/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_requirements"] >= 2
    assert data["active"] >= 1
    assert data["draft"] >= 1


async def test_auto_match_keyword(db_session: AsyncSession, test_user: User, test_entry: Entry):
    """Auto-matching should match entries by keyword in content."""
    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Track ransomware",
        priority="high",
        keywords=["ransomware", "healthcare"],
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, test_entry.id)
    assert len(matches) == 1
    assert matches[0]["match_type"] == "keyword"
    assert matches[0]["matched_on"] in ["ransomware", "healthcare"]


async def test_auto_match_respects_linked_feeds(db_session: AsyncSession, test_user: User, test_entry: Entry):
    """Requirements linked to specific feeds should only match entries from those feeds."""
    other_feed_id = uuid.uuid4()
    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Track ransomware in specific feed",
        priority="high",
        keywords=["ransomware"],
        linked_feed_ids=[other_feed_id],
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, test_entry.id)
    assert len(matches) == 0  # entry is in test_feed, not other_feed


async def test_check_requirement_expiry(db_session: AsyncSession, test_user: User):
    """Expired requirements should be transitioned to expired status."""
    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Expiring req",
        priority="medium",
        status="active",
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    db_session.add(req)
    await db_session.flush()

    count = await check_requirement_expiry(db_session)
    assert count >= 1

    await db_session.refresh(req)
    assert req.status == "expired"


# --- Entity matching, relevance tiers, content-type exclusion, lifecycle ---


async def test_auto_match_title_keyword_high_relevance(db_session: AsyncSession, test_user: User, test_entry: Entry):
    """Keywords found in the title should produce a high-relevance match."""
    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Track healthcare targeting",
        priority="high",
        keywords=["healthcare"],
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, test_entry.id)
    assert len(matches) == 1
    assert matches[0]["match_type"] == "keyword"
    assert matches[0]["relevance"] == "high"


async def test_auto_match_multi_body_keywords_medium_relevance(
    db_session: AsyncSession, test_user: User, test_feed: Feed
):
    """Two or more keywords found only in the body should be medium relevance."""
    entry = Entry(
        feed_id=test_feed.id,
        title="Weekly security roundup",
        guid="test-req-entry-body",
        content_text="Researchers observed phishing emails delivering a keylogger payload.",
    )
    db_session.add(entry)
    await db_session.flush()

    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Credential theft",
        priority="medium",
        keywords=["phishing", "keylogger"],
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, entry.id)
    assert len(matches) == 1
    assert matches[0]["relevance"] == "medium"


async def test_auto_match_single_body_keyword_low_relevance(db_session: AsyncSession, test_user: User, test_feed: Feed):
    """A single keyword found only in the body should be low relevance."""
    entry = Entry(
        feed_id=test_feed.id,
        title="Weekly security roundup",
        guid="test-req-entry-body-single",
        content_text="One vendor briefly mentioned ransomware among other topics.",
    )
    db_session.add(entry)
    await db_session.flush()

    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Ransomware tracking",
        priority="medium",
        keywords=["ransomware"],
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, entry.id)
    assert len(matches) == 1
    assert matches[0]["relevance"] == "low"


async def test_auto_match_entity(db_session: AsyncSession, test_user: User, test_entry: Entry):
    """Entries linked to a PIR entity should match with match_type=entity."""
    from app.models.threat_actor import EntryThreatActor, ThreatActor

    actor = ThreatActor(name="APT28-ReqTest")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=test_entry.id, threat_actor_id=actor.id))
    await db_session.flush()

    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Track APT28 activity",
        priority="critical",
        keywords=[],
        linked_entities={"threat_actors": [{"id": str(actor.id), "name": actor.name}]},
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, test_entry.id)
    assert len(matches) == 1
    assert matches[0]["match_type"] == "entity"
    assert matches[0]["matched_on"] == "APT28-ReqTest"
    assert matches[0]["relevance"] == "high"


async def test_min_relevance_filters_weak_matches(db_session: AsyncSession, test_user: User, test_feed: Feed):
    """A PIR with min_relevance=medium should drop single-body-keyword matches."""
    entry = Entry(
        feed_id=test_feed.id,
        title="Weekly security roundup",
        guid="test-req-entry-minrel",
        content_text="One vendor briefly mentioned ransomware among other topics.",
    )
    db_session.add(entry)
    await db_session.flush()

    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Ransomware (high signal only)",
        priority="medium",
        keywords=["ransomware"],
        min_relevance="medium",
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, entry.id)
    assert len(matches) == 0


async def test_auto_match_skips_rule_content(db_session: AsyncSession, test_user: User):
    """Entries from rule repos (github_repo + rule content_type) should not auto-match."""
    feed = Feed(
        title="Elastic detection rules",
        url="https://github.com/elastic/detection-rules",
        feed_type="github_repo",
    )
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(
        feed_id=feed.id,
        title="Ransomware - Prevented - Elastic Defend",
        guid="test-req-rule-entry",
        content_text="rule detecting ransomware behavior on endpoints",
        metadata_={"content_type": "elastic_rule"},
    )
    db_session.add(entry)
    await db_session.flush()

    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Track ransomware",
        priority="high",
        keywords=["ransomware"],
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, entry.id)
    assert matches == []


async def test_auto_match_skips_nvd_content(db_session: AsyncSession, test_user: User):
    """NVD vulnerability records should not auto-match PIRs."""
    feed = Feed(title="NVD", url="https://nvd.nist.gov", feed_type="nvd")
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(
        feed_id=feed.id,
        title="CVE-2026-0001 ransomware exploited",
        guid="test-req-nvd-entry",
        content_text="A vulnerability exploited by ransomware operators.",
    )
    db_session.add(entry)
    await db_session.flush()

    req = IntelligenceRequirement(
        created_by=test_user.id,
        title="Track ransomware",
        priority="high",
        keywords=["ransomware"],
        auto_match=True,
    )
    db_session.add(req)
    await db_session.flush()

    matches = await match_entry_against_requirements(db_session, entry.id)
    assert matches == []


async def test_update_removes_matches_for_removed_entities(
    client: AsyncClient,
    auth_headers: dict,
    db_session: AsyncSession,
    test_user: User,
    test_entry: Entry,
):
    """Removing a linked entity should delete its entity matches."""
    from app.models.threat_actor import EntryThreatActor, ThreatActor

    actor = ThreatActor(name="APT28-Cleanup")
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=test_entry.id, threat_actor_id=actor.id))
    await db_session.flush()

    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Entity cleanup test",
            "priority": "medium",
            "linked_entities": {"threat_actors": [{"id": str(actor.id), "name": actor.name}]},
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    req_id = resp.json()["id"]

    matches = await match_entry_against_requirements(db_session, test_entry.id)
    assert len(matches) >= 1

    resp = await client.patch(
        f"/api/requirements/{req_id}",
        json={
            "linked_entities": {},
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200

    resp = await client.get(f"/api/requirements/{req_id}/matches", headers=auth_headers)
    entity_matches = [m for m in resp.json()["items"] if m["match_type"] == "entity"]
    assert entity_matches == []


async def test_fulfill_requirement_with_report(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User
):
    """Fulfilling a requirement should set status and link the report."""
    from app.models.intel_report import IntelReport

    report = IntelReport(
        created_by=test_user.id,
        title="Q3 ransomware landscape",
        template_type="landscape_report",
    )
    db_session.add(report)
    await db_session.flush()

    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Fulfill test",
            "priority": "high",
        },
        headers=auth_headers,
    )
    req_id = resp.json()["id"]

    resp = await client.post(
        f"/api/requirements/{req_id}/fulfill",
        json={
            "report_id": str(report.id),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "fulfilled"
    assert data["fulfilled_by_report_id"] == str(report.id)

    # Unknown report id -> 404
    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Fulfill bad report",
            "priority": "low",
        },
        headers=auth_headers,
    )
    req_id2 = resp.json()["id"]
    resp = await client.post(
        f"/api/requirements/{req_id2}/fulfill",
        json={
            "report_id": str(uuid.uuid4()),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


async def test_fulfill_requirement_without_report(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/requirements",
        json={
            "title": "Fulfill no report",
            "priority": "low",
        },
        headers=auth_headers,
    )
    req_id = resp.json()["id"]

    resp = await client.post(f"/api/requirements/{req_id}/fulfill", json={}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "fulfilled"
    assert resp.json()["fulfilled_by_report_id"] is None


async def test_coverage_staleness_and_needs_review(
    client: AsyncClient, auth_headers: dict, db_session: AsyncSession, test_user: User
):
    """Stale = active with no matches in 30d or past expiry; needs_review = untouched 90d."""
    from sqlalchemy import update

    now = datetime.now(UTC)

    fresh = IntelligenceRequirement(
        created_by=test_user.id,
        title="Fresh req",
        priority="high",
        status="active",
        last_matched_at=now - timedelta(days=1),
    )
    stale_no_matches = IntelligenceRequirement(
        created_by=test_user.id,
        title="Stale req",
        priority="medium",
        status="active",
        last_matched_at=now - timedelta(days=45),
    )
    past_expiry = IntelligenceRequirement(
        created_by=test_user.id,
        title="Past expiry req",
        priority="low",
        status="active",
        last_matched_at=now - timedelta(days=1),
        expires_at=now - timedelta(days=2),
    )
    needs_review = IntelligenceRequirement(
        created_by=test_user.id,
        title="Needs review req",
        priority="low",
        status="active",
        last_matched_at=now - timedelta(days=1),
    )
    db_session.add_all([fresh, stale_no_matches, past_expiry, needs_review])
    await db_session.flush()

    # Backdate updated_at past the 90-day review threshold
    await db_session.execute(
        update(IntelligenceRequirement)
        .where(IntelligenceRequirement.id == needs_review.id)
        .values(updated_at=now - timedelta(days=120))
    )

    resp = await client.get("/api/requirements/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["stale"] >= 2  # stale_no_matches + past_expiry
    review_titles = [r["title"] for r in data["needs_review"]]
    assert "Needs review req" in review_titles
    assert "Fresh req" not in review_titles
