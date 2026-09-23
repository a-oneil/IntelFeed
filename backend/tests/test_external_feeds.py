"""Tests for external intelligence feed ingestion (CISA KEV, Cybergeist)."""

from datetime import UTC, date
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.intelligence.external_feeds import (
    CYBERGEIST_ACTOR_URL,
    CYBERGEIST_MALWARE_URL,
    KEV_CATALOG_URL,
    KEV_REDIS_KEY,
    apply_kev_record,
)
from app.models.cve import CVE


@pytest.fixture
def mock_kev_catalog():
    return {
        "title": "CISA KEV Catalog",
        "catalogVersion": "2024.03.01",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-21762",
                "vendorProject": "Fortinet",
                "product": "FortiOS",
                "vulnerabilityName": "Fortinet FortiOS Out-of-Bound Write",
                "shortDescription": "Out-of-bound write in FortiOS allows RCE.",
                "dateAdded": "2024-02-09",
                "requiredAction": "Apply mitigations per vendor instructions.",
                "dueDate": "2024-03-01",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2024-3400",
                "vendorProject": "Palo Alto Networks",
                "product": "PAN-OS",
                "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection",
                "shortDescription": "Command injection in GlobalProtect.",
                "dateAdded": "2024-04-12",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2024-04-19",
                "knownRansomwareCampaignUse": "Known",
            },
        ],
    }


@pytest.fixture
def mock_cybergeist_actors():
    return [
        {
            "name": "APT29",
            "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
            "description": "Russian state-sponsored threat actor.",
            "country": "Russia",
            "motivation": "Espionage",
            "publicUrl": "https://cybergeist.io/actors/apt29",
            "stixLink": "https://cybergeist.io/stix/apt29",
        },
        {
            "name": "Lazarus Group",
            "aliases": ["Hidden Cobra", "ZINC"],
            "description": "North Korean state-sponsored threat actor.",
            "country": "North Korea",
            "motivation": "Financial",
            "publicUrl": "https://cybergeist.io/actors/lazarus",
        },
    ]


@pytest.fixture
def mock_cybergeist_malware():
    return [
        {
            "name": "Emotet",
            "aliases": ["Heodo", "Geodo"],
            "description": "Banking trojan turned botnet.",
            "malware_type": "botnet",
            "publicUrl": "https://cybergeist.io/malware/emotet",
        },
        {
            "name": "Cobalt Strike",
            "aliases": [],
            "description": "Commercial adversary simulation tool frequently abused.",
            "malware_type": "rat",
        },
    ]


def test_kev_catalog_structure(mock_kev_catalog):
    """Verify test fixture has expected structure."""
    assert len(mock_kev_catalog["vulnerabilities"]) == 2
    assert mock_kev_catalog["vulnerabilities"][0]["cveID"] == "CVE-2024-21762"
    assert mock_kev_catalog["catalogVersion"] == "2024.03.01"


def test_cybergeist_actor_structure(mock_cybergeist_actors):
    """Verify test fixture has expected structure."""
    assert len(mock_cybergeist_actors) == 2
    assert mock_cybergeist_actors[0]["name"] == "APT29"
    assert "Cozy Bear" in mock_cybergeist_actors[0]["aliases"]


def test_cybergeist_malware_structure(mock_cybergeist_malware):
    """Verify test fixture has expected structure."""
    assert len(mock_cybergeist_malware) == 2
    assert mock_cybergeist_malware[0]["name"] == "Emotet"
    assert "Heodo" in mock_cybergeist_malware[0]["aliases"]


def test_kev_redis_key():
    """Verify KEV Redis key is set correctly."""
    assert KEV_REDIS_KEY == "intelfeed:kev:version"


def test_feed_urls():
    """Verify feed URLs are properly defined."""
    assert "cisa.gov" in KEV_CATALOG_URL
    assert "cybergeist.io" in CYBERGEIST_ACTOR_URL
    assert "cybergeist.io" in CYBERGEIST_MALWARE_URL
    assert "threatActor" in CYBERGEIST_ACTOR_URL
    assert "malware" in CYBERGEIST_MALWARE_URL


# ---------- KEV record application (apply_kev_record) ----------


def _kev_data(mock_kev_catalog, idx=0):
    """Build the kev_data dict the sync passes to apply_kev_record."""
    vuln = mock_kev_catalog["vulnerabilities"][idx]
    return {
        "dateAdded": vuln.get("dateAdded"),
        "requiredAction": vuln.get("requiredAction"),
        "dueDate": vuln.get("dueDate"),
        "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse"),
        "vendorProject": vuln.get("vendorProject"),
        "product": vuln.get("product"),
        "vulnerabilityName": vuln.get("vulnerabilityName"),
        "shortDescription": vuln.get("shortDescription"),
    }


def test_apply_kev_record_sets_flags_and_dates(mock_kev_catalog):
    cve = CVE(cve_id="CVE-2024-21762", exploit_sources=[])

    newly_added = apply_kev_record(cve, _kev_data(mock_kev_catalog))

    assert newly_added is True
    assert cve.is_kev is True
    assert cve.kev_date_added == date(2024, 2, 9)
    assert cve.kev_due_date == date(2024, 3, 1)
    assert cve.exploit_status == "kev"
    assert cve.exploit_availability == "active_exploitation"
    assert any(s["source"] == "kev" for s in cve.exploit_sources)


def test_apply_kev_record_already_kev_not_newly_added(mock_kev_catalog):
    cve = CVE(cve_id="CVE-2024-21762", is_kev=True, exploit_sources=[{"source": "kev"}])

    newly_added = apply_kev_record(cve, _kev_data(mock_kev_catalog))

    assert newly_added is False
    # Doesn't duplicate the kev exploit source
    assert sum(1 for s in cve.exploit_sources if s["source"] == "kev") == 1


def test_apply_kev_record_legacy_exploit_status_not_newly_added(mock_kev_catalog):
    # Pre-migration CVEs marked via exploit_status='kev' shouldn't re-fire events
    cve = CVE(cve_id="CVE-2024-21762", exploit_status="kev", exploit_sources=[])

    assert apply_kev_record(cve, _kev_data(mock_kev_catalog)) is False
    assert cve.is_kev is True


def test_apply_kev_record_respects_manual_override(mock_kev_catalog):
    """An analyst-set exploit status is never overwritten by the KEV sync."""
    cve = CVE(
        cve_id="CVE-2024-21762",
        exploit_status="under_investigation",
        exploit_availability="poc",
        exploit_status_source="manual",
        exploit_sources=[],
    )

    apply_kev_record(cve, _kev_data(mock_kev_catalog))

    # KEV facts still recorded...
    assert cve.is_kev is True
    assert cve.kev_date_added == date(2024, 2, 9)
    # ...but the manual status/availability is preserved
    assert cve.exploit_status == "under_investigation"
    assert cve.exploit_availability == "poc"


def test_apply_kev_record_handles_bad_dates(mock_kev_catalog):
    kev_data = _kev_data(mock_kev_catalog)
    kev_data["dateAdded"] = "not-a-date"
    kev_data["dueDate"] = None
    cve = CVE(cve_id="CVE-2024-21762", exploit_sources=[])

    apply_kev_record(cve, kev_data)

    assert cve.is_kev is True
    assert cve.kev_date_added is None
    assert cve.kev_due_date is None


# ---------- Bluesky integration via _fetch_extended_feed ----------


@pytest.mark.asyncio
async def test_bluesky_fetch_extended_feed_routes_to_adapter():
    """Verify _fetch_extended_feed correctly invokes the Bluesky adapter and the
    metadata returned flows through. Uses a stub adapter rather than a live HTTP
    call so it doesn't require the docker stack."""
    from datetime import datetime

    from app.adapters.base import ParsedEntry, ParsedFeedMeta
    from app.workers import feed_tasks

    captured: dict = {}

    parsed_entry = ParsedEntry(
        guid="bsky-test-guid-1",
        url="https://bsky.app/profile/x.bsky.social/post/3kabc",
        title="Test Bluesky post",
        author="Alice (@x.bsky.social)",
        content_html="<p>Hello world</p>",
        summary="Hello world",
        published_at=datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
        metadata={"source": "bluesky", "cid": "bafyrei001"},
    )
    feed_meta = ParsedFeedMeta(
        title="Bluesky: @x.bsky.social",
        description="author mode",
        site_url="https://bsky.app",
        extra={"_adapter_state": {"last_seen_cid": "bafyrei001"}},
    )

    fake_adapter = MagicMock()

    async def fake_fetch(config, since=None):
        captured["config"] = dict(config)
        captured["since"] = since
        return feed_meta, [parsed_entry]

    fake_adapter.fetch_entries = fake_fetch

    # Build a minimal fake Feed and DB session
    feed = MagicMock()
    feed.id = "feed-test-1"
    feed.feed_type = "bluesky"
    feed.adapter_config = {"mode": "author", "handle": "x.bsky.social"}
    feed.last_fetched_at = None
    feed.title = None
    feed.description = None
    feed.error_count = 0
    feed.last_error = None
    feed.auto_extract_on_ingest = False
    feed.extract_detection_rules = False

    import uuid as _uuid

    inserted_entry_id = _uuid.uuid4()

    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))

    def fake_add(obj):
        if hasattr(obj, "guid") and getattr(obj, "id", None) is None:
            obj.id = inserted_entry_id

    db.add = MagicMock(side_effect=fake_add)
    db.flush = AsyncMock()
    db.commit = AsyncMock()

    with (
        patch("app.adapters.get_extended_adapter", return_value=fake_adapter),
        patch("app.services.system_settings._ensure_cache", new=AsyncMock()),
        patch("app.services.meilisearch_client.index_entry"),
        patch.object(feed_tasks, "_create_entry_media", new=AsyncMock()),
        patch.object(feed_tasks, "_apply_post_ingest_links", new=AsyncMock()),
        patch.object(feed_tasks, "dispatch_entry_pipeline"),
        patch("app.workers.automation_tasks.run_entry_automations"),
    ):
        await feed_tasks._fetch_extended_feed(db, feed)

    # The worker passes feed_id into config
    assert captured["config"].get("_feed_id") == "feed-test-1"
    assert captured["config"].get("mode") == "author"
    # The generic _adapter_state merge should have updated feed.adapter_config
    # to include last_seen_cid (and stripped the worker-injected scratch key).
    assigned_config = feed.adapter_config
    assert assigned_config.get("last_seen_cid") == "bafyrei001"
    assert "_feed_id" not in assigned_config
