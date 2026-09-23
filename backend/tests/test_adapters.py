"""Tests for extended source adapters (Reddit, GitHub, NVD, Mastodon)."""

from unittest.mock import AsyncMock, patch

import pytest

# ---- Reddit Adapter ----


@pytest.mark.asyncio
async def test_reddit_adapter_fetch(monkeypatch):
    from app.adapters.reddit import RedditAdapter

    adapter = RedditAdapter()

    # Minimal Atom feed response from Reddit
    atom_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title>netsec</title>
      <entry>
        <id>t3_abc123</id>
        <title>Interesting vulnerability found</title>
        <link href="https://www.reddit.com/r/netsec/comments/abc123" />
        <author><name>/u/researcher</name></author>
        <published>2026-03-01T10:00:00+00:00</published>
        <content type="html">&lt;p&gt;Details about the vuln&lt;/p&gt;</content>
      </entry>
    </feed>"""

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = atom_xml
    mock_response.raise_for_status = lambda: None

    async def mock_get(*args, **kwargs):
        return mock_response

    import httpx

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        config = {"subreddit": "netsec", "sort": "new", "limit": 25}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert meta.title == "r/netsec"
        assert len(entries) >= 1
        assert entries[0].title == "Interesting vulnerability found"


def test_reddit_adapter_meta():
    from app.adapters.reddit import RedditAdapter

    adapter = RedditAdapter()
    meta = adapter.get_feed_meta({"subreddit": "netsec"})
    assert "netsec" in meta.title


# ---- GitHub Adapters ----


@pytest.mark.asyncio
async def test_github_releases_adapter(monkeypatch):
    from app.adapters.github import GitHubReleasesAdapter

    adapter = GitHubReleasesAdapter()

    releases_json = [
        {
            "id": 12345,
            "name": "v1.0.0",
            "tag_name": "v1.0.0",
            "body": "First stable release",
            "html_url": "https://github.com/SigmaHQ/sigma/releases/v1.0.0",
            "published_at": "2026-02-15T12:00:00Z",
            "draft": False,
            "prerelease": False,
            "author": {"login": "sigmahq"},
        }
    ]

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: releases_json
    mock_response.raise_for_status = lambda: None

    async def mock_get(*args, **kwargs):
        return mock_response

    import httpx

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        config = {"owner": "SigmaHQ", "repo": "sigma", "include_prereleases": False}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert entries[0].title == "v1.0.0"
        assert "First stable release" in (entries[0].content_html or "")


@pytest.mark.asyncio
async def test_github_advisories_adapter(monkeypatch):
    from app.adapters.github import GitHubAdvisoriesAdapter

    adapter = GitHubAdvisoriesAdapter()

    advisories_json = [
        {
            "ghsa_id": "GHSA-test-1234",
            "summary": "Critical auth bypass",
            "description": "A critical authentication bypass in foo package",
            "html_url": "https://github.com/advisories/GHSA-test-1234",
            "severity": "critical",
            "cvss": {"score": 9.8},
            "published_at": "2026-02-20T10:00:00Z",
            "identifiers": [
                {"type": "CVE", "value": "CVE-2026-9999"},
                {"type": "GHSA", "value": "GHSA-test-1234"},
            ],
        }
    ]

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: advisories_json
    mock_response.raise_for_status = lambda: None

    async def mock_get(*args, **kwargs):
        return mock_response

    import httpx

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        config = {"ecosystem": "pip", "severity": "critical"}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert "Critical auth bypass" in entries[0].title
        assert "CVE-2026-9999" in entries[0].metadata.get("cve_ids", [])


# ---- NVD Adapter ----


@pytest.mark.asyncio
async def test_nvd_adapter(monkeypatch):
    from app.adapters.nvd import NVDAdapter

    adapter = NVDAdapter()

    nvd_response = {
        "resultsPerPage": 1,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1234",
                    "descriptions": [{"lang": "en", "value": "A critical buffer overflow in FortiOS"}],
                    "published": "2026-02-28T10:00:00.000",
                    "references": [{"url": "https://fortiguard.com/advisory/FG-IR-2026-001"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                }
            }
        ],
    }

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: nvd_response
    mock_response.raise_for_status = lambda: None

    async def mock_get(*args, **kwargs):
        return mock_response

    import httpx

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        config = {"keywords": ["fortinet"], "min_cvss": 7.0}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert "CVE-2026-1234" in entries[0].title
        assert entries[0].metadata["cvss_score"] == 9.8
        assert entries[0].metadata["severity"] == "CRITICAL"


def test_nvd_adapter_meta():
    from app.adapters.nvd import NVDAdapter

    adapter = NVDAdapter()
    meta = adapter.get_feed_meta({"keywords": ["fortinet"], "min_cvss": 7.0})
    assert "NVD" in meta.title


# ---- Mastodon Adapter ----


@pytest.mark.asyncio
async def test_mastodon_adapter_account(monkeypatch):
    from app.adapters.mastodon import MastodonAdapter

    adapter = MastodonAdapter()

    statuses = [
        {
            "id": "109876543210",
            "content": "<p>New zero-day in FortiOS. Patch immediately.</p>",
            "url": "https://infosec.exchange/@researcher/109876543210",
            "created_at": "2026-03-01T14:30:00.000Z",
            "account": {"username": "researcher", "display_name": "Security Researcher"},
            "reblogs_count": 10,
            "favourites_count": 25,
            "tags": [{"name": "infosec"}, {"name": "zeroday"}],
        }
    ]

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: statuses
    mock_response.raise_for_status = lambda: None

    async def mock_get(*args, **kwargs):
        return mock_response

    import httpx

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        config = {
            "instance_url": "https://infosec.exchange",
            "account_id": "12345",
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert "FortiOS" in entries[0].title or "FortiOS" in (entries[0].content_html or "")
        assert entries[0].metadata.get("reblogs_count") == 10


# ---- Adapter Registry ----


def test_adapter_registry():
    from app.adapters import get_adapter, get_extended_adapter, is_extended_feed_type

    # Standard adapters
    assert get_adapter("rss") is not None
    assert get_adapter("youtube") is not None
    assert get_adapter("podcast") is not None

    # Extended adapters
    assert get_extended_adapter("reddit") is not None
    assert get_extended_adapter("github_releases") is not None
    assert get_extended_adapter("github_advisories") is not None
    assert get_extended_adapter("nvd") is not None
    assert get_extended_adapter("mastodon") is not None
    assert get_extended_adapter("nonexistent") is None

    # is_extended_feed_type
    assert is_extended_feed_type("reddit") is True
    assert is_extended_feed_type("rss") is False
