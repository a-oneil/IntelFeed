"""GitHub adapter — fetches repository releases and security advisories via the GitHub API."""

import hashlib
import logging
from datetime import datetime

import httpx

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class GitHubReleasesAdapter(ExtendedAdapter):
    """Fetches releases from a GitHub repository."""

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        owner = config.get("owner", "")
        repo = config.get("repo", "")
        include_prereleases = config.get("include_prereleases", False)
        token = config.get("token")

        if not owner or not repo:
            return ParsedFeedMeta(), []

        headers = {"Accept": "application/vnd.github+json", "User-Agent": "IntelFeed/1.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        url = f"{GITHUB_API}/repos/{owner}/{repo}/releases?per_page=30"

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            response = await client.get(url)
            if response.status_code != 200:
                logger.warning(f"GitHub API returned {response.status_code} for {owner}/{repo}")
                return ParsedFeedMeta(title=f"{owner}/{repo} releases"), []

            releases = response.json()

        meta = ParsedFeedMeta(
            title=f"{owner}/{repo} releases",
            description=f"GitHub releases for {owner}/{repo}",
            site_url=f"https://github.com/{owner}/{repo}/releases",
        )

        entries = []
        for rel in releases:
            if rel.get("draft"):
                continue
            if not include_prereleases and rel.get("prerelease"):
                continue

            published = None
            pub_str = rel.get("published_at") or rel.get("created_at")
            if pub_str:
                published = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))

            if since and published and published <= since:
                continue

            entry = ParsedEntry(
                guid=hashlib.sha256(str(rel.get("id", "")).encode()).hexdigest()[:32],
                url=rel.get("html_url"),
                title=rel.get("name") or rel.get("tag_name", "Untitled"),
                author=rel.get("author", {}).get("login"),
                content_html=rel.get("body") or "",
                published_at=published,
                metadata={
                    "source": "github_releases",
                    "owner": owner,
                    "repo": repo,
                    "tag_name": rel.get("tag_name"),
                    "prerelease": rel.get("prerelease", False),
                },
            )
            entries.append(entry)

        return meta, entries

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        owner = config.get("owner", "")
        repo = config.get("repo", "")
        return ParsedFeedMeta(
            title=f"{owner}/{repo} releases",
            description=f"GitHub releases for {owner}/{repo}",
            site_url=f"https://github.com/{owner}/{repo}/releases",
        )


class GitHubAdvisoriesAdapter(ExtendedAdapter):
    """Fetches GitHub security advisories (global)."""

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        ecosystem = config.get("ecosystem")
        severity = config.get("severity", "high,critical")
        token = config.get("token")

        headers = {"Accept": "application/vnd.github+json", "User-Agent": "IntelFeed/1.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        params: dict = {"per_page": 30, "direction": "desc", "sort": "published"}
        if ecosystem:
            params["ecosystem"] = ecosystem
        if severity:
            params["severity"] = severity

        url = f"{GITHUB_API}/advisories"

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            response = await client.get(url, params=params)
            if response.status_code != 200:
                logger.warning(f"GitHub advisories API returned {response.status_code}")
                return ParsedFeedMeta(title="GitHub Security Advisories"), []

            advisories = response.json()

        meta = ParsedFeedMeta(
            title="GitHub Security Advisories",
            description=f"Security advisories (severity: {severity})",
            site_url="https://github.com/advisories",
        )

        entries = []
        for adv in advisories:
            published = None
            pub_str = adv.get("published_at")
            if pub_str:
                published = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))

            if since and published and published <= since:
                continue

            cve_ids = [v.get("value") for v in adv.get("identifiers", []) if v.get("type") == "CVE"]

            entry = ParsedEntry(
                guid=hashlib.sha256(adv.get("ghsa_id", "").encode()).hexdigest()[:32],
                url=adv.get("html_url"),
                title=adv.get("summary", "Untitled Advisory"),
                content_html=adv.get("description") or "",
                published_at=published,
                metadata={
                    "source": "github_advisories",
                    "ghsa_id": adv.get("ghsa_id"),
                    "cve_ids": cve_ids,
                    "severity": adv.get("severity"),
                    "cvss_score": adv.get("cvss", {}).get("score") if adv.get("cvss") else None,
                    "ecosystem": ecosystem,
                },
            )
            entries.append(entry)

        return meta, entries

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        ecosystem = config.get("ecosystem", "all")
        severity = config.get("severity", "high,critical")
        return ParsedFeedMeta(
            title="GitHub Security Advisories",
            description=f"Advisories for {ecosystem} (severity: {severity})",
            site_url="https://github.com/advisories",
        )
