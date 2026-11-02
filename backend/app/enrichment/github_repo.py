"""GitHub repository facts for tools that have a repository.

A tool's ``github_url`` (from Malpedia's references, MITRE or an analyst)
names its repository. Once a week the job asks GitHub's REST API about each
one (``GET /repos/{owner}/{repo}``) and keeps what helps an analyst judge the
tool: how widely it is starred, when it was last pushed to, whether it is
archived, its license and its topics. All of it is profile context; no column
is written.

GitHub allows 60 requests an hour without a token and 5,000 with one
(docs.github.com, "Rate limits for the REST API"); the instance's
``github_token`` setting, shared with GitHub PoC, is used when set. Malware
families have no repository column, so only tools are looked up.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

import httpx
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.base import EnrichmentData, Source
from app.enrichment.gateway import SOURCE_REFUSALS, RateLimited, SourceGateway, parse_retry_after, rate_limit_signal
from app.enrichment.manifest import Context, Display, Egress, Job, License, Quota

logger = logging.getLogger(__name__)

API_URL = "https://api.github.com/repos/"

#: Tools looked up per run. Today a few dozen have a repository.
RUN_LIMIT = 200
#: A week: the job runs weekly and skips tools with a fresh answer.
TTL_HOURS = 168

_REPO = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:[/?#].*)?$"
)


class GitHubRepoSource(Source):
    source_type = "github_repo"
    display_name = "GitHub repository"
    about = "A tool's GitHub repository: stars, last push, archived state and license."
    applies_to = {entity_types.TOOL: None}
    quota = Quota(60, 3600, daily_budget=500, ceiling_per_period=60, keyed=Quota(5000, 3600, 5000))
    # Sends the repository's owner and name, already public on the profile.
    egress = Egress.LOW
    key_setting = "github_token"
    license = License("GitHub terms of service", attribution="GitHub")
    # GitHub answers its primary and secondary rate limits with 403 or 429,
    # but also sends 403 for a repository it won't show (blocked, disabled,
    # behind a SAML or IP rule). ``fetch_repo`` tells the two apart by the
    # rate-limit signal, so 403 is not a throttle status here: one blocked
    # repository must not stop the run for every other tool.
    throttle_statuses = (429, 503)
    jobs = (
        Job(
            "github-repo-sync",
            "app.workers.enrichment_tasks.run_github_repo_sync",
            {"type": "crontab", "minute": "15", "hour": "5", "day_of_week": "2"},
            "Read stars, last push, archived state, license and topics of tools' GitHub repositories",
        ),
    )
    outputs = (
        Context("stars", "Stars", Display.FACT),
        Context("pushed_at", "Last push", Display.FACT),
        Context("archived", "Archived", Display.BADGE, tones={True: "warning"}),
        Context("license", "License", Display.FACT),
        Context("topics", "Topics", Display.CHIPS),
        Context("repo", "Repository", Display.LINK),
    )


def repo_path(url: str | None) -> str | None:
    """``owner/repo`` of a github.com repository URL, or None for anything
    else (a gist, a user page, another host)."""
    match = _REPO.match((url or "").strip())
    if not match:
        return None
    owner, repo = match.groups()
    return f"{owner}/{repo}"


def repo_facts(data: dict) -> dict:
    """A ``GET /repos/{owner}/{repo}`` answer as parsed_data."""
    pushed = data.get("pushed_at")
    spdx = (data.get("license") or {}).get("spdx_id")
    facts = {
        "found": True,
        "full_name": data.get("full_name"),
        "stars": data.get("stargazers_count"),
        "pushed_at": pushed[:10] if isinstance(pushed, str) else None,
        "archived": data.get("archived") is True,
        # GitHub says NOASSERTION for a license file it can't classify.
        "license": spdx if spdx and spdx != "NOASSERTION" else None,
        "topics": [t for t in data.get("topics") or [] if isinstance(t, str)][:12],
        "repo": {"url": data["html_url"], "label": data.get("full_name")} if data.get("html_url") else None,
    }
    return {k: v for k, v in facts.items() if v not in (None, [])}


async def fetch_repo(client: httpx.AsyncClient, path: str, api_key: str | None = None) -> dict:
    """parsed_data for one repository. A repository GitHub doesn't have (or
    hides, or blocks: a 403 with no rate-limit signal) is ``found: False``; a
    renamed one is followed. A 403 that is a rate limit raises ``RateLimited``,
    which stops the run."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    resp = await client.get(API_URL + path, headers=headers)
    if resp.status_code in (404, 451):
        return {"found": False}
    if resp.status_code == 403:
        if rate_limit_signal(resp):
            raise RateLimited(GitHubRepoSource.source_type, parse_retry_after(resp.headers.get("Retry-After")) or 60.0)
        return {"found": False}
    resp.raise_for_status()
    return repo_facts(resp.json())


async def _candidates(db: AsyncSession) -> list:
    """Tools with a GitHub URL and no unexpired answer."""
    from app.models.enrichment import EnrichmentResult
    from app.models.tool import Tool

    fresh = exists().where(
        EnrichmentResult.entity_type == entity_types.TOOL,
        EnrichmentResult.entity_id == Tool.id,
        EnrichmentResult.source_type == GitHubRepoSource.source_type,
        EnrichmentResult.expires_at > datetime.now(UTC),
    )
    query = select(Tool).where(Tool.github_url.ilike("%github.com/%"), ~fresh).order_by(Tool.name).limit(RUN_LIMIT)
    return list((await db.execute(query)).scalars())


async def sync_github_repos(db: AsyncSession, gateway: SourceGateway, api_key: str | None = None) -> dict:
    """Look up each candidate tool's repository and store what GitHub says.

    ``fetched`` counts lookups answered, ``changed`` the answers that differ
    from the stored one, ``written`` the tools whose context was stored. A
    refusal stops the run and keeps what it did; another error costs that tool
    only (repeated ones open the breaker)."""
    from app.enrichment.pipeline import get_cached_result, store_result

    stats = {"fetched": 0, "changed": 0, "written": 0, "failed": 0, "skipped": 0, "stopped": None}
    async with gateway.client(timeout=20.0, follow_redirects=True) as client:
        for tool in await _candidates(db):
            path = repo_path(tool.github_url)
            if path is None:
                stats["skipped"] += 1
                continue
            try:
                parsed = await fetch_repo(client, path, api_key)
            except SOURCE_REFUSALS as e:
                logger.warning("GitHub repository sync stopping: %s", e)
                stats["stopped"] = e.status
                break
            except (httpx.HTTPError, ValueError) as e:
                logger.warning("GitHub repository %s failed: %s", path, e)
                stats["failed"] += 1
                continue
            stats["fetched"] += 1
            existing = await get_cached_result(db, entity_types.TOOL, tool.id, GitHubRepoSource.source_type)
            if existing is None or existing.parsed_data != parsed:
                stats["changed"] += 1
            data = EnrichmentData(raw_response={"repo": path}, parsed_data=parsed, ttl_hours=TTL_HOURS)
            await store_result(db, entity_types.TOOL, tool.id, GitHubRepoSource.source_type, data, existing)
            stats["written"] += 1
            await db.commit()
    return stats
