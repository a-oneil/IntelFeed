"""GitHub Repository adapter — monitors repos for new/changed files via the Commits API.

Primary use case: track detection rule repositories (SigmaHQ, Elastic, Splunk, etc.)
so analysts see new rules in their feed.

Supports two watch modes:
- ``commits`` (default): polls the Commits API for new commits since last fetch.
- ``tree_diff``: uses the Compare API to diff ``last_commit_sha`` against branch HEAD.
  More efficient for high-volume repos; handles file renames and deletions better.
"""

import hashlib
import logging
from datetime import UTC, datetime, timedelta

import httpx

from app.adapters.base import ExtendedAdapter, ParsedEntry, ParsedFeedMeta
from app.adapters.github_content_types import (
    _glob_match,
    derive_title,
    detect_content_type,
    extract_metadata,
    render_content,
)
from app.config import settings

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
MAX_FILE_SIZE_BYTES = settings.github_repo_max_file_size_kb * 1024


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class GitHubRateLimiter:
    """Track GitHub API rate limits via response headers.

    Uses Redis for cross-feed coordination when available,
    falls back to in-memory tracking.
    """

    def __init__(self) -> None:
        self._remaining: int | None = None
        self._reset_at: float | None = None

    def update_from_headers(self, headers: httpx.Headers) -> None:
        """Update rate limit state from GitHub response headers."""
        remaining = headers.get("x-ratelimit-remaining")
        reset = headers.get("x-ratelimit-reset")
        if remaining is not None:
            try:
                self._remaining = int(remaining)
            except ValueError:
                pass
        if reset is not None:
            try:
                self._reset_at = float(reset)
            except ValueError:
                pass

    @property
    def should_back_off(self) -> bool:
        """Return True if we should stop making requests."""
        if self._remaining is not None and self._remaining < 100:
            return True
        return False

    @property
    def remaining(self) -> int | None:
        return self._remaining

    async def update_redis(self, token_hash: str) -> None:
        """Store rate limit state in Redis for cross-feed coordination."""
        try:
            import redis.asyncio as aioredis

            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            async with r:
                key = f"github:ratelimit:{token_hash}"
                data = {
                    "remaining": str(self._remaining or 0),
                    "reset_at": str(self._reset_at or 0),
                }
                await r.hset(key, mapping=data)
                if self._reset_at:
                    ttl = max(int(self._reset_at - datetime.now(UTC).timestamp()), 60)
                    await r.expire(key, ttl)
        except Exception:
            logger.debug("Failed to update GitHub rate limit in Redis", exc_info=True)

    async def check_redis(self, token_hash: str) -> bool:
        """Check Redis for rate limit state from other feeds. Returns True if should back off."""
        try:
            import redis.asyncio as aioredis

            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            async with r:
                key = f"github:ratelimit:{token_hash}"
                data = await r.hgetall(key)
                if data:
                    remaining = int(data.get("remaining", 5000))
                    if remaining < 100:
                        return True
        except Exception:
            logger.debug("Failed to check GitHub rate limit in Redis", exc_info=True)
        return False


# Shared rate limiter instance
_rate_limiter = GitHubRateLimiter()


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


def _with_head_sha(entries: list[ParsedEntry], head_sha: str | None) -> list[ParsedEntry]:
    """Tag every entry with ``_head_sha`` so the worker can persist it in adapter_config."""
    if head_sha:
        for e in entries:
            e.metadata["_head_sha"] = head_sha
    return entries


def _extract_commit_author(commit: dict) -> str:
    """Extract a human-readable author name from a commit object."""
    if commit.get("author"):
        return commit.get("commit", {}).get("author", {}).get("name") or commit.get("author", {}).get(
            "login", "unknown"
        )
    return commit.get("commit", {}).get("author", {}).get("name", "unknown")


def _matches_any_pattern(file_path: str, patterns: list[str]) -> bool:
    """Check if a file path matches any of the configured glob patterns."""
    if not patterns:
        return True  # No patterns = match all files
    return any(_glob_match(file_path, p) for p in patterns)


def _get_token() -> str:
    """Get the GitHub token — DB system setting takes precedence over env."""
    from app.services.system_settings import get_setting_cached

    cached = get_setting_cached("github_token")
    if cached:
        return cached
    return settings.github_token


def _token_hash(token: str) -> str:
    """Hash a token for use as a Redis key."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


class GitHubRepoAdapter(ExtendedAdapter):
    """Monitors GitHub repositories for new/changed files.

    Supports two watch modes:
    - ``commits`` (default): polls the Commits API for new commits since last fetch.
    - ``tree_diff``: uses the Compare API to diff stored ``last_commit_sha`` against
      the branch HEAD.  Falls back to commits mode when the diff exceeds GitHub's
      250-commit / 300-file limit.

    On first poll, applies ``backfill_days`` (default 30) to limit how far back the
    initial import reaches.
    """

    async def fetch_entries(
        self, config: dict, since: datetime | None = None
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        owner = config.get("owner", "")
        repo = config.get("repo", "")
        branch = config.get("branch", "main")
        paths: list[str] = config.get("paths", [])
        max_entries = config.get("max_entries_per_poll", 50)
        include_content = config.get("include_content", True)
        watch_mode = config.get("watch_mode", "commits")
        last_commit_sha: str | None = config.get("last_commit_sha")
        backfill_days: int = config.get("backfill_days", 90)

        if not owner or not repo:
            return ParsedFeedMeta(), []

        token = _get_token()
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "IntelFeed/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # Check rate limit before starting
        if token:
            th = _token_hash(token)
            if await _rate_limiter.check_redis(th):
                logger.warning(f"GitHub rate limit low, skipping {owner}/{repo}")
                return ParsedFeedMeta(title=f"{owner}/{repo}"), []

        meta = ParsedFeedMeta(
            title=f"{owner}/{repo}",
            description=f"File changes in {owner}/{repo} ({branch})",
            site_url=f"https://github.com/{owner}/{repo}",
        )

        # Apply backfill_days on first poll (no since date and no stored SHA)
        # 0 = fetch all history (no time filter)
        if since is None and not last_commit_sha:
            if backfill_days > 0:
                since = datetime.now(UTC) - timedelta(days=backfill_days)
                logger.info(f"First poll for {owner}/{repo}, backfilling {backfill_days} days")
            else:
                logger.info(f"First poll for {owner}/{repo}, fetching all history")

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            # Route to the appropriate watch mode
            if watch_mode == "tree_diff" and last_commit_sha:
                file_changes, new_head_sha = await self._fetch_via_compare(
                    client, owner, repo, branch, last_commit_sha, paths, since
                )
            else:
                file_changes, new_head_sha = await self._fetch_via_commits(client, owner, repo, branch, paths, since)

            if not file_changes:
                # Still update head SHA even with no changes
                if new_head_sha:
                    meta.extra["_head_sha"] = new_head_sha
                return meta, []

            # Fetch content for each changed file and build entries
            entries: list[ParsedEntry] = []
            for fp, change in list(file_changes.items())[:max_entries]:
                content = None
                if include_content and change["change_type"] != "removed":
                    content = await self._fetch_file_content(client, owner, repo, change["commit_sha"], fp)

                    if _rate_limiter.should_back_off:
                        logger.warning("GitHub rate limit low during content fetch, stopping early")
                        break

                content_type = detect_content_type(owner, repo, fp)
                title = derive_title(fp, content, content_type)
                extracted_meta = extract_metadata(content, content_type)
                content_html = render_content(fp, content, content_type, extracted_meta)

                published = None
                ts = change["commit_timestamp"]
                if ts:
                    try:
                        published = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        pass

                entry = ParsedEntry(
                    guid=f"{owner}/{repo}/{fp}",
                    url=f"https://github.com/{owner}/{repo}/blob/{change['commit_sha']}/{fp}",
                    title=title,
                    author=change["commit_author"],
                    content_html=content_html,
                    summary=change["commit_message"],
                    published_at=published,
                    metadata={
                        "source": "github_repo",
                        "owner": owner,
                        "repo": repo,
                        "file_path": fp,
                        "commit_sha": change["commit_sha"],
                        "commit_message": change["commit_message"],
                        "change_type": change["change_type"],
                        "raw_content": content,
                        "content_type": content_type,
                        "extracted": extracted_meta,
                    },
                )
                entries.append(entry)

        # Update Redis rate limit state
        if token:
            await _rate_limiter.update_redis(_token_hash(token))

        # Attach head SHA to meta so the worker can persist it even with 0 entries
        if new_head_sha:
            meta.extra["_head_sha"] = new_head_sha

        return meta, _with_head_sha(entries, new_head_sha)

    def get_feed_meta(self, config: dict) -> ParsedFeedMeta:
        owner = config.get("owner", "")
        repo = config.get("repo", "")
        branch = config.get("branch", "main")
        return ParsedFeedMeta(
            title=f"{owner}/{repo}",
            description=f"File changes in {owner}/{repo} ({branch})",
            site_url=f"https://github.com/{owner}/{repo}",
        )

    # ------------------------------------------------------------------
    # High-level fetch strategies
    # ------------------------------------------------------------------

    async def _fetch_via_commits(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        branch: str,
        paths: list[str],
        since: datetime | None,
    ) -> tuple[dict[str, dict], str | None]:
        """Commits-mode: fetch commits, collect changed files, return (file_changes, head_sha)."""
        commits = await self._fetch_commits(client, owner, repo, branch, since)
        if not commits:
            return {}, None

        file_changes: dict[str, dict] = {}
        head_sha: str | None = None

        for commit in commits:
            head_sha = commit["sha"]  # last (newest) commit is the head
            commit_files = await self._get_commit_files(client, owner, repo, commit)
            for f in commit_files:
                fp = f["filename"]
                if _matches_any_pattern(fp, paths):
                    file_changes[fp] = {
                        "file_path": fp,
                        "commit_sha": commit["sha"],
                        "commit_message": commit.get("commit", {}).get("message", ""),
                        "commit_author": _extract_commit_author(commit),
                        "commit_timestamp": commit.get("commit", {}).get("author", {}).get("date"),
                        "change_type": f.get("status", "modified"),
                    }

            if _rate_limiter.should_back_off:
                logger.warning(f"GitHub rate limit low during {owner}/{repo}, stopping early")
                break

        return file_changes, head_sha

    async def _fetch_via_compare(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        branch: str,
        base_sha: str,
        paths: list[str],
        since: datetime | None,
    ) -> tuple[dict[str, dict], str | None]:
        """Tree-diff mode: use Compare API to get all changes between base_sha and branch HEAD.

        Falls back to commits mode if the diff exceeds GitHub's 250-commit / 300-file limit.
        """
        compare_data = await self._fetch_compare_api(client, owner, repo, base_sha, branch)
        if compare_data is None:
            # API error — fall back to commits mode
            logger.warning(f"Compare API failed for {owner}/{repo}, falling back to commits mode")
            return await self._fetch_via_commits(client, owner, repo, branch, paths, since)

        status = compare_data.get("status", "")
        if status == "identical":
            head_sha = compare_data.get("commits", [{}])[-1].get("sha") if compare_data.get("commits") else base_sha
            return {}, head_sha

        # Check for truncation (GitHub limits compare to 250 commits / 300 files)
        total_commits = compare_data.get("total_commits", 0)
        files = compare_data.get("files", [])
        if total_commits > 250 or len(files) >= 300:
            logger.info(
                f"Compare exceeds limits ({total_commits} commits, {len(files)} files) "
                f"for {owner}/{repo}, falling back to commits mode"
            )
            return await self._fetch_via_commits(client, owner, repo, branch, paths, since)

        # Extract head SHA from the compare response
        head_sha = compare_data.get("commits", [{}])[-1].get("sha") if compare_data.get("commits") else None

        # Build file_changes from the compare files list
        file_changes: dict[str, dict] = {}

        for f in files:
            fp = f.get("filename", "")
            if not _matches_any_pattern(fp, paths):
                continue

            # Find the latest commit that touched this file from the commits list
            commit_sha = head_sha or base_sha
            commit_message = ""
            commit_author = "unknown"
            commit_timestamp = None

            # Walk commits in reverse (newest first) to find the last one touching this file
            for commit in reversed(compare_data.get("commits", [])):
                commit_sha = commit["sha"]
                commit_message = commit.get("commit", {}).get("message", "")
                commit_author = _extract_commit_author(commit)
                commit_timestamp = commit.get("commit", {}).get("author", {}).get("date")
                # The compare API doesn't tell us which commit changed which file,
                # so we use the newest commit as the reference for all files.
                # This is a trade-off for efficiency.
                break

            file_changes[fp] = {
                "file_path": fp,
                "commit_sha": commit_sha,
                "commit_message": commit_message,
                "commit_author": commit_author,
                "commit_timestamp": commit_timestamp,
                "change_type": f.get("status", "modified"),
            }

        return file_changes, head_sha

    # ------------------------------------------------------------------
    # Low-level GitHub API helpers
    # ------------------------------------------------------------------

    async def _fetch_commits(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        branch: str,
        since: datetime | None,
    ) -> list[dict]:
        """Fetch commits from the GitHub Commits API."""
        params: dict[str, str | int] = {
            "sha": branch,
            "per_page": 100,
        }
        if since:
            params["since"] = since.isoformat()

        url = f"{GITHUB_API}/repos/{owner}/{repo}/commits"
        try:
            response = await client.get(url, params=params)
            _rate_limiter.update_from_headers(response.headers)

            if response.status_code == 304:
                return []  # Not modified
            if response.status_code == 404:
                logger.error(f"GitHub repo not found: {owner}/{repo}")
                return []
            if response.status_code == 403:
                logger.warning(f"GitHub API forbidden for {owner}/{repo} (rate limit or token issue)")
                return []
            if response.status_code == 401:
                logger.error(f"GitHub authentication failed for {owner}/{repo}")
                return []
            if response.status_code != 200:
                logger.warning(f"GitHub commits API returned {response.status_code} for {owner}/{repo}")
                return []

            commits = response.json()
            # Return in chronological order (oldest first) so latest commit wins in dedup
            return list(reversed(commits))

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching commits for {owner}/{repo}: {e}")
            return []

    async def _fetch_compare_api(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        base_sha: str,
        head: str,
    ) -> dict | None:
        """Call the Compare API: GET /repos/{owner}/{repo}/compare/{base}...{head}."""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/compare/{base_sha}...{head}"
        try:
            response = await client.get(url)
            _rate_limiter.update_from_headers(response.headers)

            if response.status_code == 404:
                logger.warning(f"Compare base {base_sha[:12]} not found for {owner}/{repo}")
                return None
            if response.status_code != 200:
                logger.warning(f"Compare API returned {response.status_code} for {owner}/{repo}")
                return None

            return response.json()

        except httpx.HTTPError as e:
            logger.error(f"HTTP error calling compare API for {owner}/{repo}: {e}")
            return None

    async def _get_commit_files(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        commit: dict,
    ) -> list[dict]:
        """Get the list of files changed in a specific commit."""
        sha = commit["sha"]
        url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"

        try:
            response = await client.get(url)
            _rate_limiter.update_from_headers(response.headers)

            if response.status_code != 200:
                logger.warning(f"Failed to get commit detail {sha[:12]} for {owner}/{repo}")
                return []

            data = response.json()
            return data.get("files", [])

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching commit {sha[:12]}: {e}")
            return []

    async def _fetch_file_content(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        commit_sha: str,
        file_path: str,
    ) -> str | None:
        """Fetch file content at a specific commit via the Contents API."""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}"
        params = {"ref": commit_sha}

        try:
            response = await client.get(url, params=params)
            _rate_limiter.update_from_headers(response.headers)

            if response.status_code != 200:
                logger.debug(f"Failed to fetch content for {file_path} at {commit_sha[:12]}")
                return None

            data = response.json()

            # Check file size
            size = data.get("size", 0)
            if size > MAX_FILE_SIZE_BYTES:
                logger.info(f"Skipping {file_path} ({size} bytes) — exceeds max file size")
                return None

            # Content is base64-encoded
            import base64

            content_b64 = data.get("content", "")
            if content_b64:
                try:
                    return base64.b64decode(content_b64).decode("utf-8", errors="replace")
                except Exception:
                    logger.debug(f"Failed to decode content for {file_path}")
                    return None

            return None

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching file {file_path}: {e}")
            return None

    # ------------------------------------------------------------------
    # Full tree scan — imports ALL matching files from a repo
    # ------------------------------------------------------------------

    async def fetch_full_tree(
        self,
        config: dict,
        existing_guids: set[str] | None = None,
    ) -> tuple[ParsedFeedMeta, list[ParsedEntry]]:
        """Walk the full Git tree and return entries for ALL matching files.

        Unlike the commit-based modes, this enumerates every file in the repo
        at the current branch HEAD. Files whose GUIDs appear in
        ``existing_guids`` are skipped to avoid re-importing known entries.

        Uses the Git Trees API (recursive) which returns the full tree in a
        single request, then fetches content for each new file individually.
        """
        owner = config.get("owner", "")
        repo = config.get("repo", "")
        branch = config.get("branch", "main")
        paths: list[str] = config.get("paths", [])
        include_content = config.get("include_content", True)

        if not owner or not repo:
            return ParsedFeedMeta(), []

        if existing_guids is None:
            existing_guids = set()

        token = _get_token()
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "IntelFeed/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        meta = ParsedFeedMeta(
            title=f"{owner}/{repo}",
            description=f"Full tree import of {owner}/{repo} ({branch})",
            site_url=f"https://github.com/{owner}/{repo}",
        )

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            # Step 1: Get the full recursive tree
            tree_files = await self._fetch_recursive_tree(client, owner, repo, branch)
            if not tree_files:
                return meta, []

            # Step 2: Filter to matching paths and skip existing entries
            matching = []
            for item in tree_files:
                fp = item["path"]
                guid = f"{owner}/{repo}/{fp}"
                if guid in existing_guids:
                    continue
                if not _matches_any_pattern(fp, paths):
                    continue
                # Only blobs (files), skip trees (directories)
                if item.get("type") != "blob":
                    continue
                # Skip oversized files
                size = item.get("size", 0)
                if size > MAX_FILE_SIZE_BYTES:
                    logger.info(f"Skipping {fp} ({size} bytes) — exceeds max file size")
                    continue
                matching.append(item)

            logger.info(
                f"Full tree scan of {owner}/{repo}: "
                f"{len(tree_files)} total files, "
                f"{len(matching)} new matching files to import"
            )

            # Step 3: Get branch HEAD sha for linking
            head_sha = await self._get_branch_head_sha(client, owner, repo, branch)

            # Step 4: Fetch content and build entries
            entries: list[ParsedEntry] = []
            for item in matching:
                fp = item["path"]
                content = None

                if include_content:
                    content = await self._fetch_file_content(client, owner, repo, head_sha or branch, fp)
                    if _rate_limiter.should_back_off:
                        logger.warning(
                            "GitHub rate limit low during full tree scan, "
                            f"stopping at {len(entries)}/{len(matching)} files"
                        )
                        break

                content_type = detect_content_type(owner, repo, fp)
                title = derive_title(fp, content, content_type)
                extracted_meta = extract_metadata(content, content_type)
                content_html = render_content(fp, content, content_type, extracted_meta)

                entry = ParsedEntry(
                    guid=f"{owner}/{repo}/{fp}",
                    url=f"https://github.com/{owner}/{repo}/blob/{head_sha or branch}/{fp}",
                    title=title,
                    author="full-tree-import",
                    content_html=content_html,
                    summary=f"Imported from full tree scan of {owner}/{repo}",
                    published_at=datetime.now(UTC),
                    metadata={
                        "source": "github_repo",
                        "owner": owner,
                        "repo": repo,
                        "file_path": fp,
                        "commit_sha": head_sha or branch,
                        "commit_message": "Full tree import",
                        "change_type": "added",
                        "raw_content": content,
                        "content_type": content_type,
                        "extracted": extracted_meta,
                    },
                )
                entries.append(entry)

        if head_sha:
            meta.extra["_head_sha"] = head_sha

        return meta, entries

    async def _fetch_recursive_tree(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        branch: str,
    ) -> list[dict]:
        """Fetch the full recursive Git tree for a branch."""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}"
        params = {"recursive": "1"}

        try:
            response = await client.get(url, params=params)
            _rate_limiter.update_from_headers(response.headers)

            if response.status_code != 200:
                logger.warning(f"Git Trees API returned {response.status_code} for {owner}/{repo}")
                return []

            data = response.json()
            if data.get("truncated"):
                logger.warning(
                    f"Git tree for {owner}/{repo} was truncated — repo may have too many files for recursive tree API"
                )

            return data.get("tree", [])

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching tree for {owner}/{repo}: {e}")
            return []

    async def _get_branch_head_sha(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        branch: str,
    ) -> str | None:
        """Get the HEAD commit SHA for a branch."""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{branch}"
        try:
            response = await client.get(url)
            _rate_limiter.update_from_headers(response.headers)
            if response.status_code == 200:
                return response.json().get("sha")
        except httpx.HTTPError:
            pass
        return None
