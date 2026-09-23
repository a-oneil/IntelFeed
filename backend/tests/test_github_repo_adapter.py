"""Tests for the GitHubRepoAdapter — monitors repos for new/changed files."""

import base64
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.adapters.github_content_types import (
    derive_title,
    detect_content_type,
    render_content,
)
from app.adapters.github_repo import (
    GitHubRepoAdapter,
    _extract_commit_author,
    _matches_any_pattern,
    _rate_limiter,
    _with_head_sha,
)

# ---------------------------------------------------------------------------
# Content type detection
# ---------------------------------------------------------------------------


class TestContentTypeDetection:
    def test_sigma_rule(self):
        assert detect_content_type("SigmaHQ", "sigma", "rules/windows/process_creation/test.yml") == "sigma_rule"

    def test_sigma_emerging_threats(self):
        assert detect_content_type("SigmaHQ", "sigma", "rules-emerging-threats/2024/test.yml") == "sigma_rule"

    def test_elastic_rule(self):
        assert detect_content_type("elastic", "detection-rules", "rules/linux/test.toml") == "elastic_rule"

    def test_splunk_detection(self):
        assert detect_content_type("splunk", "security_content", "detections/endpoint/test.yml") == "splunk_detection"

    def test_splunk_story(self):
        assert detect_content_type("splunk", "security_content", "stories/test.yml") == "splunk_story"

    def test_lolbas(self):
        assert detect_content_type("LOLBAS-Project", "LOLBAS", "yml/OSBinaries/Certutil.yml") == "lolbas_entry"

    def test_loobins(self):
        assert detect_content_type("infosecB", "LOOBins", "LOOBins/curl.yml") == "loobin_entry"

    def test_loldrivers(self):
        assert detect_content_type("loldrivers-project", "loldrivers", "yaml/drivers/test.yaml") == "loldriver_entry"

    def test_atomic_red_team(self):
        result = detect_content_type("redcanaryco", "atomic-red-team", "atomics/T1059.001/T1059.001.yaml")
        assert result == "atomic_test"

    def test_yara_signature_base(self):
        assert detect_content_type("Neo23x0", "signature-base", "yara/apt_lazarus.yar") == "yara_rule"

    def test_sentinel(self):
        assert detect_content_type("Azure", "Azure-Sentinel", "Detections/AuditLogs/test.yaml") == "sentinel_rule"

    def test_unknown_repo_yaml(self):
        assert detect_content_type("someone", "repo", "path/to/file.yml") == "yaml_file"

    def test_unknown_repo_json(self):
        assert detect_content_type("someone", "repo", "data/file.json") == "json_file"

    def test_unknown_repo_text_ext(self):
        assert detect_content_type("someone", "repo", "README.txt") == "text_file"

    def test_unknown_repo_unknown_ext(self):
        assert detect_content_type("someone", "repo", "build/artifact.bin") == "unknown"

    def test_case_insensitive_repo(self):
        assert detect_content_type("sigmahq", "sigma", "rules/test.yml") == "sigma_rule"

    def test_no_match_wrong_path(self):
        # SigmaHQ/sigma but wrong directory
        assert detect_content_type("SigmaHQ", "sigma", "docs/readme.md") == "markdown_file"


# ---------------------------------------------------------------------------
# Path filtering
# ---------------------------------------------------------------------------


class TestPathFiltering:
    def test_no_patterns_matches_all(self):
        assert _matches_any_pattern("any/file.yml", []) is True

    def test_single_pattern_match(self):
        assert _matches_any_pattern("rules/windows/test.yml", ["rules/**/*.yml"]) is True

    def test_single_pattern_no_match(self):
        assert _matches_any_pattern("docs/readme.md", ["rules/**/*.yml"]) is False

    def test_multiple_patterns_one_matches(self):
        assert _matches_any_pattern("stories/apt.yml", ["detections/**/*.yml", "stories/**/*.yml"]) is True

    def test_multiple_patterns_none_match(self):
        assert _matches_any_pattern("other/file.txt", ["rules/**/*.yml", "detections/**/*.yml"]) is False


# ---------------------------------------------------------------------------
# Title derivation
# ---------------------------------------------------------------------------


class TestTitleDerivation:
    def test_sigma_title(self):
        content = "title: Certutil Download\nstatus: stable\nlogsource:\n  product: windows"
        assert derive_title("rule.yml", content, "sigma_rule") == "Certutil Download"

    def test_sigma_no_title_fallback(self):
        content = "status: stable\nlogsource:\n  product: windows"
        assert derive_title("rule.yml", content, "sigma_rule") == "rule.yml"

    def test_elastic_title(self):
        content = '[rule]\nname = "Potential Certutil Abuse"\ndescription = "test"'
        assert derive_title("rule.toml", content, "elastic_rule") == "Potential Certutil Abuse"

    def test_splunk_title(self):
        content = "name: Certutil with URL\ntype: TTP"
        assert derive_title("det.yml", content, "splunk_detection") == "Certutil with URL"

    def test_lolbas_title(self):
        content = "Name: Certutil.exe\nDescription: Download files"
        assert derive_title("cert.yml", content, "lolbas_entry") == "Certutil.exe"

    def test_atomic_display_name(self):
        content = "display_name: T1059.001 - PowerShell\nattack_technique: T1059.001"
        assert derive_title("T1059.001.yaml", content, "atomic_test") == "T1059.001 - PowerShell"

    def test_atomic_technique_fallback(self):
        content = "attack_technique: T1059.001"
        assert derive_title("T1059.001.yaml", content, "atomic_test") == "Atomic Test: T1059.001"

    def test_markdown_heading(self):
        content = "# Getting Started\n\nSome text here."
        assert derive_title("readme.md", content, "markdown_file") == "Getting Started"

    def test_yara_rule_name(self):
        content = 'rule APT_Lazarus_Loader {\n  meta:\n    description = "Detects Lazarus loader"'
        assert derive_title("apt.yar", content, "yara_rule") == "APT_Lazarus_Loader"

    def test_nuclei_template(self):
        content = "id: cve-2024-1234\ninfo:\n  name: CVE-2024-1234 RCE\n  severity: critical"
        assert derive_title("cve.yaml", content, "nuclei_template") == "CVE-2024-1234 RCE"

    def test_sentinel_rule(self):
        content = "name: Suspicious Login\ndescription: Detects suspicious logins"
        assert derive_title("rule.yaml", content, "sentinel_rule") == "Suspicious Login"

    def test_json_name(self):
        content = '{"name": "My Dataset", "version": 1}'
        assert derive_title("data.json", content, "json_file") == "My Dataset"

    def test_no_content_fallback(self):
        assert derive_title("rules/test.yml", None, "sigma_rule") == "test.yml"

    def test_malformed_yaml_fallback(self):
        content = ":::not valid yaml:::"
        assert derive_title("bad.yml", content, "sigma_rule") == "bad.yml"

    def test_empty_content_fallback(self):
        assert derive_title("empty.yml", "", "sigma_rule") == "empty.yml"


# ---------------------------------------------------------------------------
# Content rendering
# ---------------------------------------------------------------------------


class TestContentRendering:
    def test_yaml_rendering(self):
        html = render_content("rule.yml", "title: Test Rule")
        assert "language-yaml" in html
        assert "Test Rule" in html

    def test_json_pretty_print(self):
        html = render_content("data.json", '{"key":"value"}')
        assert "language-json" in html
        assert "key" in html
        assert "value" in html

    def test_yara_rendering(self):
        html = render_content("rule.yar", "rule test { condition: true }")
        assert "language-yara" in html

    def test_python_rendering(self):
        html = render_content("rule.py", "def detect(): pass")
        assert "language-python" in html

    def test_markdown_rendering(self):
        html = render_content("readme.md", "# Hello\n\nWorld")
        # Should either render HTML or fall back to pre block
        assert "Hello" in html

    def test_no_content(self):
        html = render_content("file.yml", None)
        assert "No content available" in html

    def test_unknown_extension(self):
        html = render_content("file.xyz", "some content")
        assert "<pre><code>" in html
        assert "some content" in html

    def test_html_escaping(self):
        html = render_content("file.yml", '<script>alert("xss")</script>')
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_malformed_json_fallback(self):
        html = render_content("bad.json", "not json {{{")
        # Should still render something, not crash
        assert "not json" in html


# ---------------------------------------------------------------------------
# Adapter: fetch_entries
# ---------------------------------------------------------------------------


def _make_commit(sha: str, message: str, author: str = "testuser", date: str = "2026-03-01T10:00:00Z"):
    """Helper to build a commit object for mocking."""
    return {
        "sha": sha,
        "commit": {
            "message": message,
            "author": {"name": author, "date": date},
        },
        "author": {"login": author},
    }


def _make_commit_detail(sha: str, files: list[dict]):
    """Helper to build a commit detail response."""
    return {
        "sha": sha,
        "files": files,
    }


def _make_file_content(content: str, size: int | None = None):
    """Helper to build a Contents API response."""
    encoded = base64.b64encode(content.encode()).decode()
    return {
        "content": encoded,
        "size": size or len(content),
        "encoding": "base64",
    }


def _mock_headers(remaining: int = 4900, reset: int = 9999999999):
    """Build fake rate limit headers."""
    return httpx.Headers(
        {
            "x-ratelimit-remaining": str(remaining),
            "x-ratelimit-reset": str(reset),
        }
    )


def _is_list_commits_call(url: str, kwargs: dict) -> bool:
    """Check if this is the list-commits API call (has params with 'sha' key)."""
    return "/commits" in url and "sha" in kwargs.get("params", {})


def _is_commit_detail_call(url: str, sha: str) -> bool:
    """Check if this is a commit detail call (URL ends with /commits/{sha})."""
    return url.endswith(f"/commits/{sha}")


@pytest.mark.asyncio
async def test_fetch_entries_basic():
    """Test basic flow: one commit with one new file."""
    adapter = GitHubRepoAdapter()

    commit_sha = "abc123def456"
    sigma_content = "title: Certutil Download\nstatus: stable\nlogsource:\n  product: windows"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Add certutil rule")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/windows/certutil.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content(sigma_content)
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None
        _rate_limiter._reset_at = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "branch": "main",
            "paths": ["rules/**/*.yml"],
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert meta.title == "SigmaHQ/sigma"
        assert len(entries) == 1
        entry = entries[0]
        assert entry.title == "Certutil Download"
        assert entry.guid == "SigmaHQ/sigma/rules/windows/certutil.yml"
        assert entry.metadata["content_type"] == "sigma_rule"
        assert entry.metadata["change_type"] == "added"
        assert entry.metadata["raw_content"] == sigma_content
        assert "language-yaml" in entry.content_html


@pytest.mark.asyncio
async def test_fetch_entries_path_filtering():
    """Files not matching path globs should be excluded."""
    adapter = GitHubRepoAdapter()

    commit_sha = "abc123"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()

        url_str = str(url)
        if _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Update docs and rules")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/test.yml", "status": "added"},
                    {"filename": "docs/readme.md", "status": "modified"},
                    {"filename": "rules/nested/deep.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Test")
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        # Only the two .yml files in rules/ should match
        assert len(entries) == 2
        paths = [e.metadata["file_path"] for e in entries]
        assert "docs/readme.md" not in paths


@pytest.mark.asyncio
async def test_fetch_entries_dedup_same_file():
    """Same file changed in multiple commits should produce one entry with latest content."""
    adapter = GitHubRepoAdapter()

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            # Two commits, oldest first after reversal in adapter
            resp.json = lambda: [
                _make_commit("newer_sha", "Update rule v2", date="2026-03-02T10:00:00Z"),
                _make_commit("older_sha", "Add rule v1", date="2026-03-01T10:00:00Z"),
            ]
        elif _is_commit_detail_call(url_str, "older_sha"):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                "older_sha",
                [
                    {"filename": "rules/test.yml", "status": "added"},
                ],
            )
        elif _is_commit_detail_call(url_str, "newer_sha"):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                "newer_sha",
                [
                    {"filename": "rules/test.yml", "status": "modified"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Updated Rule")
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {"owner": "SigmaHQ", "repo": "sigma", "paths": ["rules/**/*.yml"]}
        meta, entries = await adapter.fetch_entries(config, since=None)

        # Should deduplicate to one entry
        assert len(entries) == 1
        # Should have the newer commit's data
        assert entries[0].metadata["commit_sha"] == "newer_sha"
        assert entries[0].metadata["change_type"] == "modified"


@pytest.mark.asyncio
async def test_fetch_entries_max_entries_cap():
    """max_entries_per_poll should limit output."""
    adapter = GitHubRepoAdapter()

    commit_sha = "abc123"
    files = [{"filename": f"rules/rule{i}.yml", "status": "added"} for i in range(10)]

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Bulk add")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(commit_sha, files)
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Rule")
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {"owner": "test", "repo": "rules", "max_entries_per_poll": 3}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 3


@pytest.mark.asyncio
async def test_fetch_entries_removed_file():
    """Removed files should have no content and change_type 'removed'."""
    adapter = GitHubRepoAdapter()

    commit_sha = "abc123"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Remove old rule")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/old.yml", "status": "removed"},
                ],
            )
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {"owner": "SigmaHQ", "repo": "sigma", "paths": ["rules/**/*.yml"]}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert entries[0].metadata["change_type"] == "removed"
        assert entries[0].metadata["raw_content"] is None


@pytest.mark.asyncio
async def test_fetch_entries_404_repo():
    """404 response should return empty entries, not crash."""
    adapter = GitHubRepoAdapter()

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        resp.status_code = 404
        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {"owner": "nonexistent", "repo": "repo"}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert entries == []


@pytest.mark.asyncio
async def test_fetch_entries_403_rate_limit():
    """403 response should return empty entries gracefully."""
    adapter = GitHubRepoAdapter()

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers(remaining=0)
        resp.status_code = 403
        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {"owner": "SigmaHQ", "repo": "sigma"}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert entries == []


@pytest.mark.asyncio
async def test_fetch_entries_empty_config():
    """Missing owner/repo should return empty."""
    adapter = GitHubRepoAdapter()
    meta, entries = await adapter.fetch_entries({}, since=None)
    assert entries == []


@pytest.mark.asyncio
async def test_fetch_entries_file_too_large():
    """Files exceeding max_file_size_kb should be skipped (no content)."""
    adapter = GitHubRepoAdapter()

    commit_sha = "abc123"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Add large file")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "data/huge.json", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            # Report size larger than 5MB
            resp.json = lambda: {"content": "", "size": 10 * 1024 * 1024, "encoding": "base64"}
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {"owner": "test", "repo": "repo"}
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert entries[0].metadata["raw_content"] is None


# ---------------------------------------------------------------------------
# Adapter: get_feed_meta
# ---------------------------------------------------------------------------


def test_get_feed_meta():
    adapter = GitHubRepoAdapter()
    meta = adapter.get_feed_meta({"owner": "SigmaHQ", "repo": "sigma", "branch": "main"})
    assert meta.title == "SigmaHQ/sigma"
    assert "github.com/SigmaHQ/sigma" in meta.site_url


def test_get_feed_meta_custom_branch():
    adapter = GitHubRepoAdapter()
    meta = adapter.get_feed_meta({"owner": "elastic", "repo": "detection-rules", "branch": "dev"})
    assert "dev" in meta.description


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_update_from_headers(self):
        from app.adapters.github_repo import GitHubRateLimiter

        limiter = GitHubRateLimiter()
        headers = httpx.Headers(
            {
                "x-ratelimit-remaining": "150",
                "x-ratelimit-reset": "1700000000",
            }
        )
        limiter.update_from_headers(headers)
        assert limiter.remaining == 150
        assert limiter.should_back_off is False

    def test_should_back_off_when_low(self):
        from app.adapters.github_repo import GitHubRateLimiter

        limiter = GitHubRateLimiter()
        headers = httpx.Headers(
            {
                "x-ratelimit-remaining": "50",
                "x-ratelimit-reset": "1700000000",
            }
        )
        limiter.update_from_headers(headers)
        assert limiter.should_back_off is True

    def test_no_headers_no_backoff(self):
        from app.adapters.github_repo import GitHubRateLimiter

        limiter = GitHubRateLimiter()
        assert limiter.should_back_off is False


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------


def test_github_repo_in_registry():
    from app.adapters import get_extended_adapter, is_extended_feed_type

    assert is_extended_feed_type("github_repo") is True
    adapter = get_extended_adapter("github_repo")
    assert adapter is not None
    assert isinstance(adapter, GitHubRepoAdapter)


# ---------------------------------------------------------------------------
# Phase 5: Helper functions
# ---------------------------------------------------------------------------


class TestExtractCommitAuthor:
    def test_with_author_login(self):
        commit = {
            "commit": {"author": {"name": "Florian Roth"}},
            "author": {"login": "Neo23x0"},
        }
        assert _extract_commit_author(commit) == "Florian Roth"

    def test_with_author_login_no_name(self):
        commit = {
            "commit": {"author": {"name": ""}},
            "author": {"login": "Neo23x0"},
        }
        assert _extract_commit_author(commit) == "Neo23x0"

    def test_no_author_field(self):
        commit = {
            "commit": {"author": {"name": "Bot User"}},
            "author": None,
        }
        assert _extract_commit_author(commit) == "Bot User"

    def test_empty_commit(self):
        assert _extract_commit_author({}) == "unknown"


class TestWithHeadSha:
    def test_tags_entries(self):
        from app.adapters.base import ParsedEntry

        entries = [ParsedEntry(guid="a"), ParsedEntry(guid="b")]
        result = _with_head_sha(entries, "abc123")
        assert all(e.metadata.get("_head_sha") == "abc123" for e in result)

    def test_no_sha(self):
        from app.adapters.base import ParsedEntry

        entries = [ParsedEntry(guid="a")]
        result = _with_head_sha(entries, None)
        assert "_head_sha" not in result[0].metadata

    def test_empty_entries_with_sha(self):
        result = _with_head_sha([], "abc123")
        assert result == []


# ---------------------------------------------------------------------------
# Phase 5: Tree diff watch mode
# ---------------------------------------------------------------------------


def _make_compare_response(
    status: str = "ahead",
    total_commits: int = 2,
    files: list[dict] | None = None,
    commits: list[dict] | None = None,
):
    """Helper to build a Compare API response."""
    if commits is None:
        commits = [
            _make_commit("old_sha", "First commit", date="2026-03-01T10:00:00Z"),
            _make_commit("new_head_sha", "Latest commit", date="2026-03-02T10:00:00Z"),
        ]
    if files is None:
        files = []
    return {
        "status": status,
        "total_commits": total_commits,
        "merge_base_commit": _make_commit("base_sha", "Base"),
        "commits": commits,
        "files": files,
    }


@pytest.mark.asyncio
async def test_tree_diff_mode_basic():
    """Tree diff mode should use Compare API and return changed files."""
    adapter = GitHubRepoAdapter()

    compare_data = _make_compare_response(
        files=[
            {"filename": "rules/new_rule.yml", "status": "added"},
            {"filename": "rules/updated.yml", "status": "modified"},
        ]
    )

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if "/compare/" in url_str:
            resp.status_code = 200
            resp.json = lambda: compare_data
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Test Rule")
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "branch": "main",
            "paths": ["rules/**/*.yml"],
            "watch_mode": "tree_diff",
            "last_commit_sha": "old_base_sha",
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 2
        assert entries[0].metadata["change_type"] == "added"
        assert entries[1].metadata["change_type"] == "modified"
        # Should have head SHA tagged
        assert entries[0].metadata.get("_head_sha") == "new_head_sha"


@pytest.mark.asyncio
async def test_tree_diff_identical():
    """When compare status is identical, no entries should be returned."""
    adapter = GitHubRepoAdapter()

    compare_data = _make_compare_response(
        status="identical",
        commits=[_make_commit("same_sha", "Same")],
        files=[],
    )

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        if "/compare/" in str(url):
            resp.status_code = 200
            resp.json = lambda: compare_data
        else:
            resp.status_code = 200
            resp.json = lambda: []
        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "watch_mode": "tree_diff",
            "last_commit_sha": "same_sha",
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 0


@pytest.mark.asyncio
async def test_tree_diff_exceeds_limit_falls_back():
    """When compare exceeds 250 commits, should fall back to commits mode."""
    adapter = GitHubRepoAdapter()

    # Compare response that exceeds limits
    compare_data = _make_compare_response(total_commits=300)

    commit_sha = "fallback_sha"
    sigma_content = "title: Fallback Rule"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if "/compare/" in url_str:
            resp.status_code = 200
            resp.json = lambda: compare_data
        elif _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Fallback commit")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/fallback.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content(sigma_content)
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
            "watch_mode": "tree_diff",
            "last_commit_sha": "old_sha",
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        # Should have fallen back to commits mode and found the rule
        assert len(entries) == 1
        assert entries[0].title == "Fallback Rule"


@pytest.mark.asyncio
async def test_tree_diff_compare_404_falls_back():
    """When Compare API returns 404, should fall back to commits mode."""
    adapter = GitHubRepoAdapter()

    commit_sha = "fb_sha"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if "/compare/" in url_str:
            resp.status_code = 404
            return resp
        elif _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Found via fallback")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/found.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Found")
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
            "watch_mode": "tree_diff",
            "last_commit_sha": "gone_sha",
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert entries[0].title == "Found"


@pytest.mark.asyncio
async def test_tree_diff_without_last_sha_uses_commits():
    """tree_diff mode without last_commit_sha should fall back to commits mode."""
    adapter = GitHubRepoAdapter()

    commit_sha = "first_sha"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        # Should NOT call compare API since no last_commit_sha
        assert "/compare/" not in url_str

        if _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Initial")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/init.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Initial Rule")
        else:
            resp.status_code = 200
            resp.json = lambda: []

        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
            "watch_mode": "tree_diff",
            # No last_commit_sha — should use commits mode
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1


@pytest.mark.asyncio
async def test_tree_diff_path_filtering():
    """Tree diff mode should respect path filters."""
    adapter = GitHubRepoAdapter()

    compare_data = _make_compare_response(
        files=[
            {"filename": "rules/good.yml", "status": "added"},
            {"filename": "docs/readme.md", "status": "modified"},
            {"filename": "tests/test.py", "status": "added"},
        ]
    )

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if "/compare/" in url_str:
            resp.status_code = 200
            resp.json = lambda: compare_data
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Test")
        else:
            resp.status_code = 200
            resp.json = lambda: []
        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
            "watch_mode": "tree_diff",
            "last_commit_sha": "old_sha",
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert entries[0].metadata["file_path"] == "rules/good.yml"


# ---------------------------------------------------------------------------
# Phase 5: Selective backfill
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backfill_days_applied_on_first_poll():
    """On first poll (no since, no last_commit_sha), backfill_days should limit history."""
    adapter = GitHubRepoAdapter()

    captured_params: list[dict] = []
    commit_sha = "bf_sha"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            captured_params.append(kwargs.get("params", {}))
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Backfill commit")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/bf.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Backfill")
        else:
            resp.status_code = 200
            resp.json = lambda: []
        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
            "backfill_days": 7,
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        # Verify the commits API was called with a 'since' parameter
        assert len(captured_params) == 1
        since_param = captured_params[0].get("since", "")
        # The since date should be roughly 7 days ago
        since_dt = datetime.fromisoformat(since_param)
        expected = datetime.now(UTC) - timedelta(days=7)
        assert abs((since_dt - expected).total_seconds()) < 60


@pytest.mark.asyncio
async def test_backfill_days_not_applied_with_since():
    """When since is provided, backfill_days should NOT override it."""
    adapter = GitHubRepoAdapter()

    captured_params: list[dict] = []
    explicit_since = datetime(2026, 1, 1, tzinfo=UTC)
    commit_sha = "explicit_sha"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            captured_params.append(kwargs.get("params", {}))
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Explicit since")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/test.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: T")
        else:
            resp.status_code = 200
            resp.json = lambda: []
        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
            "backfill_days": 7,
        }
        meta, entries = await adapter.fetch_entries(config, since=explicit_since)

        # Should use the explicit since date, not backfill
        since_param = captured_params[0].get("since", "")
        assert "2026-01-01" in since_param


@pytest.mark.asyncio
async def test_backfill_zero_means_no_limit():
    """backfill_days=0 should not apply any since filter."""
    adapter = GitHubRepoAdapter()

    captured_params: list[dict] = []
    commit_sha = "nolimit_sha"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            captured_params.append(kwargs.get("params", {}))
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "All history")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/all.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: All")
        else:
            resp.status_code = 200
            resp.json = lambda: []
        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
            "backfill_days": 0,
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        # Should NOT have a 'since' parameter
        assert "since" not in captured_params[0]


# ---------------------------------------------------------------------------
# Phase 5: Head SHA tracking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_head_sha_tracked_in_entries():
    """Entries should contain _head_sha for the worker to persist."""
    adapter = GitHubRepoAdapter()

    commit_sha = "head_abc123"

    async def mock_get(url, **kwargs):
        resp = AsyncMock()
        resp.headers = _mock_headers()
        url_str = str(url)

        if _is_list_commits_call(url_str, kwargs):
            resp.status_code = 200
            resp.json = lambda: [_make_commit(commit_sha, "Track head")]
        elif _is_commit_detail_call(url_str, commit_sha):
            resp.status_code = 200
            resp.json = lambda: _make_commit_detail(
                commit_sha,
                [
                    {"filename": "rules/track.yml", "status": "added"},
                ],
            )
        elif "/contents/" in url_str:
            resp.status_code = 200
            resp.json = lambda: _make_file_content("title: Track")
        else:
            resp.status_code = 200
            resp.json = lambda: []
        return resp

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        _rate_limiter._remaining = None

        config = {
            "owner": "SigmaHQ",
            "repo": "sigma",
            "paths": ["rules/**/*.yml"],
        }
        meta, entries = await adapter.fetch_entries(config, since=None)

        assert len(entries) == 1
        assert entries[0].metadata["_head_sha"] == commit_sha


# ---------------------------------------------------------------------------
# Phase 5: Bulk import templates
# ---------------------------------------------------------------------------


class TestBulkImportTemplates:
    def test_templates_list(self):
        from app.services.github_repo_templates import DETECTION_REPO_TEMPLATES

        # Should have all expected repos
        owners = [t["owner"] for t in DETECTION_REPO_TEMPLATES]
        assert "SigmaHQ" in owners
        assert "elastic" in owners
        assert "splunk" in owners
        assert "LOLBAS-Project" in owners
        assert "redcanaryco" in owners
        assert "Neo23x0" in owners
        assert "Azure" in owners
        assert "projectdiscovery" in owners
        assert "chronicle" in owners

    def test_template_structure(self):
        from app.services.github_repo_templates import DETECTION_REPO_TEMPLATES

        for tmpl in DETECTION_REPO_TEMPLATES:
            assert "owner" in tmpl
            assert "repo" in tmpl
            assert "paths" in tmpl
            assert "label" in tmpl
            assert "description" in tmpl
            assert "content_types" in tmpl
            assert len(tmpl["paths"]) > 0

    def test_get_template_feed_configs(self):
        from app.services.github_repo_templates import get_template_feed_configs

        configs = get_template_feed_configs(backfill_days=14, interval_minutes=60)

        assert len(configs) > 0
        for cfg in configs:
            assert cfg["feed_type"] == "github_repo"
            assert cfg["fetch_interval_minutes"] == 60
            assert cfg["adapter_config"]["backfill_days"] == 14
            assert "owner" in cfg["adapter_config"]
            assert "repo" in cfg["adapter_config"]
            assert "paths" in cfg["adapter_config"]
            assert cfg["url"].startswith("https://github.com/")
            assert cfg["intel_extraction_mode"] == "full"

    def test_get_template_feed_configs_defaults(self):
        from app.services.github_repo_templates import get_template_feed_configs

        configs = get_template_feed_configs()

        for cfg in configs:
            assert cfg["fetch_interval_minutes"] == 1440
            assert cfg["adapter_config"]["backfill_days"] == 90
            assert cfg["adapter_config"]["watch_mode"] == "commits"
            assert cfg["adapter_config"]["include_content"] is True

    def test_sigma_template_correct(self):
        from app.services.github_repo_templates import DETECTION_REPO_TEMPLATES

        sigma = next(t for t in DETECTION_REPO_TEMPLATES if t["owner"] == "SigmaHQ")
        assert sigma["repo"] == "sigma"
        assert "rules/**/*.yml" in sigma["paths"]
        assert "sigma_rule" in sigma["content_types"]

    def test_elastic_template_correct(self):
        from app.services.github_repo_templates import DETECTION_REPO_TEMPLATES

        elastic = next(t for t in DETECTION_REPO_TEMPLATES if t["owner"] == "elastic")
        assert elastic["repo"] == "detection-rules"
        assert "rules/**/*.toml" in elastic["paths"]
