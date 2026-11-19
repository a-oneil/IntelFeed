"""Rule editor rework: every query language is a conversion target, the convert
request carries a dialect and notes, and a mirrored rule cannot be renamed."""

import re
import uuid

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select

from app.ai.query_language import QUERY_LANGUAGES
from app.intelligence.rule_validation import UNCHECKED_RULE_TYPES, validate_rule
from app.models.detection_rule import DetectionRule
from app.schemas.intelligence import RULE_TYPE_PATTERN, RuleConvertRequest


def test_every_query_language_is_a_library_rule_type():
    """Settings › Reading offers eleven languages; Convert must be able to store each one."""
    pattern = re.compile(RULE_TYPE_PATTERN)
    for lang in QUERY_LANGUAGES.values():
        assert lang.rule_type, f"{lang.id} has no rule_type"
        assert pattern.match(lang.rule_type), f"{lang.rule_type} is not in RULE_TYPE_PATTERN"


@pytest.mark.parametrize("rule_type", sorted(UNCHECKED_RULE_TYPES))
def test_unchecked_rule_types_validate_as_saved_as_written(rule_type):
    result = validate_rule(rule_type, "SELECT 1")
    assert result.valid is True
    assert result.errors == []
    assert any("No syntax check" in s for s in result.suggestions)


def test_unknown_rule_type_is_still_an_error():
    result = validate_rule("not_a_format", "x")
    assert result.valid is False
    assert "Unknown rule type" in result.errors[0].message


def test_convert_request_accepts_dialect_and_notes():
    body = RuleConvertRequest(target_type="elastic_ql", dialect="esql", notes="Keep the regex.")
    assert body.dialect == "esql"
    assert body.notes == "Keep the regex."
    assert RuleConvertRequest(target_type="yaral").dialect is None


def test_convert_request_rejects_unknown_target():
    with pytest.raises(ValidationError):
        RuleConvertRequest(target_type="cobol")


@pytest.mark.asyncio
async def test_convert_rejects_dialect_of_another_format(client: AsyncClient, auth_headers: dict):
    create = await client.post(
        "/api/detection-rules",
        json={"title": "Reg save", "rule_content": "title: x\ndetection:\n  condition: sel", "rule_type": "sigma"},
        headers=auth_headers,
    )
    assert create.status_code == 201
    rule_id = create.json()["id"]
    # KQL is not an elastic_ql dialect; refused before any provider is looked up.
    resp = await client.post(
        f"/api/detection-rules/{rule_id}/convert",
        json={"target_type": "elastic_ql", "dialect": "kql"},
        headers=auth_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "bad_dialect"


@pytest.mark.asyncio
async def test_convert_to_same_type_is_refused_before_dialect_check(client: AsyncClient, auth_headers: dict):
    create = await client.post(
        "/api/detection-rules",
        json={"title": "Same", "rule_content": "title: x", "rule_type": "sigma"},
        headers=auth_headers,
    )
    rule_id = create.json()["id"]
    resp = await client.post(
        f"/api/detection-rules/{rule_id}/convert", json={"target_type": "sigma"}, headers=auth_headers
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "same_type"


@pytest.mark.asyncio
async def test_rename_is_locked_for_a_mirrored_rule(client: AsyncClient, auth_headers: dict, db_session):
    create = await client.post(
        "/api/detection-rules",
        json={"title": "Dumping of Sensitive Hives Via Reg.EXE", "rule_content": "title: x", "rule_type": "sigma"},
        headers=auth_headers,
    )
    rule_id = create.json()["id"]
    # Mirrored rules carry their repo in metadata; the sync finds them by title.
    rule = (await db_session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))).scalar_one()
    rule.metadata_ = {"owner": "SigmaHQ", "repo": "sigma", "file_path": "rules/x.yml"}
    await db_session.flush()

    resp = await client.put(f"/api/detection-rules/{rule_id}", json={"title": "Renamed"}, headers=auth_headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "rename_locked"

    # Sending the current title back (the editor does on every save) is not a rename.
    same = await client.put(
        f"/api/detection-rules/{rule_id}",
        json={"title": "Dumping of Sensitive Hives Via Reg.EXE", "severity": "high"},
        headers=auth_headers,
    )
    assert same.status_code == 200
    assert same.json()["severity"] == "high"


@pytest.mark.asyncio
async def test_rename_works_for_an_authored_rule(client: AsyncClient, auth_headers: dict):
    create = await client.post(
        "/api/detection-rules",
        json={"title": "Draft", "rule_content": "title: x", "rule_type": "kql"},
        headers=auth_headers,
    )
    rule_id = create.json()["id"]
    resp = await client.put(
        f"/api/detection-rules/{rule_id}", json={"title": "Reg.exe hive export"}, headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Reg.exe hive export"


@pytest.mark.asyncio
async def test_new_formats_create_and_validate_through_the_api(client: AsyncClient, auth_headers: dict):
    create = await client.post(
        "/api/detection-rules",
        json={"title": "QRadar reg save", "rule_content": "SELECT * FROM events", "rule_type": "aql"},
        headers=auth_headers,
    )
    assert create.status_code == 201
    assert create.json()["rule_type"] == "aql"
    validate = await client.post(
        "/api/detection-rules/validate",
        json={"rule_type": "aql", "rule_content": "SELECT * FROM events"},
        headers=auth_headers,
    )
    assert validate.status_code == 200
    assert validate.json()["valid"] is True


# --- provenance survives saves -------------------------------------------------

from app.intelligence.rule_metadata import IMPORT_METADATA_KEYS, extract_and_apply, merge_client_metadata  # noqa: E402

PROVENANCE = {
    "owner": "splunk",
    "repo": "security_content",
    "file_path": "detections/endpoint/macos_reopened_applications.yml",
    "commit_sha": "d6afc62b0000000000000000000000000000abcd",
    "commit_author": "splunk",
    "commit_message": "update",
    "commit_date": "2026-11-10T00:00:00+00:00",
    "change_type": "modified",
    "commit_history": [{"sha": "d6afc62b0000000000000000000000000000abcd", "author": "splunk", "message": "update"}],
}


def test_merge_client_metadata_keeps_provenance_the_client_left_out():
    merged = merge_client_metadata(
        {**PROVENANCE, "ai_chat_history": [{"role": "user", "content": "hi"}]}, {"rule_level": "high"}
    )
    assert merged["rule_level"] == "high"
    for key in IMPORT_METADATA_KEYS:
        assert merged[key] == PROVENANCE[key]
    # Keys that are the client's to set are not resurrected.
    assert "ai_chat_history" not in merged


def test_extract_and_apply_keeps_provenance():
    class Rule:
        rule_type = "sigma"
        rule_content = (
            "title: Reg save\nlevel: high\nlogsource:\n  product: windows\n"
            "detection:\n  sel:\n    a: b\n  condition: sel"
        )
        metadata_ = {**PROVENANCE, "ai_chat_history": [], "extended_from": "x"}
        severity = None
        tags = []
        mitre_tactics = []
        source_ttps = []
        data_sources = []
        log_sources = {}
        references = []
        description = None
        title = "Reg save"

    rule = Rule()
    extract_and_apply(rule, set())
    for key in IMPORT_METADATA_KEYS:
        assert rule.metadata_[key] == PROVENANCE[key], key
    assert rule.metadata_["extended_from"] == "x"
    assert "rule_level" in rule.metadata_


@pytest.mark.asyncio
async def test_saving_a_mirrored_rule_keeps_it_mirrored(client: AsyncClient, auth_headers: dict, db_session):
    create = await client.post(
        "/api/detection-rules",
        json={"title": "MacOS - Re-opened Applications", "rule_content": "title: x", "rule_type": "sigma"},
        headers=auth_headers,
    )
    rule_id = create.json()["id"]
    rule = (await db_session.execute(select(DetectionRule).where(DetectionRule.id == rule_id))).scalar_one()
    rule.metadata_ = dict(PROVENANCE)
    await db_session.flush()

    # What the editor used to send: the extractor's view of the body, no provenance.
    resp = await client.put(
        f"/api/detection-rules/{rule_id}",
        json={
            "severity": "high",
            "metadata": {"rule_title": "x", "ai_chat_history": [{"role": "user", "content": "hi"}]},
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_repo"] == "security_content"
    assert body["is_authored_local"] is False

    # A body edit re-extracts metadata; the provenance survives that too.
    resp = await client.put(
        f"/api/detection-rules/{rule_id}",
        json={
            "rule_content": (
                "title: y\nlevel: low\nlogsource:\n  product: windows\ndetection:\n  sel:\n    a: b\n  condition: sel"
            )
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["source_repo"] == "security_content"
    commits = await client.get(f"/api/detection-rules/{rule_id}/commits", headers=auth_headers)
    assert commits.json()["commits"][0]["short_sha"] == "d6afc62b"


# --- repair: restore provenance, merge duplicates ------------------------------

from datetime import UTC, datetime, timedelta  # noqa: E402

from app.models.detection_rule_version import DetectionRuleVersion  # noqa: E402
from app.models.entry import Entry  # noqa: E402
from app.services.github_rule_import import merge_duplicate_rules, restore_provenance  # noqa: E402


def _github_entry(feed_id, sha: str, when: datetime, body: str = "title: x") -> Entry:
    return Entry(
        feed_id=feed_id,
        guid=f"splunk/security_content/detections/endpoint/reopened.yml#{sha}",
        url=f"https://github.com/splunk/security_content/blob/{sha}/detections/endpoint/reopened.yml",
        title="MacOS - Re-opened Applications",
        author="splunk",
        content_text=body,
        published_at=when,
        metadata_={
            "source": "github_repo",
            "owner": "splunk",
            "repo": "security_content",
            "file_path": "detections/endpoint/reopened.yml",
            "commit_sha": sha,
            "commit_message": f"commit {sha[:4]}",
            "change_type": "modified",
            "raw_content": body,
            "content_type": "splunk_detection",
        },
    )


@pytest.mark.asyncio
async def test_restore_provenance_from_the_entry(db_session, test_user, test_feed):
    entry = _github_entry(test_feed.id, "d6afc62b" + "0" * 32, datetime(2026, 11, 10, tzinfo=UTC))
    db_session.add(entry)
    await db_session.flush()
    rule = DetectionRule(
        entry_id=entry.id,
        created_by=test_user.id,
        rule_type="splunk_spl",
        title="MacOS - Re-opened Applications",
        rule_content="| tstats count",
        notes="Imported from splunk/security_content via commit d6afc62b",
        # What a save left behind: the extractor's keys, nothing about the repo.
        metadata_={"search_query": "| tstats count", "ai_chat_history": []},
    )
    db_session.add(rule)
    await db_session.flush()
    assert rule.is_authored_local

    restored = restore_provenance(rule, entry)
    assert set(restored) >= {"owner", "repo", "file_path", "commit_sha", "commit_history"}
    assert rule.source_repo == "security_content"
    assert not rule.is_authored_local
    assert rule.metadata_["ai_chat_history"] == []
    assert rule.metadata_["commit_history"][0]["sha"].startswith("d6afc62b")
    # Idempotent.
    assert restore_provenance(rule, entry) == []


@pytest.mark.asyncio
async def test_merge_duplicate_rules_keeps_oldest_and_builds_history(db_session, test_user, test_feed):
    t0 = datetime(2026, 11, 1, tzinfo=UTC)
    shas = ["a" * 40, "b" * 40, "c" * 40]
    rows = []
    for i, sha in enumerate(shas):
        entry = _github_entry(test_feed.id, sha, t0 + timedelta(days=i), body=f"body {i}")
        db_session.add(entry)
        await db_session.flush()
        rule = DetectionRule(
            entry_id=entry.id,
            created_by=test_user.id,
            rule_type="splunk_spl",
            title="MacOS - Re-opened Applications",
            rule_content=f"body {i}",
            tags=[f"t{i}"],
            source_entries=[entry.id],
            metadata_={
                "owner": "splunk",
                "repo": "security_content",
                "file_path": "detections/endpoint/reopened.yml",
                "commit_sha": sha,
                "commit_message": f"commit {sha[:4]}",
                "commit_date": (t0 + timedelta(days=i)).isoformat(),
                "commit_history": [
                    {"sha": sha, "message": f"commit {sha[:4]}", "date": (t0 + timedelta(days=i)).isoformat()}
                ],
            },
        )
        db_session.add(rule)
        await db_session.flush()
        rule.created_at = t0 + timedelta(days=i)
        rows.append(rule)
    await db_session.flush()
    keeper = rows[0]
    child = DetectionRule(
        created_by=test_user.id, rule_type="kql", title="child", rule_content="x", derived_from=rows[2].id
    )
    db_session.add(child)
    await db_session.flush()

    result = await merge_duplicate_rules(db_session, list(rows), test_user.id)
    assert result["keeper"] == str(keeper.id)
    assert set(result["removed"]) == {str(rows[1].id), str(rows[2].id)}
    assert result["versions_added"] == 2
    assert result["commits"] == 3

    await db_session.refresh(keeper)
    assert keeper.rule_content == "body 2"
    assert keeper.metadata_["commit_sha"] == "c" * 40
    assert [c["sha"][0] for c in keeper.metadata_["commit_history"]] == ["c", "b", "a"]
    assert sorted(keeper.tags) == ["t0", "t1", "t2"]
    assert len(keeper.source_entries) == 3
    versions = (
        (
            await db_session.execute(
                select(DetectionRuleVersion)
                .where(DetectionRuleVersion.rule_id == keeper.id)
                .order_by(DetectionRuleVersion.version_number)
            )
        )
        .scalars()
        .all()
    )
    assert [v.rule_content for v in versions] == ["body 0", "body 1"]
    assert versions[0].change_description.startswith("Upstream aaaaaaaa")
    await db_session.refresh(child)
    assert child.derived_from == keeper.id
    gone = (await db_session.execute(select(DetectionRule).where(DetectionRule.id == rows[1].id))).scalar_one_or_none()
    assert gone is None


# --- the fetcher follows a repo file to its next commit ------------------------

from types import SimpleNamespace  # noqa: E402
from unittest.mock import AsyncMock, MagicMock, patch  # noqa: E402

from app.workers.feed_tasks import _github_entry_moved, _refresh_github_entry  # noqa: E402


def _parsed(sha: str, body: str = "title: y"):
    return SimpleNamespace(
        guid="splunk/security_content/detections/x.yml",
        url=f"https://github.com/splunk/security_content/blob/{sha}/detections/x.yml",
        title="x",
        author="splunk",
        summary="commit msg",
        content_html=f"<pre>{body}</pre>",
        published_at=datetime(2026, 11, 12, tzinfo=UTC),
        metadata={
            "source": "github_repo",
            "owner": "splunk",
            "repo": "security_content",
            "file_path": "detections/x.yml",
            "commit_sha": sha,
            "commit_message": "commit msg",
            "change_type": "modified",
            "raw_content": body,
            "content_type": "splunk_detection",
        },
    )


def test_github_entry_moved_only_on_a_new_commit():
    entry = SimpleNamespace(metadata_={"commit_sha": "a" * 40})
    assert _github_entry_moved(entry, _parsed("b" * 40))
    assert not _github_entry_moved(entry, _parsed("a" * 40))
    assert not _github_entry_moved(SimpleNamespace(metadata_={}), SimpleNamespace(metadata={}))


@pytest.mark.asyncio
async def test_refresh_github_entry_updates_the_row_and_reimports():
    entry = SimpleNamespace(
        id=uuid.uuid4(),
        url="old",
        title="old",
        author="old",
        summary=None,
        content_html="<pre>title: x</pre>",
        content_text="title: x",
        word_count=2,
        content_hash="h",
        published_at=datetime(2026, 11, 1, tzinfo=UTC),
        metadata_={"commit_sha": "a" * 40, "content_type": "splunk_detection", "raw_content": "title: x"},
        language=None,
    )
    feed = SimpleNamespace(id=uuid.uuid4(), feed_type="github_repo", title="splunk", extract_detection_rules=True)
    db = MagicMock()
    db.flush = AsyncMock()
    system_user = uuid.uuid4()
    with (
        patch("app.services.github_rule_import.process_github_entry", new=AsyncMock(return_value={})) as proc,
        patch("app.services.system_user.get_system_user_id", new=AsyncMock(return_value=system_user)),
        patch("app.services.meilisearch_client.index_entry"),
    ):
        await _refresh_github_entry(db, feed, entry, _parsed("b" * 40, body="title: y"))
        proc.assert_awaited_once()
        assert proc.await_args.args[1] is entry
        assert proc.await_args.args[2] == system_user
    assert entry.metadata_["commit_sha"] == "b" * 40
    assert entry.metadata_["raw_content"] == "title: y"
    assert entry.url.endswith("/" + "b" * 40 + "/detections/x.yml")
    assert entry.published_at == datetime(2026, 11, 12, tzinfo=UTC)
    db.flush.assert_awaited()


@pytest.mark.asyncio
async def test_refresh_github_entry_skips_import_when_the_feed_does_not_extract():
    entry = SimpleNamespace(
        id=uuid.uuid4(),
        url="old",
        title="old",
        author="old",
        summary=None,
        content_html="",
        content_text="",
        word_count=0,
        content_hash="h",
        published_at=None,
        metadata_={"commit_sha": "a" * 40, "content_type": "splunk_detection"},
        language=None,
    )
    feed = SimpleNamespace(id=uuid.uuid4(), feed_type="github_repo", title="splunk", extract_detection_rules=False)
    db = MagicMock()
    db.flush = AsyncMock()
    with (
        patch("app.services.github_rule_import.process_github_entry", new=AsyncMock()) as proc,
        patch("app.services.meilisearch_client.index_entry"),
    ):
        await _refresh_github_entry(db, feed, entry, _parsed("b" * 40))
        proc.assert_not_awaited()
    assert entry.metadata_["commit_sha"] == "b" * 40


# --- full sync lists known files whose blob moved on -----------------------------

from app.adapters.github_repo import GitHubRepoAdapter, blob_sha_of  # noqa: E402


def test_blob_sha_matches_git():
    # `printf 'hello\n' | git hash-object --stdin`
    assert blob_sha_of("hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"
    assert blob_sha_of(None) is None


@pytest.mark.asyncio
async def test_full_tree_lists_new_and_changed_files_only():
    adapter = GitHubRepoAdapter()
    tree = [
        {"path": "rules/same.yml", "type": "blob", "sha": blob_sha_of("title: same\n"), "size": 12},
        {"path": "rules/changed.yml", "type": "blob", "sha": blob_sha_of("title: v2\n"), "size": 10},
        {"path": "rules/new.yml", "type": "blob", "sha": blob_sha_of("title: new\n"), "size": 11},
        {"path": "rules/unknown-blob.yml", "type": "blob", "sha": "f" * 40, "size": 5},
    ]
    bodies = {
        "rules/changed.yml": "title: v2\n",
        "rules/new.yml": "title: new\n",
        "rules/unknown-blob.yml": "title: u\n",
    }
    latest = {
        "sha": "c" * 40,
        "commit": {"message": "tighten the regex", "author": {"name": "redsand", "date": "2026-11-13T08:54:04Z"}},
        "author": {"login": "redsand"},
    }
    known_guids = {"o/r/rules/same.yml", "o/r/rules/changed.yml", "o/r/rules/unknown-blob.yml"}
    known_blobs = {
        "o/r/rules/same.yml": blob_sha_of("title: same\n"),
        "o/r/rules/changed.yml": blob_sha_of("title: v1\n"),
        # unknown-blob.yml has no stored text, so nothing to compare against.
    }
    with (
        patch.object(adapter, "_fetch_recursive_tree", new=AsyncMock(return_value=tree)),
        patch.object(adapter, "_get_branch_head_sha", new=AsyncMock(return_value="h" * 40)),
        patch.object(adapter, "_fetch_file_content", new=AsyncMock(side_effect=lambda c, o, r, sha, fp: bodies[fp])),
        patch.object(adapter, "_fetch_latest_commit_for_path", new=AsyncMock(return_value=latest)) as latest_mock,
        patch("app.adapters.github_repo._get_token", return_value=""),
    ):
        _meta, entries = await adapter.fetch_full_tree(
            {"owner": "o", "repo": "r", "branch": "main", "paths": ["rules/**"]},
            existing_guids=known_guids,
            known_blobs=known_blobs,
        )
    by_path = {e.metadata["file_path"]: e for e in entries}
    assert set(by_path) == {"rules/changed.yml", "rules/new.yml", "rules/unknown-blob.yml"}
    changed = by_path["rules/changed.yml"]
    assert changed.metadata["change_type"] == "modified"
    assert changed.metadata["commit_sha"] == "c" * 40
    assert changed.metadata["commit_message"] == "tighten the regex"
    assert changed.author == "redsand"
    assert changed.url.endswith("/" + "c" * 40 + "/rules/changed.yml")
    new = by_path["rules/new.yml"]
    assert new.metadata["change_type"] == "added"
    assert new.metadata["commit_sha"] == "h" * 40
    # One commit lookup per changed known file, none for new files.
    assert latest_mock.await_count == 2


@pytest.mark.asyncio
async def test_full_tree_without_known_blobs_skips_every_known_file():
    adapter = GitHubRepoAdapter()
    tree = [{"path": "rules/a.yml", "type": "blob", "sha": "a" * 40, "size": 3}]
    with (
        patch.object(adapter, "_fetch_recursive_tree", new=AsyncMock(return_value=tree)),
        patch.object(adapter, "_get_branch_head_sha", new=AsyncMock(return_value="h" * 40)),
        patch.object(adapter, "_fetch_file_content", new=AsyncMock(return_value="x")),
        patch("app.adapters.github_repo._get_token", return_value=""),
    ):
        _meta, entries = await adapter.fetch_full_tree(
            {"owner": "o", "repo": "r", "branch": "main", "paths": []}, existing_guids={"o/r/rules/a.yml"}
        )
    assert entries == []
