"""Repo rule re-imports: no per-rule entry join, and derived children ignored.

DetectionRule.entry is lazy="joined". Every rule from one YARA file shares one
entry, whose metadata holds the whole file body, so a joined select sends that
body once per rule. On prod a re-import of Yara-Rules/rules packers/packer.yar
decoded gigabytes of JSON and was OOM-killed; since repo syncs re-import changed
files, the celery worker would hit the same.
"""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from sqlalchemy import event, select
from sqlalchemy.engine import Engine

from app.models.detection_rule import DetectionRule
from app.models.entry import Entry
from app.services.github_rule_import import import_detection_rule

_YARA = "\n\n".join(
    f'rule Packer_{i} {{\n  strings:\n    $a = "packer-{i}-{{version}}"\n  condition:\n    $a\n}}' for i in range(3)
)


def _yara_entry(feed_id, sha: str, body: str) -> Entry:
    return Entry(
        feed_id=feed_id,
        guid="Yara-Rules/rules/packers/packer.yar",
        url=f"https://github.com/Yara-Rules/rules/blob/{sha}/packers/packer.yar",
        title="packer.yar",
        author="Yara-Rules",
        content_text=body,
        published_at=datetime(2026, 11, 1, tzinfo=UTC),
        metadata_={
            "source": "github_repo",
            "owner": "Yara-Rules",
            "repo": "rules",
            "file_path": "packers/packer.yar",
            "commit_sha": sha,
            "commit_message": f"commit {sha[:4]}",
            "change_type": "modified",
            "raw_content": body,
            "content_type": "yara_rule",
            "extracted": {},
        },
    )


@pytest.mark.asyncio
async def test_reimporting_a_yara_file_does_not_join_its_entry_per_rule(db_session, test_user, test_feed):
    entry = _yara_entry(test_feed.id, "a" * 40, _YARA.replace("{version}", "1"))
    db_session.add(entry)
    await db_session.flush()
    with patch("app.services.entity_indexer.bulk_index_entities"):
        first = await import_detection_rule(db_session, entry, test_user.id)
    assert len(first) == 3

    new_body = _YARA.replace("{version}", "2")
    entry.metadata_ = {**entry.metadata_, "commit_sha": "b" * 40, "raw_content": new_body}
    await db_session.flush()

    statements: list[str] = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(Engine, "before_cursor_execute", capture)
    try:
        with patch("app.services.entity_indexer.bulk_index_entities"):
            second = await import_detection_rule(db_session, entry, test_user.id)
    finally:
        event.remove(Engine, "before_cursor_execute", capture)

    assert {r.id for r in second} == {r.id for r in first}
    rule_selects = [s for s in statements if s.lstrip().upper().startswith("SELECT") and "FROM detection_rules" in s]
    assert rule_selects, "the re-import should look its rules up"
    assert not [s for s in rule_selects if "JOIN entries" in s]

    rows = (await db_session.execute(select(DetectionRule).where(DetectionRule.entry_id == entry.id))).scalars().all()
    # Strings read "packer-<i>-<version>": every rule now carries version 2.
    assert all('-2"' in r.rule_content for r in rows)
    assert all(r.metadata_["commit_sha"] == "b" * 40 for r in rows)


def _sigma_entry(feed_id, sha: str, body: str) -> Entry:
    return Entry(
        feed_id=feed_id,
        guid="SigmaHQ/sigma/rules/windows/proc_creation_win_x.yml",
        url=f"https://github.com/SigmaHQ/sigma/blob/{sha}/rules/windows/proc_creation_win_x.yml",
        title="proc_creation_win_x.yml",
        author="SigmaHQ",
        content_text=body,
        published_at=datetime(2026, 11, 1, tzinfo=UTC),
        metadata_={
            "source": "github_repo",
            "owner": "SigmaHQ",
            "repo": "sigma",
            "file_path": "rules/windows/proc_creation_win_x.yml",
            "commit_sha": sha,
            "commit_message": f"commit {sha[:4]}",
            "change_type": "modified",
            "raw_content": body,
            "content_type": "sigma_rule",
            "extracted": {"title": "Suspicious X"},
        },
    )


@pytest.mark.asyncio
async def test_reimport_ignores_a_converted_child_sharing_the_entry(db_session, test_user, test_feed):
    """A conversion copies its parent's entry_id. The importer's entry_id lookup
    used scalar_one_or_none(), so the file's next sync raised MultipleResultsFound
    (prod, 2026-11-19: an Elastic rule with a CrowdStrike conversion)."""
    entry = _sigma_entry(test_feed.id, "a" * 40, "title: Suspicious X\ndetection:\n  sel: {Image: x.exe}\n")
    db_session.add(entry)
    await db_session.flush()
    with patch("app.services.entity_indexer.bulk_index_entities"):
        root = await import_detection_rule(db_session, entry, test_user.id)
    child = DetectionRule(
        entry_id=entry.id,
        created_by=test_user.id,
        rule_type="kql",
        title=f"{root.title} (KQL)",
        rule_content="DeviceProcessEvents | where FileName == 'x.exe'",
        derived_from=root.id,
        metadata_={**root.metadata_, "conversion": {"converted_from": str(root.id)}},
    )
    db_session.add(child)
    await db_session.flush()

    entry.metadata_ = {
        **entry.metadata_,
        "commit_sha": "b" * 40,
        "raw_content": "title: Suspicious X\ndetection:\n  sel: {Image: y.exe}\n",
    }
    await db_session.flush()
    with patch("app.services.entity_indexer.bulk_index_entities"):
        again = await import_detection_rule(db_session, entry, test_user.id)

    assert again.id == root.id
    assert "y.exe" in again.rule_content
    assert again.metadata_["commit_sha"] == "b" * 40
    assert child.rule_content == "DeviceProcessEvents | where FileName == 'x.exe'"
