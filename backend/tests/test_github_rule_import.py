"""Tests for github_rule_import service — Phase 3 of GitHub repo feeds."""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.github_rule_import import (
    _METADATA_ONLY_TYPES,
    _RULE_TYPE_MAP,
    _extract_cve_ids,
    _extract_tactic_names,
    _extract_technique_ids,
    _is_stable_rule,
    _normalize_severity,
    correlate_with_campaigns,
    find_related_intelligence,
    get_detection_coverage,
    get_validation_for_technique,
    import_detection_rule,
    link_entry_cves,
    link_entry_ttps,
    process_github_entry,
    score_rule_relevance,
    tag_metadata_only_entry,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(
    content_type: str = "sigma_rule",
    extracted: dict | None = None,
    raw_content: str = "rule content here",
    owner: str = "SigmaHQ",
    repo: str = "sigma",
    commit_sha: str = "abc1234567890",
) -> MagicMock:
    """Create a mock Entry with github_repo metadata."""
    entry = MagicMock()
    entry.id = uuid.uuid4()
    entry.title = "Test Rule"
    entry.published_at = datetime.now(UTC)
    entry.feed = MagicMock()
    entry.feed.title = "SigmaHQ/sigma"
    entry.metadata_ = {
        "source": "github_repo",
        "owner": owner,
        "repo": repo,
        "file_path": "rules/test.yml",
        "commit_sha": commit_sha,
        "commit_message": "Add test rule",
        "change_type": "added",
        "raw_content": raw_content,
        "content_type": content_type,
        "extracted": extracted or {},
    }
    return entry


def _make_sigma_entry(**overrides) -> MagicMock:
    """Create a mock Entry with typical Sigma metadata."""
    extracted = {
        "rule_title": "Suspicious PowerShell Execution",
        "rule_description": "Detects suspicious PS execution",
        "rule_status": "stable",
        "rule_level": "high",
        "rule_author": "Florian Roth",
        "mitre_attack_ids": ["T1059.001", "T1027"],
        "mitre_tactics": ["execution", "defense-evasion"],
        "log_source": {"category": "process_creation", "product": "windows"},
        "false_positives": ["Admin scripts"],
    }
    extracted.update(overrides.pop("extracted_overrides", {}))
    return _make_entry(content_type="sigma_rule", extracted=extracted, **overrides)


def _make_elastic_entry(**overrides) -> MagicMock:
    extracted = {
        "rule_name": "Credential Dumping via LSASS",
        "rule_description": "Detects LSASS access",
        "rule_severity": "high",
        "rule_risk_score": 73,
        "rule_type": "eql",
        "rule_query": 'process where process.name == "mimikatz.exe"',
        "mitre_attack_ids": ["T1003.001"],
        "mitre_tactics": [],
    }
    return _make_entry(content_type="elastic_rule", extracted=extracted, **overrides)


def _make_nuclei_entry(**overrides) -> MagicMock:
    extracted = {
        "template_name": "CVE-2023-1234 RCE",
        "template_description": "Remote code execution",
        "template_severity": "critical",
        "template_author": "pd-team",
        "cve_ids": ["CVE-2023-1234", "CVE-2023-5678"],
        "mitre_attack_ids": [],
        "mitre_tactics": [],
    }
    return _make_entry(
        content_type="yara_rule",  # nuclei maps through extension
        extracted=extracted,
        owner="projectdiscovery",
        repo="nuclei-templates",
        **overrides,
    )


def _make_lolbas_entry(**overrides) -> MagicMock:
    extracted = {
        "binary_name": "certutil.exe",
        "mitre_attack_ids": ["T1105", "T1140"],
        "mitre_tactics": ["command-and-control", "defense-evasion"],
        "abuse_functions": ["Download", "Decode"],
    }
    return _make_entry(content_type="lolbas_entry", extracted=extracted, **overrides)


def _make_atomic_entry(**overrides) -> MagicMock:
    extracted = {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "atomic_tests": [
            {"name": "Mimikatz Download", "executor_type": "powershell"},
        ],
        "supported_platforms": ["windows"],
        "mitre_attack_ids": ["T1059.001"],
        "mitre_tactics": ["execution"],
    }
    return _make_entry(content_type="atomic_test", extracted=extracted, **overrides)


# ---------------------------------------------------------------------------
# Mock database helpers
# ---------------------------------------------------------------------------


class MockScalarResult:
    """Mock for db.execute().scalar_one_or_none()."""

    def __init__(self, value=None):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def scalars(self):
        return self

    def all(self):
        if self._value is None:
            return []
        if isinstance(self._value, list):
            return self._value
        return [self._value]


class MockRowResult:
    """Mock for db.execute() returning rows with attributes."""

    def __init__(self, rows=None):
        self._rows = rows or []

    def all(self):
        return self._rows

    def scalars(self):
        return self

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


def _make_db():
    """Create a mock AsyncSession."""
    db = AsyncMock()
    # Default: no existing records found
    db.execute.return_value = MockScalarResult(None)
    db.flush = AsyncMock()
    db.add = MagicMock()
    return db


# ---------------------------------------------------------------------------
# Unit tests: helper functions
# ---------------------------------------------------------------------------


class TestNormalizeSeverity:
    def test_sigma_levels(self):
        assert _normalize_severity("informational") == "info"
        assert _normalize_severity("low") == "low"
        assert _normalize_severity("medium") == "medium"
        assert _normalize_severity("high") == "high"
        assert _normalize_severity("critical") == "critical"

    def test_case_insensitive(self):
        assert _normalize_severity("HIGH") == "high"
        assert _normalize_severity("Critical") == "critical"

    def test_empty_defaults_to_medium(self):
        assert _normalize_severity("") == "medium"
        assert _normalize_severity(None) == "medium"

    def test_unknown_passes_through(self):
        assert _normalize_severity("urgent") == "urgent"


class TestIsStableRule:
    def test_sigma_stable(self):
        assert _is_stable_rule({"rule_status": "stable"}, "sigma_rule") is True

    def test_sigma_test(self):
        assert _is_stable_rule({"rule_status": "test"}, "sigma_rule") is True

    def test_sigma_experimental(self):
        assert _is_stable_rule({"rule_status": "experimental"}, "sigma_rule") is False

    def test_elastic_always_stable(self):
        assert _is_stable_rule({}, "elastic_rule") is True

    def test_splunk_hunting_is_draft(self):
        assert _is_stable_rule({"rule_type": "Hunting"}, "splunk_detection") is False

    def test_splunk_detection_is_stable(self):
        assert _is_stable_rule({"rule_type": "TTP"}, "splunk_detection") is True


class TestExtractTechniqueIds:
    def test_extracts_technique_ids(self):
        meta = {"mitre_attack_ids": ["T1059.001", "T1027", "execution"]}
        assert _extract_technique_ids(meta) == ["T1059.001", "T1027"]

    def test_empty_meta(self):
        assert _extract_technique_ids({}) == []

    def test_no_techniques(self):
        meta = {"mitre_attack_ids": ["execution", "defense-evasion"]}
        assert _extract_technique_ids(meta) == []


class TestExtractTacticNames:
    def test_extracts_tactics(self):
        meta = {"mitre_tactics": ["execution", "defense-evasion"]}
        assert _extract_tactic_names(meta) == ["execution", "defense-evasion"]

    def test_empty(self):
        assert _extract_tactic_names({}) == []


class TestExtractCveIds:
    def test_extracts_cves(self):
        meta = {"cve_ids": ["CVE-2023-1234", "CVE-2023-5678"]}
        assert _extract_cve_ids(meta) == ["CVE-2023-1234", "CVE-2023-5678"]

    def test_empty(self):
        assert _extract_cve_ids({}) == []


class TestRuleTypeMap:
    def test_all_expected_types(self):
        assert _RULE_TYPE_MAP["sigma_rule"] == "sigma"
        assert _RULE_TYPE_MAP["elastic_rule"] == "elastic_ql"
        assert _RULE_TYPE_MAP["splunk_detection"] == "splunk_spl"
        assert _RULE_TYPE_MAP["sentinel_rule"] == "kql"
        assert _RULE_TYPE_MAP["yara_rule"] == "yara"

    def test_metadata_only_types_not_in_rule_map(self):
        for ct in _METADATA_ONLY_TYPES:
            assert ct not in _RULE_TYPE_MAP


# ---------------------------------------------------------------------------
# Unit tests: import_detection_rule
# ---------------------------------------------------------------------------


class TestImportDetectionRule:
    @pytest.mark.asyncio
    async def test_creates_sigma_rule(self):
        db = _make_db()
        entry = _make_sigma_entry()
        user_id = uuid.uuid4()

        rule = await import_detection_rule(db, entry, user_id)

        assert rule is not None
        # Verify db.add was called with a DetectionRule
        db.add.assert_called()
        added = db.add.call_args[0][0]
        assert added.rule_type == "sigma"
        assert added.title == "Suspicious PowerShell Execution"
        assert added.severity == "high"
        assert added.source_ttps == ["T1059.001", "T1027"]
        assert added.mitre_tactics == ["execution", "defense-evasion"]
        assert added.is_draft is False  # stable status
        assert "SigmaHQ/sigma" in added.tags
        assert added.entry_id == entry.id
        assert added.created_by == user_id

    @pytest.mark.asyncio
    async def test_creates_elastic_rule(self):
        db = _make_db()
        entry = _make_elastic_entry()
        user_id = uuid.uuid4()

        rule = await import_detection_rule(db, entry, user_id)

        assert rule is not None
        added = db.add.call_args[0][0]
        assert added.rule_type == "elastic_ql"
        assert added.title == "Credential Dumping via LSASS"

    @pytest.mark.asyncio
    async def test_skips_non_rule_content_type(self):
        db = _make_db()
        entry = _make_entry(content_type="lolbas_entry")
        rule = await import_detection_rule(db, entry, uuid.uuid4())
        assert rule is None
        db.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_unknown_content_type(self):
        db = _make_db()
        entry = _make_entry(content_type="markdown")
        rule = await import_detection_rule(db, entry, uuid.uuid4())
        assert rule is None

    @pytest.mark.asyncio
    async def test_updates_existing_rule(self):
        db = _make_db()
        entry = _make_sigma_entry()
        user_id = uuid.uuid4()

        # Simulate existing rule. metadata_ must be a real dict: the importer
        # merges commit history into it and sorts by date, which a bare
        # MagicMock attribute cannot support.
        existing_rule = MagicMock()
        existing_rule.id = uuid.uuid4()
        existing_rule.metadata_ = {}
        db.execute.return_value = MockScalarResult(existing_rule)

        rule = await import_detection_rule(db, entry, user_id)

        # Should update existing, not add new
        assert rule is existing_rule
        assert existing_rule.title == "Suspicious PowerShell Execution"
        assert existing_rule.rule_type == "sigma"
        assert existing_rule.severity == "high"
        # db.add should NOT be called for updates
        db.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_experimental_sigma_is_draft(self):
        db = _make_db()
        entry = _make_sigma_entry(extracted_overrides={"rule_status": "experimental"})
        await import_detection_rule(db, entry, uuid.uuid4())
        added = db.add.call_args[0][0]
        assert added.is_draft is True

    @pytest.mark.asyncio
    async def test_notes_include_repo_and_commit(self):
        db = _make_db()
        entry = _make_sigma_entry(owner="SigmaHQ", repo="sigma", commit_sha="deadbeef12345678")
        await import_detection_rule(db, entry, uuid.uuid4())
        added = db.add.call_args[0][0]
        assert "SigmaHQ/sigma" in added.notes
        assert "deadbeef" in added.notes

    @pytest.mark.asyncio
    async def test_log_sources_from_sigma(self):
        db = _make_db()
        entry = _make_sigma_entry()
        await import_detection_rule(db, entry, uuid.uuid4())
        added = db.add.call_args[0][0]
        assert added.log_sources == {"category": "process_creation", "product": "windows"}

    @pytest.mark.asyncio
    async def test_author_in_tags(self):
        db = _make_db()
        entry = _make_sigma_entry()
        await import_detection_rule(db, entry, uuid.uuid4())
        added = db.add.call_args[0][0]
        assert "author:Florian Roth" in added.tags


# ---------------------------------------------------------------------------
# Unit tests: link_entry_ttps
# ---------------------------------------------------------------------------


class TestLinkEntryTtps:
    @pytest.mark.asyncio
    async def test_creates_new_ttp_and_link(self):
        """When no existing TTP, creates new TTP and EntryTTP link."""
        db = _make_db()
        entry_id = uuid.uuid4()
        added_objects = []
        db.add = lambda obj: added_objects.append(obj)

        # All lookups return None (no existing TTP, no existing link)
        db.execute.return_value = MockScalarResult(None)

        ttps = await link_entry_ttps(db, entry_id, ["T1059.001"], ["execution"])

        assert len(ttps) == 1
        # Should have added a TTP and an EntryTTP
        assert len(added_objects) == 2

    @pytest.mark.asyncio
    async def test_updates_existing_ttp(self):
        """When TTP already exists, updates article_count and last_seen_at."""
        db = _make_db()
        entry_id = uuid.uuid4()

        existing_ttp = MagicMock()
        existing_ttp.id = uuid.uuid4()
        existing_ttp.technique_id = "T1059.001"
        existing_ttp.last_seen_at = datetime(2024, 1, 1, tzinfo=UTC)
        existing_ttp.article_count = 3
        existing_ttp.first_seen_at = datetime(2024, 1, 1, tzinfo=UTC)

        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            # First call: TTP lookup (exists), second: EntryTTP lookup (not exists)
            if call_count == 1:
                return MockScalarResult(existing_ttp)
            return MockScalarResult(None)

        db.execute = mock_execute
        added_objects = []
        db.add = lambda obj: added_objects.append(obj)

        ttps = await link_entry_ttps(db, entry_id, ["T1059.001"], ["execution"])

        assert len(ttps) == 1
        assert existing_ttp.article_count == 4
        # Should only add EntryTTP, not a new TTP
        assert len(added_objects) == 1

    @pytest.mark.asyncio
    async def test_empty_technique_ids(self):
        db = _make_db()
        ttps = await link_entry_ttps(db, uuid.uuid4(), [], [])
        assert ttps == []

    @pytest.mark.asyncio
    async def test_skips_blank_ids(self):
        db = _make_db()
        ttps = await link_entry_ttps(db, uuid.uuid4(), ["", "  "], [])
        assert ttps == []

    @pytest.mark.asyncio
    async def test_high_confidence_for_rule_sourced_ttps(self):
        """TTPs from detection rules should have high confidence."""
        db = _make_db()
        entry_id = uuid.uuid4()
        added_objects = []
        db.add = lambda obj: added_objects.append(obj)
        db.execute.return_value = MockScalarResult(None)

        await link_entry_ttps(db, entry_id, ["T1059.001"])

        # Find the EntryTTP object
        entry_ttp = [o for o in added_objects if hasattr(o, "confidence")]
        assert len(entry_ttp) == 1
        assert entry_ttp[0].confidence == "high"


# ---------------------------------------------------------------------------
# Unit tests: link_entry_cves
# ---------------------------------------------------------------------------


class TestLinkEntryCves:
    @pytest.mark.asyncio
    async def test_empty_cve_ids(self):
        db = _make_db()
        cves = await link_entry_cves(db, uuid.uuid4(), [])
        assert cves == []

    @pytest.mark.asyncio
    async def test_skips_blank_ids(self):
        db = _make_db()
        cves = await link_entry_cves(db, uuid.uuid4(), ["", "  "])
        assert cves == []

    @pytest.mark.asyncio
    async def test_creates_new_cve_and_link(self):
        db = _make_db()
        entry_id = uuid.uuid4()
        added_objects = []
        db.add = lambda obj: added_objects.append(obj)
        db.execute.return_value = MockScalarResult(None)

        cves = await link_entry_cves(db, entry_id, ["CVE-2023-1234"])

        assert len(cves) == 1
        # Should have added a CVE and an EntryCVE
        assert len(added_objects) == 2

    @pytest.mark.asyncio
    async def test_updates_existing_cve(self):
        db = _make_db()
        entry_id = uuid.uuid4()

        existing_cve = MagicMock()
        existing_cve.id = uuid.uuid4()
        existing_cve.cve_id = "CVE-2023-1234"
        existing_cve.updated_at = datetime(2024, 1, 1, tzinfo=UTC)
        existing_cve.first_seen_at = datetime(2024, 1, 1, tzinfo=UTC)

        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return MockScalarResult(existing_cve)
            return MockScalarResult(None)

        db.execute = mock_execute
        added_objects = []
        db.add = lambda obj: added_objects.append(obj)

        cves = await link_entry_cves(db, entry_id, ["CVE-2023-1234"])

        assert len(cves) == 1
        # Should only add EntryCVE, not a new CVE
        assert len(added_objects) == 1


# ---------------------------------------------------------------------------
# Unit tests: tag_metadata_only_entry
# ---------------------------------------------------------------------------


class TestTagMetadataOnlyEntry:
    def test_lolbas_tagged_as_detection_opportunity(self):
        entry = _make_lolbas_entry()
        result = tag_metadata_only_entry(entry)
        assert "detection_opportunity" in result["import_tags"]
        assert result["technique_ids"] == ["T1105", "T1140"]

    def test_atomic_tagged_as_validation(self):
        entry = _make_atomic_entry()
        result = tag_metadata_only_entry(entry)
        assert "validation_available" in result["import_tags"]
        assert result["technique_ids"] == ["T1059.001"]

    def test_loobin_tagged(self):
        entry = _make_entry(
            content_type="loobin_entry",
            extracted={
                "mitre_attack_ids": ["T1059.004"],
                "mitre_tactics": ["execution"],
            },
        )
        result = tag_metadata_only_entry(entry)
        assert "detection_opportunity" in result["import_tags"]

    def test_loldriver_tagged(self):
        entry = _make_entry(
            content_type="loldriver_entry",
            extracted={
                "mitre_attack_ids": [],
                "mitre_tactics": [],
            },
        )
        result = tag_metadata_only_entry(entry)
        assert "detection_opportunity" in result["import_tags"]


# ---------------------------------------------------------------------------
# Unit tests: process_github_entry (orchestrator)
# ---------------------------------------------------------------------------


class TestProcessGithubEntry:
    @pytest.mark.asyncio
    async def test_sigma_entry_full_pipeline(self):
        db = _make_db()
        entry = _make_sigma_entry()
        user_id = uuid.uuid4()

        # Mock the sub-functions to avoid deep DB interactions
        with (
            patch("app.services.github_rule_import.import_detection_rule") as mock_import,
            patch("app.services.github_rule_import.link_entry_ttps") as mock_ttps,
            patch("app.services.github_rule_import.find_related_intelligence") as mock_related,
        ):
            mock_rule = MagicMock()
            mock_rule.id = uuid.uuid4()
            mock_rule.rule_type = "sigma"
            mock_import.return_value = mock_rule
            mock_ttps.return_value = [MagicMock(), MagicMock()]
            mock_related.return_value = []

            result = await process_github_entry(db, entry, user_id)

        assert result["status"] == "processed"
        assert result["content_type"] == "sigma_rule"
        assert result["rule_type"] == "sigma"
        assert result["ttps_linked"] == 2
        mock_import.assert_called_once()
        mock_ttps.assert_called_once()

    @pytest.mark.asyncio
    async def test_lolbas_entry_no_rule_created(self):
        db = _make_db()
        entry = _make_lolbas_entry()
        user_id = uuid.uuid4()

        with (
            patch("app.services.github_rule_import.import_detection_rule") as mock_import,
            patch("app.services.github_rule_import.link_entry_ttps") as mock_ttps,
            patch("app.services.github_rule_import.find_related_intelligence") as mock_related,
        ):
            mock_ttps.return_value = [MagicMock(), MagicMock()]
            mock_related.return_value = []

            result = await process_github_entry(db, entry, user_id)

        assert result["status"] == "processed"
        assert "detection_opportunity" in result["import_tags"]
        # import_detection_rule should NOT be called for LOLBAS
        mock_import.assert_not_called()
        # But TTPs should still be linked
        mock_ttps.assert_called_once()

    @pytest.mark.asyncio
    async def test_atomic_entry_links_ttps(self):
        db = _make_db()
        entry = _make_atomic_entry()
        user_id = uuid.uuid4()

        with (
            patch("app.services.github_rule_import.import_detection_rule") as mock_import,
            patch("app.services.github_rule_import.link_entry_ttps") as mock_ttps,
            patch("app.services.github_rule_import.find_related_intelligence") as mock_related,
        ):
            mock_ttps.return_value = [MagicMock()]
            mock_related.return_value = []

            result = await process_github_entry(db, entry, user_id)

        assert result["status"] == "processed"
        assert "validation_available" in result["import_tags"]
        mock_import.assert_not_called()
        mock_ttps.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_content_type_skipped(self):
        db = _make_db()
        entry = _make_entry(content_type="")
        result = await process_github_entry(db, entry, uuid.uuid4())
        assert result["status"] == "skipped"

    @pytest.mark.asyncio
    async def test_cross_references_stored_in_metadata(self):
        db = _make_db()
        entry = _make_sigma_entry()
        user_id = uuid.uuid4()

        related = [
            {
                "entry_id": str(uuid.uuid4()),
                "title": "APT29 Report",
                "feed_title": "Mandiant Blog",
                "shared_ttps": ["T1059.001"],
                "published_at": datetime.now(UTC).isoformat(),
            }
        ]

        with (
            patch("app.services.github_rule_import.import_detection_rule") as mock_import,
            patch("app.services.github_rule_import.link_entry_ttps") as mock_ttps,
            patch("app.services.github_rule_import.find_related_intelligence") as mock_related,
        ):
            mock_import.return_value = MagicMock(id=uuid.uuid4(), rule_type="sigma")
            mock_ttps.return_value = [MagicMock()]
            mock_related.return_value = related

            result = await process_github_entry(db, entry, user_id)

        assert result["related_intelligence_count"] == 1
        assert "related_intelligence" in entry.metadata_

    @pytest.mark.asyncio
    async def test_nuclei_links_cves(self):
        db = _make_db()
        entry = _make_entry(
            content_type="yara_rule",
            extracted={
                "template_name": "CVE-2023-1234",
                "cve_ids": ["CVE-2023-1234"],
                "mitre_attack_ids": [],
                "mitre_tactics": [],
            },
        )
        user_id = uuid.uuid4()

        with (
            patch("app.services.github_rule_import.import_detection_rule") as mock_import,
            patch("app.services.github_rule_import.link_entry_cves") as mock_cves,
            patch("app.services.github_rule_import.find_related_intelligence") as mock_related,
        ):
            mock_import.return_value = MagicMock(id=uuid.uuid4(), rule_type="yara")
            mock_cves.return_value = [MagicMock()]
            mock_related.return_value = []

            result = await process_github_entry(db, entry, user_id)

        assert result["cves_linked"] == 1
        mock_cves.assert_called_once()


# ---------------------------------------------------------------------------
# Unit tests: find_related_intelligence
# ---------------------------------------------------------------------------


class TestFindRelatedIntelligence:
    @pytest.mark.asyncio
    async def test_empty_technique_ids(self):
        db = _make_db()
        result = await find_related_intelligence(db, uuid.uuid4(), [])
        assert result == []

    @pytest.mark.asyncio
    async def test_no_matching_ttps(self):
        db = _make_db()
        db.execute.return_value = MockRowResult([])
        result = await find_related_intelligence(db, uuid.uuid4(), ["T9999"])
        assert result == []


# ---------------------------------------------------------------------------
# Unit tests: get_detection_coverage
# ---------------------------------------------------------------------------


class TestGetDetectionCoverage:
    @pytest.mark.asyncio
    async def test_empty_database(self):
        db = _make_db()
        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            return MockRowResult([])

        db.execute = mock_execute
        result = await get_detection_coverage(db, uuid.uuid4())

        assert result["total_ttps_in_intelligence"] == 0
        assert result["coverage_percentage"] == 0.0
        assert result["coverage_gaps"] == []

    @pytest.mark.asyncio
    async def test_coverage_calculation(self):
        db = _make_db()

        class TTPRow:
            def __init__(self, tid, name, count):
                self.technique_id = tid
                self.technique_name = name
                self.article_count = count

        class RuleRow:
            def __init__(self, ttps, title, rtype):
                self.source_ttps = ttps
                self.title = title
                self.rule_type = rtype

        intel_ttps = [
            TTPRow("T1059.001", "PowerShell", 5),
            TTPRow("T1027", "Obfuscation", 3),
            TTPRow("T1003.001", "LSASS", 2),
        ]
        rules = [
            RuleRow(["T1059.001"], "PS Detection", "sigma"),
        ]

        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return MockRowResult(intel_ttps)
            return MockRowResult(rules)

        db.execute = mock_execute
        result = await get_detection_coverage(db, uuid.uuid4())

        assert result["total_ttps_in_intelligence"] == 3
        assert result["ttps_with_detection"] == 1
        assert result["ttps_without_detection"] == 2
        assert result["coverage_percentage"] == pytest.approx(33.3, abs=0.1)
        # Gaps should be sorted by article_count desc
        assert len(result["coverage_gaps"]) == 2
        assert result["coverage_gaps"][0]["technique_id"] == "T1027"


# ---------------------------------------------------------------------------
# Unit tests: get_validation_for_technique
# ---------------------------------------------------------------------------


class TestGetValidationForTechnique:
    @pytest.mark.asyncio
    async def test_no_matching_entries(self):
        db = _make_db()
        db.execute.return_value = MockRowResult([])
        result = await get_validation_for_technique(db, "T1059.001")
        assert result == []


# ---------------------------------------------------------------------------
# Mapping completeness tests
# ---------------------------------------------------------------------------


class TestMappingCompleteness:
    def test_all_rule_types_produce_valid_detection_rule_type(self):
        """Every import mapping must land on a rule_type the API will accept.

        The accepted set is derived from RULE_TYPE_PATTERN rather than repeated
        here, so adding a format in one place cannot silently break the other.
        """
        import re

        from app.schemas.intelligence import RULE_TYPE_PATTERN

        valid_types = set(re.fullmatch(r"\^\((.+)\)\$", RULE_TYPE_PATTERN).group(1).split("|"))
        assert "sigma" in valid_types  # guard against the pattern shape changing

        for content_type, rule_type in _RULE_TYPE_MAP.items():
            assert rule_type in valid_types, f"{content_type} maps to invalid {rule_type}"

    def test_metadata_only_types_are_complete(self):
        expected = {"lolbas_entry", "loobin_entry", "loldriver_entry", "atomic_test"}
        assert _METADATA_ONLY_TYPES == expected


# ---------------------------------------------------------------------------
# Phase 6: Intelligence scoring
# ---------------------------------------------------------------------------


class TestScoreRuleRelevance:
    @pytest.mark.asyncio
    async def test_empty_entry_gets_base_score(self):
        """An entry with no techniques and unknown repo gets a low score."""
        db = _make_db()
        entry = _make_entry(
            content_type="sigma_rule",
            extracted={"mitre_attack_ids": [], "mitre_tactics": []},
            owner="unknown",
        )
        db.execute.return_value = MockRowResult([])

        score = await score_rule_relevance(db, entry, uuid.uuid4())
        assert score == 0

    @pytest.mark.asyncio
    async def test_authority_bonus_sigmahq(self):
        """SigmaHQ stable rules should get authority bonus."""
        db = _make_db()
        entry = _make_entry(
            content_type="sigma_rule",
            extracted={
                "mitre_attack_ids": [],
                "mitre_tactics": [],
                "rule_status": "stable",
            },
            owner="SigmaHQ",
        )
        db.execute.return_value = MockRowResult([])

        score = await score_rule_relevance(db, entry, uuid.uuid4())
        # 10 (authority repo) + 5 (stable rule) = 15
        assert score == 15

    @pytest.mark.asyncio
    async def test_breadth_bonus_multiple_techniques(self):
        """Rules covering multiple techniques should score higher."""
        db = _make_db()
        entry = _make_entry(
            content_type="sigma_rule",
            extracted={
                "mitre_attack_ids": ["T1059.001", "T1027", "T1003.001"],
                "mitre_tactics": ["execution"],
                "rule_status": "stable",
            },
            owner="SigmaHQ",
        )
        # All db queries return empty (no recent TTP activity, no existing coverage)
        db.execute.return_value = MockRowResult([])

        score = await score_rule_relevance(db, entry, uuid.uuid4())
        # 10 (authority) + 5 (stable) + 20 (3 techniques breadth) = 35
        # Coverage gap: all 3 are uncovered → min(3*12, 35) = 35
        # Total could be up to 70 depending on coverage query
        assert score >= 35

    @pytest.mark.asyncio
    async def test_single_technique(self):
        """Rule with a single technique gets breadth=5."""
        db = _make_db()
        entry = _make_entry(
            content_type="yara_rule",
            extracted={
                "mitre_attack_ids": ["T1059.001"],
                "mitre_tactics": [],
            },
            owner="Neo23x0",
        )
        db.execute.return_value = MockRowResult([])

        score = await score_rule_relevance(db, entry, uuid.uuid4())
        # 5 (one technique) + some coverage gap
        assert score >= 5

    @pytest.mark.asyncio
    async def test_score_capped_at_100(self):
        """Score should never exceed 100."""
        db = _make_db()
        entry = _make_entry(
            content_type="sigma_rule",
            extracted={
                "mitre_attack_ids": [f"T10{i:02d}" for i in range(10)],
                "mitre_tactics": ["execution"],
                "rule_status": "stable",
            },
            owner="SigmaHQ",
        )

        class FakeRecentRow:
            def __init__(self, tid):
                self._data = (tid,)

            def __getitem__(self, i):
                return self._data[i]

        call_count = 0

        async def mock_execute(stmt):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Recent TTPs — return all techniques as recent
                return MockRowResult([FakeRecentRow(f"T10{i:02d}") for i in range(10)])
            return MockRowResult([])

        db.execute = mock_execute
        score = await score_rule_relevance(db, entry, uuid.uuid4())
        assert score <= 100

    @pytest.mark.asyncio
    async def test_elastic_authority(self):
        """Elastic detection rules get authority bonus."""
        db = _make_db()
        entry = _make_entry(
            content_type="elastic_rule",
            extracted={"mitre_attack_ids": [], "mitre_tactics": []},
            owner="elastic",
        )
        db.execute.return_value = MockRowResult([])

        score = await score_rule_relevance(db, entry, uuid.uuid4())
        # 10 (authority) + 5 (elastic_rule bonus) = 15
        assert score == 15


# ---------------------------------------------------------------------------
# Phase 6: Campaign correlation
# ---------------------------------------------------------------------------


class TestCorrelateWithCampaigns:
    @pytest.mark.asyncio
    async def test_empty_technique_ids(self):
        db = _make_db()
        result = await correlate_with_campaigns(db, uuid.uuid4(), [])
        assert result == []

    @pytest.mark.asyncio
    async def test_no_matching_ttps(self):
        db = _make_db()
        db.execute.return_value = MockRowResult([])
        result = await correlate_with_campaigns(db, uuid.uuid4(), ["T9999"])
        assert result == []


# ---------------------------------------------------------------------------
# Phase 6: process_github_entry integration (scoring + campaigns)
# ---------------------------------------------------------------------------


class TestProcessGithubEntryPhase6:
    @pytest.mark.asyncio
    async def test_relevance_score_stored_in_metadata(self):
        db = _make_db()
        entry = _make_sigma_entry()
        user_id = uuid.uuid4()

        with (
            patch("app.services.github_rule_import.import_detection_rule") as mock_import,
            patch("app.services.github_rule_import.link_entry_ttps") as mock_ttps,
            patch("app.services.github_rule_import.find_related_intelligence") as mock_related,
            patch("app.services.github_rule_import.score_rule_relevance") as mock_score,
            patch("app.services.github_rule_import.correlate_with_campaigns") as mock_campaigns,
        ):
            mock_import.return_value = MagicMock(id=uuid.uuid4(), rule_type="sigma")
            mock_ttps.return_value = [MagicMock()]
            mock_related.return_value = []
            mock_score.return_value = 75
            mock_campaigns.return_value = []

            result = await process_github_entry(db, entry, user_id)

        assert result["relevance_score"] == 75
        assert entry.metadata_["relevance_score"] == 75

    @pytest.mark.asyncio
    async def test_campaign_matches_stored_in_metadata(self):
        db = _make_db()
        entry = _make_sigma_entry()
        user_id = uuid.uuid4()

        campaign_match = {
            "campaign_id": str(uuid.uuid4()),
            "campaign_name": "Volt Typhoon Activity",
            "status": "active",
            "shared_ttps": ["T1059.001"],
        }

        with (
            patch("app.services.github_rule_import.import_detection_rule") as mock_import,
            patch("app.services.github_rule_import.link_entry_ttps") as mock_ttps,
            patch("app.services.github_rule_import.find_related_intelligence") as mock_related,
            patch("app.services.github_rule_import.score_rule_relevance") as mock_score,
            patch("app.services.github_rule_import.correlate_with_campaigns") as mock_campaigns,
        ):
            mock_import.return_value = MagicMock(id=uuid.uuid4(), rule_type="sigma")
            mock_ttps.return_value = [MagicMock()]
            mock_related.return_value = []
            mock_score.return_value = 80
            mock_campaigns.return_value = [campaign_match]

            result = await process_github_entry(db, entry, user_id)

        assert result["campaign_matches"] == 1
        assert entry.metadata_["campaign_matches"][0]["campaign_name"] == "Volt Typhoon Activity"
