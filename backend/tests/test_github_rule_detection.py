"""GitHub repo files typed by extension and content, not only by per-repo pattern.

Covers .kql files, generic YAML/TOML recognised as a supported rule format,
and the LOLDrivers org move.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.adapters.github_content_types import derive_title, detect_content_type, extract_metadata
from app.models.detection_rule import DetectionRule
from app.services.github_rule_import import import_detection_rule, process_github_entry, rule_type_for

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

KQL_FILE = """// Azure VM Password Reset Detection
// https://example.com/post-about-it
// Maps to T1098 and T1078.004

AzureActivity
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/extensions/write"
| summarize count() by Caller
"""

SIGMA_YAML = """title: Suspicious Certutil Download
id: 0c4d1d7e-0000-4000-8000-000000000001
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\certutil.exe'
    CommandLine|contains: 'urlcache'
  condition: selection
tags:
  - attack.t1105
  - attack.command_and_control
level: high
"""

SIGMA_NO_STATUS = SIGMA_YAML.replace("status: experimental\n", "")

SIGMA_NO_CONDITION = """title: Broken
logsource:
  product: windows
detection:
  selection:
    Image: x
"""

SENTINEL_SCHEDULED = """id: 86e9ba6f-d1ed-48b8-a849-c26f77db8c1b
name: Entra Connect account outside watchlist
kind: Scheduled
severity: Medium
queryFrequency: 1h
queryPeriod: 14d
tactics:
  - Persistence
relevantTechniques:
  - T1098
query: |
  IdentityInfo
  | where TimeGenerated > ago(14d)
  | summarize arg_max(TimeGenerated, *) by AccountObjectId
"""

SENTINEL_FREQUENCY_ONLY = SENTINEL_SCHEDULED.replace("kind: Scheduled\n", "")

SENTINEL_BAD_QUERY = SENTINEL_SCHEDULED.replace("by AccountObjectId", "by (AccountObjectId")

SPLUNK_DETECTION = """name: Suspicious Rundll32 StartW
id: 9319dda5-73f2-4d43-a85a-67ce961bddb7
type: TTP
data_source:
  - Sysmon EventID 1
search: '| tstats count from datamodel=Endpoint.Processes where Processes.process_name=rundll32.exe by Processes.dest'
mitre_attack_id:
  - T1218.011
tags:
  analytic_story:
    - Cobalt Strike
"""

ANVILOGIC_SPLUNK = """id: '12916.18554'
title: WMIC Explicit Credentials
description: 'Threat actors test credentials with WMI.'
logic_format: Splunk
logic: ' `get_endpoint_data` (("wmic" OR "wmic.exe") "/password") | stats values(*) as * by host'
techniques:
- persistence:valid accounts
- privilege-escalation:valid accounts
technique_id:
- T1078
- T1047
data_category:
- EDR Logs
references:
- https://thedfirreport.com/2022/04/25/quantum-ransomware/
"""

ANVILOGIC_SNOWFLAKE = ANVILOGIC_SPLUNK.replace("logic_format: Splunk", "logic_format: snowflake")

ELASTIC_TOML = """[metadata]
creation_date = "2024/01/01"

[rule]
name = "LSASS Access"
type = "eql"
language = "eql"
query = '''
process where process.name == "procdump.exe"
'''
"""

LOLDRIVER_YAML = """Id: a2a53148-ff02-4d63-9269-e47966431c62
Tags:
- heysafe_drv.sys
Verified: 'TRUE'
MitreID: T1068
Category: vulnerable driver
CVE:
- CVE-2023-52271
- ''
Commands:
  Command: sc.exe create heysafe binPath=C:\\heysafe_drv.sys type=kernel
  Description: A vulnerable minifilter that terminates arbitrary processes.
"""

PLAIN_YAML = "name: config\nversion: 2\nsettings:\n  debug: true\n"


# ---------------------------------------------------------------------------
# Content-type detection
# ---------------------------------------------------------------------------


class TestKqlFiles:
    def test_kql_extension_maps_to_kql_query(self):
        assert detect_content_type("SlimKQL", "Hunting-Queries-Detection-Rules", "Azure/VM Reset.kql") == "kql_query"

    def test_kql_metadata_title_refs_and_techniques(self):
        meta = extract_metadata(KQL_FILE, "kql_query")
        assert meta["rule_name"] == "Azure VM Password Reset Detection"
        assert meta["references"] == ["https://example.com/post-about-it"]
        assert meta["mitre_attack_ids"] == ["T1098", "T1078.004"]
        assert meta["rule_query"] == KQL_FILE

    def test_kql_title(self):
        assert derive_title("Azure/VM Reset.kql", KQL_FILE, "kql_query") == "Azure VM Password Reset Detection"
        assert derive_title("x/Plain.kql", "SigninLogs | take 10", "kql_query") == "Plain.kql"

    def test_kql_rule_type(self):
        assert rule_type_for("kql_query", {}) == "kql"


class TestGenericYamlRecognition:
    def test_sigma_outside_listed_repos(self):
        assert detect_content_type("someone", "rules", "sigma/certutil.yml", SIGMA_YAML) == "sigma_rule"

    def test_sigma_without_status_still_sigma(self):
        assert detect_content_type("someone", "rules", "certutil.yml", SIGMA_NO_STATUS) == "sigma_rule"

    def test_sigma_shape_failing_validation_stays_generic(self):
        assert detect_content_type("someone", "rules", "broken.yml", SIGMA_NO_CONDITION) == "yaml_file"

    def test_sentinel_kind_scheduled(self):
        ct = detect_content_type("Cloud-Architekt", "AzureSentinel", "Detections/x.yaml", SENTINEL_SCHEDULED)
        assert ct == "sentinel_rule"

    def test_sentinel_query_frequency_without_kind(self):
        assert detect_content_type("a", "b", "x.yaml", SENTINEL_FREQUENCY_ONLY) == "sentinel_rule"

    def test_sentinel_with_invalid_query_stays_generic(self):
        assert detect_content_type("a", "b", "x.yaml", SENTINEL_BAD_QUERY) == "yaml_file"

    def test_splunk_detection(self):
        assert detect_content_type("a", "b", "detections/x.yml", SPLUNK_DETECTION) == "splunk_detection"

    def test_anvilogic_splunk(self):
        ct = detect_content_type("anvilogic-forge", "armory", "detections/endpoint/wmic.yml", ANVILOGIC_SPLUNK)
        assert ct == "anvilogic_rule"

    def test_anvilogic_unsupported_format_stays_generic(self):
        ct = detect_content_type("anvilogic-forge", "armory", "detections/endpoint/wmic.yml", ANVILOGIC_SNOWFLAKE)
        assert ct == "yaml_file"

    def test_anvilogic_metadata(self):
        meta = extract_metadata(ANVILOGIC_SPLUNK, "anvilogic_rule")
        assert meta["rule_title"] == "WMIC Explicit Credentials"
        assert meta["import_rule_type"] == "splunk_spl"
        assert meta["mitre_attack_ids"] == ["T1078", "T1047"]
        assert meta["mitre_tactics"] == ["Persistence", "Privilege Escalation"]
        assert meta["rule_query"].strip().startswith("`get_endpoint_data`")
        assert rule_type_for("anvilogic_rule", meta) == "splunk_spl"
        assert rule_type_for("anvilogic_rule", {"import_rule_type": ""}) is None

    def test_elastic_toml_outside_listed_repo(self):
        assert detect_content_type("a", "b", "rules/lsass.toml", ELASTIC_TOML) == "elastic_rule"

    def test_plain_yaml_stays_generic(self):
        assert detect_content_type("a", "b", "config.yml", PLAIN_YAML) == "yaml_file"

    def test_no_content_stays_generic(self):
        assert detect_content_type("a", "b", "x.yaml", None) == "yaml_file"

    def test_repo_pattern_generic_yaml_is_also_sniffed(self):
        # WithSecureLabs/iocs **/*.yml is typed yaml_file by its repo pattern
        assert detect_content_type("WithSecureLabs", "iocs", "x/rule.yml", SIGMA_YAML) == "sigma_rule"

    def test_repo_pattern_wins_over_content(self):
        # A SigmaHQ path pattern decides without reading the file
        assert detect_content_type("SigmaHQ", "sigma", "rules/windows/x.yml", PLAIN_YAML) == "sigma_rule"


class TestLolDrivers:
    @pytest.mark.parametrize(
        "owner,repo",
        [
            ("magicsword-io", "LOLDrivers"),
            ("MagicSword-IO", "loldrivers"),
            ("loldrivers-project", "loldrivers"),
        ],
    )
    def test_either_org_matches(self, owner, repo):
        assert detect_content_type(owner, repo, "yaml/a2a53148.yaml", LOLDRIVER_YAML) == "loldriver_entry"

    def test_metadata_carries_attack_and_cve(self):
        meta = extract_metadata(LOLDRIVER_YAML, "loldriver_entry")
        assert meta["mitre_attack_ids"] == ["T1068"]
        assert meta["cve_ids"] == ["CVE-2023-52271"]
        assert meta["driver_name"] == "heysafe_drv.sys"
        assert meta["driver_description"].startswith("A vulnerable minifilter")


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


def _entry(content_type: str, raw: str, extracted: dict, owner="a", repo="b", fp="x") -> MagicMock:
    entry = MagicMock()
    entry.id = uuid.uuid4()
    entry.title = fp
    entry.metadata_ = {
        "source": "github_repo",
        "owner": owner,
        "repo": repo,
        "file_path": fp,
        "commit_sha": "abc1234567890",
        "commit_message": "add",
        "change_type": "added",
        "raw_content": raw,
        "content_type": content_type,
        "extracted": extracted,
    }
    return entry


def _db() -> MagicMock:
    db = MagicMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    empty = MagicMock()
    empty.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=empty)
    return db


class TestImport:
    @pytest.mark.asyncio
    async def test_kql_file_imports_as_kql_rule(self):
        db = _db()
        entry = _entry("kql_query", KQL_FILE, extract_metadata(KQL_FILE, "kql_query"), fp="Azure/VM Reset.kql")
        with patch("app.services.github_rule_import.index_rule", new=AsyncMock()):
            await import_detection_rule(db, entry, uuid.uuid4())
        rule = db.add.call_args[0][0]
        assert isinstance(rule, DetectionRule)
        assert rule.rule_type == "kql"
        assert rule.title == "Azure VM Password Reset Detection"
        assert rule.rule_content == KQL_FILE
        assert rule.source_ttps == ["T1098", "T1078.004"]

    @pytest.mark.asyncio
    async def test_anvilogic_imports_with_per_file_rule_type(self):
        db = _db()
        meta = extract_metadata(ANVILOGIC_SPLUNK, "anvilogic_rule")
        entry = _entry("anvilogic_rule", ANVILOGIC_SPLUNK, meta, owner="anvilogic-forge", repo="armory")
        with patch("app.services.github_rule_import.index_rule", new=AsyncMock()):
            await import_detection_rule(db, entry, uuid.uuid4())
        rule = db.add.call_args[0][0]
        assert rule.rule_type == "splunk_spl"
        assert rule.title == "WMIC Explicit Credentials"
        assert "get_endpoint_data" in rule.rule_content
        assert rule.references == ["https://thedfirreport.com/2022/04/25/quantum-ransomware/"]

    @pytest.mark.asyncio
    async def test_process_runs_import_for_per_file_type(self):
        db = _db()
        meta = extract_metadata(ANVILOGIC_SPLUNK, "anvilogic_rule")
        entry = _entry("anvilogic_rule", ANVILOGIC_SPLUNK, meta)
        with (
            patch("app.services.github_rule_import.import_detection_rule", new=AsyncMock(return_value=None)) as imp,
            patch("app.services.github_rule_import.link_entry_ttps", new=AsyncMock(return_value=[])),
            patch("app.services.github_rule_import.find_related_intelligence", new=AsyncMock(return_value=[])),
            patch("app.services.github_rule_import.score_rule_relevance", new=AsyncMock(return_value=0)),
            patch("app.services.github_rule_import.correlate_with_campaigns", new=AsyncMock(return_value=[])),
        ):
            await process_github_entry(db, entry, uuid.uuid4())
        imp.assert_awaited_once()


def test_anvilogic_formats_map_to_accepted_rule_types():
    import re

    from app.adapters.github_content_types import ANVILOGIC_LOGIC_FORMATS
    from app.schemas.intelligence import RULE_TYPE_PATTERN

    valid_types = set(re.fullmatch(r"\^\((.+)\)\$", RULE_TYPE_PATTERN).group(1).split("|"))
    assert set(ANVILOGIC_LOGIC_FORMATS.values()) <= valid_types
