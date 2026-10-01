"""Tests for the reference-feed parsers that populate entity profile fields.

Each of these covers a field that was empty in production because the parser
either read a key the upstream source no longer publishes, or never looked at
data the source was already handing us.
"""

from app.intelligence.actor_attributes import coerce_motivation
from app.intelligence.attack_catalog import parse_attack_bundle
from app.intelligence.rule_metadata import derive_data_sources
from app.workers.enrichment_tasks import parse_metasploit_modules, parse_misp_galaxy_attributes

# --- ATT&CK v17 detection strategies ----------------------------------------


def _v17_bundle() -> dict:
    """Bundle in the post-v17 shape: no x_mitre_data_sources / x_mitre_detection
    on the technique; detection lives in a strategy -> analytic -> log source chain."""
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--t1059-001",
                "name": "PowerShell",
                "description": "Adversaries may abuse PowerShell.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.001", "url": "https://x"},
                ],
                "kill_chain_phases": [{"phase_name": "execution"}],
                "x_mitre_platforms": ["Windows"],
                "x_mitre_is_subtechnique": True,
            },
            {
                "type": "x-mitre-data-component",
                "id": "x-mitre-data-component--dc1",
                "name": "Script Execution",
            },
            {
                "type": "x-mitre-analytic",
                "id": "x-mitre-analytic--an1",
                "description": "Monitor for encoded PowerShell commands.",
                "x_mitre_log_source_references": [
                    {"name": "WinEventLog:PowerShell", "channel": "Operational"},
                    {"x_mitre_data_component_ref": "x-mitre-data-component--dc1"},
                ],
            },
            {
                "type": "x-mitre-detection-strategy",
                "id": "x-mitre-detection-strategy--ds1",
                "name": "Abuse of PowerShell for Arbitrary Execution",
                "x_mitre_analytic_refs": ["x-mitre-analytic--an1"],
            },
            {
                "type": "relationship",
                "relationship_type": "detects",
                "source_ref": "x-mitre-detection-strategy--ds1",
                "target_ref": "attack-pattern--t1059-001",
            },
        ],
    }


def test_detection_strategies_populate_data_sources_and_detection():
    parsed = parse_attack_bundle(_v17_bundle(), "enterprise")
    tech = next(t for t in parsed.techniques if t["technique_id"] == "T1059.001")

    # Named log source wins; the unnamed reference falls back to its data component
    assert tech["data_sources"] == ["Script Execution", "WinEventLog:PowerShell"]
    assert "Abuse of PowerShell for Arbitrary Execution" in tech["detection"]
    assert "encoded PowerShell commands" in tech["detection"]


def test_technique_without_detection_strategy_keeps_empty_fields():
    bundle = _v17_bundle()
    bundle["objects"] = [o for o in bundle["objects"] if o.get("relationship_type") != "detects"]
    parsed = parse_attack_bundle(bundle, "enterprise")
    tech = next(t for t in parsed.techniques if t["technique_id"] == "T1059.001")
    assert tech["data_sources"] == []
    assert tech["detection"] is None


def test_legacy_bundle_keys_still_read():
    """Pre-v17 bundles put both fields on the technique — keep honoring them."""
    bundle = _v17_bundle()
    for obj in bundle["objects"]:
        if obj["type"] == "attack-pattern":
            obj["x_mitre_data_sources"] = ["Process: Process Creation"]
            obj["x_mitre_detection"] = "Legacy detection prose."
    bundle["objects"] = [o for o in bundle["objects"] if o.get("relationship_type") != "detects"]
    parsed = parse_attack_bundle(bundle, "enterprise")
    tech = parsed.techniques[0]
    assert tech["data_sources"] == ["Process: Process Creation"]
    assert tech["detection"] == "Legacy detection prose."


def test_software_and_group_attributes_are_parsed():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--g1",
                "name": "APT38",
                "aliases": ["APT38", "Bluenoroff"],
                "description": "A North Korean group.\n\nMore detail.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0082"}],
            },
            {
                "type": "tool",
                "id": "tool--s1",
                "name": "Net",
                "x_mitre_aliases": ["Net", "net.exe"],
                "x_mitre_platforms": ["Windows"],
                "description": "The Net utility.\n\nSecond para.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0039"}],
            },
        ],
    }
    parsed = parse_attack_bundle(bundle, "enterprise")

    assert parsed.intrusion_sets[0]["name"] == "APT38"
    software = parsed.software["tool--s1"]
    assert software["kind"] == "tool"
    assert software["aliases"] == ["net.exe"]
    assert software["platforms"] == ["Windows"]
    assert software["mitre_id"] == "S0039"
    # Only the first paragraph, matching how descriptions are stored elsewhere
    assert software["description"] == "The Net utility."


# --- Detection rule data_sources --------------------------------------------


def test_sigma_logsource_maps_to_known_channel():
    assert derive_data_sources("sigma", {"product": "windows", "service": "security", "category": ""}) == [
        "WinEventLog:Security"
    ]


def test_sigma_logsource_falls_back_to_product_category():
    assert derive_data_sources("sigma", {"product": "windows", "service": "", "category": "process_creation"}) == [
        "windows:process_creation"
    ]
    assert derive_data_sources("sigma", {"product": "linux", "service": "", "category": ""}) == ["linux"]


def test_elastic_indices_become_data_sources():
    assert derive_data_sources("elastic_ql", {"indices": ["winlogbeat-*", "logs-system.security*"]}) == [
        "winlogbeat-*",
        "logs-system.security*",
    ]


def test_splunk_sources_come_from_the_query_text():
    spl = 'index=main sourcetype="WinEventLog:Security" | stats count by host'
    assert derive_data_sources("splunk_spl", None, spl) == ["main", "wineventlog:security"]


def test_artifact_scanning_formats_declare_no_telemetry():
    """YARA scans files, not log streams — an empty list is the correct answer,
    not a coverage gap."""
    assert derive_data_sources("yara", {"product": "windows"}, "rule x {}") == []
    assert derive_data_sources("nuclei", {"product": "windows"}) == []


# --- Metasploit --------------------------------------------------------------


def test_metasploit_modules_map_by_cve():
    metadata = {
        "exploit_windows/smb/ms17_010": {
            "fullname": "exploit/windows/smb/ms17_010_eternalblue",
            "references": ["CVE-2017-0144", "MSB-MS17-010", "URL-https://example.com"],
        },
        "auxiliary_scanner/smb/smb_ms17_010": {
            "fullname": "auxiliary/scanner/smb/smb_ms17_010",
            "references": ["cve-2017-0144"],
        },
        "exploit_no_cve": {"fullname": "exploit/multi/handler", "references": ["URL-https://example.com"]},
    }
    by_cve = parse_metasploit_modules(metadata)
    assert by_cve == {
        "CVE-2017-0144": [
            "auxiliary/scanner/smb/smb_ms17_010",
            "exploit/windows/smb/ms17_010_eternalblue",
        ]
    }


# --- MISP Galaxy -------------------------------------------------------------


def test_misp_galaxy_attributes_extracted():
    data = {
        "values": [
            {
                "value": "APT1",
                "description": "A Chinese group.",
                "meta": {
                    "synonyms": ["Comment Crew"],
                    "country": "CN",
                    "cfr-target-category": ["Private sector", "Government"],
                    "cfr-type-of-incident": "Espionage",
                },
            },
            {"value": "NoMeta"},
        ]
    }
    attrs = parse_misp_galaxy_attributes(data)
    assert attrs["APT1"]["country"] == "CN"
    assert attrs["APT1"]["motivation"] == "Espionage"
    assert "Government" in attrs["APT1"]["sectors"]
    assert "NoMeta" not in attrs


def test_motivation_coerced_to_vocabulary():
    assert coerce_motivation("Espionage") == "espionage"
    assert coerce_motivation("Financial gain") == "financial"
    assert coerce_motivation("Financial extortion") == "financial"
    assert coerce_motivation("DDoS campaigns") == "disruption"
    # No signal — better empty than an ungroupable value on the facet
    assert coerce_motivation("unknown") is None
    assert coerce_motivation("") is None
    assert coerce_motivation("Pro-Iran amplification actor") is None


# --- Splunk security_content schema drift -----------------------------------


def test_splunk_top_level_attack_mapping_is_read():
    """splunk/security_content moved mitre_attack_id, analytic_story and
    data_source from `tags` to the top level and left `tags` empty. Reading only
    tags.* silently produced no ATT&CK mapping for every detection on the newer
    schema."""
    from app.adapters.github_content_types import extract_metadata

    yaml_doc = """
name: Windows Query Registry UnInstall Program List
description: Detects enumeration of installed programs.
type: TTP
search: '`wineventlog_security` EventCode=4663'
mitre_attack_id:
    - T1012
analytic_story:
    - StealC Stealer
data_source:
    - Windows Event Log Security 4663
tags: {}
"""
    meta = extract_metadata(yaml_doc, "splunk_detection")
    assert meta["mitre_attack_ids"] == ["T1012"]
    assert meta["data_source"] == ["Windows Event Log Security 4663"]
    assert meta["analytic_stories"] == ["StealC Stealer"]


def test_splunk_legacy_tags_schema_still_read():
    """Older files nest the same fields under `tags` — keep honoring them."""
    from app.adapters.github_content_types import extract_metadata

    yaml_doc = """
name: Legacy Detection
search: 'index=main'
tags:
    mitre_attack_id:
        - T1059.001
    analytic_story:
        - Some Story
"""
    meta = extract_metadata(yaml_doc, "splunk_detection")
    assert meta["mitre_attack_ids"] == ["T1059.001"]
    assert meta["analytic_stories"] == ["Some Story"]


def test_splunk_data_source_becomes_rule_data_sources():
    from app.intelligence.rule_metadata import map_metadata_to_fields

    mapped = map_metadata_to_fields({"data_source": ["Windows Event Log Security 4663"], "mitre_attack_ids": ["T1012"]})
    assert mapped["data_sources"] == ["Windows Event Log Security 4663"]
    assert mapped["source_ttps"] == ["T1012"]
