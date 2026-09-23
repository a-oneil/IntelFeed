"""Tests for TTP extraction, storage, and ATT&CK Navigator layer generation."""

from app.intelligence.ttp import (
    extract_ttp_ids_regex,
    generate_navigator_layer,
    name_contradicts_catalog,
)


def test_extract_ttp_ids_regex_basic():
    text = "The attacker used T1059 for command execution and T1071 for C2."
    results = extract_ttp_ids_regex(text)
    technique_ids = {r["technique_id"] for r in results}
    assert "T1059" in technique_ids
    assert "T1071" in technique_ids
    assert len(results) == 2
    for r in results:
        assert r["source"] == "regex"
        assert r["confidence"] == "medium"


def test_extract_ttp_ids_regex_sub_technique():
    text = "Spearphishing attachment T1566.001 was used alongside T1566.002 link-based phishing."
    results = extract_ttp_ids_regex(text)
    technique_ids = {r["technique_id"] for r in results}
    assert "T1566.001" in technique_ids
    assert "T1566.002" in technique_ids
    assert len(results) == 2


def test_extract_ttp_ids_regex_empty():
    assert extract_ttp_ids_regex("") == []
    assert extract_ttp_ids_regex(None) == []


def test_extract_ttp_ids_regex_no_match():
    text = "This article discusses general cybersecurity topics without any technique references."
    results = extract_ttp_ids_regex(text)
    assert results == []


def test_navigator_layer_structure():
    ttps = [
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "confidence": "high",
            "tactic": "Execution",
            "source_text": "Used PowerShell for execution",
        },
        {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "confidence": "medium",
            "tactic": "Command and Control",
        },
    ]
    layer = generate_navigator_layer(ttps, title="Test Report")

    # Top-level structure
    assert layer["name"] == "TTPs from: Test Report"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["navigator"] == "4.9.1"
    assert layer["domain"] == "enterprise-attack"
    assert "gradient" in layer
    assert "techniques" in layer
    assert len(layer["techniques"]) == 2

    # First technique (high confidence)
    t1 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059")
    assert t1["color"] == "#ff6666"
    assert t1["score"] == 100
    assert t1["enabled"] is True
    assert t1["tactic"] == "execution"
    assert t1["comment"] == "Used PowerShell for execution"

    # Second technique (medium confidence)
    t2 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1071")
    assert t2["color"] == "#ffcc66"
    assert t2["score"] == 75


def test_navigator_layer_empty():
    layer = generate_navigator_layer([], title="Empty Layer")
    assert layer["name"] == "TTPs from: Empty Layer"
    assert layer["techniques"] == []
    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert "gradient" in layer


def test_navigator_layer_confidence_colors():
    ttps = [
        {"technique_id": "T1059", "confidence": "high", "tactic": ""},
        {"technique_id": "T1071", "confidence": "medium", "tactic": ""},
        {"technique_id": "T1566", "confidence": "low", "tactic": ""},
    ]
    layer = generate_navigator_layer(ttps)

    high = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059")
    medium = next(t for t in layer["techniques"] if t["techniqueID"] == "T1071")
    low = next(t for t in layer["techniques"] if t["techniqueID"] == "T1566")

    assert high["color"] == "#ff6666"
    assert medium["color"] == "#ffcc66"
    assert low["color"] == "#ffff99"

    assert high["score"] == 100
    assert medium["score"] == 75
    assert low["score"] == 50


class TestNameContradictsCatalog:
    """The extractor's technique_name as a free second opinion on its ID."""

    def test_exact_match_agrees(self):
        assert not name_contradicts_catalog("Windows Command Shell", "Windows Command Shell", "T1059.003")

    def test_case_and_punctuation_insensitive(self):
        assert not name_contradicts_catalog(
            "obfuscated files or information", "Obfuscated Files or Information", "T1027"
        )

    def test_parent_prefixed_subtechnique_agrees(self):
        # Models commonly prefix the parent; the catalog stores the child alone.
        assert not name_contradicts_catalog(
            "Impair Defenses: Disable or Modify Tools", "Disable or Modify Tools", "T1562.001"
        )

    def test_real_mispairing_is_flagged(self):
        # Observed: T1562.004 is "Disable or Modify System Firewall".
        assert name_contradicts_catalog("Clear Windows Event Logs", "Disable or Modify System Firewall", "T1562.004")
        # Observed: T1087.001 is "Local Account".
        assert name_contradicts_catalog("Account Discovery", "Local Account", "T1087.001")

    def test_no_name_claim_is_not_a_contradiction(self):
        # The regex layer emits technique_name == technique_id: asserts nothing.
        assert not name_contradicts_catalog("T1059", "Command and Scripting Interpreter", "T1059")
        assert not name_contradicts_catalog("", "Command and Scripting Interpreter", "T1059")

    def test_unhydrated_catalog_stub_is_not_a_contradiction(self):
        assert not name_contradicts_catalog("Windows Command Shell", "T1059.003", "T1059.003")
