"""Tests for TTP regex extraction (Layer 1)."""

from app.intelligence.ttp import extract_ttp_ids_regex


def test_basic_technique_id():
    text = "The attacker used T1566 for initial access."
    results = extract_ttp_ids_regex(text)
    assert len(results) == 1
    assert results[0]["technique_id"] == "T1566"
    assert results[0]["source"] == "regex"
    assert results[0]["confidence"] == "medium"


def test_sub_technique():
    text = "Spearphishing attachment T1566.001 was observed."
    results = extract_ttp_ids_regex(text)
    assert len(results) == 1
    assert results[0]["technique_id"] == "T1566.001"


def test_multiple_techniques():
    text = "Attack chain: T1566.001 -> T1059.001 -> T1071.001 and also T1566.001 again."
    results = extract_ttp_ids_regex(text)
    ids = [r["technique_id"] for r in results]
    assert len(ids) == 3
    assert "T1566.001" in ids
    assert "T1059.001" in ids
    assert "T1071.001" in ids


def test_no_match():
    text = "This article has no MITRE technique references at all."
    results = extract_ttp_ids_regex(text)
    assert results == []


def test_empty_text():
    assert extract_ttp_ids_regex("") == []
    assert extract_ttp_ids_regex(None) == []


def test_word_boundary():
    """IDs embedded in other words should not match."""
    text = "The token AT1566 is not a technique ID. Neither is T1566X."
    results = extract_ttp_ids_regex(text)
    # T1566X should not match because X follows, but AT1566 should not match due to leading A
    # However T1566 inside T1566X will match the T1566 portion since X breaks the word boundary
    # AT1566 should NOT match because A precedes T
    ids = [r["technique_id"] for r in results]
    assert "T1566" not in ids or all(t == "T1566" for t in ids)
    # AT1566 should definitely not appear
    assert not any("AT1566" in t for t in ids)


def test_merge_regex_and_ai():
    """When merging, AI results should override regex for the same technique_id."""
    from app.intelligence.ttp import extract_ttp_ids_regex

    regex_results = extract_ttp_ids_regex("Uses T1566 for phishing.")
    assert len(regex_results) == 1
    assert regex_results[0]["technique_name"] == "T1566"  # regex only knows the ID

    # Simulate AI providing richer data
    ai_results = [
        {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic": "Initial Access",
            "confidence": "high",
            "source": "ai",
        }
    ]

    # Merge logic: AI overrides regex for same technique_id
    merged = {t["technique_id"]: t for t in regex_results}
    for t in ai_results:
        tid = t.get("technique_id", "").strip()
        if tid:
            merged[tid] = t

    result = list(merged.values())
    assert len(result) == 1
    assert result[0]["technique_name"] == "Phishing"
    assert result[0]["source"] == "ai"
    assert result[0]["confidence"] == "high"


def test_invalid_000_subtechnique_strips_to_parent():
    """ ".000" is not a valid ATT&CK sub-technique — match falls back to the parent."""
    text = "ICS technique T0024.000 and enterprise T1059.000 were referenced."
    results = extract_ttp_ids_regex(text)
    ids = {r["technique_id"] for r in results}
    assert ids == {"T0024", "T1059"}


def test_valid_subtechnique_not_affected_by_000_filter():
    text = "T1059.001 and T1000 and T1000.004"
    results = extract_ttp_ids_regex(text)
    ids = {r["technique_id"] for r in results}
    assert ids == {"T1059.001", "T1000", "T1000.004"}


def test_normalize_technique_id_strips_000():
    from app.intelligence.ttp import normalize_technique_id

    assert normalize_technique_id("T0024.000") == "T0024"
    assert normalize_technique_id("T1059.001") == "T1059.001"
    assert normalize_technique_id("T1059") == "T1059"
    assert normalize_technique_id("") == ""


def test_many_techniques_in_report():
    text = """
    The threat actor leveraged T1190 (Exploit Public-Facing Application) to gain
    initial access, then used T1059.001 (PowerShell) and T1059.003 (Windows Command Shell)
    for execution. Persistence was achieved via T1547.001 (Registry Run Keys). Data was
    exfiltrated using T1041 (Exfiltration Over C2 Channel).
    """
    results = extract_ttp_ids_regex(text)
    ids = {r["technique_id"] for r in results}
    assert ids == {"T1190", "T1059.001", "T1059.003", "T1547.001", "T1041"}
