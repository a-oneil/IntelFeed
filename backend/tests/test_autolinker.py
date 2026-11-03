"""Tests for the entity auto-linker (Aho-Corasick dictionary-based entity recognition)."""

import uuid
from unittest.mock import MagicMock

from app.intelligence.autolinker import (
    FALSE_POSITIVE_NAMES,
    EntityVocabulary,
    _is_word_boundary,
    scan_text,
    split_into_paragraphs,
)
from app.intelligence.correlation import _compute_proximity_score


def _make_actor(name, aliases=None):
    actor = MagicMock()
    actor.id = uuid.uuid4()
    actor.name = name
    actor.aliases = aliases or []
    return actor


def _make_malware(name, aliases=None):
    malware = MagicMock()
    malware.id = uuid.uuid4()
    malware.name = name
    malware.aliases = aliases or []
    return malware


def _build_and_activate(actors=None, malware=None):
    """Build vocabulary and set it as the module-level singleton."""
    import app.intelligence.autolinker as mod

    vocab = EntityVocabulary()
    vocab.build_from_entities(actors or [], malware or [])
    mod._vocabulary = vocab
    mod._vocab_version = vocab.version
    return vocab


def test_build_vocabulary():
    actors = [_make_actor("APT29", ["Cozy Bear", "The Dukes"])]
    malware = [_make_malware("Emotet", ["Heodo"])]
    vocab = EntityVocabulary()
    count = vocab.build_from_entities(actors, malware)
    assert count > 0
    assert vocab.built


def test_scan_threat_actor():
    actor = _make_actor("APT29", ["Cozy Bear"])
    _build_and_activate(actors=[actor])

    matches = scan_text("The threat actor APT29 was linked to the campaign.")
    actor_matches = [m for m in matches if m["entity_type"] == "threat_actor"]
    assert len(actor_matches) == 1
    assert actor_matches[0]["canonical_name"] == "APT29"
    assert actor_matches[0]["confidence"] == "high"
    assert actor_matches[0]["source"] == "auto_link"
    assert actor_matches[0]["paragraph_indices"] == [0]


def test_scan_alias():
    actor = _make_actor("APT29", ["Cozy Bear"])
    _build_and_activate(actors=[actor])

    matches = scan_text("Cozy Bear was observed targeting government agencies.")
    actor_matches = [m for m in matches if m["entity_type"] == "threat_actor"]
    assert len(actor_matches) == 1
    assert actor_matches[0]["canonical_name"] == "APT29"
    assert actor_matches[0]["confidence"] == "medium"  # alias match


def test_scan_malware():
    malware = _make_malware("Emotet", ["Heodo"])
    _build_and_activate(malware=[malware])

    matches = scan_text("Samples of Emotet were found in the wild.")
    malware_matches = [m for m in matches if m["entity_type"] == "malware"]
    assert len(malware_matches) == 1
    assert malware_matches[0]["canonical_name"] == "Emotet"


def test_scan_case_insensitive():
    actor = _make_actor("APT29")
    _build_and_activate(actors=[actor])

    matches = scan_text("Research shows apt29 is active again.")
    assert len([m for m in matches if m["entity_type"] == "threat_actor"]) == 1


def test_scan_cve_regex():
    _build_and_activate()

    matches = scan_text("The vulnerability CVE-2024-21762 is being exploited in the wild.")
    cve_matches = [m for m in matches if m["entity_type"] == "cve"]
    assert len(cve_matches) == 1
    assert cve_matches[0]["lookup_key"] == "CVE-2024-21762"


def test_scan_ttp_regex():
    _build_and_activate()

    matches = scan_text("The actor used T1059 and T1059.001 for execution.")
    ttp_matches = [m for m in matches if m["entity_type"] == "ttp"]
    assert len(ttp_matches) == 2
    technique_ids = {m["lookup_key"] for m in ttp_matches}
    assert "T1059" in technique_ids
    assert "T1059.001" in technique_ids


def test_scan_multiple_entities():
    actor = _make_actor("APT28", ["Fancy Bear"])
    malware = _make_malware("Emotet")
    _build_and_activate(actors=[actor], malware=[malware])

    text = "APT28, also known as Fancy Bear, deployed Emotet in a targeted campaign. CVE-2024-3400 was exploited."
    matches = scan_text(text)
    types = {m["entity_type"] for m in matches}
    assert "threat_actor" in types
    assert "malware" in types
    assert "cve" in types


def test_dedup_same_entity():
    actor = _make_actor("APT29", ["Cozy Bear"])
    _build_and_activate(actors=[actor])

    # Both "APT29" and "Cozy Bear" refer to same entity — should only match once
    matches = scan_text("APT29, also known as Cozy Bear, was active.")
    actor_matches = [m for m in matches if m["entity_type"] == "threat_actor"]
    assert len(actor_matches) == 1


def test_word_boundary_validation():
    assert _is_word_boundary("hello APT29 world", 6, 11)
    assert not _is_word_boundary("helloAPT29 world", 5, 10)  # No left boundary
    assert not _is_word_boundary("hello APT29world", 6, 11)  # No right boundary
    assert _is_word_boundary("APT29", 0, 5)  # Start/end of string
    assert not _is_word_boundary("RTM_NEWLINK", 0, 3)  # code identifier
    assert not _is_word_boundary("nft_meta", 0, 3)


def test_word_boundary_prevents_partial_match():
    actor = _make_actor("HIVE")
    _build_and_activate(actors=[actor])

    # "HIVE" inside "ARCHIVE" should not match
    matches = scan_text("The user checked the ARCHIVE for old files.")
    assert len([m for m in matches if m["entity_type"] == "threat_actor"]) == 0

    # "HIVE" as standalone should match
    matches = scan_text("The HIVE ransomware encrypted all files.")
    assert len([m for m in matches if m["entity_type"] == "threat_actor"]) == 1


def test_lowercase_dotted_package_id_is_not_a_mention():
    actor = _make_actor("The Com")
    _build_and_activate(actors=[actor])

    # A macOS bundle id / Java package path is code, not the group.
    assert not scan_text("Running as root, it loads the com.apple.screensharing agent.")
    # The group written as a name still matches, even before a full stop.
    matches = scan_text("Researchers tied the attack to The Com. Arrests followed.")
    assert len([m for m in matches if m["entity_type"] == "threat_actor"]) == 1


def test_short_acronym_and_mixed_case_forms_match_their_own_casing():
    trap = _make_malware("TRAP")
    ios = _make_malware("iOS")
    _build_and_activate(malware=[trap, ios])

    def names(text):
        return {m["canonical_name"] for m in scan_text(text) if m["entity_type"] == "malware"}

    assert names("The kernel hit a page-fault trap. Digitization Trap, a book.") == set()
    assert names("Proofpoint TRAP pulled the email back.") == {"TRAP"}
    assert names("Cisco IOS XE is affected.") == set()
    assert names("The iOS update fixes it.") == {"iOS"}


def test_a_name_inside_a_longer_name_is_not_matched():
    korea = _make_actor("Korea")
    north = _make_actor("North Korea")
    _build_and_activate(actors=[korea, north])

    found = {m["canonical_name"] for m in scan_text("North Korea's hackers struck again.")}
    assert found == {"North Korea"}
    found = {m["canonical_name"] for m in scan_text("Korea and North Korea both issued warnings.")}
    assert found == {"Korea", "North Korea"}  # a separate mention still counts


def test_a_name_inside_a_longer_name_of_another_type_still_counts():
    # the vendor-in-product case ("Microsoft" in "Microsoft Exchange"), with types the helper builds
    actor = _make_actor("Sandworm")
    malware = _make_malware("Sandworm Loader")
    _build_and_activate(actors=[actor], malware=[malware])

    found = {(m["entity_type"], m["canonical_name"]) for m in scan_text("Sandworm Loader was seen again.")}
    assert found == {("threat_actor", "Sandworm"), ("malware", "Sandworm Loader")}


def test_single_dotted_segment_still_matches():
    malware = _make_malware("Lumma7")
    _build_and_activate(malware=[malware])

    # "lumma7.exe" is one segment: the file is the malware, keep the match.
    matches = scan_text("The dropper wrote lumma7.exe to disk.")
    assert len([m for m in matches if m["entity_type"] == "malware"]) == 1


def test_word_boundary_prevents_partial_alias_match():
    """Aliases must be word-boundary checked just like names — an alias 'foxx'
    must not match inside 'firefoxx'."""
    # Use a non-ambiguous alias (>4 chars, alpha-only would be ambiguous so add digit)
    actor = _make_actor("ActorOne", aliases=["foxx7"])
    _build_and_activate(actors=[actor])

    # Embedded inside another word — should NOT match
    matches = scan_text("The browser firefoxx7 was patched.")
    assert len([m for m in matches if m["entity_type"] == "threat_actor"]) == 0

    # Standalone — should match
    matches = scan_text("The group foxx7 was tracked.")
    assert len([m for m in matches if m["entity_type"] == "threat_actor"]) == 1


def test_false_positive_filtering():
    """Entity names in the false positive set should be excluded."""
    # "agent" is in FALSE_POSITIVE_NAMES
    actor = _make_actor("Agent")
    _build_and_activate(actors=[actor])

    matches = scan_text("The agent deployed the malware.")
    assert len([m for m in matches if m["entity_type"] == "threat_actor"]) == 0


def test_min_length_filtering():
    """Entities shorter than MIN_NAME_LENGTH are excluded."""
    actor = _make_actor("AP")  # 2 chars, below the shipped autolinker_min_name_length of 3
    _build_and_activate(actors=[actor])

    matches = scan_text("AP was mentioned in the report.")
    assert len([m for m in matches if m["entity_type"] == "threat_actor"]) == 0


def test_empty_text():
    _build_and_activate(actors=[_make_actor("APT29")])
    assert scan_text("") == []
    assert scan_text(None) == []


def test_no_vocabulary():
    """Scan with no vocabulary built returns empty."""
    import app.intelligence.autolinker as mod

    mod._vocabulary = None
    assert scan_text("APT29 is active") == []


def test_multiple_cves():
    _build_and_activate()

    text = "CVE-2024-21762 and CVE-2024-3400 are both critical."
    matches = scan_text(text)
    cve_matches = [m for m in matches if m["entity_type"] == "cve"]
    assert len(cve_matches) == 2


def test_ttp_subtechnique():
    _build_and_activate()

    text = "The actor used technique T1059.001 for PowerShell execution."
    matches = scan_text(text)
    ttp_matches = [m for m in matches if m["entity_type"] == "ttp"]
    # Both T1059 and T1059.001 will match since \b exists between digits and "."
    technique_ids = {m["lookup_key"] for m in ttp_matches}
    assert "T1059.001" in technique_ids


def test_false_positive_set_is_lowercase():
    """All entries in the false positive set should be lowercase for matching."""
    for name in FALSE_POSITIVE_NAMES:
        assert name == name.lower(), f"False positive '{name}' should be lowercase"


def test_ambiguous_name_requires_capitalization():
    """Single short alpha-only names must appear capitalized in the source text."""
    # "Hive" (ransomware) — ambiguous surface form
    malware = _make_malware("Hive")
    _build_and_activate(malware=[malware])

    # Lowercase usage = common English word → should NOT match
    assert scan_text("The hive of bees was disturbed.") == []
    assert scan_text("a hive mind approach to security") == []

    # Capitalized usage = proper noun reference → should match
    result = scan_text("Hive ransomware extorted multiple hospitals.")
    malware_matches = [m for m in result if m["entity_type"] == "malware"]
    assert len(malware_matches) == 1
    assert malware_matches[0]["canonical_name"] == "Hive"


def test_ambiguous_name_high_frequency_skipped():
    """Ambiguous names appearing too many times in one article are skipped."""
    malware = _make_malware("Play")
    _build_and_activate(malware=[malware])

    # "Play" 4 times — over the default threshold of 3 → should not match
    text = "Play a key role. Play nice. Play the game. Play along with the analysis."
    result = scan_text(text)
    assert len([m for m in result if m["entity_type"] == "malware"]) == 0


def test_non_ambiguous_name_matches_case_insensitively():
    """Names with digits, spaces, or hyphens are not ambiguous — still match lowercase."""
    actor = _make_actor("APT29")  # has digit → not ambiguous
    _build_and_activate(actors=[actor])

    # Lowercase should still match since it's not an ambiguous surface form
    result = scan_text("Research shows apt29 is still active.")
    assert len([m for m in result if m["entity_type"] == "threat_actor"]) == 1


def test_system_tool_names_in_fp_list():
    """Windows built-in tool names (cmd, ping, net, etc.) should be filtered out."""
    for tool_name in ("cmd", "ping", "net", "reg", "ftp"):
        malware = _make_malware(tool_name)
        _build_and_activate(malware=[malware])
        result = scan_text(f"The analyst ran {tool_name} to check connectivity.")
        assert result == [], f"Expected no match for tool name '{tool_name}'"


def test_fp_names_honor_db_setting_override(monkeypatch):
    """A false-positive name added via Settings > System (DB override) must take
    effect on the next vocabulary rebuild, not just the .env default —
    regression test for settings.get() vs direct settings.X attribute access
    silently ignoring DB overrides. FP filtering happens at vocab-build time
    (see build_from_entities), so the override only applies after a rebuild —
    exactly the "append + refresh vocab" flow the FP-report endpoint drives."""
    import app.services.system_settings as ss_mod
    from app.intelligence.autolinker import _get_fp_names

    actor = _make_actor("Widget")
    _build_and_activate(actors=[actor])
    assert scan_text("The Widget campaign was observed.") != []

    monkeypatch.setattr(ss_mod, "_cache", {"autolinker_false_positive_names": "widget,agent"})
    try:
        assert "widget" in _get_fp_names()
        _build_and_activate(actors=[actor])  # rebuild picks up the new FP set
        assert scan_text("The Widget campaign was observed.") == []
    finally:
        monkeypatch.setattr(ss_mod, "_cache", None)


# ── Paragraph-awareness tests ──


def test_split_into_paragraphs():
    """split_into_paragraphs splits title/summary/content into indexed paragraphs."""
    paragraphs = split_into_paragraphs(
        "My Title",
        "Summary text",
        "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.",
    )
    assert len(paragraphs) == 5
    assert paragraphs[0] == (0, "My Title")
    assert paragraphs[1] == (1, "Summary text")
    assert paragraphs[2] == (2, "First paragraph.")
    assert paragraphs[3] == (3, "Second paragraph.")
    assert paragraphs[4] == (4, "Third paragraph.")


def test_split_into_paragraphs_empty_fields():
    """Empty title/summary are skipped in paragraph indices."""
    paragraphs = split_into_paragraphs("", "", "First.\n\nSecond.")
    assert len(paragraphs) == 2
    assert paragraphs[0] == (0, "First.")
    assert paragraphs[1] == (1, "Second.")


def test_scan_text_with_paragraphs():
    """scan_text accepts (paragraph_index, text) tuples and returns paragraph_indices."""
    actor = _make_actor("APT29")
    malware = _make_malware("Emotet")
    _build_and_activate(actors=[actor], malware=[malware])

    paragraphs = [
        (0, "APT29 was seen targeting financial sector."),
        (1, "This is an unrelated paragraph about markets."),
        (2, "Emotet was deployed via phishing emails."),
        (3, "APT29 also used spear-phishing with Emotet payloads."),
    ]
    matches = scan_text(paragraphs)

    actor_match = next(m for m in matches if m["entity_type"] == "threat_actor")
    malware_match = next(m for m in matches if m["entity_type"] == "malware")

    assert actor_match["paragraph_indices"] == [0, 3]
    assert malware_match["paragraph_indices"] == [2, 3]


def test_scan_text_paragraph_indices_single_string():
    """Backward compat: plain string gets paragraph_indices=[0]."""
    actor = _make_actor("APT29")
    _build_and_activate(actors=[actor])

    matches = scan_text("APT29 is active.")
    assert matches[0]["paragraph_indices"] == [0]


def test_scan_text_cve_paragraph_tracking():
    """CVE regex matches also track paragraph positions."""
    _build_and_activate()

    paragraphs = [
        (0, "First paragraph."),
        (1, "CVE-2024-21762 is critical."),
        (2, "Another paragraph."),
        (3, "CVE-2024-21762 is still being exploited."),
    ]
    matches = scan_text(paragraphs)
    cve_match = next(m for m in matches if m["entity_type"] == "cve")
    assert cve_match["paragraph_indices"] == [1, 3]


def test_scan_text_dedup_across_paragraphs():
    """Same entity in multiple paragraphs → single match with all paragraph indices."""
    actor = _make_actor("APT29", ["Cozy Bear"])
    _build_and_activate(actors=[actor])

    paragraphs = [
        (0, "APT29 launched an attack."),
        (1, "Cozy Bear is the same group."),
    ]
    matches = scan_text(paragraphs)
    actor_matches = [m for m in matches if m["entity_type"] == "threat_actor"]
    assert len(actor_matches) == 1  # Deduped
    assert actor_matches[0]["paragraph_indices"] == [0, 1]


# ── Proximity score computation tests ──


def test_proximity_score_same_paragraph():
    """Same paragraph → distance 0 → score 1.0."""
    assert _compute_proximity_score([0], [0]) == 1.0
    assert _compute_proximity_score([3, 5], [5, 7]) == 1.0


def test_proximity_score_adjacent_paragraphs():
    """Adjacent paragraphs → distance 1 → score 0.5."""
    assert _compute_proximity_score([0], [1]) == 0.5
    assert _compute_proximity_score([5], [4]) == 0.5


def test_proximity_score_distant_paragraphs():
    """Distance 4 → score 0.2."""
    assert _compute_proximity_score([0], [4]) == 0.2


def test_proximity_score_null_indices():
    """NULL paragraph data → degraded default 0.3."""
    assert _compute_proximity_score(None, [1, 2]) == 0.3
    assert _compute_proximity_score([1, 2], None) == 0.3
    assert _compute_proximity_score(None, None) == 0.3


def test_proximity_score_empty_indices():
    """Empty list → degraded default 0.3."""
    assert _compute_proximity_score([], [1, 2]) == 0.3
    assert _compute_proximity_score([1], []) == 0.3


def test_proximity_score_multiple_positions():
    """Multiple positions → uses minimum distance."""
    # Source at [0, 10], target at [3, 7] → min distance is min(3, 7, 7, 3) = 3
    score = _compute_proximity_score([0, 10], [3, 7])
    assert score == 1.0 / (1 + 3)  # 0.25
