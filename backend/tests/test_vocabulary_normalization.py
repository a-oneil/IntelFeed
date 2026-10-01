"""Vocabulary columns fold onto one spelling however they are written.

The bug these cover: `rule.tactic:persistence` and `rule.tactic:Persistence`
were two rows in the search facet because six write paths each picked their own
casing, and `rule.tactic:defense_evasion` missed rules stored as "Defense
Evasion" outright, since the filter compares substrings rather than words.
"""

import pytest

from app.api.search import _array_element_values
from app.intelligence.actor_attributes import normalize_country, normalize_motivation
from app.intelligence.platforms import canonical_platform, is_not_a_platform
from app.intelligence.tactics import CANONICAL_TACTICS, canonical_tactic, canonical_tactics
from app.models.detection_rule import DetectionRule
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool


@pytest.mark.parametrize(
    "raw,expected",
    [
        # The four spellings that actually coexisted in the rules table
        ("Persistence", "persistence"),
        ("persistence", "persistence"),
        ("Defense Evasion", "defense-evasion"),
        ("DefenseEvasion", "defense-evasion"),
        ("command-and-control", "command-and-control"),
        ("CommandAndControl", "command-and-control"),
        ("Command and Control", "command-and-control"),
        # Sigma writes the namespaced tag
        ("attack.defense_evasion", "defense-evasion"),
        ("attack.privilege_escalation", "privilege-escalation"),
        # Enterprise tactic IDs
        ("TA0005", "defense-evasion"),
        ("ta0011", "command-and-control"),
        # v18 tactics are canonical already and must survive untouched
        ("stealth", "stealth"),
        ("defense-impairment", "defense-impairment"),
        # Shorthand
        ("C2", "command-and-control"),
        ("privesc", "privilege-escalation"),
        # Nothing to fold
        ("  Persistence  ", "persistence"),
        ("unknown", None),
        ("", None),
        (None, None),
    ],
)
def test_canonical_tactic_folds_every_spelling(raw, expected):
    assert canonical_tactic(raw) == expected


def test_canonical_tactic_output_is_in_the_vocabulary():
    for raw in ("Persistence", "DefenseEvasion", "TA0011", "attack.execution", "C2"):
        assert canonical_tactic(raw) in CANONICAL_TACTICS


def test_technique_ids_pass_through_unmangled():
    """The campaign coverage join looks for technique IDs in mitre_tactics as a
    fallback to source_ttps, so slugifying them would silently break it."""
    assert canonical_tactic("T1059.001") == "T1059.001"
    assert canonical_tactic("t1059") == "T1059"


def test_canonical_tactics_dedupes_and_keeps_order():
    folded = canonical_tactics(["Execution", "Persistence", "persistence", "attack.execution"])
    assert folded == ["execution", "persistence"]


def test_canonical_tactics_handles_empty_and_scalar():
    assert canonical_tactics([]) == []
    assert canonical_tactics(None) == []
    assert canonical_tactics("Persistence") == ["persistence"]


def test_unknown_tactic_is_slugified_not_dropped():
    """A tactic the vocabulary hasn't heard of is more likely a new ATT&CK
    release than junk — keeping it lowercase still collapses case variants."""
    assert canonical_tactic("Some New Tactic") == "some-new-tactic"


# --- the validators: the point is that no caller can skip them ---------------


def test_rule_validator_folds_on_construction():
    rule = DetectionRule(
        rule_type="sigma",
        title="t",
        rule_content="x",
        mitre_tactics=["Persistence", "persistence", "attack.defense_evasion", "DefenseEvasion"],
    )
    assert rule.mitre_tactics == ["persistence", "defense-evasion"]


def test_rule_validator_folds_on_assignment_and_setattr():
    rule = DetectionRule(rule_type="sigma", title="t", rule_content="x", mitre_tactics=[])
    rule.mitre_tactics = ["Command and Control"]
    assert rule.mitre_tactics == ["command-and-control"]
    setattr(rule, "mitre_tactics", ["InitialAccess"])
    assert rule.mitre_tactics == ["initial-access"]
    rule.mitre_tactics = []
    assert rule.mitre_tactics == []


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Financial Extortion", "financial"),
        ("financial extortion", "financial"),
        ("Financial gain", "financial"),
        ("Espionage", "espionage"),
        ("ideological", "hacktivism"),
        ("ransomware", "financial"),
        # No signal — stored as NULL rather than as a value the facet can't group
        ("Unknown", None),
        ("unknown", None),
        ("n/a", None),
        ("", None),
        (None, None),
        # Outside the vocabulary but real information: kept, lowercased, so the
        # facet still collapses the case variants
        ("Terrorism", "terrorism"),
        ("terrorism", "terrorism"),
    ],
)
def test_normalize_motivation(raw, expected):
    assert normalize_motivation(raw) == expected


def test_actor_validator_folds_on_construction_and_assignment():
    actor = ThreatActor(name="x", motivation="Financial Extortion")
    assert actor.motivation == "financial"
    actor.motivation = "Espionage"
    assert actor.motivation == "espionage"
    actor.motivation = "Unknown"
    assert actor.motivation is None


# --- platforms --------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Windows", "Windows"),
        ("windows", "Windows"),
        ('\\"Windows\\"', "Windows"),  # JSON escaping survived the extraction response
        ("macos", "macOS"),
        ("Mac", "macOS"),
        ("ios", "iOS"),
        # Distributions and vendor advisory strings are all Linux
        ("Ubuntu", "Linux"),
        ("Unix", "Linux"),
        ("Red Hat Enterprise Linux 9.4 Update Services for SAP Solutions", "Linux"),
        ("RHEL 8", "Linux"),
        # ATT&CK split the old "Cloud" platform; a provider name is IaaS
        ("AWS", "IaaS"),
        ("cloud", "IaaS"),
        ("Google Cloud", "IaaS"),
        ("Docker", "Containers"),
        ("Kubernetes", "Containers"),
        ("network appliance", "Network Devices"),
        ("", None),
        (None, None),
        ("unknown", None),
    ],
)
def test_canonical_platform(raw, expected):
    assert canonical_platform(raw) == expected


def test_unmapped_platform_keeps_its_wording():
    """ATT&CK has no name for these, but they still say where a tool runs."""
    assert canonical_platform("web") == "Web"
    assert canonical_platform("Web") == "Web"
    assert canonical_platform("OT") == "OT"
    assert canonical_platform("Industrial Control Systems") == "Industrial Control Systems"


def test_unmapped_platform_keeps_its_brackets():
    """Stripping edge punctuation off a kept value would leave it unbalanced."""
    assert canonical_platform("UNIX variants (UNIX, Linux, OSX)") == "UNIX variants (UNIX, Linux, OSX)"


@pytest.mark.parametrize(
    "value,rejected",
    [
        # Architectures, runtimes and build tags answer a different question
        ("x86_64", True),
        ("ppc64le", True),
        ("aarch64", True),
        ("Python", True),
        ("Node.js", True),
        ("el8eap", True),
        ("Multiple", True),
        ("9.4", True),
        # Real platforms, and unmapped-but-meaningful values, are not pruned
        ("Windows", False),
        ("Web", False),
        ("OT", False),
        ("WordPress", False),
    ],
)
def test_is_not_a_platform(value, rejected):
    assert is_not_a_platform(value) is rejected


def test_tool_validator_folds_and_dedupes():
    tool = Tool(name="x", platforms=["Windows", "windows", '\\"Windows\\"', "AWS", "Azure"])
    assert tool.platforms == ["Windows", "IaaS"]
    tool.platforms = ["Ubuntu", "linux"]
    assert tool.platforms == ["Linux"]


def test_tool_validator_keeps_unmapped_platforms():
    """The validator normalizes spelling but never drops — pruning is the
    backfill's job, where what it removed is reported."""
    tool = Tool(name="x", platforms=["web", "Python"])
    assert tool.platforms == ["Web", "Python"]


# --- country ----------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Unknown", None),
        ("unknown", None),
        ("unattributed", None),
        ("n/a", None),
        ("", None),
        (None, None),
        ("China", "China"),
        ("  Russia  ", "Russia"),
        ("North Korea", "North Korea"),
    ],
)
def test_normalize_country(raw, expected):
    assert normalize_country(raw) == expected


def test_actor_country_validator():
    actor = ThreatActor(name="x", country="Unknown")
    assert actor.country is None
    actor.country = "  China  "
    assert actor.country == "China"


# --- the dropdown itself ----------------------------------------------------


@pytest.mark.asyncio
async def test_autocomplete_groups_case_variants(db_session):
    """The reported bug: two spellings of one value listed as two suggestions.

    Tags and log-source names come from upstream rule repos as published, so
    these are folded when the suggestions are built rather than by rewriting
    the rows. The filter is case-insensitive, so the one suggestion offered
    still matches every spelling it stands for.
    """
    # "dns" outnumbers "DNS" 3:1, so the suggestion offered is the spelling
    # most rows use rather than whichever the tie broke toward.
    for tags in (["DNS", "dns"], ["dns"], ["dns"]):
        db_session.add(DetectionRule(rule_type="sigma", title="t", rule_content="x", tags=tags, data_sources=tags))
    await db_session.flush()

    for field in ("rule.tag", "rule.data_source"):
        suggestions = [s["text"] for s in await _array_element_values(db_session, field, "dns")]
        assert suggestions == ["dns"], f"{field} offered {suggestions}"
