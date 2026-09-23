"""Alias coverage tests for the autolinker vocabulary.

Every alias of every alias-bearing entity type must map to the CANONICAL
entity id, so an alias mention links to the existing entity instead of
looking like a new one. Guards the dedup work: merges fold the loser's name
into the winner's aliases, and those aliases must keep resolving to the
winner in the extraction path.
"""

import uuid
from unittest.mock import MagicMock

from app.intelligence.autolinker import EntityVocabulary, scan_text


def _make_entity(name, aliases=None):
    entity = MagicMock()
    entity.id = uuid.uuid4()
    entity.name = name
    entity.aliases = aliases or []
    return entity


def _activate(vocab):
    import app.intelligence.autolinker as mod

    mod._vocabulary = vocab
    mod._vocab_version = vocab.version


def _build(**kwargs):
    vocab = EntityVocabulary()
    vocab.build_from_entities(
        actors=kwargs.get("actors", []),
        malware_families=kwargs.get("malware", []),
        countries=kwargs.get("countries", []),
        vendors=kwargs.get("vendors", []),
        products=kwargs.get("products", []),
        tools=kwargs.get("tools", []),
        mitigations=kwargs.get("mitigations", []),
    )
    _activate(vocab)
    return vocab


def test_aliases_map_to_canonical_id_for_every_type():
    """An alias match must carry the canonical entity id + name for all types."""
    cases = {
        "threat_actor": ("actors", _make_entity("APT29", ["Cozy Bear", "Midnight Blizzard"])),
        "malware": ("malware", _make_entity("Pegasus", ["Chrysaor", "NSO Pegasus"])),
        "country": ("countries", _make_entity("Netherlands", ["Holland"])),
        "vendor": ("vendors", _make_entity("Microsoft Corporation", ["MSFT Corp"])),
        "product": ("products", _make_entity("Windows Server", ["WinServer 2022"])),
        "tool": ("tools", _make_entity("Cobalt Strike", ["CobaltStrike Beacon"])),
    }
    for entity_type, (kwarg, entity) in cases.items():
        _build(**{kwarg: [entity]})
        for alias in entity.aliases:
            matches = scan_text(f"Researchers observed {alias} activity this week.")
            typed = [m for m in matches if m["entity_type"] == entity_type]
            assert typed, f"{entity_type} alias {alias!r} produced no match"
            assert typed[0]["entity_id"] == str(entity.id), (
                f"{entity_type} alias {alias!r} did not resolve to the canonical entity id"
            )
            assert typed[0]["canonical_name"] == entity.name


def test_alias_and_name_mentions_collapse_to_one_entity():
    """Mentioning the name and an alias in one text yields a single linked entity."""
    malware = _make_entity("Pegasus", ["Chrysaor"])
    _build(malware=[malware])
    matches = scan_text("Pegasus, also known as Chrysaor, targets mobile devices.")
    malware_matches = [m for m in matches if m["entity_type"] == "malware"]
    assert len(malware_matches) == 1
    assert malware_matches[0]["entity_id"] == str(malware.id)
    assert set(malware_matches[0]["surface_forms"]) == {"Pegasus", "Chrysaor"}


def test_alias_duplicating_name_is_not_double_registered():
    """Merges can leave an alias equal to the canonical name (case variant).

    The vocabulary must register that surface form once, so a single mention
    doesn't accumulate duplicate payload entries for the same entity.
    """
    actor = _make_entity("LockBit", ["LOCKBIT", "lockbit", "LockBit Gang"])
    vocab = _build(actors=[actor])
    # name + 1 case-duplicate collapses: LockBit / LOCKBIT / lockbit are one
    # lowercased form; "LockBit Gang" is a second.
    assert vocab.entry_count == 2

    payload = vocab.automaton.get("lockbit")
    assert len(payload) == 1
    assert payload[0].entity_id == actor.id


def test_two_entities_sharing_a_surface_form_both_link():
    """Shared surface forms still return each distinct canonical entity."""
    malware = _make_entity("Pegasus", [])
    actor = _make_entity("Winged Horse", ["Pegasus"])
    _build(actors=[actor], malware=[malware])
    matches = scan_text("New Pegasus samples were attributed this week.")
    ids = {(m["entity_type"], m["entity_id"]) for m in matches}
    assert ("malware", str(malware.id)) in ids
    assert ("threat_actor", str(actor.id)) in ids


# ---------------------------------------------------------------------------
# Version stability
# ---------------------------------------------------------------------------
#
# `_ensure_vocabulary` decides freshness by comparing a worker's local version
# against the one published in Redis. The version used to be a build timestamp,
# so two workers loading identical data always disagreed and rebuilt each other
# in a loop — a ~27s full rebuild in front of nearly every autolink call.


def test_version_is_identical_for_identical_input():
    actor = _make_entity("Lazarus Group", ["Hidden Cobra"])
    malware = _make_entity("Emotet", ["Geodo"])

    a = EntityVocabulary()
    a.build_from_entities(actors=[actor], malware_families=[malware])
    b = EntityVocabulary()
    b.build_from_entities(actors=[actor], malware_families=[malware])

    assert a.version == b.version


def test_version_ignores_row_order():
    """The source queries carry no ORDER BY — workers may load rows in any order."""
    one = _make_entity("Lazarus Group", ["Hidden Cobra"])
    two = _make_entity("Emotet", ["Geodo"])
    three = _make_entity("Sandworm", [])

    forward = EntityVocabulary()
    forward.build_from_entities(malware_families=[], actors=[one, two, three])
    reverse = EntityVocabulary()
    reverse.build_from_entities(malware_families=[], actors=[three, two, one])

    assert forward.version == reverse.version


def test_version_changes_when_an_alias_is_added():
    before = EntityVocabulary()
    before.build_from_entities(malware_families=[], actors=[_make_entity("Lazarus Group", ["Hidden Cobra"])])
    after = EntityVocabulary()
    after.build_from_entities(malware_families=[], actors=[_make_entity("Lazarus Group", ["Hidden Cobra", "APT38"])])

    assert before.version != after.version


def test_version_changes_when_an_entity_is_renamed():
    original = _make_entity("Lazarus Group", ["Hidden Cobra"])
    before = EntityVocabulary()
    before.build_from_entities(malware_families=[], actors=[original])

    original.name = "Lazarus"
    after = EntityVocabulary()
    after.build_from_entities(malware_families=[], actors=[original])

    assert before.version != after.version


def test_rebuilding_the_same_vocabulary_object_is_stable():
    """A worker that rebuilds unchanged data must land on the version it already had."""
    actor = _make_entity("Lazarus Group", ["Hidden Cobra"])
    vocab = EntityVocabulary()
    vocab.build_from_entities(malware_families=[], actors=[actor])
    first = vocab.version
    vocab.build_from_entities(malware_families=[], actors=[actor])

    assert vocab.version == first
