"""Context rules for autolinker matches, from the 2026-11 Review-queue triage.

Each test is a false positive the adjudicator had to remove by hand, plus the
real mention the rule must keep. "held" means the match goes to the pending
tier for the AI to confirm; "dropped" means it never links.
"""

import uuid
from unittest.mock import MagicMock

import pytest

import app.intelligence.autolinker as mod
from app.intelligence.autolinker import EntityVocabulary, scan_text


def _entity(name, aliases=None):
    entity = MagicMock()
    entity.id = uuid.uuid4()
    entity.name = name
    entity.aliases = aliases or []
    return entity


def _activate(**kwargs):
    vocab = EntityVocabulary()
    vocab.build_from_entities(
        actors=kwargs.get("actors", []),
        malware_families=kwargs.get("malware", []),
        countries=kwargs.get("countries", []),
        vendors=kwargs.get("vendors", []),
        products=kwargs.get("products", []),
        tools=kwargs.get("tools", []),
    )
    mod._vocabulary = vocab
    mod._vocab_version = vocab.version
    return vocab


@pytest.fixture
def tier_on(monkeypatch):
    monkeypatch.setattr(mod, "pending_tier_enabled", lambda: True)


@pytest.fixture
def tier_off(monkeypatch):
    monkeypatch.setattr(mod, "pending_tier_enabled", lambda: False)


def _state(text, name):
    """'linked', 'held' or None for the entity called ``name``."""
    for m in scan_text(text):
        if m["canonical_name"] == name:
            return "held" if m.get("provisional") else "linked"
    return None


# ── 1. Names that collide with ordinary text ───────────────────────────────


def test_rtm_release_suffix_and_rtmp_are_not_the_group(tier_on):
    _activate(actors=[_entity("RTM")])
    assert _state("Upgrade to Windows 10 RTM before support ends.", "RTM") is None
    assert _state("SQL Server 2019 RTM ships today.", "RTM") is None
    assert _state("The RTM build is the one customers get.", "RTM") is None
    assert _state("The stream uses RTMP and RTMPS.", "RTM") is None
    assert _state("The banking trojan was spread by RTM in Russia.", "RTM") == "linked"


def test_title_case_name_inside_a_longer_name_is_held(tier_on):
    _activate(actors=[_entity("Inception")], malware=[_entity("Quasar"), _entity("DEADWOOD")])
    assert _state("The startup joined the NVIDIA Inception program.", "Inception") == "held"
    assert _state("The app is built on the Quasar Framework for Vue.", "Quasar") == "held"
    assert _state("Talks at WWHF Deadwood covered phishing.", "DEADWOOD") is None
    # Said what it is, or standing alone: a mention.
    assert _state("The actor deployed Quasar RAT on the hosts.", "Quasar") == "linked"
    assert _state("Researchers tracked Inception across Europe.", "Inception") == "linked"
    assert _state("The DEADWOOD wiper hit Saudi targets.", "DEADWOOD") == "linked"


def test_name_run_drops_instead_of_holding_when_the_tier_is_off(tier_off):
    _activate(actors=[_entity("Inception")])
    assert _state("The startup joined the NVIDIA Inception program.", "Inception") is None
    assert _state("Researchers tracked Inception across Europe.", "Inception") == "linked"


def test_demonym_before_a_name_does_not_make_a_name_run(tier_on):
    _activate(
        actors=[_entity("Sandworm"), _entity("Kimsuky")],
        countries=[_entity("Russia", ["Russian"]), _entity("North Korea", ["North Korean"])],
    )
    assert _state("The Russian Sandworm unit struck again.", "Sandworm") == "linked"
    assert _state("Officials blamed Russia's Sandworm for the outage.", "Sandworm") == "linked"
    assert _state("The North Korean Kimsuky crew phished diplomats.", "Kimsuky") == "linked"


def test_camelcase_name_needs_its_own_casing():
    _activate(actors=[_entity("SynAck"), _entity("BlackWater")])
    assert _state("Synack runs a pentest platform.", "SynAck") is None
    assert _state("SynAck ransomware used doppelganging.", "SynAck") == "linked"
    assert _state("The Blackwater contractor was in the news.", "BlackWater") is None
    assert _state("The BlackWater backdoor used Cloudflare Workers.", "BlackWater") == "linked"


def test_initials_name_is_held_for_the_ai(tier_on):
    _activate(actors=[_entity("J.P. Morgan")])
    assert _state("Analysts at J.P. Morgan cut their forecast.", "J.P. Morgan") == "held"


def test_threat_name_shared_with_a_vendor_is_held(tier_on):
    _activate(malware=[_entity("Quasar7")], vendors=[_entity("Quasar7")])
    found = {m["entity_type"]: m.get("provisional") for m in scan_text("Quasar7 shipped an update.")}
    assert found == {"malware": True, "vendor": False}


def test_multiword_name_needs_its_head_word_cased():
    _activate(actors=[_entity("The Com")], vendors=[_entity("Push Security")])
    assert _state("It registers the COM object at startup.", "The Com") is None
    assert _state("Members of The Com were arrested.", "The Com") == "linked"
    assert _state("Checks run on push security patches.", "Push Security") is None
    assert _state("Push Security found the phishing kit.", "Push Security") == "linked"


def test_inc_acronym_is_not_the_company_suffix(tier_on):
    _activate(actors=[_entity("INC Ransom", ["INC"])])
    assert _state("Acme Holdings, Inc. reported a breach.", "INC Ransom") is None
    assert _state("ACME INC was named on the leak site.", "INC Ransom") == "held"
    # "INC" is also a dictionary word, so even a clean mention waits for the AI.
    assert _state("The INC gang posted the data.", "INC Ransom") == "held"


def test_mask_inside_cpumask_is_not_careto(tier_on):
    _activate(actors=[_entity("Careto", ["Mask"])])
    assert _state("The patch fixes cpumask handling.", "Careto") is None
    assert _state("struct cpumask *mask = NULL;", "Careto") is None


# ── 2. Purely numeric names ────────────────────────────────────────────────


def test_numeric_name_is_not_a_number(tier_on):
    _activate(actors=[_entity("764")])
    for text in (
        "The process (PID: 764) spawned cmd.exe.",
        "It listens on port 764 for commands.",
        "Losses reached $764 million.",
        "Over 1,764 hosts were hit.",
        "It ran for 764 seconds.",
        "Build 2.764 is affected.",
    ):
        assert _state(text, "764") is None, text
    # A real mention is still only held: the AI decides.
    assert _state("Members of 764 groomed minors online.", "764") == "held"


def test_numeric_name_drops_with_the_tier_off(tier_off):
    _activate(actors=[_entity("764")])
    assert _state("Members of 764 groomed minors online.", "764") is None


# ── 3. Names inside file names and paths ───────────────────────────────────


def test_name_inside_a_file_name_or_path_is_dropped():
    _activate(vendors=[_entity("Push Security")], products=[_entity("Ed25519")])
    assert _state("The workflow push security-audit.yml runs nightly.", "Push Security") is None
    assert _state("Copy the key to ~/.ssh/id_ed25519 first.", "Ed25519") is None
    assert _state("Copy the key to ~/.ssh/id-ed25519 first.", "Ed25519") is None
    assert _state("The key lives in /home/user/ed25519.pub now.", "Ed25519") is None
    assert _state("It signs with Ed25519 keys.", "Ed25519") == "linked"


def test_hyphen_before_a_non_ascii_letter_does_not_crash():
    # isalnum() takes "é"; the ASCII-only run regex does not
    _activate(products=[_entity("Ed25519")])
    assert _state("It signs with Ed25519-é keys.", "Ed25519") == "linked"
    assert _state("It signs with Ed25519-² keys.", "Ed25519") == "linked"


# ── 4. Languages and surnames are not countries ────────────────────────────


def test_language_words_do_not_link_countries():
    _activate(
        countries=[
            _entity("Iran", ["Persian", "Iranian"]),
            _entity("Spain", ["Spanish"]),
            _entity("Portugal", ["Portuguese"]),
        ]
    )
    assert _state("Staff who speak Persian answered the calls.", "Iran") is None
    assert _state("The lure was written in Spanish.", "Spain") is None
    assert _state("A Spanish-speaking crew ran the scam.", "Spain") is None
    assert _state("The page shows Portuguese text to visitors.", "Portugal") is None
    # A demonym used as one, and the country's own name, still link.
    assert _state("Iranian hackers targeted the port.", "Iran") == "linked"
    assert _state("Attacks hit hospitals in Spain.", "Spain") == "linked"


def test_simplified_chinese_is_a_language():
    _activate(countries=[_entity("China", ["Chinese"])])
    assert _state("The operator's scripts carry Simplified Chinese comments.", "China") is None
    assert _state("Chinese hackers breached the ministry.", "China") == "linked"


def test_country_name_inside_a_longer_place_name_is_dropped(tier_on):
    _activate(
        countries=[
            _entity("United States", ["America", "American"]),
            _entity("Korea"),
            _entity("Sudan"),
            _entity("Ukraine"),
        ]
    )
    assert _state("The broker ships freight across North America.", "United States") is None
    assert _state("The Latin American leader in access control.", "United States") is None
    assert _state("Investigators blamed North Korea.", "Korea") is None
    assert _state("Fighting spread in South Sudan.", "Sudan") is None
    # A region of the country is still the country.
    assert _state("Power went out across eastern Ukraine.", "Ukraine") == "linked"
    assert _state("American banks reported the fraud.", "United States") == "linked"


def test_surname_matching_a_demonym_is_held(tier_on):
    _activate(countries=[_entity("Moldova", ["Moldovan"])])
    assert _state("The talk was given by researcher Adi Moldovan last week.", "Moldova") == "held"
    assert _state("A Moldovan official confirmed the arrests.", "Moldova") == "linked"


# ── 5. Inline "Related:" headlines ─────────────────────────────────────────


def test_related_headlines_link_nothing():
    _activate(actors=[_entity("APT28")], vendors=[_entity("Fortinet")])
    inline = (
        "The flaw was patched in May. Related: APT28 Targets Fortinet Devices in New Campaign "
        "Researchers said the bug is easy to exploit."
    )
    assert _state(inline, "APT28") is None
    assert _state(inline, "Fortinet") is None
    line = "Patch now.\nRelated: APT28 Hits Fortinet Again\nNothing else to add."
    assert _state(line, "APT28") is None
    # A CVE in the headline is the other article's.
    assert not [m for m in scan_text("Related: CVE-2025-1234 Exploited in the Wild") if m["entity_type"] == "cve"]


def test_text_after_an_inline_related_headline_still_links():
    _activate(vendors=[_entity("Microsoft")])
    text = "Patch now. Related: Hackers Exploit New Bug Microsoft said the fix ships today."
    assert _state(text, "Microsoft") == "linked"


# ── 7. Hyphenated compounds ────────────────────────────────────────────────


def test_hyphenated_compound_is_a_different_name():
    _activate(
        malware=[_entity("X-Agent")],
        vendors=[_entity("Proton")],
        products=[_entity("LangChain", ["Langchain"])],
    )
    assert _state("The request sets an X-Agent-Secret header.", "X-Agent") is None
    assert _state("Proton-J is an AMQP library.", "Proton") is None
    assert _state("The Langchain-Chatchat project was patched.", "LangChain") is None
    # A word after the hyphen that only describes it keeps the match.
    assert _state("The X-Agent-based implant beaconed home.", "X-Agent") == "linked"
    assert _state("An APT28-Linked Group Uses X-Agent", "X-Agent") == "linked"


# ── 8. Title-case common words; lower-case packages ────────────────────────


def test_common_word_product_inside_a_capitalised_phrase_is_dropped():
    _activate(products=[_entity("Microsoft Teams", ["Teams"])])
    assert _state("Most SOC Teams lack the staff.", "Microsoft Teams") is None
    assert _state("The lure arrived over Teams chat.", "Microsoft Teams") == "linked"
    assert _state("Attackers abused Microsoft Teams again.", "Microsoft Teams") == "linked"


def test_lowercase_package_name_matches_lowercase_text_only(tier_off):
    _activate(tools=[_entity("axios")])
    assert _state("The attacker published a malicious axios release to npm.", "axios") == "linked"
    assert _state("The story was first reported by Axios on Monday.", "axios") is None


def test_lowercase_package_capitalised_mid_sentence_is_held(tier_on):
    _activate(tools=[_entity("axios")])
    assert _state("The story was first reported by Axios on Monday.", "axios") == "held"
    # One clean lower-case mention elsewhere links it.
    text = "The story was first reported by Axios. The axios package was trojanized."
    assert _state(text, "axios") == "linked"


# ── CVE ids with a CVSS score glued on ─────────────────────────────────────


def _cves(text):
    return sorted(m["lookup_key"] for m in scan_text(text) if m["entity_type"] == "cve")


def test_cvss_score_glued_onto_a_cve_id_is_stripped():
    _activate()
    assert _cves("CVE-2026-10384910.0 Critical remote code execution") == ["CVE-2026-103849"]
    assert _cves("CVE-2026-1027649.8 High") == ["CVE-2026-102764"]
    assert _cves("Patch CVE-2024-21762 now.") == ["CVE-2024-21762"]


def test_implausible_cve_ids_are_not_matched():
    _activate()
    assert _cves("See CVE-2026-123456789 for details.") == []
    assert _cves("See CVE-2026-012345 for details.") == []


def test_cve_paragraph_indices_survive_the_extractor():
    _activate()
    matches = scan_text([(0, "CVE-2024-21762 is critical."), (1, "Nothing."), (2, "CVE-2024-21762 again.")])
    assert [m["paragraph_indices"] for m in matches if m["entity_type"] == "cve"] == [[0, 2]]
