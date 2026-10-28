"""What enrichment results write onto an entity.

Characterizes ``apply_enrichment_results_to_entity``: the Wikipedia / MITRE
ATT&CK / Malpedia column fills, the alias union, and the observable reputation
fold. Every case runs the applier and compares the entity's columns afterwards.
"""

import uuid

from sqlalchemy import select

from app.enrichment.entity_updater import apply_enrichment_results_to_entity
from app.models.entity_field_claim import EntityFieldClaim
from app.models.malware_family import MalwareFamily
from app.models.mitigation import Mitigation
from app.models.observable import Observable
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool
from app.models.ttp import TTP


def _ok(source: str, data: dict, status: str = "success") -> dict:
    return {"source_type": source, "status": status, "parsed_data": data}


WIKI = {
    "found": True,
    "wikipedia_url": "https://en.wikipedia.org/wiki/Fancy_Bear",
    "wikipedia_content": "Fancy Bear is a Russian cyber espionage group. More text.",
    "wikipedia_image_url": "https://upload.wikimedia.org/fancy.png",
    "first_paragraph": "  Fancy Bear is a Russian cyber espionage group.  ",
}
MITRE_GROUP = {
    "found": True,
    "mitre_id": " G0007 ",
    "description": "APT28 is a threat group attributed to the GRU.",
    "aliases": ["APT28", "Sofacy", "STRONTIUM", "AB", 42],
}
MALPEDIA_ACTOR = {
    "found": True,
    "description": "Malpedia text about APT28.",
    "alt_names": ["sofacy", "Pawn Storm", "  Sednit  "],
    "country": " RU ",
}


async def _add(db, entity):
    db.add(entity)
    await db.flush()
    return entity


async def _apply(db, entity_type, entity, results):
    changed = await apply_enrichment_results_to_entity(db, entity_type, entity.id, results)
    await db.flush()
    return changed


# ── Reference entities: fills, ranks, unions ─────────────────────────


async def test_blank_actor_takes_every_fill(db_session):
    actor = await _add(db_session, ThreatActor(name="APT28"))

    changed = await _apply(
        db_session,
        "threat_actor",
        actor,
        [_ok("wikipedia", WIKI), _ok("mitre_attack", MITRE_GROUP), _ok("malpedia", MALPEDIA_ACTOR)],
    )

    assert changed
    assert actor.wikipedia_url == WIKI["wikipedia_url"]
    assert actor.wikipedia_content == WIKI["wikipedia_content"]
    assert actor.wikipedia_image_url == WIKI["wikipedia_image_url"]
    assert actor.description == "Fancy Bear is a Russian cyber espionage group."  # Wikipedia ranks first
    assert actor.mitre_id == "G0007"
    # MITRE's list first, then Malpedia's; junk ("AB", non-strings, the name
    # itself) and case-insensitive repeats are dropped, whitespace trimmed.
    assert actor.aliases == ["Sofacy", "STRONTIUM", "Pawn Storm", "Sednit"]
    assert actor.country == "RU"


async def test_curated_actor_keeps_its_fields_and_gains_new_aliases(db_session):
    actor = await _add(
        db_session,
        ThreatActor(name="APT28", description="Analyst text.", mitre_id="G9999", country="CN", aliases=["Sednit"]),
    )

    changed = await _apply(
        db_session, "threat_actor", actor, [_ok("mitre_attack", MITRE_GROUP), _ok("malpedia", MALPEDIA_ACTOR)]
    )

    assert changed
    assert (actor.description, actor.mitre_id, actor.country) == ("Analyst text.", "G9999", "CN")
    assert actor.aliases == ["Sednit", "Sofacy", "STRONTIUM", "Pawn Storm"]


async def test_description_falls_through_the_ranked_sources(db_session):
    a = await _add(db_session, ThreatActor(name="Group A", description="   "))
    await _apply(db_session, "threat_actor", a, [_ok("malpedia", MALPEDIA_ACTOR), _ok("mitre_attack", MITRE_GROUP)])
    assert a.description == MITRE_GROUP["description"]

    b = await _add(db_session, ThreatActor(name="Group B"))
    await _apply(
        db_session,
        "threat_actor",
        b,
        [_ok("wikipedia", {**WIKI, "first_paragraph": " "}), _ok("mitre_attack", {"description": ""})]
        + [_ok("malpedia", MALPEDIA_ACTOR)],
    )
    assert b.description == MALPEDIA_ACTOR["description"]


async def test_mitre_id_falls_back_to_external_id(db_session):
    mitigation = await _add(db_session, Mitigation(name="User Training", mitre_id=None))
    await _apply(db_session, "mitigation", mitigation, [_ok("mitre_attack", {"external_id": "M1017"})])
    assert mitigation.mitre_id == "M1017"


async def test_tool_fills_references_and_platforms(db_session):
    tool = await _add(db_session, Tool(name="Mimikatz"))
    malpedia = {
        "found": True,
        "malpedia_url": " https://malpedia.caad.fkie.fraunhofer.de/details/win.mimikatz ",
        "urls": [{"url": "https://blog.example/mimikatz"}, "https://github.com/gentilkiwi/mimikatz", "x"],
        "alt_names": ["Mimikatz", "MimiKatz2"],
    }
    mitre = {"found": True, "platforms": ["Windows", None, 3], "aliases": ["mimikatz"]}

    await _apply(db_session, "tool", tool, [_ok("malpedia", malpedia), _ok("mitre_attack", mitre)])

    assert tool.malpedia_url == "https://malpedia.caad.fkie.fraunhofer.de/details/win.mimikatz"
    assert tool.github_url == "https://github.com/gentilkiwi/mimikatz"
    assert tool.platforms == ["Windows"]
    assert tool.aliases == ["MimiKatz2"]


async def test_tool_github_url_from_a_dict_reference_and_blank_platforms_stay(db_session):
    tool = await _add(db_session, Tool(name="Rubeus", platforms=["Linux"]))
    malpedia = {"urls": [{"url": "https://github.com/GhostPack/Rubeus"}]}
    await _apply(db_session, "tool", tool, [_ok("malpedia", malpedia), _ok("mitre_attack", {"platforms": ["Windows"]})])
    assert tool.github_url == "https://github.com/GhostPack/Rubeus"
    assert tool.platforms == ["Linux"]


async def test_ttp_takes_platforms_and_description(db_session):
    ttp = await _add(db_session, TTP(technique_id="T9101", technique_name="Phish"))
    await _apply(
        db_session, "ttp", ttp, [_ok("mitre_attack", {"description": "Adversaries phish.", "platforms": ["macOS"]})]
    )
    assert (ttp.description, ttp.platforms) == ("Adversaries phish.", ["macOS"])


async def test_wikipedia_columns_move_together_with_the_url(db_session):
    same = await _add(
        db_session,
        MalwareFamily(
            name="Emotet",
            wikipedia_url=WIKI["wikipedia_url"],
            wikipedia_content="old text",
            wikipedia_image_url="https://old/img.png",
            description="kept",
        ),
    )
    changed = await _apply(db_session, "malware", same, [_ok("wikipedia", WIKI, status="cached")])
    assert not changed
    assert (same.wikipedia_content, same.wikipedia_image_url) == ("old text", "https://old/img.png")

    moved = await _add(
        db_session,
        MalwareFamily(
            name="Trickbot",
            wikipedia_url="https://en.wikipedia.org/wiki/Old",
            wikipedia_content="old text",
            wikipedia_image_url="https://old/img.png",
            description="kept",
        ),
    )
    new = {**WIKI, "wikipedia_image_url": None}
    assert await _apply(db_session, "malware", moved, [_ok("wikipedia", new)])
    assert moved.wikipedia_url == WIKI["wikipedia_url"]
    assert moved.wikipedia_content == WIKI["wikipedia_content"]
    assert moved.wikipedia_image_url is None  # the old article's image doesn't stay

    nourl = await _add(db_session, MalwareFamily(name="Qakbot", wikipedia_url="https://x/y", description="kept"))
    assert not await _apply(db_session, "malware", nourl, [_ok("wikipedia", {"found": False})])
    assert nourl.wikipedia_url == "https://x/y"


async def test_only_usable_results_count_and_the_first_per_source_wins(db_session):
    actor = await _add(db_session, ThreatActor(name="Group C"))
    results = [
        {"source_type": "mitre_attack", "status": "error", "parsed_data": {"description": "from an error"}},
        {"source_type": "mitre_attack", "status": "rate_limited"},
        _ok("mitre_attack", {"description": "first"}),
        _ok("mitre_attack", {"description": "second"}),
        {"source_type": None, "status": "success", "parsed_data": {"description": "nameless"}},
    ]
    assert await _apply(db_session, "threat_actor", actor, results)
    assert actor.description == "first"


async def test_nothing_to_write_reports_no_change(db_session):
    actor = await _add(db_session, ThreatActor(name="Group D", description="d"))
    assert not await _apply(db_session, "threat_actor", actor, [_ok("mitre_attack", {"description": "x"})])
    assert not await apply_enrichment_results_to_entity(db_session, "threat_actor", uuid.uuid4(), [])
    assert not await apply_enrichment_results_to_entity(db_session, "no_such_type", actor.id, [])


async def test_fills_record_who_asserted_them(db_session):
    actor = await _add(db_session, ThreatActor(name="APT28"))
    await _apply(
        db_session,
        "threat_actor",
        actor,
        [_ok("wikipedia", WIKI), _ok("mitre_attack", MITRE_GROUP), _ok("malpedia", MALPEDIA_ACTOR)],
    )
    claims = {
        (c.field, c.source_ref)
        for c in (
            await db_session.execute(select(EntityFieldClaim).where(EntityFieldClaim.entity_id == actor.id))
        ).scalars()
    }
    assert {("description", "wikipedia"), ("mitre_id", "mitre_attack"), ("country", "malpedia")} <= claims


# ── Observables: the reputation fold ─────────────────────────────────


def _obs(value="45.33.32.156", **fields) -> Observable:
    return Observable(kind="ipv4", value=value, base_confidence=0.8, current_confidence=0.8, **fields)


async def test_reputation_folds_every_source(db_session):
    obs = await _add(db_session, _obs())
    changed = await _apply(
        db_session,
        "observable",
        obs,
        [
            _ok("shodan", {"found": True, "ports": "22, 443", "tags": "cloud, vpn", "hostnames": "", "vulns": None}),
            _ok("greynoise", {"found": True, "noise_class": "benign", "noise": False, "riot": False, "name": ""}),
            _ok(
                "virustotal",
                {"found": True, "detection_ratio": "3/92", "malicious_votes": 0, "asn": 63949, "country": "US"},
            ),
        ],
    )
    assert changed
    rep = dict(obs.reputation)
    assert rep.pop("enriched_at")
    assert rep == {
        "ports": "22, 443",
        "shodan_tags": "cloud, vpn",
        "gn_noise": False,
        "gn_riot": False,
        "vt_ratio": "3/92",
        "vt_malicious": 0,
    }
    # Network facts and the GreyNoise class live in their own columns.
    assert (obs.asn, obs.geo_country, obs.noise_class) == (63949, "US", "benign")
    assert obs.infra_tag == "vpn"


async def test_reputation_keeps_what_a_new_result_lacks(db_session):
    obs = await _add(db_session, _obs(asn=1, asn_org="Old AS", reputation={"ports": "80", "vt_ratio": "1/9"}))
    await _apply(
        db_session,
        "observable",
        obs,
        [
            _ok("virustotal", {"found": True, "detection_ratio": "5/90", "as_owner": ""}),
            _ok("shodan", {"ports": "8080"}),
        ],
    )
    assert (obs.asn, obs.asn_org) == (1, "Old AS")
    assert {k: obs.reputation[k] for k in ("ports", "vt_ratio")} == {"ports": "8080", "vt_ratio": "5/90"}


async def test_infra_tag_order_and_fill_only(db_session):
    first_known = await _add(db_session, _obs("10.0.0.1"))
    await _apply(db_session, "observable", first_known, [_ok("shodan", {"tags": "tor,proxy"})])
    assert first_known.infra_tag == "proxy"  # vpn, then proxy, then tor

    riot = await _add(db_session, _obs("8.8.4.4"))
    await _apply(db_session, "observable", riot, [_ok("greynoise", {"found": True, "riot": True, "name": "Google"})])
    assert riot.infra_tag == "benign_service"
    assert riot.reputation["gn_name"] == "Google"

    shodan_beats_riot = await _add(db_session, _obs("10.0.0.2"))
    await _apply(
        db_session,
        "observable",
        shodan_beats_riot,
        [_ok("greynoise", {"riot": True}), _ok("shodan", {"tags": "vpn"})],
    )
    assert shodan_beats_riot.infra_tag == "vpn"

    tagged = await _add(db_session, _obs("10.0.0.3", infra_tag="rmm"))
    await _apply(db_session, "observable", tagged, [_ok("shodan", {"tags": "vpn"}), _ok("greynoise", {"riot": True})])
    assert tagged.infra_tag == "rmm"


async def test_a_bare_result_still_stamps_the_reputation(db_session):
    obs = await _add(db_session, _obs())
    assert await _apply(db_session, "observable", obs, [_ok("virustotal", {"found": False})])
    assert list(obs.reputation) == ["enriched_at"]
    assert obs.infra_tag is None

    untouched = await _add(db_session, _obs("1.2.3.4", infra_tag="rmm"))
    assert not await _apply(db_session, "observable", untouched, [])
    assert untouched.reputation is None and untouched.infra_tag == "rmm"
