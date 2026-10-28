"""Relation outputs, ETDA Threat Group Cards and ransomware.live group profiles.

The ETDA export and the ransomware.live /v2/group/akira answer are trimmed
recordings of the live sources (2026-10-28) in ``tests/fixtures/enrichment``,
served through a real SourceGateway by ``httpx.MockTransport``.
"""

import copy
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select

from app.config import settings
from app.enrichment.base import EnrichmentData, Source
from app.enrichment.etda import ETDASource, card_facts, match_cards, sync_etda
from app.enrichment.gateway import SourceGateway
from app.enrichment.manifest import Egress, License, Quota, Relation
from app.enrichment.pipeline import apply_catalog_result
from app.enrichment.ransomware_groups import group_facts, sync_group_profiles
from app.enrichment.registry import SOURCE_REGISTRY
from app.enrichment.relations import RESOLVABLE_TARGETS, apply_relations, relations_for
from app.intelligence.relationship_matrix import orient_relationship
from app.intelligence.sectors import sector_uuid
from app.models.country import Country
from app.models.enrichment import EnrichmentResult, EnrichmentSource, EntityContext, EntityRelationClaim
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import MalwareFamily
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.sector import ThreatActorTargetSector
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool
from app.models.ttp import TTP

FIXTURES = Path(__file__).parent / "fixtures" / "enrichment"
CARDS = json.loads((FIXTURES / "etda_cards.json").read_text())
AKIRA = json.loads((FIXTURES / "ransomware_live_group_akira.json").read_text())


def _card(prefix: str) -> dict:
    return next(c for c in CARDS["values"] if c["actor"].startswith(prefix))


def _gateway(source_type: str, handler) -> SourceGateway:
    return SourceGateway(
        source_type,
        rate_limit_config={"requests_per_period": 100, "period_seconds": 60},
        inner=httpx.MockTransport(handler),
    )


def _serve(payload, status: int = 200):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if status != 200:
            return httpx.Response(status, headers={"Retry-After": "600"})
        return httpx.Response(200, json=payload)

    handler.requests = requests
    return handler


async def _claims(db, source_type: str, entity_id=None) -> list[EntityRelationClaim]:
    query = select(EntityRelationClaim).where(EntityRelationClaim.source_type == source_type)
    if entity_id is not None:
        query = query.where(EntityRelationClaim.entity_id == entity_id)
    return list((await db.execute(query.order_by(EntityRelationClaim.target_key))).scalars())


async def _edges(db, entity_id) -> dict[tuple[str, str, str], EntityRelationship]:
    rows = (await db.execute(select(EntityRelationship).where(EntityRelationship.source_id == entity_id))).scalars()
    return {(r.relationship_type, r.target_type, str(r.target_id)): r for r in rows}


async def _context(db, entity_id, source_type) -> dict:
    rows = (
        await db.execute(
            select(EntityContext).where(EntityContext.entity_id == entity_id, EntityContext.source_type == source_type)
        )
    ).scalars()
    return {r.key: r.value for r in rows}


async def _sector_rows(db, actor_id) -> dict[str, ThreatActorTargetSector]:
    rows = (
        await db.execute(select(ThreatActorTargetSector).where(ThreatActorTargetSector.threat_actor_id == actor_id))
    ).scalars()
    return {str(r.sector_id): r for r in rows}


async def _count(db, model) -> int:
    return (await db.execute(select(func.count()).select_from(model))).scalar_one()


# ── The manifests ────────────────────────────────────────────────────


def test_every_relation_output_is_one_the_matrix_allows_and_can_resolve():
    declared = [(cls, r) for cls in SOURCE_REGISTRY.values() for r in cls.relations()]
    assert {(cls.source_type, r.key) for cls, r in declared} >= {
        ("etda", "sectors"),
        ("etda", "countries"),
        ("etda", "tools"),
        ("ransomware_live", "techniques"),
        ("ransomware_live", "tools"),
        ("threatfox", "c2_families"),
        ("threatfox", "families"),
        ("urlhaus", "families"),
        ("malwarebazaar", "families"),
    }
    for cls, relation in declared:
        for entity_type in cls.applies_to:
            for target_type in relation.target_types:
                # Either way round: an observable's source names the family behind it.
                assert orient_relationship(entity_type, relation.relation, target_type), (cls, relation)
                assert target_type in RESOLVABLE_TARGETS, (cls, relation)


def test_licenses_bar_commercial_use():
    assert ETDASource.license.commercial_ok is False
    assert "CC BY-NC-SA 4.0" in ETDASource.license.name
    assert SOURCE_REGISTRY["ransomware_live"].license.commercial_ok is False


# ── The applier, through a source of its own ─────────────────────────


class _Ref(Source):
    """A reference source with relations the matrix allows and one it doesn't."""

    source_type = "ref_catalog"
    display_name = "Reference catalog"
    applies_to = {"threat_actor": None}
    quota = Quota(10, 60, daily_budget=None)
    egress = Egress.NONE
    license = License("test")
    outputs = (
        Relation("tools", "uses", ("malware", "tool"), item={"name": "name", "evidence": "how"}),
        Relation("places", "uses", ("ttp", "country")),
        Relation("victims", "targets", ("tool",)),
    )


class _Other(_Ref):
    source_type = "other_catalog"
    display_name = "Other catalog"


@pytest.fixture
def ref_sources(monkeypatch):
    monkeypatch.setitem(SOURCE_REGISTRY, "ref_catalog", _Ref)
    monkeypatch.setitem(SOURCE_REGISTRY, "other_catalog", _Other)


@pytest.fixture
async def world(db_session):
    actor = ThreatActor(name="APT29", aliases=["Cozy Bear"])
    cobalt = Tool(name="Cobalt Strike", aliases=["CobaltStrike"])
    duke = MalwareFamily(name="CozyDuke")
    twin_tool, twin_malware = Tool(name="BloodHound"), MalwareFamily(name="BloodHound")
    russia = Country(name="Russia", iso_code="RU")
    db_session.add_all([actor, cobalt, duke, twin_tool, twin_malware, russia])
    await db_session.flush()
    return {"actor": actor, "cobalt": cobalt, "duke": duke, "russia": russia}


def _tools(*names) -> dict:
    return {"tools": [{"name": n, "how": f"{n} in the toolkit"} for n in names]}


async def test_relations_resolve_never_create_and_hold_the_rest(db_session, ref_sources, world):
    actor = world["actor"]
    tools_before, malware_before = await _count(db_session, Tool), await _count(db_session, MalwareFamily)

    data = {**_tools("cobaltstrike", "CozyDuke", "BloodHound", "Nonexistent RAT"), "places": ["Russia"]}
    assert await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", data)

    assert (await _count(db_session, Tool), await _count(db_session, MalwareFamily)) == (tools_before, malware_before)
    claims = {c.target_name: c for c in await _claims(db_session, "ref_catalog")}
    # Exact name or alias in the resolver's normalized form; a tool and a
    # malware family sharing a name is ambiguous; an unknown name is held.
    assert (claims["cobaltstrike"].target_type, claims["cobaltstrike"].target_id) == ("tool", world["cobalt"].id)
    assert (claims["CozyDuke"].target_type, claims["CozyDuke"].target_id) == ("malware", world["duke"].id)
    assert (claims["BloodHound"].target_id, claims["BloodHound"].held_reason) == (None, "ambiguous")
    assert (claims["Nonexistent RAT"].target_id, claims["Nonexistent RAT"].held_reason) == (None, "unknown")
    # "Russia" resolves to a country, and the matrix has no actor-uses-country:
    # no claim. The "victims" output ("targets" a tool) never runs at all.
    assert "Russia" not in claims
    assert [r.key for r in relations_for(_Ref, "threat_actor")] == ["tools", "places"]

    edges = await _edges(db_session, actor.id)
    cobalt = edges[("uses", "tool", str(world["cobalt"].id))]
    assert (cobalt.source, cobalt.confidence, cobalt.description) == (
        "enrichment",
        "probable",
        "cobaltstrike in the toolkit",
    )
    assert set(edges) == {("uses", "tool", str(world["cobalt"].id)), ("uses", "malware", str(world["duke"].id))}


async def test_a_rerun_changes_nothing_and_a_held_name_links_once_the_entity_exists(db_session, ref_sources, world):
    actor = world["actor"]
    data = _tools("Cobalt Strike", "Nonexistent RAT")
    assert await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", data)
    first = [(c.target_key, c.target_id, c.first_seen_at) for c in await _claims(db_session, "ref_catalog")]

    assert not await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", data)
    assert [(c.target_key, c.target_id, c.first_seen_at) for c in await _claims(db_session, "ref_catalog")] == first
    assert len(await _edges(db_session, actor.id)) == 1

    rat = Tool(name="Nonexistent RAT")
    db_session.add(rat)
    await db_session.flush()
    assert await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", data)
    assert ("uses", "tool", str(rat.id)) in await _edges(db_session, actor.id)
    assert all(c.held_reason is None for c in await _claims(db_session, "ref_catalog"))


async def test_withdrawal_keeps_what_another_source_still_claims(db_session, ref_sources, world):
    actor, cobalt, duke = world["actor"], world["cobalt"], world["duke"]
    await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", _tools("Cobalt Strike", "CozyDuke"))
    await apply_relations(db_session, "threat_actor", actor.id, "other_catalog", _tools("Cobalt Strike"))

    # The reference source drops both: CozyDuke's edge goes; Cobalt Strike's
    # stays, because the other source still claims it.
    assert await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", {"tools": []})
    assert await _claims(db_session, "ref_catalog") == []
    assert [c.target_name for c in await _claims(db_session, "other_catalog")] == ["Cobalt Strike"]
    assert set(await _edges(db_session, actor.id)) == {("uses", "tool", str(cobalt.id))}

    await apply_relations(db_session, "threat_actor", actor.id, "other_catalog", {})
    assert await _edges(db_session, actor.id) == {}
    assert ("uses", "malware", str(duke.id)) not in await _edges(db_session, actor.id)


async def test_edges_from_other_paths_are_never_taken_or_removed(db_session, ref_sources, world):
    actor, cobalt, duke = world["actor"], world["cobalt"], world["duke"]
    mitre = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="confirmed",
        source="external_feed",
        description="MITRE ATT&CK",
    )
    rejected = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="malware",
        target_id=duke.id,
        relationship_type="uses",
        confidence="possible",
        source="analyst_rejected",
    )
    db_session.add_all([mitre, rejected])
    await db_session.flush()

    assert not await apply_relations(
        db_session, "threat_actor", actor.id, "ref_catalog", _tools("Cobalt Strike", "CozyDuke")
    )
    assert (mitre.source, mitre.confidence, mitre.description) == ("external_feed", "confirmed", "MITRE ATT&CK")
    assert (rejected.source, rejected.confidence) == ("analyst_rejected", "possible")
    assert len(await _claims(db_session, "ref_catalog")) == 2

    await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", {})
    edges = await _edges(db_session, actor.id)
    assert edges[("uses", "tool", str(cobalt.id))].source == "external_feed"
    assert edges[("uses", "malware", str(duke.id))].source == "analyst_rejected"


async def test_a_co_occurrence_edge_is_lifted_then_handed_back(db_session, ref_sources, world):
    actor, cobalt = world["actor"], world["cobalt"]
    entry_id = uuid.uuid4()  # an article the co-mention came from
    edge = EntityRelationship(
        source_type="threat_actor",
        source_id=actor.id,
        target_type="tool",
        target_id=cobalt.id,
        relationship_type="uses",
        confidence="possible",
        source="co_occurrence",
        evidence_entry_ids=[entry_id],
    )
    db_session.add(edge)
    await db_session.flush()

    assert await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", _tools("Cobalt Strike"))
    assert (edge.source, edge.confidence, edge.description) == (
        "enrichment",
        "probable",
        "Cobalt Strike in the toolkit",
    )

    assert await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", {})
    assert (edge.source, edge.confidence) == ("co_occurrence", "possible")
    assert edge.evidence_entry_ids == [entry_id]

    edge.adjudication_verdict = "coincidental"
    await db_session.flush()
    assert not await apply_relations(db_session, "threat_actor", actor.id, "ref_catalog", _tools("Cobalt Strike"))
    assert (edge.source, edge.confidence) == ("co_occurrence", "possible")


async def test_target_sectors_land_in_the_junction_and_leave_other_doors_alone(db_session):
    actor = ThreatActor(name="Turla")
    db_session.add(actor)
    await db_session.flush()
    gov, energy, media = sector_uuid("government"), sector_uuid("energy"), sector_uuid("media")
    db_session.add_all(
        [
            ThreatActorTargetSector(threat_actor_id=actor.id, sector_id=energy, source="rollup", article_count=3),
            ThreatActorTargetSector(threat_actor_id=actor.id, sector_id=media, source="analyst"),
        ]
    )
    await db_session.flush()

    data = {"sectors": ["government", "energy", "media"]}
    assert await apply_relations(db_session, "threat_actor", actor.id, "etda", data)
    rows = await _sector_rows(db_session, actor.id)
    assert {k: r.source for k, r in rows.items()} == {
        str(gov): "enrichment",
        str(energy): "enrichment",
        str(media): "analyst",
    }
    assert set(actor.targeted_sectors) == {"Government", "Energy", "Media"}
    # Sector targets live in the junction, not entity_relationships.
    assert await _edges(db_session, actor.id) == {}

    assert await apply_relations(db_session, "threat_actor", actor.id, "etda", {"sectors": []})
    rows = await _sector_rows(db_session, actor.id)
    # Its own row goes, the rollup gets its row back, the analyst keeps theirs.
    assert {k: r.source for k, r in rows.items()} == {str(energy): "rollup", str(media): "analyst"}
    assert set(actor.targeted_sectors) == {"Energy", "Media"}


# ── ETDA ─────────────────────────────────────────────────────────────


@pytest.fixture
async def etda_world(db_session):
    countries = {
        name: Country(name=name, iso_code=iso, aliases=aliases)
        for name, iso, aliases in (
            ("Russia", "RU", []),
            ("North Korea", "KP", ["DPRK"]),
            ("United States", "US", ["USA"]),
            ("Japan", "JP", []),
        )
    }
    actors = {
        "apt29": ThreatActor(name="APT29", mitre_id="G0016", motivation="espionage"),
        # Owns "The Dukes", which the APT 29 card also lists.
        "dukes": ThreatActor(name="The Dukes"),
        "lazarus": ThreatActor(name="Lazarus", aliases=["Hidden Cobra"]),
        "kimsuky": ThreatActor(name="Kimsuky", mitre_id="G0094"),
    }
    tools = {"Cobalt Strike": Tool(name="Cobalt Strike"), "AdFind": Tool(name="AdFind")}
    malware = {"CozyDuke": MalwareFamily(name="CozyDuke"), "AppleJeus": MalwareFamily(name="AppleJeus")}
    db_session.add_all([*countries.values(), *actors.values(), *tools.values(), *malware.values()])
    db_session.add(EnrichmentSource(source_type="etda", display_name="ETDA Threat Group Cards", is_enabled=True))
    await db_session.flush()
    return {"actors": actors, "countries": countries, "tools": tools, "malware": malware}


def test_card_facts_read_the_export():
    facts = card_facts(_card("APT 29"))
    assert facts["names"][:3] == ["APT 29", "Cozy Bear", "The Dukes"]
    assert (facts["country"], facts["motivation"], facts["mitre_id"]) == ("Russia", "espionage", "G0016")
    # ETDA's sector names onto the 21: Embassies and Law enforcement are
    # government, Think Tanks and NGOs are NGO; Imagery is no sector at all.
    assert facts["sectors"] == [
        "aerospace", "defense", "education", "government", "energy", "financial-services", "healthcare",
        "media", "ngo", "telecommunications", "transportation",
    ]  # fmt: skip
    lazarus = card_facts(_card("Lazarus Group"))
    assert "transportation" in lazarus["sectors"] and "cryptocurrency" in lazarus["sectors"]  # Shipping, BitCoin
    assert lazarus["mitre_id"] == "G0032"
    assert card_facts(_card("Kimsuky"))["mitre_id"] == "G0094"
    assert card_facts(_card("AeroBlade"))["country"] is None  # "[Unknown]"

    op = facts["operations"][0]
    assert op["date"] == "2013-02"
    assert op["text"].startswith("Since the original announcement") and op["text"].endswith(
        "(https://securelist.com/the-miniduke-mystery-pdf-0-day-government-spy-assembler-0x29a-micro-backdoor/31112/)"
    )
    assert facts["operations"][2]["text"].startswith("Operation “Ghost” (https://www.welivesecurity.com/")
    assert facts["card"]["url"] == (
        "https://apt.etda.or.th/cgi-bin/showcard.cgi?g=APT%2029%2C%20Cozy%20Bear%2C%20The%20Dukes&n=1"
    )


async def test_cards_match_by_group_id_then_by_exact_name(db_session, etda_world):
    actors = etda_world["actors"]
    matches, stats = await match_cards(db_session, CARDS["values"])
    named = {actor_id: card["actor"].split(",")[0] for actor_id, card in matches.items()}
    assert named == {
        actors["apt29"].id: "APT 29",
        actors["lazarus"].id: "Lazarus Group",
        actors["kimsuky"].id: "Kimsuky",
    }
    assert stats == {"cards": 5, "ambiguous": 0, "unmatched": 2}  # Agrius and AeroBlade: no such actor

    # An actor whose MITRE id the card contradicts is a different group.
    actors["lazarus"].mitre_id = "G0138"
    await db_session.flush()
    matches, stats = await match_cards(db_session, CARDS["values"])
    assert actors["lazarus"].id not in matches and stats["unmatched"] == 3

    # A card whose names land on two actors matches neither.
    db_session.add_all([ThreatActor(name="Agrius"), ThreatActor(name="Pink Sandstorm")])
    await db_session.flush()
    _, stats = await match_cards(db_session, CARDS["values"])
    assert stats["ambiguous"] == 1


async def test_etda_sync_fills_gates_claims_and_shows(db_session, etda_world):
    actors, countries = etda_world["actors"], etda_world["countries"]
    handler = _serve(CARDS)
    stats = await sync_etda(db_session, _gateway("etda", handler))
    assert len(handler.requests) == 1 and handler.requests[0].url.params["g"] == "all"
    assert stats == {
        "cards": 5, "matched": 3, "updated": 3, "ambiguous": 0, "unmatched": 2, "withdrawn": 0, "stopped": None,
    }  # fmt: skip

    apt29, lazarus, kimsuky = actors["apt29"], actors["lazarus"], actors["kimsuky"]
    # Fill-blank columns: the country resolves to the countries table's name.
    assert (lazarus.country, lazarus.origin_country_id) == ("North Korea", countries["North Korea"].id)
    # ETDA lists espionage first for Lazarus.
    assert (lazarus.mitre_id, lazarus.motivation) == ("G0032", "espionage")
    assert (apt29.country, apt29.mitre_id, apt29.motivation) == ("Russia", "G0016", "espionage")
    # Aliases pass the gate: "The Dukes" belongs to another actor, and
    # "APT 29" is the actor's own name in the resolver's normal form.
    assert {"Cozy Bear", "Yttrium"} <= set(apt29.aliases)
    assert not {"The Dukes", "APT 29"} & set(apt29.aliases)
    assert "Labyrinth Chollima" in lazarus.aliases and lazarus.aliases.count("Hidden Cobra") == 1

    # Relations: sectors in the junction, countries and tools in entity_relationships.
    sectors = await _sector_rows(db_session, apt29.id)
    assert str(sector_uuid("government")) in sectors and len(sectors) == 11
    assert all(r.source == "enrichment" for r in sectors.values())
    edges = await _edges(db_session, apt29.id)
    assert ("targets", "country", str(countries["Russia"].id)) not in edges  # observed-countries has no Russia
    assert ("uses", "tool", str(etda_world["tools"]["Cobalt Strike"].id)) in edges
    assert ("uses", "malware", str(etda_world["malware"]["CozyDuke"].id)) in edges
    assert ("uses", "tool", str(etda_world["tools"]["AdFind"].id)) in edges
    assert ("targets", "country", str(countries["United States"].id)) in await _edges(db_session, kimsuky.id)
    assert ("targets", "country", str(countries["Japan"].id)) in await _edges(db_session, kimsuky.id)
    assert ("uses", "malware", str(etda_world["malware"]["AppleJeus"].id)) in await _edges(db_session, lazarus.id)
    held = {c.target_name for c in await _claims(db_session, "etda", apt29.id) if c.target_id is None}
    assert {"BEATDROP", "Australia", "CEELOADER"} <= held

    context = await _context(db_session, apt29.id, "etda")
    assert context["sponsor"] == "State-sponsored"
    assert context["first_seen"] == "2008"
    assert context["card_changed"] == "2025-08-16"
    assert [e["date"] for e in context["operations"]] == ["2013-02", "2013", "2013"]
    assert context["counter_operations"][0]["text"].startswith("Dutch agencies provide crucial intel")
    assert context["card"]["label"] == "APT 29, Cozy Bear, The Dukes"

    # A second run with the same cards changes nothing.
    claims_before = [(c.target_key, c.target_id) for c in await _claims(db_session, "etda")]
    edges_before = await _count(db_session, EntityRelationship)
    stats = await sync_etda(db_session, _gateway("etda", _serve(CARDS)))
    assert stats["updated"] == 0
    assert [(c.target_key, c.target_id) for c in await _claims(db_session, "etda")] == claims_before
    assert await _count(db_session, EntityRelationship) == edges_before


async def test_an_actor_whose_card_stops_matching_loses_its_claims_and_context(db_session, etda_world):
    apt29 = etda_world["actors"]["apt29"]
    await sync_etda(db_session, _gateway("etda", _serve(CARDS)))
    assert await _claims(db_session, "etda", apt29.id)

    fewer = copy.deepcopy(CARDS)
    fewer["values"] = [c for c in fewer["values"] if not c["actor"].startswith("APT 29")]
    stats = await sync_etda(db_session, _gateway("etda", _serve(fewer)))
    assert stats["withdrawn"] == 1 and stats["matched"] == 2
    assert await _claims(db_session, "etda", apt29.id) == []
    assert await _context(db_session, apt29.id, "etda") == {}
    assert await _sector_rows(db_session, apt29.id) == {}
    assert await _edges(db_session, apt29.id) == {}
    # Filled columns stay: like any source's fill, they are the actor's now.
    assert apt29.mitre_id == "G0016"
    # The other actors' claims are untouched.
    assert await _claims(db_session, "etda", etda_world["actors"]["lazarus"].id)


async def test_an_empty_export_withdraws_nothing(db_session, etda_world):
    await sync_etda(db_session, _gateway("etda", _serve(CARDS)))
    claims = len(await _claims(db_session, "etda"))
    stats = await sync_etda(db_session, _gateway("etda", _serve({**CARDS, "values": []})))
    assert stats["stopped"] == "empty_export" and stats["withdrawn"] == 0
    assert len(await _claims(db_session, "etda")) == claims


async def test_etda_stops_cleanly_when_refused(db_session, etda_world):
    stats = await sync_etda(db_session, _gateway("etda", _serve(CARDS, status=429)))
    assert stats["stopped"] == "rate_limited"
    assert await _claims(db_session, "etda") == []
    assert etda_world["actors"]["lazarus"].mitre_id is None


# ── ransomware.live group profiles ───────────────────────────────────


@pytest.fixture
async def akira(db_session):
    actor = ThreatActor(name="Akira", actor_type="ransomware")
    victim = RansomwareVictim(name="Example Corp")
    ttps = [TTP(technique_id=t, technique_name=t) for t in ("T1078", "T1078.002", "T1047")]
    tools = [Tool(name="Mimikatz"), Tool(name="LaZagne"), Tool(name="Advanced IP Scanner")]
    db_session.add_all([actor, victim, *ttps, *tools])
    db_session.add(EnrichmentSource(source_type="ransomware_live", display_name="ransomware.live", is_enabled=True))
    await db_session.flush()
    now = datetime.now(UTC)
    for n, (slug, days) in enumerate((("akira", 1), ("akira_old", 30))):
        db_session.add(
            VictimDisclosure(
                victim_id=victim.id,
                group_id=actor.id,
                group_name_raw=slug,
                posted_at=now - timedelta(days=days),
                source="ransomware.live",
                guid=f"g-{n}-{uuid.uuid4().hex[:8]}",
            )
        )
    await db_session.flush()
    return {"actor": actor, "ttps": {t.technique_id: t for t in ttps}, "tools": {t.name: t for t in tools}}


def _groups(payload=AKIRA, status=200):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if status != 200:
            return httpx.Response(status, headers={"Retry-After": "600"})
        if request.url.path == "/v2/group/akira":
            return httpx.Response(200, json=payload)
        return httpx.Response(404, json={"error": "not found"})

    handler.requests = requests
    return handler


def test_group_facts_keep_no_onion_address():
    facts = group_facts(AKIRA)
    assert facts["leak_sites"] == [{"type": "DLS", "status": "up"}, {"type": "Chat", "status": "up"}]
    assert ".onion" not in json.dumps(facts)
    assert facts["description"].startswith("The Akira ransomware group is said to have emerged in March 2023")
    assert "<br>" not in facts["description"]
    assert [t["technique_id"] for t in facts["techniques"]] == ["T1078", "T1078.002", "T1047", "T1059"]
    assert facts["tools_by_category"][0] == {"category": "CredentialTheft", "tools": ["DonPAPI", "LaZagne", "Mimikatz"]}


async def test_group_profiles_claim_techniques_and_tools_with_evidence(db_session, akira):
    actor = akira["actor"]
    handler = _groups()
    stats = await sync_group_profiles(db_session, _gateway("ransomware_live", handler))
    # One lookup, by the slug that posted most recently.
    assert [r.url.path for r in handler.requests] == ["/v2/group/akira"]
    assert stats == {"looked_up": 1, "found": 1, "updated": 1, "failed": 0, "stopped": None}

    edges = await _edges(db_session, actor.id)
    valid = edges[("uses", "ttp", str(akira["ttps"]["T1078"].id))]
    assert (valid.source, valid.confidence, valid.description) == (
        "enrichment",
        "probable",
        "Utilizes compromised VPN credentials.",
    )
    assert ("uses", "ttp", str(akira["ttps"]["T1047"].id)) in edges
    assert ("uses", "tool", str(akira["tools"]["Mimikatz"].id)) in edges
    assert ("uses", "tool", str(akira["tools"]["Advanced IP Scanner"].id)) in edges
    claims = {c.target_name: c for c in await _claims(db_session, "ransomware_live")}
    assert claims["T1059"].held_reason == "unknown"  # no such TTP row here
    assert claims["T1078"].evidence == "Utilizes compromised VPN credentials."
    assert claims["DonPAPI"].held_reason == "unknown"

    context = await _context(db_session, actor.id, "ransomware_live")
    assert context["leak_sites"] == {"columns": ["Type", "Status"], "rows": [["DLS", "up"], ["Chat", "up"]]}
    assert context["tools_by_category"]["rows"][0] == ["CredentialTheft", "DonPAPI, LaZagne, Mimikatz"]
    assert context["page"] == {"url": "https://www.ransomware.live/group/akira", "label": "ransomware.live"}
    stored = (
        await db_session.execute(select(EnrichmentResult).where(EnrichmentResult.source_type == "ransomware_live"))
    ).scalar_one()
    assert ".onion" not in json.dumps([context, stored.raw_response, stored.parsed_data])

    # Fresh for a week: the next run asks nothing.
    handler = _groups()
    assert (await sync_group_profiles(db_session, _gateway("ransomware_live", handler)))["looked_up"] == 0
    assert handler.requests == []


async def test_group_profiles_are_hidden_from_visitors(client, auth_headers, db_session, akira, monkeypatch):
    await sync_group_profiles(db_session, _gateway("ransomware_live", _groups()))
    url = f"/api/entities/threat_actor/{akira['actor'].id}/context"

    body = (await client.get(url, headers=auth_headers)).json()
    source = next(s for s in body["sources"] if s["source_type"] == "ransomware_live")
    assert {i["key"] for i in source["items"]} == {"description", "tools_by_category", "leak_sites", "page"}
    assert ".onion" not in json.dumps(body)

    monkeypatch.setattr(settings, "public_read_only_enabled", True)
    resp = await client.get(url)
    assert "ransomware_live" not in resp.text and ".onion" not in resp.text


async def test_group_profiles_stop_cleanly_when_refused(db_session, akira):
    stats = await sync_group_profiles(db_session, _gateway("ransomware_live", _groups(status=429)))
    assert stats["stopped"] == "rate_limited" and stats["looked_up"] == 0
    assert await _claims(db_session, "ransomware_live") == []
    assert await _context(db_session, akira["actor"].id, "ransomware_live") == {}


async def test_group_profiles_store_a_group_ransomware_live_does_not_know(db_session, akira):
    def missing(request):
        return httpx.Response(404, json={"error": "not found"})

    stats = await sync_group_profiles(db_session, _gateway("ransomware_live", missing))
    assert stats == {"looked_up": 1, "found": 0, "updated": 0, "failed": 0, "stopped": None}
    result = (
        await db_session.execute(select(EnrichmentResult).where(EnrichmentResult.source_type == "ransomware_live"))
    ).scalar_one()
    assert result.parsed_data == {"found": False}


# ── The console ──────────────────────────────────────────────────────


async def test_console_detail_lists_relationship_outputs(client, admin_headers, db_session, etda_world):
    await sync_etda(db_session, _gateway("etda", _serve(CARDS)))
    detail = (await client.get("/api/enrichment/sources/etda/detail", headers=admin_headers)).json()
    relations = {o["field"]: o for o in detail["outputs"] if o["kind"] == "relationship"}
    assert set(relations) == {"sectors", "countries", "tools"}
    tools = relations["tools"]
    assert tools["target"] == "relationship: uses malware or tool"
    claims = await _claims(db_session, "etda")
    tool_claims = [c for c in claims if c.output == "tools"]
    assert tools["linked"] == sum(c.target_id is not None for c in tool_claims) == 4
    assert tools["held"] == sum(c.target_id is None for c in tool_claims)

    console = (await client.get("/api/enrichment/console", headers=admin_headers)).json()
    etda = next(s for s in console["sources"] if s["source_type"] == "etda")
    assert etda["fills"] == "aliases, country, origin country ID, motivation +10 more"


async def test_catalog_answers_apply_relations_through_the_pipeline(db_session, etda_world):
    """The catalog path is the generic one: apply_catalog_result runs the
    relation applier like it runs the column applier."""
    kimsuky = etda_world["actors"]["kimsuky"]
    data = EnrichmentData(raw_response={}, parsed_data={"found": True, "countries": ["DPRK"]}, ttl_hours=1)
    assert await apply_catalog_result(db_session, "threat_actor", kimsuky.id, "etda", data)
    assert ("targets", "country", str(etda_world["countries"]["North Korea"].id)) in await _edges(
        db_session, kimsuky.id
    )
