"""Timeline relationship events render direction-aware verbs.

The viewed entity is the implicit subject of each event title: outbound
relationships (viewed → other) read actively ("Uses malware “Pegasus”"),
inbound (other → viewed) read passively ("Used by actor “NSO Group”").
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.correlation import entity_timeline
from app.models.country import Country
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import MalwareFamily
from app.models.threat_actor import ThreatActor


def _relationship_titles(events: list[dict]) -> list[str]:
    return [e["title"] for e in events if e["event_type"] == "relationship"]


@pytest.mark.asyncio
async def test_timeline_verb_direction(db_session: AsyncSession):
    actor = ThreatActor(name="NSO Group")
    malware = MalwareFamily(name="Pegasus Spyware")
    db_session.add_all([actor, malware])
    await db_session.flush()

    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=actor.id,
            target_type="malware",
            target_id=malware.id,
            relationship_type="uses",
            confidence="confirmed",
            source="analyst_created",
        )
    )
    await db_session.flush()

    # Actor is the SOURCE → active form on the actor's timeline.
    actor_titles = _relationship_titles(await entity_timeline(db_session, "threat_actor", actor.id))
    assert "Uses malware “Pegasus Spyware”" in actor_titles

    # Malware is the TARGET → passive form on the malware's timeline.
    malware_titles = _relationship_titles(await entity_timeline(db_session, "malware", malware.id))
    assert "Used by actor “NSO Group”" in malware_titles


@pytest.mark.asyncio
async def test_timeline_targeted_country_reads_passively(db_session: AsyncSession):
    actor = ThreatActor(name="APT28")
    country = Country(name="Germany", iso_code="DE")
    db_session.add_all([actor, country])
    await db_session.flush()

    db_session.add(
        EntityRelationship(
            source_type="threat_actor",
            source_id=actor.id,
            target_type="country",
            target_id=country.id,
            relationship_type="targets",
            confidence="probable",
            source="co_occurrence",
        )
    )
    await db_session.flush()

    country_titles = _relationship_titles(await entity_timeline(db_session, "country", country.id))
    assert "Targeted by actor “APT28”" in country_titles

    actor_titles = _relationship_titles(await entity_timeline(db_session, "threat_actor", actor.id))
    assert "Targets country “Germany”" in actor_titles
