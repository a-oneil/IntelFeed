"""Threat actor and malware family extraction and storage."""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.ai.caller import Caller
from app.ai.engine import run_task
from app.intelligence.entity_dedup import (
    find_entity_by_name_or_alias,
    find_entity_id_by_name_or_alias,
    link_entry_to_entity,
)
from app.intelligence.entity_resolution import (
    coerce_malware_type,
    gate_aliases,
    resolve_entity_creation,
)
from app.intelligence.relationship_matrix import orient_relationship
from app.models.country import Country, EntryCountry
from app.models.entity_relationship import EntityRelationship
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.observable import ALL_KINDS as ALL_OBSERVABLE_KINDS
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.services.claim_provenance import record_claims

logger = logging.getLogger(__name__)


async def _resolve_country_id(db: AsyncSession, country_name: str | None) -> uuid.UUID | None:
    """Resolve a free-text country name to a Country entity ID."""
    if not country_name or not country_name.strip():
        return None
    name = country_name.strip()
    # Try exact name match first
    result = await db.execute(select(Country.id).where(func.lower(Country.name) == name.lower()))
    row = result.scalar_one_or_none()
    if row:
        return row
    # Try exact alias match (case-insensitive, per-element — not substring)
    result = await db.execute(
        select(Country.id)
        .where(text("EXISTS (SELECT 1 FROM unnest(aliases) AS a WHERE lower(a) = :search)"))
        .params(search=name.lower())
    )
    row = result.scalar_one_or_none()
    return row


def _ai_status(result: dict | None) -> tuple[str, str | None]:
    """Extract status from an AI result."""
    if result is None:
        return "ai_not_configured", None
    if isinstance(result, dict) and result.get("_extraction_status") == "provider_error":
        return "provider_error", result.get("_error")
    if isinstance(result, dict) and result.get("_extraction_status") == "parse_error":
        return "parse_error", None
    return "success", None


_ENTITY_TYPE_MODEL_MAP = {
    "threat_actor": (ThreatActor, "name"),
    "malware": (MalwareFamily, "name"),
    "cve": None,  # resolved by cve_id
    "ttp": None,  # resolved by technique_id
    "country": (Country, "name"),
}


async def _resolve_entity_id(
    db: AsyncSession, entity_type: str, name: str, *, kind: str | None = None
) -> uuid.UUID | None:
    """Resolve an entity name to its UUID. ``kind`` is the observable kind
    when the AI disambiguated one (``target_kind``)."""
    if entity_type == "cve":
        from app.models.cve import CVE

        result = await db.execute(select(CVE.id).where(CVE.cve_id == name))
        return result.scalar_one_or_none()
    if entity_type == "ttp":
        from app.models.ttp import TTP

        result = await db.execute(select(TTP.id).where(TTP.technique_id == name))
        return result.scalar_one_or_none()
    if entity_type == "tool":
        from app.models.tool import Tool

        return await find_entity_id_by_name_or_alias(db, Tool, name)
    if entity_type == "observable":
        # The "name" is the indicator value as the article printed it (possibly
        # defanged). A stated kind resolves exactly through that kind's
        # normalizer; otherwise classify to the canonical (kind, value); then
        # fall back to a value lookup over every host kind's normal form so a
        # command line the model printed with doubled spaces still matches the
        # whitespace-collapsed row. Only rows a judgment door already created
        # can match — this path never creates one.
        from app.intelligence.observables import classify_value, normalize_value, refang
        from app.models.observable import HOST_KINDS, Observable

        stripped = name.strip()
        if kind and kind in ALL_OBSERVABLE_KINDS:
            result = await db.execute(
                select(Observable.id).where(
                    Observable.kind == kind,
                    Observable.value == normalize_value(kind, stripped),
                    Observable.is_denied.is_(False),
                )
            )
            found = result.scalar_one_or_none()
            if found:
                return found
        classified = classify_value(stripped)
        if classified:
            result = await db.execute(
                select(Observable.id).where(
                    Observable.kind == classified[0],
                    Observable.value == classified[1],
                    Observable.is_denied.is_(False),
                )
            )
            return result.scalar_one_or_none()
        forms = {refang(stripped)} | {normalize_value(k, stripped) for k in HOST_KINDS}
        result = await db.execute(
            select(Observable.id)
            .where(Observable.value.in_(forms), Observable.is_denied.is_(False))
            .order_by(Observable.sighting_count.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()
    cfg = _ENTITY_TYPE_MODEL_MAP.get(entity_type)
    if cfg:
        model, _name_col = cfg
        return await find_entity_id_by_name_or_alias(db, model, name)
    return None


# Relationship verbs the AI may assert — the co-occurrence verb map plus the
# same-type verbs statistics can never produce (actor↔actor, malware↔malware).
_AI_RELATIONSHIP_TYPES = {
    "uses",
    "targets",
    "exploits",
    "attributed_to",
    "variant_of",
    "successor_of",
    "subgroup_of",
    "overlaps_with",
    "related_to",
    # Observable-target verbs (matrix: actor/malware/tool → observable).
    "communicates_with",
    "controls",
}
_AI_RELATIONSHIP_ENTITY_TYPES = {"threat_actor", "malware", "tool", "country", "cve", "ttp", "observable"}
_CONFIDENCE_RANK = {"possible": 0, "probable": 1, "confirmed": 2}


def _payload_entity_names(parsed: dict) -> set[str]:
    """Lowercased names + aliases of every entity the payload extracted."""
    names: set[str] = set()
    for key in ("threat_actors", "malware", "tools", "countries"):
        for item in parsed.get(key) or []:
            if isinstance(item, dict):
                candidates = [item.get("name") or ""] + list(item.get("aliases") or [])
            elif isinstance(item, str):
                candidates = [item]
            else:
                continue
            names.update(c.strip().lower() for c in candidates if c and c.strip())
    # Extracted indicators count as payload entities too, so an observable
    # endpoint passes the self-consistency gate (values as printed — the same
    # possibly-defanged form the evidence sentence carries).
    for item in parsed.get("iocs") or []:
        if isinstance(item, dict) and item.get("value"):
            names.add(str(item["value"]).strip().lower())
    return names


async def store_ai_relationships(
    db: AsyncSession,
    relationships: list[dict],
    entry_id: uuid.UUID,
    parsed: dict | None = None,
) -> int:
    """Store AI-asserted relationship triples as EntityRelationship records.

    Anti-newsletter guards: the evidence sentence must name both endpoints
    (co-mention in a list or roundup produces no evidence sentence containing
    both), and when the full payload is provided both endpoints must appear in
    the extracted entity lists. An assertion matching an existing
    co_occurrence edge upgrades it (source, confidence, evidence) instead of
    being silently dropped; analyst_rejected edges are never resurrected.

    Returns count of relationships stored or merged.
    """
    payload_names = _payload_entity_names(parsed) if parsed is not None else None
    # High caps at "probable" (reported): a single-article AI assertion never
    # mints the corroborated tier — that's earned by the adjudicator reviewing
    # accumulated evidence, an authority import, or an analyst pin.
    conf_map = {"high": "probable", "medium": "probable", "low": "possible"}
    stored = 0
    touched: set[tuple[str, uuid.UUID]] = set()
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        src_type = (rel.get("source_type") or "").strip()
        src_name = (rel.get("source_name") or "").strip()
        tgt_type = (rel.get("target_type") or "").strip()
        tgt_name = (rel.get("target_name") or "").strip()
        tgt_kind = (rel.get("target_kind") or "").strip() or None
        rel_type = (rel.get("relationship_type") or "related_to").strip()
        evidence = (rel.get("evidence") or "").strip()
        confidence = (rel.get("confidence") or "medium").strip()
        confidence = conf_map.get(confidence, confidence)

        if not all([src_type, src_name, tgt_type, tgt_name]):
            continue
        if src_type not in _AI_RELATIONSHIP_ENTITY_TYPES or tgt_type not in _AI_RELATIONSHIP_ENTITY_TYPES:
            continue
        if rel_type not in _AI_RELATIONSHIP_TYPES:
            rel_type = "related_to"
        if confidence not in _CONFIDENCE_RANK:
            confidence = "possible"
        # Enforce the semantic matrix. A reversed assertion (e.g. "country
        # attributed_to actor") is flipped to its allowed orientation; a pair
        # with no valid orientation (country related_to cve) is dropped.
        oriented = orient_relationship(src_type, rel_type, tgt_type)
        if oriented is None:
            continue
        if oriented[0] != src_type:
            src_type, tgt_type = oriented[0], oriented[2]
            src_name, tgt_name = tgt_name, src_name
        # Evidence sentence must actually assert the connection — it has to
        # name both endpoints. Entity dumps and newsletters fail this check.
        evidence_lower = evidence.lower()
        if not evidence or src_name.lower() not in evidence_lower or tgt_name.lower() not in evidence_lower:
            continue
        # Self-consistency: both endpoints must be entities the same payload
        # extracted (hallucinated pairs don't survive this).
        if payload_names is not None and (
            src_name.lower() not in payload_names or tgt_name.lower() not in payload_names
        ):
            continue

        src_id = await _resolve_entity_id(db, src_type, src_name)
        tgt_id = await _resolve_entity_id(db, tgt_type, tgt_name, kind=tgt_kind if tgt_type == "observable" else None)
        if not src_id or not tgt_id or (src_type == tgt_type and src_id == tgt_id):
            continue
        touched.add((src_type, src_id))
        touched.add((tgt_type, tgt_id))

        # Merge with an existing edge in either orientation so an AI assertion
        # strengthens the co-occurrence row instead of minting a mirror edge.
        existing = (
            (
                await db.execute(
                    select(EntityRelationship).where(
                        EntityRelationship.relationship_type == rel_type,
                        or_(
                            (EntityRelationship.source_type == src_type)
                            & (EntityRelationship.source_id == src_id)
                            & (EntityRelationship.target_type == tgt_type)
                            & (EntityRelationship.target_id == tgt_id),
                            (EntityRelationship.source_type == tgt_type)
                            & (EntityRelationship.source_id == tgt_id)
                            & (EntityRelationship.target_type == src_type)
                            & (EntityRelationship.target_id == src_id),
                        ),
                    )
                )
            )
            .scalars()
            .first()
        )

        if existing is not None:
            if existing.source == "analyst_rejected":
                continue
            if entry_id not in (existing.evidence_entry_ids or []):
                existing.evidence_entry_ids = (existing.evidence_entry_ids or []) + [entry_id]
            # Edges the adjudicator ruled coincidental keep accumulating
            # evidence but never regain confidence from fresh AI assertions.
            if existing.adjudication_verdict == "coincidental":
                stored += 1
                continue
            if existing.source == "co_occurrence":
                existing.source = "auto_extracted"
            if _CONFIDENCE_RANK.get(confidence, 0) > _CONFIDENCE_RANK.get(existing.confidence or "possible", 0):
                existing.confidence = confidence
            stored += 1
            continue

        await db.execute(
            pg_insert(EntityRelationship)
            .values(
                source_type=src_type,
                source_id=src_id,
                target_type=tgt_type,
                target_id=tgt_id,
                relationship_type=rel_type,
                confidence=confidence,
                source="auto_extracted",
                evidence_entry_ids=[entry_id],
            )
            .on_conflict_do_nothing()
        )
        stored += 1

    if stored:
        await db.flush()
    if stored and touched:
        # A fresh claim must show on both profiles now, not after the pivot
        # cache's TTL — the observable's Infrastructure/Attribution panels
        # read the same cached pivot.
        try:
            from app.intelligence.correlation_cache import invalidate_entity_cache

            for etype, eid in touched:
                await invalidate_entity_cache(etype, str(eid))
        except Exception:
            logger.debug("pivot cache invalidation skipped", exc_info=True)
    return stored


async def extract_threat_actors(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    caller: Caller | None = None,
) -> tuple[list[tuple[ThreatActor, bool]], str, str | None]:
    """Extract threat actors from entry using AI and store them.

    Returns (items, status, error_message).
    """
    # Routed through the consolidated entry_analysis task (the per-type task is
    # deprecated). run_task's is_current dedup means successive per-type extract
    # calls on the same entry share a single AI call.
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name="entry_analysis",
        variables={"entry": entry_data},
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        caller=caller,
    )

    status, error_msg = _ai_status(result)
    if not result or "threat_actors" not in result:
        return [], status, error_msg

    stored = await store_threat_actors(db, entry_id, result["threat_actors"], result.get("relationships"))
    return stored, "success", None


async def store_threat_actors(
    db: AsyncSession,
    entry_id: uuid.UUID,
    actors_data: list[dict],
    relationships: list | None = None,
) -> list[tuple[ThreatActor, bool]]:
    """Persist AI-extracted threat actors + entry links.

    Shared by manual extraction (extract_threat_actors) and the one-pass
    entry_analysis fan-out (services/entry_analysis.py).
    """
    stored: list[tuple[ThreatActor, bool]] = []
    for actor_data in actors_data:
        name = actor_data.get("name", "").strip()
        if not name:
            continue

        # Resolver: exact + normalized matching, cross-type tombstones, and the
        # creation/alias gates (planning/entity-creation-guardrails.md) in one place.
        decision = await resolve_entity_creation(
            db, "threat_actor", name, actor_data.get("aliases"), source="ai", entry_id=entry_id
        )
        if decision.action == "tombstone":
            tombstone = decision.tombstone
            await link_entry_to_entity(db, entry_id, tombstone.target_type, tombstone.target_id, matched_name=name)
            continue
        if decision.action in ("blocked", "held"):
            # No new profile — but an unambiguous cross-type hold still knows
            # the survivor, so the mention reaches it instead of being dropped.
            if decision.link_target:
                await link_entry_to_entity(db, entry_id, *decision.link_target, matched_name=name)
            continue

        actor = decision.entity

        if actor:
            actor.last_seen_at = datetime.now(UTC)
            actor.article_count += 1
            # Merge new profile data without overwriting existing values
            new_aliases = await gate_aliases(
                db, "threat_actor", actor.name, actor_data.get("aliases"), entity_id=actor.id
            )
            if new_aliases:
                existing_set = {a.lower() for a in (actor.aliases or [])}
                merged = list(actor.aliases or [])
                for alias in new_aliases:
                    if alias.lower() not in existing_set:
                        merged.append(alias)
                        existing_set.add(alias.lower())
                if len(merged) != len(actor.aliases or []):
                    actor.aliases = merged
            if not actor.country and actor_data.get("country"):
                actor.country = actor_data["country"]
            if not actor.origin_country_id and actor_data.get("country"):
                resolved = await _resolve_country_id(db, actor_data["country"])
                if resolved:
                    actor.origin_country_id = resolved
            if not actor.motivation and actor_data.get("motivation"):
                actor.motivation = actor_data["motivation"]
            if not actor.description and actor_data.get("description"):
                actor.description = actor_data["description"]
            if not actor.mitre_id and actor_data.get("mitre_id"):
                actor.mitre_id = actor_data["mitre_id"]
            is_new = False
        else:
            resolved_country = await _resolve_country_id(db, actor_data.get("country"))
            actor = ThreatActor(
                name=name,
                aliases=await gate_aliases(db, "threat_actor", name, actor_data.get("aliases")),
                country=actor_data.get("country"),
                origin_country_id=resolved_country,
                motivation=actor_data.get("motivation"),
                created_via="ai_extraction",
                created_from_entry_id=entry_id,
                created_confidence=actor_data.get("confidence"),
                needs_review=bool(decision.shadow_reason),
            )
            db.add(actor)
            await db.flush()
            is_new = True

        # Link to entry (atomic upsert — prevents duplicates under concurrency)
        await db.execute(
            pg_insert(EntryThreatActor)
            .values(
                entry_id=entry_id,
                threat_actor_id=actor.id,
                confidence=actor_data.get("confidence"),
                source="ai",
                matched_names=[name] if name else None,
            )
            .on_conflict_do_nothing()
        )

        # Provenance: record what this article asserted about the actor, whether
        # or not the value won the "don't overwrite an existing value" contest.
        # A claim that lost still explains why a competing value is on record.
        await record_claims(
            db,
            entity_type=entity_types.THREAT_ACTOR,
            entity_id=actor.id,
            values={
                field: actor_data.get(field)
                for field in ("description", "motivation", "country", "mitre_id")
                if actor_data.get(field)
            },
            source_kind="ai_extraction",
            entry_id=entry_id,
            confidence=actor_data.get("confidence"),
        )

        stored.append((actor, is_new))

    await db.flush()

    # Store AI-extracted relationships
    if relationships:
        await store_ai_relationships(db, relationships, entry_id)

    # Refresh auto-linker vocabulary if new entities were created
    if any(is_new for _, is_new in stored):
        try:
            from app.workers.intel_feed_tasks import refresh_autolinker_vocabulary

            refresh_autolinker_vocabulary.delay()
        except Exception:
            logger.warning("Failed to dispatch autolinker refresh after threat actor extraction", exc_info=True)

    return stored


async def extract_malware(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    caller: Caller | None = None,
) -> tuple[list[tuple[MalwareFamily, bool]], str, str | None]:
    """Extract malware families from entry using AI and store them.

    Returns (items, status, error_message).
    """
    # Routed through the consolidated entry_analysis task (the per-type task is
    # deprecated). run_task's is_current dedup means successive per-type extract
    # calls on the same entry share a single AI call.
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name="entry_analysis",
        variables={"entry": entry_data},
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        caller=caller,
    )

    status, error_msg = _ai_status(result)
    if not result or "malware" not in result:
        return [], status, error_msg

    stored = await store_malware(db, entry_id, result["malware"], result.get("relationships"))
    return stored, "success", None


async def store_malware(
    db: AsyncSession,
    entry_id: uuid.UUID,
    malware_data_list: list[dict],
    relationships: list | None = None,
) -> list[tuple[MalwareFamily, bool]]:
    """Persist AI-extracted malware families + entry links (shared with entry_analysis)."""
    stored: list[tuple[MalwareFamily, bool]] = []
    for malware_data in malware_data_list:
        name = malware_data.get("name", "").strip()
        if not name:
            continue

        # Resolver: exact + normalized matching, cross-type tombstones, and the
        # creation/alias gates (planning/entity-creation-guardrails.md) in one place.
        decision = await resolve_entity_creation(
            db, "malware", name, malware_data.get("aliases"), source="ai", entry_id=entry_id
        )
        if decision.action == "tombstone":
            tombstone = decision.tombstone
            await link_entry_to_entity(db, entry_id, tombstone.target_type, tombstone.target_id, matched_name=name)
            continue
        if decision.action in ("blocked", "held"):
            # No new profile — but an unambiguous cross-type hold still knows
            # the survivor, so the mention reaches it instead of being dropped.
            if decision.link_target:
                await link_entry_to_entity(db, entry_id, *decision.link_target, matched_name=name)
            continue

        malware = decision.entity

        if malware:
            malware.last_seen_at = datetime.now(UTC)
            malware.article_count += 1
            # Merge new profile data without overwriting existing values
            new_aliases = await gate_aliases(
                db, "malware", malware.name, malware_data.get("aliases"), entity_id=malware.id
            )
            if new_aliases:
                existing_set = {a.lower() for a in (malware.aliases or [])}
                merged = list(malware.aliases or [])
                for alias in new_aliases:
                    if alias.lower() not in existing_set:
                        merged.append(alias)
                        existing_set.add(alias.lower())
                if len(merged) != len(malware.aliases or []):
                    malware.aliases = merged
            if not malware.malware_type and malware_data.get("malware_type"):
                coerced, raw = coerce_malware_type(malware_data["malware_type"])
                malware.malware_type = coerced
                if raw:
                    malware.metadata_ = {**(malware.metadata_ or {}), "raw_malware_type": raw}
            if not malware.description and malware_data.get("description"):
                malware.description = malware_data["description"]
            # Merge associated_actors list
            new_actors = malware_data.get("associated_actors", [])
            if new_actors:
                existing_actors = set()
                for a in malware.associated_actors or []:
                    if isinstance(a, str):
                        existing_actors.add(a.lower())
                    elif isinstance(a, dict) and a.get("name"):
                        existing_actors.add(a["name"].lower())
                merged_actors = list(malware.associated_actors or [])
                for a in new_actors:
                    a_name = a if isinstance(a, str) else (a.get("name", "") if isinstance(a, dict) else "")
                    if a_name and a_name.lower() not in existing_actors:
                        merged_actors.append(a)
                        existing_actors.add(a_name.lower())
                if len(merged_actors) != len(malware.associated_actors or []):
                    malware.associated_actors = merged_actors
            is_new = False
        else:
            coerced, raw = coerce_malware_type(malware_data.get("malware_type"))
            malware = MalwareFamily(
                name=name,
                aliases=await gate_aliases(db, "malware", name, malware_data.get("aliases")),
                malware_type=coerced,
                associated_actors=malware_data.get("associated_actors", []),
                metadata_={"raw_malware_type": raw} if raw else {},
                created_via="ai_extraction",
                created_from_entry_id=entry_id,
                created_confidence=malware_data.get("confidence"),
                needs_review=bool(decision.shadow_reason),
            )
            db.add(malware)
            await db.flush()
            is_new = True

        # Link to entry (atomic upsert — prevents duplicates under concurrency)
        await db.execute(
            pg_insert(EntryMalware)
            .values(
                entry_id=entry_id,
                malware_family_id=malware.id,
                confidence=malware_data.get("confidence"),
                source="ai",
                matched_names=[name] if name else None,
            )
            .on_conflict_do_nothing()
        )

        await record_claims(
            db,
            entity_type=entity_types.MALWARE,
            entity_id=malware.id,
            values={
                field: malware_data.get(field) for field in ("description", "malware_type") if malware_data.get(field)
            },
            source_kind="ai_extraction",
            entry_id=entry_id,
            confidence=malware_data.get("confidence"),
        )

        stored.append((malware, is_new))

    await db.flush()

    # Store AI-extracted relationships
    if relationships:
        await store_ai_relationships(db, relationships, entry_id)

    # Refresh auto-linker vocabulary if new entities were created
    if any(is_new for _, is_new in stored):
        try:
            from app.workers.intel_feed_tasks import refresh_autolinker_vocabulary

            refresh_autolinker_vocabulary.delay()
        except Exception:
            logger.warning("Failed to dispatch autolinker refresh after malware extraction", exc_info=True)

    return stored


async def extract_countries(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    caller: Caller | None = None,
) -> tuple[list[tuple[Country, bool]], str, str | None]:
    """Extract countries from entry using AI and store them.

    Returns (items, status, error_message).
    """
    # Routed through the consolidated entry_analysis task (the per-type task is
    # deprecated). run_task's is_current dedup means successive per-type extract
    # calls on the same entry share a single AI call.
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name="entry_analysis",
        variables={"entry": entry_data},
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        caller=caller,
    )

    status, error_msg = _ai_status(result)
    if not result or "countries" not in result:
        return [], status, error_msg

    stored = await store_countries(db, entry_id, result["countries"])
    return stored, "success", None


async def store_countries(
    db: AsyncSession,
    entry_id: uuid.UUID,
    countries_data: list[dict],
) -> list[tuple[Country, bool]]:
    """Persist AI-extracted countries + entry links (shared with entry_analysis)."""
    stored: list[tuple[Country, bool]] = []
    for country_data in countries_data:
        name = country_data.get("name", "").strip()
        if not name:
            continue

        country = await find_entity_by_name_or_alias(db, Country, name, country_data.get("aliases"))

        if country:
            country.last_seen_at = datetime.now(UTC)
            country.article_count += 1
            new_aliases = country_data.get("aliases", [])
            if new_aliases:
                existing_set = {a.lower() for a in (country.aliases or [])}
                merged = list(country.aliases or [])
                for alias in new_aliases:
                    if alias.strip() and alias.lower() not in existing_set and alias.lower() != country.name.lower():
                        merged.append(alias.strip())
                        existing_set.add(alias.lower())
                if len(merged) != len(country.aliases or []):
                    country.aliases = merged
            if not country.iso_code and country_data.get("iso_code"):
                country.iso_code = country_data["iso_code"]
            if not country.region and country_data.get("region"):
                country.region = country_data["region"]
            if not country.description and country_data.get("description"):
                country.description = country_data["description"]
            is_new = False
        else:
            country = Country(
                name=name,
                aliases=country_data.get("aliases", []),
                iso_code=country_data.get("iso_code"),
                region=country_data.get("region"),
                description=country_data.get("description"),
            )
            db.add(country)
            await db.flush()
            is_new = True

        await db.execute(
            pg_insert(EntryCountry)
            .values(
                entry_id=entry_id,
                country_id=country.id,
                confidence=country_data.get("confidence"),
                source="ai",
                role=country_data.get("role"),
                matched_names=[name] if name else None,
            )
            .on_conflict_do_nothing()
        )

        stored.append((country, is_new))

    await db.flush()

    if any(is_new for _, is_new in stored):
        try:
            from app.workers.intel_feed_tasks import refresh_autolinker_vocabulary

            refresh_autolinker_vocabulary.delay()
        except Exception:
            logger.warning("Failed to dispatch autolinker refresh after country extraction", exc_info=True)

    return stored


async def extract_sectors(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    caller: Caller | None = None,
) -> tuple[list[dict], str, str | None]:
    """Extract targeted victim sectors from an entry using AI and store them.

    Output is normalized to the controlled vocabulary in
    app.intelligence.sectors — unknown sector names are dropped.

    Returns (items, status, error_message) where each item is
    {"sector": slug, "label": display label, "confidence": ..., "source": "ai"}.
    """
    # Routed through the consolidated entry_analysis task (the per-type task is
    # deprecated). run_task's is_current dedup means successive per-type extract
    # calls on the same entry share a single AI call.
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name="entry_analysis",
        variables={"entry": entry_data},
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        caller=caller,
    )

    status, error_msg = _ai_status(result)
    if not result or "sectors" not in result:
        return [], status, error_msg

    stored = await store_sectors(db, entry_id, result["sectors"])
    return stored, "success", None


async def store_sectors(
    db: AsyncSession,
    entry_id: uuid.UUID,
    sectors_data: list[dict],
) -> list[dict]:
    """Persist AI-extracted victim sectors (shared with entry_analysis).

    The only writer of entry↔sector links: sectors are never autolinked, so a
    row here always means the one-pass analysis judged the sector *targeted*.
    Each new link bumps the sector entity's article count the way the
    autolinker does for every other type.
    """
    from app.intelligence.autolinker import _bump_entity_stats
    from app.intelligence.sectors import normalize_sector, sector_label, sector_uuid
    from app.models.entry_sector import EntrySector
    from app.models.sector import Sector

    stored: list[dict] = []
    seen: set[str] = set()
    for sector_data in sectors_data:
        slug = normalize_sector(sector_data.get("name"))
        if not slug or slug in seen:
            continue
        seen.add(slug)
        confidence = (sector_data.get("confidence") or "").strip() or None
        sector_id = sector_uuid(slug)

        result = await db.execute(
            pg_insert(EntrySector)
            .values(
                entry_id=entry_id,
                sector=slug,
                sector_id=sector_id,
                confidence=confidence,
                source="ai",
                role="target",
            )
            .on_conflict_do_nothing()
        )
        if result.rowcount:
            await _bump_entity_stats(db, Sector, sector_id)
        stored.append(
            {
                "id": str(sector_id),
                "slug": slug,
                "name": sector_label(slug),
                "sector": slug,
                "label": sector_label(slug),
                "confidence": confidence,
                "source": "ai",
            }
        )

    if stored:
        await db.flush()

    return stored


_VALID_REPORT_TYPES = {
    "news",
    "advisory",
    "incident_report",
    "malware_analysis",
    "research",
    "vendor_marketing",
    "opinion",
}
_VALID_PATCH_STATUS = {"available", "workaround", "none", "unknown"}


def normalize_article_metadata(raw: dict | None) -> dict:
    """Coerce AI article-metadata output to a stored shape, dropping junk.

    Powers plan items 3.9.6 (patch availability), 3.9.7 (victim orgs),
    3.9.8 (timeline anchors), 3.9.9 (report-type classification).
    """
    raw = raw or {}

    report_type = str(raw.get("report_type") or "").strip().lower().replace(" ", "_").replace("-", "_")
    if report_type not in _VALID_REPORT_TYPES:
        report_type = None

    victims = raw.get("victim_organizations") or []
    victim_orgs = []
    seen: set[str] = set()
    for v in victims if isinstance(victims, list) else []:
        name = str(v).strip()
        key = name.lower()
        if name and key not in seen:
            seen.add(key)
            victim_orgs.append(name)

    tl_in = raw.get("timeline") or {}
    timeline = {
        k: (str(tl_in[k]).strip() or None) if isinstance(tl_in, dict) and tl_in.get(k) else None
        for k in ("disclosure_date", "compromise_date", "patch_date")
    }

    patch_in = raw.get("patch") or {}
    status = str(patch_in.get("status") or "unknown").strip().lower() if isinstance(patch_in, dict) else "unknown"
    if status not in _VALID_PATCH_STATUS:
        status = "unknown"
    reference = None
    if isinstance(patch_in, dict) and patch_in.get("reference"):
        reference = str(patch_in["reference"]).strip() or None
    patch = {"status": status, "reference": reference}

    return {
        "report_type": report_type,
        "victim_organizations": victim_orgs,
        "timeline": timeline,
        "patch": patch,
    }


async def extract_article_metadata(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_id: uuid.UUID,
    entry_data: dict,
    caller: Caller | None = None,
) -> tuple[dict, str, str | None]:
    """Extract report type, victim orgs, timeline anchors, and patch availability.

    Stores the normalized result on ``entry.metadata_["article_intel"]`` (no
    migration needed). Returns (metadata, status, error_message).
    """
    # Routed through the consolidated entry_analysis task (the per-type task is
    # deprecated). run_task's is_current dedup means successive per-type extract
    # calls on the same entry share a single AI call.
    result = await run_task(
        db=db,
        user_id=user_id,
        task_name="entry_analysis",
        variables={"entry": entry_data},
        entry_id=entry_id,
        target_type="entry",
        target_id=entry_id,
        caller=caller,
    )

    status, error_msg = _ai_status(result)
    if not result:
        return {}, status, error_msg

    meta = await store_article_metadata(db, entry_id, result)
    return meta, "success", None


async def store_article_metadata(db: AsyncSession, entry_id: uuid.UUID, raw: dict) -> dict:
    """Normalize + persist article metadata on entry.metadata_ (shared with entry_analysis)."""
    from app.models.entry import Entry

    meta = normalize_article_metadata(raw)
    entry = await db.get(Entry, entry_id)
    if entry is not None:
        merged = dict(entry.metadata_ or {})
        merged["article_intel"] = meta
        entry.metadata_ = merged
        await db.flush()
    return meta
