"""Correlation event detection — identifies interesting new relationships after entity extraction."""

import dataclasses
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.ttp import TTP, EntryTTP

logger = logging.getLogger(__name__)

# Event severity scoring
EVENT_SEVERITY: dict[str, str] = {
    "coverage_gap": "high",
    "trending_entity": "medium",
    "campaign_match": "medium",
    "requirement_match": "medium",
    "new_intel_for_rule": "low",
    "new_ttp_for_known_actor": "medium",
    "new_ttp_for_known_malware": "medium",
    "new_malware_for_known_actor": "medium",
    "actor_malware_cooccurrence": "low",
    "feed_stale": "low",
    "feed_error": "medium",
    "exploit_status_change": "high",
    "cve_score_change": "high",
    "new_exploit_discovered": "high",
    "kev_addition": "high",
}


@dataclasses.dataclass
class CorrelationEvent:
    """An interesting relationship discovered during entity extraction."""

    event_type: str
    entry_id: uuid.UUID | None
    source_entity_type: str
    source_entity_id: uuid.UUID
    source_entity_label: str
    related_entity_type: str
    related_entity_id: uuid.UUID
    related_entity_label: str
    context: str
    created_at: datetime = dataclasses.field(default_factory=lambda: datetime.now(UTC))

    @property
    def severity(self) -> str:
        return EVENT_SEVERITY.get(self.event_type, "low")

    def to_dict(self) -> dict:
        """Serialize for Celery JSON transport."""
        return {
            "event_type": self.event_type,
            "entry_id": str(self.entry_id) if self.entry_id else None,
            "source_entity_type": self.source_entity_type,
            "source_entity_id": str(self.source_entity_id),
            "source_entity_label": self.source_entity_label,
            "related_entity_type": self.related_entity_type,
            "related_entity_id": str(self.related_entity_id),
            "related_entity_label": self.related_entity_label,
            "context": self.context,
            "severity": self.severity,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CorrelationEvent":
        return cls(
            event_type=data["event_type"],
            entry_id=uuid.UUID(data["entry_id"]) if data.get("entry_id") else None,
            source_entity_type=data["source_entity_type"],
            source_entity_id=uuid.UUID(data["source_entity_id"]),
            source_entity_label=data["source_entity_label"],
            related_entity_type=data["related_entity_type"],
            related_entity_id=uuid.UUID(data["related_entity_id"]),
            related_entity_label=data["related_entity_label"],
            context=data["context"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


async def _deduplicate_event(db: AsyncSession, event: CorrelationEvent) -> bool:
    """Check if same event type + same primary entity exists within 24h.

    If duplicate found, increments occurrence_count on existing record.
    Returns True if this is a duplicate (should skip creating new record).
    """
    from app.models.correlation_event import CorrelationEventRecord

    cutoff = datetime.now(UTC) - timedelta(hours=24)
    result = await db.execute(
        select(CorrelationEventRecord)
        .where(
            CorrelationEventRecord.event_type == event.event_type,
            CorrelationEventRecord.source_entity_id == event.source_entity_id,
            CorrelationEventRecord.created_at > cutoff,
        )
        .limit(1)
    )
    existing = result.scalar_one_or_none()
    if existing:
        await db.execute(
            update(CorrelationEventRecord)
            .where(CorrelationEventRecord.id == existing.id)
            .values(occurrence_count=CorrelationEventRecord.occurrence_count + 1)
        )
        return True
    return False


async def correlate_new_entities(db: AsyncSession, entry_id: uuid.UUID) -> list[CorrelationEvent]:
    """Detect interesting new relationships for entities linked to an entry.

    Call this AFTER intelligence extraction has stored entities and junction records.
    Returns correlation events for patterns like:
    - New TTP for a known actor or malware family
    - New malware for a known actor
    - Coverage gaps (TTP with no active detection rule)
    - Actor-malware co-occurrence
    """
    events: list[CorrelationEvent] = []

    # Gather entities linked to this entry
    actors = await _get_entry_actors(db, entry_id)
    ttps = await _get_entry_ttps(db, entry_id)
    malware = await _get_entry_malware(db, entry_id)

    # Known actors = those with article_count > 1 (existed before this entry)
    known_actors = [(a, aid) for a, aid in actors if a.article_count > 1]
    # Known malware = those with article_count > 1
    known_malware = [(m, mid) for m, mid in malware if m.article_count > 1]

    # --- new_ttp_for_known_actor ---
    new_ttps = [(t, tid) for t, tid in ttps if _is_new_entity(t)]
    for ttp, _ in new_ttps:
        for actor, _ in known_actors:
            events.append(
                CorrelationEvent(
                    event_type="new_ttp_for_known_actor",
                    entry_id=entry_id,
                    source_entity_type="ttp",
                    source_entity_id=ttp.id,
                    source_entity_label=f"{ttp.technique_id} {ttp.technique_name}",
                    related_entity_type="threat_actor",
                    related_entity_id=actor.id,
                    related_entity_label=actor.name,
                    context=f"New TTP {ttp.technique_id} found in article mentioning known actor {actor.name}",
                )
            )

    # --- new_ttp_for_known_malware ---
    for ttp, _ in new_ttps:
        for mw, _ in known_malware:
            events.append(
                CorrelationEvent(
                    event_type="new_ttp_for_known_malware",
                    entry_id=entry_id,
                    source_entity_type="ttp",
                    source_entity_id=ttp.id,
                    source_entity_label=f"{ttp.technique_id} {ttp.technique_name}",
                    related_entity_type="malware",
                    related_entity_id=mw.id,
                    related_entity_label=mw.name,
                    context=f"New TTP {ttp.technique_id} found in article mentioning known malware {mw.name}",
                )
            )

    # --- new_malware_for_known_actor ---
    # New malware appearing with a known actor
    new_malware = [(m, mid) for m, mid in malware if _is_new_entity(m)]
    for mw, _ in new_malware:
        for actor, _ in known_actors:
            events.append(
                CorrelationEvent(
                    event_type="new_malware_for_known_actor",
                    entry_id=entry_id,
                    source_entity_type="malware",
                    source_entity_id=mw.id,
                    source_entity_label=mw.name,
                    related_entity_type="threat_actor",
                    related_entity_id=actor.id,
                    related_entity_label=actor.name,
                    context=f"Malware {mw.name} found in article mentioning known actor {actor.name}",
                )
            )

    # --- known_actor_with_known_malware ---
    # Known actor appears with known malware (tracking ongoing activity)
    for actor, _ in known_actors:
        for mw, _ in known_malware:
            events.append(
                CorrelationEvent(
                    event_type="actor_malware_cooccurrence",
                    entry_id=entry_id,
                    source_entity_type="threat_actor",
                    source_entity_id=actor.id,
                    source_entity_label=actor.name,
                    related_entity_type="malware",
                    related_entity_id=mw.id,
                    related_entity_label=mw.name,
                    context=f"Known actor {actor.name} linked to known malware {mw.name} in new article",
                )
            )

    # --- coverage_gap ---
    # TTPs observed in this entry that have no detection rules (draft or published)
    if ttps:
        from app.models.detection_rule import DetectionRule

        for ttp, _ in ttps:
            rule_result = await db.execute(
                select(func.count())
                .select_from(DetectionRule)
                .where(
                    or_(
                        DetectionRule.source_ttps.contains([ttp.technique_id]),
                        DetectionRule.mitre_tactics.any(ttp.technique_id),
                    ),
                )
            )
            rule_count = rule_result.scalar() or 0
            if rule_count == 0:
                events.append(
                    CorrelationEvent(
                        event_type="coverage_gap",
                        entry_id=entry_id,
                        source_entity_type="ttp",
                        source_entity_id=ttp.id,
                        source_entity_label=f"{ttp.technique_id} {ttp.technique_name}",
                        related_entity_type="ttp",
                        related_entity_id=ttp.id,
                        related_entity_label=f"{ttp.technique_id} {ttp.technique_name}",
                        context=f"TTP {ttp.technique_id} ({ttp.technique_name}) observed with no active detection rule",
                    )
                )

    # --- new_intel_for_rule ---
    # New TTPs that already have active detection rules (useful for rule tuning)
    if ttps:
        from app.models.detection_rule import DetectionRule

        for ttp, _ in ttps:
            rule_result = await db.execute(
                select(DetectionRule.id, DetectionRule.title)
                .where(
                    or_(
                        DetectionRule.source_ttps.contains([ttp.technique_id]),
                        DetectionRule.mitre_tactics.any(ttp.technique_id),
                    ),
                    DetectionRule.is_draft.is_(False),
                )
                .limit(1)
            )
            rule = rule_result.first()
            if rule:
                events.append(
                    CorrelationEvent(
                        event_type="new_intel_for_rule",
                        entry_id=entry_id,
                        source_entity_type="ttp",
                        source_entity_id=ttp.id,
                        source_entity_label=f"{ttp.technique_id} {ttp.technique_name}",
                        related_entity_type="detection_rule",
                        related_entity_id=rule.id,
                        related_entity_label=rule.title,
                        context=f"New article about {ttp.technique_id} which has active rule '{rule.title}'",
                    )
                )

    # Persist events with deduplication
    if events:
        from app.intelligence.correlation_cache import invalidate_entity_cache
        from app.models.correlation_event import CorrelationEventRecord

        invalidated: set[tuple[str, str]] = set()
        persisted_events: list[CorrelationEvent] = []

        for event in events:
            # Deduplicate: skip if same event type + entity within 24h
            is_dup = await _deduplicate_event(db, event)
            if is_dup:
                continue

            db.add(
                CorrelationEventRecord(
                    event_type=event.event_type,
                    entry_id=event.entry_id,
                    source_entity_type=event.source_entity_type,
                    source_entity_id=event.source_entity_id,
                    source_entity_label=event.source_entity_label,
                    related_entity_type=event.related_entity_type,
                    related_entity_id=event.related_entity_id,
                    related_entity_label=event.related_entity_label,
                    context=event.context,
                    severity=event.severity,
                )
            )
            persisted_events.append(event)

            for etype, eid in [
                (event.source_entity_type, str(event.source_entity_id)),
                (event.related_entity_type, str(event.related_entity_id)),
            ]:
                key = (etype, eid)
                if key not in invalidated:
                    await invalidate_entity_cache(etype, eid)
                    invalidated.add(key)

        if persisted_events:
            await db.flush()
            logger.info(
                f"Entry {entry_id}: {len(persisted_events)} correlation event(s) persisted "
                f"({len(events) - len(persisted_events)} deduplicated)"
            )

            # Publish SSE for real-time notification
            from app.api.events import publish_event

            for event in persisted_events:
                publish_event("broadcast", "correlation_event", event.to_dict())

    return events


# --- Standalone event creators for use outside of correlate_new_entities ---


async def create_campaign_match_event(
    db: AsyncSession, entry_id: uuid.UUID, campaign_id: uuid.UUID, campaign_name: str, overlap_count: int
) -> CorrelationEvent | None:
    """Create event when an entry shares 3+ entities with an active campaign."""
    event = CorrelationEvent(
        event_type="campaign_match",
        entry_id=entry_id,
        source_entity_type="entry",
        source_entity_id=entry_id,
        source_entity_label="entry",
        related_entity_type="campaign",
        related_entity_id=campaign_id,
        related_entity_label=campaign_name,
        context=f"Entry shares {overlap_count} entities with campaign '{campaign_name}'",
    )
    return await _persist_single_event(db, event)


async def create_requirement_match_event(
    db: AsyncSession, entry_id: uuid.UUID, requirement_id: uuid.UUID, requirement_title: str, matched_on: str
) -> CorrelationEvent | None:
    """Create event when an entry matches an active intelligence requirement."""
    event = CorrelationEvent(
        event_type="requirement_match",
        entry_id=entry_id,
        source_entity_type="entry",
        source_entity_id=entry_id,
        source_entity_label="entry",
        related_entity_type="requirement",
        related_entity_id=requirement_id,
        related_entity_label=requirement_title,
        context=f"Entry matches requirement '{requirement_title}' on: {matched_on}",
    )
    return await _persist_single_event(db, event)


async def create_feed_stale_event(
    db: AsyncSession, feed_id: uuid.UUID, feed_title: str, days_since_entry: int
) -> CorrelationEvent | None:
    """Create event when a feed hasn't produced new entries in >N days."""
    event = CorrelationEvent(
        event_type="feed_stale",
        entry_id=None,
        source_entity_type="feed",
        source_entity_id=feed_id,
        source_entity_label=feed_title,
        related_entity_type="feed",
        related_entity_id=feed_id,
        related_entity_label=feed_title,
        context=f"Feed '{feed_title}' has not produced new entries in {days_since_entry} days",
    )
    return await _persist_single_event(db, event)


async def create_feed_error_event(
    db: AsyncSession, feed_id: uuid.UUID, feed_title: str, error_count: int, last_error: str | None
) -> CorrelationEvent | None:
    """Create event when a feed has failed 3+ consecutive fetch attempts."""
    event = CorrelationEvent(
        event_type="feed_error",
        entry_id=None,
        source_entity_type="feed",
        source_entity_id=feed_id,
        source_entity_label=feed_title,
        related_entity_type="feed",
        related_entity_id=feed_id,
        related_entity_label=feed_title,
        context=f"Feed '{feed_title}' has {error_count} consecutive errors. Last: {last_error or 'unknown'}",
    )
    return await _persist_single_event(db, event)


async def create_exploit_status_change_event(
    db: AsyncSession, cve_id_str: str, cve_uuid: uuid.UUID, old_status: str | None, new_status: str
) -> CorrelationEvent | None:
    """Create event when a CVE's exploit availability escalates."""
    event = CorrelationEvent(
        event_type="exploit_status_change",
        entry_id=None,
        source_entity_type="cve",
        source_entity_id=cve_uuid,
        source_entity_label=cve_id_str,
        related_entity_type="cve",
        related_entity_id=cve_uuid,
        related_entity_label=cve_id_str,
        context=f"{cve_id_str} exploit status changed: {old_status or 'none'} → {new_status}",
    )
    return await _persist_single_event(db, event)


async def create_trending_entity_event(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    entity_label: str,
    entry_id: uuid.UUID,
    current_count: int,
    average_count: float,
) -> CorrelationEvent | None:
    """Create event when entity mentions spike above 2x 7-day average."""
    event = CorrelationEvent(
        event_type="trending_entity",
        entry_id=entry_id,
        source_entity_type=entity_type,
        source_entity_id=entity_id,
        source_entity_label=entity_label,
        related_entity_type=entity_type,
        related_entity_id=entity_id,
        related_entity_label=entity_label,
        context=f"{entity_label} mentions spiked to {current_count} (7-day avg: {average_count:.1f})",
    )
    return await _persist_single_event(db, event)


async def create_cve_score_change_event(
    db: AsyncSession,
    cve_id_str: str,
    cve_uuid: uuid.UUID,
    field: str,
    old_value: float | None,
    new_value: float | None,
) -> CorrelationEvent | None:
    """Create event when a CVE's CVSS or EPSS score changes significantly."""
    field_label = "CVSS" if field == "cvss_score" else "EPSS"
    old_display = f"{old_value:.1f}" if old_value is not None else "none"
    new_display = f"{new_value:.1f}" if new_value is not None else "none"
    event = CorrelationEvent(
        event_type="cve_score_change",
        entry_id=None,
        source_entity_type="cve",
        source_entity_id=cve_uuid,
        source_entity_label=cve_id_str,
        related_entity_type="cve",
        related_entity_id=cve_uuid,
        related_entity_label=cve_id_str,
        context=f"{cve_id_str} {field_label} score changed: {old_display} → {new_display}",
    )
    return await _persist_single_event(db, event)


async def create_new_exploit_discovered_event(
    db: AsyncSession,
    cve_id_str: str,
    cve_uuid: uuid.UUID,
    poc_count: int,
    poc_urls: list[str],
) -> CorrelationEvent | None:
    """Create event when new proof-of-concept exploits are discovered for a CVE."""
    urls_summary = ", ".join(poc_urls[:3])
    if len(poc_urls) > 3:
        urls_summary += f" (+{len(poc_urls) - 3} more)"
    event = CorrelationEvent(
        event_type="new_exploit_discovered",
        entry_id=None,
        source_entity_type="cve",
        source_entity_id=cve_uuid,
        source_entity_label=cve_id_str,
        related_entity_type="cve",
        related_entity_id=cve_uuid,
        related_entity_label=cve_id_str,
        context=f"{cve_id_str}: {poc_count} public exploit(s) found — {urls_summary}",
    )
    return await _persist_single_event(db, event)


async def create_kev_addition_event(
    db: AsyncSession,
    cve_id_str: str,
    cve_uuid: uuid.UUID,
) -> CorrelationEvent | None:
    """Create event when a CVE is added to the CISA Known Exploited Vulnerabilities catalog."""
    event = CorrelationEvent(
        event_type="kev_addition",
        entry_id=None,
        source_entity_type="cve",
        source_entity_id=cve_uuid,
        source_entity_label=cve_id_str,
        related_entity_type="cve",
        related_entity_id=cve_uuid,
        related_entity_label=cve_id_str,
        context=f"{cve_id_str} added to CISA Known Exploited Vulnerabilities catalog",
    )
    return await _persist_single_event(db, event)


async def _persist_single_event(db: AsyncSession, event: CorrelationEvent) -> CorrelationEvent | None:
    """Persist a single event with deduplication. Returns None if deduplicated."""
    from app.models.correlation_event import CorrelationEventRecord

    is_dup = await _deduplicate_event(db, event)
    if is_dup:
        return None

    db.add(
        CorrelationEventRecord(
            event_type=event.event_type,
            entry_id=event.entry_id,
            source_entity_type=event.source_entity_type,
            source_entity_id=event.source_entity_id,
            source_entity_label=event.source_entity_label,
            related_entity_type=event.related_entity_type,
            related_entity_id=event.related_entity_id,
            related_entity_label=event.related_entity_label,
            context=event.context,
            severity=event.severity,
        )
    )
    await db.flush()

    from app.api.events import publish_event

    publish_event("broadcast", "correlation_event", event.to_dict())

    return event


# --- Event TTL / Archival ---


async def archive_old_events(db: AsyncSession, retention_days: int = 90) -> int:
    """Delete read events older than retention period."""
    from app.models.correlation_event import CorrelationEventRecord

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    result = await db.execute(
        delete(CorrelationEventRecord).where(
            CorrelationEventRecord.created_at < cutoff,
            CorrelationEventRecord.is_read.is_(True),
        )
    )
    count = result.rowcount
    if count > 0:
        logger.info("Archived %d read correlation events older than %d days", count, retention_days)
    return count


# --- Helpers ---


def _is_new_entity(entity) -> bool:
    """Check if an entity was newly created (article_count=1 or no article_count attr)."""
    count = getattr(entity, "article_count", None)
    if count is not None:
        return count <= 1
    # Fallback: check if first_seen == last_seen (approximately)
    first = getattr(entity, "first_seen_at", None)
    last = getattr(entity, "last_seen_at", None)
    if first and last:
        return abs((last - first).total_seconds()) < 5
    return True


async def _get_entry_actors(db: AsyncSession, entry_id: uuid.UUID) -> list[tuple[ThreatActor, uuid.UUID]]:
    result = await db.execute(
        select(ThreatActor, EntryThreatActor.threat_actor_id)
        .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
        .where(EntryThreatActor.entry_id == entry_id)
    )
    return [(row[0], row[1]) for row in result.all()]


async def _get_entry_ttps(db: AsyncSession, entry_id: uuid.UUID) -> list[tuple[TTP, uuid.UUID]]:
    result = await db.execute(
        select(TTP, EntryTTP.ttp_id).join(EntryTTP, EntryTTP.ttp_id == TTP.id).where(EntryTTP.entry_id == entry_id)
    )
    return [(row[0], row[1]) for row in result.all()]


async def _get_entry_malware(db: AsyncSession, entry_id: uuid.UUID) -> list[tuple[MalwareFamily, uuid.UUID]]:
    result = await db.execute(
        select(MalwareFamily, EntryMalware.malware_family_id)
        .join(EntryMalware, EntryMalware.malware_family_id == MalwareFamily.id)
        .where(EntryMalware.entry_id == entry_id)
    )
    return [(row[0], row[1]) for row in result.all()]
