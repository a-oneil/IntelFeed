"""Recording and reading provenance for entity profile fields.

Every path that writes a scalar fact onto an entity — an analyst's inline edit,
an enrichment adapter, the AI gap-fill, a reference-feed import — calls
``record_claim`` alongside the column write. Reading it back groups the claims
per field and marks each one as agreeing with, or diverging from, whatever the
column says right now.

Two rules the module exists to enforce:

1. **Recording never fails the write.** A claim is an audit trail, not a
   transaction participant: if provenance can't be recorded, the field edit
   still lands. Callers get a bool, not an exception.
2. **Agreement is computed, never stored.** A stored "is current" flag drifts
   the moment someone edits the column without going through here. Comparing
   against the live row at read time cannot drift.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.models.entity_field_claim import EntityFieldClaim

logger = logging.getLogger(__name__)

#: Fields carrying provenance, per entity type. Anything listed here is expected
#: to be attributable: the profile marks a populated field with no claims as
#: unsourced rather than silently presenting it as fact.
PROVENANCE_FIELDS: dict[str, tuple[str, ...]] = {
    entity_types.THREAT_ACTOR: (
        "description",
        "motivation",
        "country",
        "actor_type",
        "targeted_sectors",
        "mitre_id",
        "aliases",
    ),
    entity_types.MALWARE: ("description", "malware_type", "mitre_id", "aliases", "targeted_sectors"),
    entity_types.TOOL: ("description", "tool_type", "mitre_id", "aliases"),
    # Both exploit columns are real and both are analyst-editable: exploit_status
    # is the extraction's wording, exploit_availability is what the header badge
    # edits. Tracking only one leaves the other's claims with no UI to surface them.
    entity_types.CVE: (
        "description",
        "cvss_score",
        "severity",
        "exploit_status",
        "exploit_availability",
        "aliases",
    ),
    entity_types.TTP: ("description", "tactic", "detection"),
    entity_types.CWE: ("description",),
    entity_types.VENDOR: ("description",),
    entity_types.PRODUCT: ("description", "vendor_id"),
    entity_types.COUNTRY: ("description",),
    entity_types.SECTOR: ("description",),
    entity_types.MITIGATION: ("description",),
}

#: Human labels for the source kinds, used by the API and the profile popover.
SOURCE_KIND_LABEL: dict[str, str] = {
    "analyst": "Analyst edit",
    "ai_extraction": "AI extraction",
    "ai_assessment": "AI assessment",
    "enrichment": "Enrichment",
    "external_feed": "Reference feed",
    "seed": "Seed data",
}


def render_value(value) -> str:
    """Render a field value the way the profile shows it, for storage + comparison."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value if v not in (None, ""))
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (float, Decimal)):
        # 9.8, 9.80 and Decimal("10.0") vs 10.0 are the same claim about a CVSS score.
        return f"{float(value):g}"
    return str(value).strip()


def claim_key(
    entity_type: str,
    entity_id: uuid.UUID,
    field: str,
    value_text: str,
    source_kind: str,
    source_ref: str | None,
    entry_id: uuid.UUID | None,
) -> str:
    """Digest of what makes one claim distinct from another.

    Deliberately excludes the quote, the user and the timestamp: the same source
    re-asserting the same value for the same field is one claim seen twice, not
    two claims. Two *different* articles asserting it stay distinct, because
    that is the corroboration the profile counts.
    """
    parts = [
        entity_type,
        str(entity_id),
        field,
        value_text.casefold(),
        source_kind,
        source_ref or "",
        str(entry_id or ""),
    ]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


async def record_claim(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: uuid.UUID,
    field: str,
    value,
    source_kind: str,
    source_ref: str | None = None,
    entry_id: uuid.UUID | None = None,
    quote: str | None = None,
    confidence: str | None = None,
    created_by: uuid.UUID | None = None,
    ai_result_id: uuid.UUID | None = None,
) -> bool:
    """Record that ``source_kind`` asserted ``value`` for one entity field.

    Returns False (never raises) when the claim is empty or could not be
    written — the field write that prompted it must not be rolled back because
    its audit trail failed.
    """
    value_text = render_value(value)
    if not value_text:
        return False
    try:
        key = claim_key(entity_type, entity_id, field, value_text, source_kind, source_ref, entry_id)
        stmt = pg_insert(EntityFieldClaim).values(
            id=uuid.uuid4(),
            entity_type=entity_type,
            entity_id=entity_id,
            field=field,
            value_text=value_text[:4000],
            source_kind=source_kind,
            source_ref=source_ref,
            entry_id=entry_id,
            quote=(quote or None) and quote.strip()[:2000],
            confidence=confidence,
            created_by=created_by,
            ai_result_id=ai_result_id,
            claim_key=key,
        )
        # A repeat assertion refreshes recency (and fills in a quote the first
        # pass lacked) without minting a second row.
        stmt = stmt.on_conflict_do_update(
            index_elements=[EntityFieldClaim.claim_key],
            set_={
                "last_asserted_at": stmt.excluded.last_asserted_at,
                "quote": stmt.excluded.quote,
                "confidence": stmt.excluded.confidence,
            },
        )
        await db.execute(stmt)
        return True
    except Exception:
        logger.warning("Failed to record field claim %s.%s for %s", entity_type, field, entity_id, exc_info=True)
        return False


async def record_claims(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: uuid.UUID,
    values: dict,
    source_kind: str,
    **kwargs,
) -> int:
    """Record several fields from one asserter. Returns how many landed.

    Fields outside PROVENANCE_FIELDS for the type are skipped, so a caller can
    hand over a whole update payload without filtering it first.
    """
    tracked = PROVENANCE_FIELDS.get(entity_type, ())
    written = 0
    for field, value in values.items():
        if field not in tracked:
            continue
        if await record_claim(
            db,
            entity_type=entity_type,
            entity_id=entity_id,
            field=field,
            value=value,
            source_kind=source_kind,
            **kwargs,
        ):
            written += 1
    return written


async def get_entity_claims(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    entity_row=None,
) -> dict:
    """Claims for one entity, grouped per field and resolved for display.

    Each claim carries its article (title + feed + the feed's A–F reliability
    grade) so the popover can show the chain without a second round trip. When
    ``entity_row`` is supplied, every field is also marked ``agrees`` against
    the live column value, and populated tracked fields with no claims at all
    are reported as unsourced.
    """
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.models.user import User

    rows = (
        (
            await db.execute(
                select(EntityFieldClaim)
                .where(
                    EntityFieldClaim.entity_type == entity_type,
                    EntityFieldClaim.entity_id == entity_id,
                )
                .order_by(EntityFieldClaim.last_asserted_at.desc())
            )
        )
        .scalars()
        .all()
    )

    entry_ids = {r.entry_id for r in rows if r.entry_id}
    entries: dict[uuid.UUID, dict] = {}
    if entry_ids:
        for entry_id_, title, published_at, feed_title, reliability in (
            await db.execute(
                select(Entry.id, Entry.title, Entry.published_at, Feed.title, Feed.reliability_rating)
                .join(Feed, Feed.id == Entry.feed_id)
                .where(Entry.id.in_(entry_ids))
            )
        ).all():
            entries[entry_id_] = {
                "id": str(entry_id_),
                "title": title,
                "published_at": published_at.isoformat() if published_at else None,
                "feed_title": feed_title,
                "feed_reliability": reliability,
            }

    user_ids = {r.created_by for r in rows if r.created_by}
    usernames: dict[uuid.UUID, str] = {}
    if user_ids:
        usernames = dict((await db.execute(select(User.id, User.username).where(User.id.in_(user_ids)))).all())

    from app.core.public_access import viewer_is_anonymous

    visitor = viewer_is_anonymous()
    fields: dict[str, dict] = {}
    for row in rows:
        # The article lookup above went through the visitor filter: a claim
        # drawn from an article they can't see (its quote is that article's
        # text) is left out rather than shown without its source.
        if visitor and row.entry_id and row.entry_id not in entries:
            continue
        bucket = fields.setdefault(row.field, {"current_value": None, "claims": []})
        bucket["claims"].append(
            {
                "id": str(row.id),
                "value": row.value_text,
                "source_kind": row.source_kind,
                "source_label": SOURCE_KIND_LABEL.get(row.source_kind, row.source_kind),
                "source_ref": row.source_ref,
                "quote": row.quote,
                "confidence": row.confidence,
                "analyst": usernames.get(row.created_by) if row.created_by else None,
                "entry": entries.get(row.entry_id) if row.entry_id else None,
                "first_asserted_at": row.first_asserted_at.isoformat() if row.first_asserted_at else None,
                "last_asserted_at": row.last_asserted_at.isoformat() if row.last_asserted_at else None,
                "agrees": None,
            }
        )

    tracked = PROVENANCE_FIELDS.get(entity_type, ())
    unsourced: list[str] = []
    if entity_row is not None:
        for field in tracked:
            current = render_value(getattr(entity_row, field, None))
            bucket = fields.get(field)
            if bucket is not None:
                bucket["current_value"] = current
                for claim in bucket["claims"]:
                    claim["agrees"] = claim["value"].casefold() == current.casefold()
                bucket["agreeing"] = sum(1 for c in bucket["claims"] if c["agrees"])
                bucket["conflicting"] = sum(1 for c in bucket["claims"] if c["agrees"] is False)
            elif current:
                # Populated but never attributed — the profile says so rather
                # than presenting an unsourced value as established fact.
                unsourced.append(field)

    return {
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "fields": fields,
        "unsourced_fields": unsourced,
        "tracked_fields": list(tracked),
    }
