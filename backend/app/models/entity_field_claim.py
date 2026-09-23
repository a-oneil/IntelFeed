"""Provenance for the scalar facts on an entity profile.

The relationship trust ladder already answers "who says these two entities are
connected, and how strongly" (``EntityRelationship.source`` /
``adjudication_verdict`` / ``evidence_entry_ids``). Profile *fields* had no
such answer: an actor's motivation, origin country or targeted sectors simply
appeared, with no way to tell an analyst's deliberate edit from a Wikipedia
scrape, an AI gap-fill, or a reference-feed import — nor which article a claim
came out of.

One row per (field, value, asserter). Rows are never rewritten when a field
changes: a claim records that a source *asserted* a value at a point in time,
so a superseded claim stays on the record as the reason the field once read
differently. Whether a claim still agrees with the live column is decided at
read time by comparing against the entity row, which keeps the table free of
a "current" flag that could drift out of step with the column it describes.

Repeat assertions collapse on ``claim_key`` — the same source re-scraping the
same value nightly bumps ``last_asserted_at`` instead of growing the table —
while two *different* sources asserting the same value stay two rows, because
that is exactly the corroboration the UI needs to count.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

#: How a claim came to exist. Ordered loosely by how much an analyst should
#: trust it — ``analyst`` is a deliberate human edit, ``seed`` is bootstrap data
#: whose original source is no longer recoverable.
SOURCE_KINDS = (
    "analyst",  # a person edited the field in the UI or via the API
    "ai_extraction",  # minted by AI extraction while reading an article
    "ai_assessment",  # filled by the AI gap-fill / maintenance pass
    "enrichment",  # an enrichment adapter (wikipedia, mitre_attack, malpedia…)
    "external_feed",  # a reference feed import (cybergeist, ransomware.live…)
    "seed",  # seeded reference data
)


class EntityFieldClaim(Base):
    __tablename__ = "entity_field_claims"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # app.entity_types slug — never the model class name.
    entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # Column name on the entity model, e.g. "motivation", "targeted_sectors".
    field: Mapped[str] = mapped_column(String(40), nullable=False)
    # The asserted value, rendered for display and comparison. Lists are joined
    # so a claim about targeted_sectors reads the way the profile shows it.
    value_text: Mapped[str] = mapped_column(Text, nullable=False)

    source_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    # Which adapter/feed/task within that kind: "wikipedia", "mitre_attack",
    # "cybergeist", "ransomware.live". Null for analyst edits.
    source_ref: Mapped[str | None] = mapped_column(String(100))
    # The article the claim was read out of, when there was one.
    entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # The sentence that carries the claim, when the asserter could give one.
    quote: Mapped[str | None] = mapped_column(Text)
    # Asserter's own confidence, where it reports one: high | medium | low.
    confidence: Mapped[str | None] = mapped_column(String(10))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    ai_result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ai_results.id", ondelete="SET NULL"), nullable=True
    )

    # Stable digest of everything that makes this claim distinct — see
    # app.services.claim_provenance.claim_key().
    claim_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    first_asserted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_asserted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_entity_field_claims_lookup", "entity_type", "entity_id", "field"),
        Index("ix_entity_field_claims_recent", "entity_type", "last_asserted_at"),
    )
