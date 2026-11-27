import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EntityRelationship(Base):
    __tablename__ = "entity_relationships"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    # A verb the semantic allowlist in app/intelligence/relationship_matrix.py permits for the type pair:
    # uses, exploits, targets, attributed_to, variant_of, subgroup_of, successor_of, overlaps_with,
    # communicates_with, delivers, drops, controls, exposes, operates_in, related_to
    confidence: Mapped[str] = mapped_column(String(20), default="possible")
    # confirmed, probable, possible
    source: Mapped[str] = mapped_column(String(20), default="analyst_created")
    # co_occurrence, auto_extracted, analyst_confirmed, analyst_created,
    # analyst_rejected (hidden + never resurrected by co-occurrence), external_feed,
    # enrichment (an enrichment source's Relation output; see app/enrichment/relations.py)
    description: Mapped[str | None] = mapped_column(Text)
    # The reviewers' verdict (see app/services/edge_settlement.py):
    #   kept         — an edge-level review (the sweep, or an analyst's Restore)
    #                  found the claim stated; out of the Review lens
    #   corroborated — kept by articles from two or more feeds; confirmed
    #   disputed     — kept by one article, demoted by another; stays in Review
    #   coincidental — no reviewed article states it; hidden from display
    #                  surfaces and never re-promoted by co-occurrence
    #   unsure       — the retired nightly job's "could not tell"
    adjudication_verdict: Mapped[str | None] = mapped_column(String(20))
    adjudicated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_entry_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    # Entries on which the adjudicate stage, in apply mode, kept this edge.
    # Distinct entries; at relationship_evidence_promote_count the edge is
    # promoted to confirmed.
    reviewer_kept_entry_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), default=list, server_default="{}"
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("source_type", "source_id", "target_type", "target_id", "relationship_type"),)

    # Relationships
    creator = relationship("User")


class RelationshipReview(Base):
    """One reviewer's judgment of one edge, usually against one article.

    The per-article review writes one per edge item it offered, whether or
    not the model answered (``verdict="unanswered"``), so "asked and silent"
    is a fact the sweep can act on. The sweep writes one per edge it judged,
    with the article its quote came from. ``counted`` marks the rows that
    settle the edge (apply mode, at or above the confidence floor);
    ``edge_settlement.settle_edge`` reads only those.
    """

    __tablename__ = "relationship_reviews"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    relationship_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entity_relationships.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # No FK: retention deletes articles, and the review should outlive them.
    entry_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    feed_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # adjudicator | sweep | analyst
    reviewer: Mapped[str] = mapped_column(String(20), nullable=False)
    # keep | demote | reverb | unanswered | unsure
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(10))
    reason: Mapped[str | None] = mapped_column(Text)
    quote: Mapped[str | None] = mapped_column(Text)
    # reverb: the verb the reviewer says the article states, and whether the
    # claim runs the other way
    suggested_verb: Mapped[str | None] = mapped_column(String(30))
    flipped: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    counted: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    ai_result_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
