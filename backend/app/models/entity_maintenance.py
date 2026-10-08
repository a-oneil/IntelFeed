"""Audit log + history for autonomous entity-maintenance actions.

Two tables:

  entity_maintenance_log   — one row per proposed (shadow) or applied action
                              taken on an entity: the adjudicate stage's
                              verdicts (adjudication_* actions), the on-demand
                              hygiene scans' proposals, actor profile refreshes,
                              resolver decisions. Generic across entity types.

  actor_description_history — versioned snapshots of every change to a
                              threat actor's description field. Same row
                              type whether the change came from AI refresh
                              or manual editing.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EntityMaintenanceLog(Base):
    __tablename__ = "entity_maintenance_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # 'threat_actor' | 'malware' (extend as new entity types join the maintenance loop)
    entity_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    # Surviving entity for merge actions; updated entity for update actions; NULL for cluster no-ops.
    entity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    # 'merge' | 'update_description' | 'update_aliases' | 'no_op'
    action: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    # 'shadow' | 'apply'
    mode: Mapped[str] = mapped_column(String(10), nullable=False)
    before: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_results.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (Index("ix_entity_maintenance_log_entity_type_action", "entity_type", "action", "created_at"),)


class ActorDescriptionHistory(Base):
    __tablename__ = "actor_description_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_actors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    change_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 'ai_refresh' | 'manual' | 'initial_extraction'
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    ai_result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_results.id", ondelete="SET NULL"),
        nullable=True,
    )
    applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class EntityReclassifyTombstone(Base):
    """Suppresses recreation of an entity that was deliberately folded cross-type.

    When a reclassify moves an entity out of ``source_type`` into
    ``target_type`` (e.g. the malware family "Akira" folded into the "Akira"
    threat actor), we write one row per folded name/alias. Automated creation
    paths — AI extraction (``intelligence/enrichment.py``) and the Cybergeist
    sync (``intelligence/external_feeds.py``) — consult this table before making
    a new entity: a hit on ``(source_type, normalized_name)`` means the name was
    deliberately folded away and the canonical entity now lives at
    ``(target_type, target_id)``, so they skip creation and link/merge into the
    survivor instead.

    Same-type merges already survive resurrection because the loser's name lands
    in the survivor's ``aliases`` array (see ``entity_dedup``); this table closes
    the *cross-type* gap, which alias-following can't, since each importer only
    searches its own table.

    Legitimately-distinct same-name entities (Jupyter product vs Jupyter stealer)
    never get a tombstone, so they are unaffected. Set ``active=False`` to
    intentionally re-allow a split later.
    """

    __tablename__ = "entity_reclassify_tombstones"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # Lowercased, stripped name/alias that must not be recreated under source_type.
    normalized_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # ENTITY_TYPE_REGISTRY slug the name was folded OUT of ('malware' | 'threat_actor' | ...).
    source_type: Mapped[str] = mapped_column(String(30), nullable=False)
    # Slug + id of the surviving canonical entity to link/merge into instead.
    target_type: Mapped[str] = mapped_column(String(30), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("source_type", "normalized_name", name="uq_reclassify_tombstone_src_name"),
        Index("ix_reclassify_tombstone_lookup", "source_type", "normalized_name", "active"),
    )


class EntityMergeSuggestionDismissal(Base):
    """A merge-suggestion pair the analyst dismissed from the workbench.

    Pairs are stored in canonical order — (entity_type, str(entity_id))
    ascending, see ``pair_key`` in app/intelligence/merge_suggestions.py — so
    one row covers the pair regardless of the direction it was suggested in.
    Entity ids are intentionally not FKs: a dismissed pair should stay
    dismissed even if one side is later deleted and recreated elsewhere, and
    stale rows are harmless (they simply never match a live pair again).
    """

    __tablename__ = "entity_merge_suggestion_dismissals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # API entity-type slugs ('threat_actor' | 'malware' | 'tool' | 'vendor' | 'product' | 'country')
    entity_type_a: Mapped[str] = mapped_column(String(30), nullable=False)
    entity_id_a: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_type_b: Mapped[str] = mapped_column(String(30), nullable=False)
    entity_id_b: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    dismissed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "entity_type_a",
            "entity_id_a",
            "entity_type_b",
            "entity_id_b",
            name="uq_merge_suggestion_dismissal_pair",
        ),
    )
