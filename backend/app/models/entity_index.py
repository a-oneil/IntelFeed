"""Normalized-name infrastructure for entity resolution (phase 1 of
the entity creation guardrails, docs/engine-settings.md).

Three pieces, kept together because they share the ``entity_norm`` SQL function:

  entity_norm(text)     — IMMUTABLE SQL function computing the hardened
                          normalization (lowercase → NFKC → leetspeak fold →
                          strip non-alphanumerics). Must produce byte-identical
                          output to ``normalize_entity_name().norm_exact`` in
                          app/intelligence/entity_resolution.py; a test asserts
                          the two stay in lockstep.

  entity_alias_index    — one row per (entity, surface form): the canonical name
                          plus every alias of the five name+aliases entity
                          tables, with the normalized form. Maintained by DB
                          triggers on those tables so every write path (AI
                          extraction, merge API alias unions, manual edits, raw
                          SQL) keeps it consistent. Powers O(1) normalized
                          lookups, cross-entity alias-collision checks, and the
                          bidirectional cross-type check.

  entity_name_denylist  — names that must never become an entity of the given
                          type again. Seeded from the 2026-08 prod cleanup's
                          review_delete verdicts (the 353 deleted junk entities
                          have no tombstones and would resurrect without this).

The function and triggers are attached to ``Base.metadata`` create events so
the test suite (which builds schema via ``metadata.create_all``, not alembic)
exercises the exact same machinery as production.
"""

import uuid
from datetime import datetime

from sqlalchemy import DDL, Boolean, DateTime, Index, String, Text, UniqueConstraint, event, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

# ENTITY_TYPE_REGISTRY slugs (matches entity_dedup._TYPE_JUNCTION) → table name.
ALIAS_INDEXED_TABLES: dict[str, str] = {
    "threat_actor": "threat_actors",
    "malware": "malware_families",
    "tool": "tools",
    "vendor": "vendors",
    "product": "products",
    "ransomware_victim": "ransomware_victims",
}

# Single source of truth for the SQL side of norm_exact. Mirrors
# normalize_entity_name() step-for-step: lower → NFKC → lower → leet fold →
# strip non-[a-z0-9]. The leet fold runs BEFORE the strip so '$'/'@' fold to
# letters instead of being discarded.
ENTITY_NORM_FN_SQL = """
CREATE OR REPLACE FUNCTION entity_norm(txt text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
    SELECT regexp_replace(
        translate(lower(normalize(lower(txt), NFKC)), '013457$@', 'oleastsa'),
        '[^a-z0-9]', '', 'g'
    )
$fn$;
"""

ALIAS_INDEX_TRIGGER_FN_SQL = """
CREATE OR REPLACE FUNCTION sync_entity_alias_index() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM entity_alias_index
        WHERE entity_type = TG_ARGV[0] AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    DELETE FROM entity_alias_index
    WHERE entity_type = TG_ARGV[0] AND entity_id = NEW.id;
    INSERT INTO entity_alias_index (id, entity_type, entity_id, surface, normalized, is_name)
    SELECT gen_random_uuid(), TG_ARGV[0], NEW.id, f.surface, entity_norm(f.surface), f.is_name
    FROM (
        SELECT NEW.name AS surface, true AS is_name
        UNION ALL
        SELECT a, false FROM unnest(COALESCE(NEW.aliases, '{}'::text[])) AS a
    ) f
    WHERE f.surface IS NOT NULL AND entity_norm(f.surface) <> ''
    ON CONFLICT (entity_type, entity_id, normalized) DO NOTHING;
    RETURN NEW;
END
$fn$;
"""


def alias_index_trigger_sql(table: str, slug: str) -> str:
    return (
        f"CREATE OR REPLACE TRIGGER trg_{table}_alias_index "
        f"AFTER INSERT OR DELETE OR UPDATE OF name, aliases ON {table} "
        f"FOR EACH ROW EXECUTE FUNCTION sync_entity_alias_index('{slug}')"
    )


class EntityAliasIndex(Base):
    """Trigger-maintained (entity, surface form, normalized form) index.

    ``entity_id`` is deliberately not a foreign key — it points into five
    different tables; the DELETE trigger on each parent keeps rows in sync.
    """

    __tablename__ = "entity_alias_index"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    # Original name/alias as stored on the entity row.
    surface: Mapped[str] = mapped_column(Text, nullable=False)
    normalized: Mapped[str] = mapped_column(String(255), nullable=False)
    is_name: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", "normalized", name="uq_entity_alias_index_row"),
        Index("ix_entity_alias_index_lookup", "entity_type", "normalized"),
        Index("ix_entity_alias_index_normalized", "normalized"),
    )


class KnownAliasMap(Base):
    """Read-only industry alias knowledge (Phase 4 of the guardrails plan).

    Rows come from external reference sources — the MISP Galaxy threat-actor
    cluster and MITRE ATT&CK intrusion sets — refreshed on the enrichment beat
    (full replace per ``source``). The resolver consults it after string
    matching: an incoming name whose known synonym cluster maps to an existing
    profile resolves without an AI call (kills the F4 vendor-name-blindness
    class: "Secret Blizzard" → cluster{Turla, Krypton, Venomous Bear} → the
    stored Turla profile). It never writes aliases to profiles — alias writes
    still pass the Phase 2 gate.
    """

    __tablename__ = "known_alias_map"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    canonical_name: Mapped[str] = mapped_column(Text, nullable=False)
    alias: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_canonical: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_alias: Mapped[str] = mapped_column(String(255), nullable=False)
    # 'misp_galaxy' | 'mitre_attack'
    source: Mapped[str] = mapped_column(String(30), nullable=False)

    __table_args__ = (
        UniqueConstraint("source", "normalized_canonical", "normalized_alias", name="uq_known_alias_map_row"),
        Index("ix_known_alias_map_alias", "normalized_alias"),
        Index("ix_known_alias_map_canonical", "normalized_canonical"),
    )


class EntityNameDenylist(Base):
    """Names banned from entity creation for a given entity type.

    Checked (normalized, both exact and descriptor-stripped forms) by the
    Phase 2 creation gate in app/intelligence/entity_resolution.py. Rows carry
    the original display name and the cleanup rationale for the Hygiene UI.
    """

    __tablename__ = "entity_name_denylist"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # ENTITY_TYPE_REGISTRY slug the name is banned in ('threat_actor' | 'malware' | ...).
    entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 'cleanup_2026_08' (migration seed) | 'manual'
    source: Mapped[str] = mapped_column(String(40), nullable=False, default="manual")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("entity_type", "normalized_name", name="uq_entity_name_denylist"),
        Index("ix_entity_name_denylist_lookup", "entity_type", "normalized_name", "active"),
    )


# entity_norm() must exist before create_all emits the generated
# normalized_name columns that reference it. Each statement is registered as
# its own DDL event — asyncpg rejects multi-command prepared statements.
for _sql in ("CREATE EXTENSION IF NOT EXISTS pg_trgm", ENTITY_NORM_FN_SQL):
    event.listen(Base.metadata, "before_create", DDL(_sql).execute_if(dialect="postgresql"))

event.listen(Base.metadata, "after_create", DDL(ALIAS_INDEX_TRIGGER_FN_SQL).execute_if(dialect="postgresql"))
for _slug, _table in ALIAS_INDEXED_TABLES.items():
    event.listen(
        Base.metadata,
        "after_create",
        DDL(alias_index_trigger_sql(_table, _slug)).execute_if(dialect="postgresql"),
    )
