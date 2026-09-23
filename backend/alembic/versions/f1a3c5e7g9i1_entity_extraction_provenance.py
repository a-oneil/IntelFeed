"""AI-extraction provenance columns on entity tables (Engine → Extraction tab)

Adds created_via / created_from_entry_id / created_confidence / needs_review to
the five entity types AI extraction can mint (threat_actors, malware_families,
tools, cves, ttps), and backfills the resolver-gated types from the existing
entity_maintenance_log ``resolution_created`` audit trail.

Revision ID: f1a3c5e7g9i1
Revises: d4e6f8h0j2l4
Create Date: 2026-08-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision: str = "f1a3c5e7g9i1"
down_revision: str = "d4e6f8h0j2l4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Every entity type AI extraction can create.
TABLES = ["threat_actors", "malware_families", "tools", "cves", "ttps"]

# Resolver-gated types whose creations are recorded in entity_maintenance_log
# (cves/ttps are catalog-keyed and never hit the resolver, so no backfill source).
BACKFILL = {
    "threat_actors": "threat_actor",
    "malware_families": "malware_family",
    "tools": "tool",
}


def upgrade() -> None:
    for table in TABLES:
        op.add_column(table, sa.Column("created_via", sa.String(20), nullable=True))
        op.add_column(table, sa.Column("created_from_entry_id", UUID(as_uuid=True), nullable=True))
        op.add_column(table, sa.Column("created_confidence", sa.String(10), nullable=True))
        op.add_column(
            table,
            sa.Column("needs_review", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
        op.create_index(f"ix_{table}_created_via", table, ["created_via"])
        op.create_foreign_key(
            f"fk_{table}_created_from_entry",
            table,
            "entries",
            ["created_from_entry_id"],
            ["id"],
            ondelete="SET NULL",
        )

    # Backfill resolver-gated entities from the audit log. The log row predates
    # the entity id, so we match on the (lowercased) name recorded at create time.
    # created_from_entry_id is resolved through a LEFT JOIN so a since-deleted
    # source entry lands as NULL rather than violating the new FK.
    for table, entity_type in BACKFILL.items():
        op.execute(
            sa.text(
                f"""
                UPDATE {table} AS t
                SET created_via = 'ai_extraction',
                    created_from_entry_id = e.id
                FROM (
                    SELECT DISTINCT ON (lower(l.before ->> 'name'))
                        lower(l.before ->> 'name') AS nm,
                        l.before ->> 'entry_id'    AS entry_id
                    FROM entity_maintenance_log AS l
                    WHERE l.action = 'resolution_created'
                      AND l.entity_type = :etype
                    ORDER BY lower(l.before ->> 'name'), l.created_at ASC
                ) AS src
                LEFT JOIN entries AS e ON e.id = NULLIF(src.entry_id, '')::uuid
                WHERE lower(t.name) = src.nm
                  AND t.created_via IS NULL
                """
            ).bindparams(etype=entity_type)
        )


def downgrade() -> None:
    for table in TABLES:
        op.drop_constraint(f"fk_{table}_created_from_entry", table, type_="foreignkey")
        op.drop_index(f"ix_{table}_created_via", table_name=table)
        op.drop_column(table, "needs_review")
        op.drop_column(table, "created_confidence")
        op.drop_column(table, "created_from_entry_id")
        op.drop_column(table, "created_via")
