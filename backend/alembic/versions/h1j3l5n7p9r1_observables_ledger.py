"""observables ledger: observables + entry_observables + candidate staging

The IOC ledger, second attempt (v1 was dropped in 060_remove_ioc_tables).
Nothing is backfilled inline; scripts/maintenance/backfill_observables.py
upserts the pre-curated EntryTTP.observable_value rows and parses ioc_list
feed bodies after deploy.

Revision ID: h1j3l5n7p9r1
Revises: g8i0k2m4o6q8
Create Date: 2026-09-19
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

from alembic import op

revision = "h1j3l5n7p9r1"
down_revision = "g8i0k2m4o6q8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "observables",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(20), nullable=False, index=True),
        sa.Column("value", sa.Text(), nullable=False, index=True),
        sa.Column("label", sa.String(200)),
        sa.Column("content", sa.Text()),
        sa.Column("language", sa.String(20)),
        sa.Column("role", sa.String(20), index=True),
        sa.Column("description", sa.Text()),
        sa.Column("evidence", sa.Text()),
        sa.Column("base_confidence", sa.Float(), nullable=False, server_default="0.8"),
        sa.Column("current_confidence", sa.Float(), nullable=False, server_default="0.8"),
        sa.Column("confidence_pinned", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("status", sa.String(12), nullable=False, server_default="active", index=True),
        sa.Column("is_denied", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_via", sa.String(20), index=True),
        sa.Column("created_from_entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="SET NULL")),
        sa.Column("created_confidence", sa.String(10)),
        sa.Column("needs_review", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("article_count", sa.Integer(), server_default="0"),
        sa.Column("sighting_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("kind", "value", name="uq_observable_kind_value"),
    )
    op.create_table(
        "entry_observables",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True),
        sa.Column(
            "observable_id",
            UUID(as_uuid=True),
            sa.ForeignKey("observables.id", ondelete="CASCADE"),
            primary_key=True,
            index=True,
        ),
        sa.Column("confidence", sa.String(10)),
        sa.Column("source", sa.String(20)),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("paragraph_indices", ARRAY(sa.SmallInteger())),
        sa.Column("surface_form", sa.Text()),
        sa.Column("was_defanged", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("ttp_id", UUID(as_uuid=True), sa.ForeignKey("ttps.id", ondelete="SET NULL")),
    )
    op.add_column("entries", sa.Column("observable_candidates", JSONB, nullable=False, server_default="[]"))


def downgrade() -> None:
    op.drop_column("entries", "observable_candidates")
    op.drop_table("entry_observables")
    op.drop_table("observables")
