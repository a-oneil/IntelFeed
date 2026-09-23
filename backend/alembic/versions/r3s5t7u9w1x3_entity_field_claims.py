"""Provenance for entity profile fields

Revision ID: r3s5t7u9w1x3
Revises: q2r4s6t8u0w2
Create Date: 2026-09-12

Extends the relationship trust ladder to scalar profile fields: one row per
(field, value, asserter), so an actor's motivation, origin country or targeted
sectors can name the article, adapter or analyst that put them there.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "r3s5t7u9w1x3"
down_revision = "q2r4s6t8u0w2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_field_claims",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.String(30), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("field", sa.String(40), nullable=False),
        sa.Column("value_text", sa.Text(), nullable=False),
        sa.Column("source_kind", sa.String(20), nullable=False),
        sa.Column("source_ref", sa.String(100), nullable=True),
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("quote", sa.Text(), nullable=True),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "ai_result_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("claim_key", sa.String(64), nullable=False, unique=True),
        sa.Column("first_asserted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_asserted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_entity_field_claims_lookup", "entity_field_claims", ["entity_type", "entity_id", "field"])
    op.create_index("ix_entity_field_claims_recent", "entity_field_claims", ["entity_type", "last_asserted_at"])
    op.create_index("ix_entity_field_claims_entry_id", "entity_field_claims", ["entry_id"])


def downgrade() -> None:
    op.drop_index("ix_entity_field_claims_entry_id", table_name="entity_field_claims")
    op.drop_index("ix_entity_field_claims_recent", table_name="entity_field_claims")
    op.drop_index("ix_entity_field_claims_lookup", table_name="entity_field_claims")
    op.drop_table("entity_field_claims")
