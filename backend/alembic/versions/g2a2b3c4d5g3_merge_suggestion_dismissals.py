"""Add entity_merge_suggestion_dismissals table

Persists merge-suggestion pairs the analyst dismissed in the Find Duplicates
workbench so the suggestion engine (app/intelligence/merge_suggestions.py)
never re-surfaces them. Pairs are stored canonically ordered by
(entity_type, entity_id::text) ascending.

Revision ID: g2a2b3c4d5g3
Revises: f2a2b3c4d5g2
Create Date: 2026-07-04

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "g2a2b3c4d5g3"
down_revision = "f2a2b3c4d5g2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_merge_suggestion_dismissals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("entity_type_a", sa.String(30), nullable=False),
        sa.Column("entity_id_a", UUID(as_uuid=True), nullable=False),
        sa.Column("entity_type_b", sa.String(30), nullable=False),
        sa.Column("entity_id_b", UUID(as_uuid=True), nullable=False),
        sa.Column(
            "dismissed_by",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.UniqueConstraint(
            "entity_type_a",
            "entity_id_a",
            "entity_type_b",
            "entity_id_b",
            name="uq_merge_suggestion_dismissal_pair",
        ),
    )


def downgrade() -> None:
    op.drop_table("entity_merge_suggestion_dismissals")
