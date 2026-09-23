"""add entity_maintenance_log + actor_description_history tables

Backing tables for the autonomous entity-maintenance worker. Each row records
either a proposed (shadow) or applied autonomous action — merge, alias edit,
description rewrite — so the analyst can audit, promote, or revert anything
the AI did to the workbench.

Revision ID: x1a2b3c4d5f4
Revises: w1a2b3c4d5f3
Create Date: 2026-05-24

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "x1a2b3c4d5f4"
down_revision = "w1a2b3c4d5f3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_maintenance_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("entity_type", sa.String(length=30), nullable=False, index=True),
        # Surviving entity for merge actions, or the updated entity for update actions.
        # Nullable for cluster-level "no_op" decisions where there isn't a single survivor.
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=True, index=True),
        sa.Column("action", sa.String(length=40), nullable=False, index=True),
        # shadow | apply
        sa.Column("mode", sa.String(length=10), nullable=False),
        # Snapshots before/after for diff display and revert.
        sa.Column("before", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("reasoning", sa.Text(), nullable=True),
        # Source AI result that produced this action (nullable when action was manual).
        sa.Column(
            "ai_result_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_results.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("applied", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_index(
        "ix_entity_maintenance_log_entity_type_action",
        "entity_maintenance_log",
        ["entity_type", "action", "created_at"],
    )

    op.create_table(
        "actor_description_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_actors.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("previous_text", sa.Text(), nullable=True),
        sa.Column("new_text", sa.Text(), nullable=True),
        sa.Column("change_reason", sa.Text(), nullable=True),
        # ai_refresh | manual | initial_extraction
        sa.Column("source", sa.String(length=30), nullable=False),
        sa.Column(
            "ai_result_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("applied", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_table("actor_description_history")
    op.drop_index("ix_entity_maintenance_log_entity_type_action", table_name="entity_maintenance_log")
    op.drop_table("entity_maintenance_log")
