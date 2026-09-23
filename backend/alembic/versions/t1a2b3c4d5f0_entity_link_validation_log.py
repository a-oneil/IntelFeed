"""entity_link_validation_log table + entries.last_link_validation_at

Adds the audit log for the scheduled AI-driven entity-link validator. Each
decision the validator makes (shadow_remove, removed, restored) gets one
row, with snapshot columns so removed links can be restored from the log.

Also adds a `last_link_validation_at` column on `entries` to support
oldest-first selection in the kickoff task.

Revision ID: t1a2b3c4d5f0
Revises: s1a2b3c4d5f9
Create Date: 2026-05-23

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "t1a2b3c4d5f0"
down_revision = "s1a2b3c4d5f9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "entries",
        sa.Column("last_link_validation_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_entries_last_link_validation_at",
        "entries",
        ["last_link_validation_at"],
        postgresql_ops={"last_link_validation_at": "NULLS FIRST"},
    )

    op.create_table(
        "entity_link_validation_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(length=20), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_name_snapshot", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("original_source", sa.String(length=20), nullable=True),
        sa.Column("original_confidence", sa.String(length=10), nullable=True),
        sa.Column("original_matched_names", postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column(
            "original_paragraph_indices",
            postgresql.ARRAY(sa.SmallInteger()),
            nullable=True,
        ),
        sa.Column("original_extracted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "ai_result_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_entity_link_validation_log_entry_id",
        "entity_link_validation_log",
        ["entry_id"],
    )
    op.create_index(
        "ix_link_validation_log_entity",
        "entity_link_validation_log",
        ["entity_type", "entity_id"],
    )
    op.create_index(
        "ix_link_validation_log_created_at_desc",
        "entity_link_validation_log",
        ["created_at"],
    )
    op.create_index(
        "ix_link_validation_log_action_created_at",
        "entity_link_validation_log",
        ["action", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_link_validation_log_action_created_at", table_name="entity_link_validation_log")
    op.drop_index("ix_link_validation_log_created_at_desc", table_name="entity_link_validation_log")
    op.drop_index("ix_link_validation_log_entity", table_name="entity_link_validation_log")
    op.drop_index("ix_entity_link_validation_log_entry_id", table_name="entity_link_validation_log")
    op.drop_table("entity_link_validation_log")
    op.drop_index("ix_entries_last_link_validation_at", table_name="entries")
    op.drop_column("entries", "last_link_validation_at")
