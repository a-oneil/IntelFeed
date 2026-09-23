"""Phase 5: Automation rules, logs, boards, board entries

Revision ID: 006
Revises: 005
Create Date: 2026-03-04
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Automation Rules
    op.create_table(
        "automation_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_enabled", sa.Boolean, server_default=sa.text("TRUE"), nullable=False),
        sa.Column("trigger_type", sa.String(50), nullable=False),
        sa.Column("trigger_config", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("conditions", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("actions", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_count", sa.Integer, server_default=sa.text("0"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_automation_rules_user", "automation_rules", ["user_id"])
    op.create_index("idx_automation_rules_trigger", "automation_rules", ["trigger_type"])
    op.create_index(
        "idx_automation_rules_enabled",
        "automation_rules",
        ["user_id", "is_enabled"],
        postgresql_where=sa.text("is_enabled = TRUE"),
    )

    # Automation Logs
    op.create_table(
        "automation_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "rule_id", UUID(as_uuid=True), sa.ForeignKey("automation_rules.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="SET NULL"), nullable=True),
        sa.Column("trigger_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("actions_executed", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_automation_logs_rule", "automation_logs", ["rule_id"])
    op.create_index("idx_automation_logs_date", "automation_logs", ["executed_at"])

    # Boards
    op.create_table(
        "boards",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_public", sa.Boolean, server_default=sa.text("FALSE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_boards_user", "boards", ["user_id"])

    # Board Entries
    op.create_table(
        "board_entries",
        sa.Column("board_id", UUID(as_uuid=True), sa.ForeignKey("boards.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("position", sa.Integer, server_default=sa.text("0"), nullable=False),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("board_id", "entry_id"),
    )


def downgrade() -> None:
    op.drop_table("board_entries")
    op.drop_table("boards")
    op.drop_table("automation_logs")
    op.drop_table("automation_rules")
