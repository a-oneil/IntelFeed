"""Triage state for the Intel → Rules threat board

Three states, no lifecycle: open / handled / muted. IntelFeed does not deploy
rules and cannot observe whether one is running, so there is deliberately no
stage, owner, review date or deployment column here.

new_count_at_decision replaces a snooze date. A handled threat reappears once
its live count of first-seen-in-window techniques exceeds the count recorded
when it was dismissed, so new tradecraft reopens the row on its own and a quiet
fortnight does not.

Revision ID: l7g9i1k3m5o7
Revises: k6f8h0j2l4n6
Create Date: 2026-09-02
"""

import sqlalchemy as sa

from alembic import op

revision = "l7g9i1k3m5o7"
down_revision = "k6f8h0j2l4n6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_board_state",
        sa.Column("entity_type", sa.String(30), nullable=False),
        sa.Column("entity_key", sa.String(255), nullable=False),
        sa.Column("state", sa.String(10), nullable=False, server_default="open"),
        sa.Column("new_count_at_decision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "decided_by",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("entity_type", "entity_key"),
    )
    # The board filters by state on every load.
    op.create_index("ix_threat_board_state_state", "threat_board_state", ["state"])


def downgrade() -> None:
    op.drop_index("ix_threat_board_state_state", table_name="threat_board_state")
    op.drop_table("threat_board_state")
