"""Drop boards feature tables

The Boards feature was unused and has been removed from the application
(models, API router, automation action, agent tools, and frontend). This
migration drops the backing tables. Downgrade recreates them with the
schema they had at the time of removal (post-059 shared data model:
created_by audit column with SET NULL).

Revision ID: f2a2b3c4d5g2
Revises: e2a2b3c4d5g1
Create Date: 2026-07-04

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "f2a2b3c4d5g2"
down_revision = "e2a2b3c4d5g1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("board_entries")
    op.drop_table("boards")


def downgrade() -> None:
    op.create_table(
        "boards",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_public", sa.Boolean, server_default=sa.text("FALSE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_boards_user_id", "boards", ["created_by"])

    op.create_table(
        "board_entries",
        sa.Column("board_id", UUID(as_uuid=True), sa.ForeignKey("boards.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("position", sa.Integer, server_default=sa.text("0"), nullable=False),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("board_id", "entry_id"),
    )
    op.create_index("ix_board_entries_entry_id", "board_entries", ["entry_id"])
