"""Drop thread following

Revision ID: w8y0z2a4c6e8
Revises: v7x9y1z3b5c7
Create Date: 2026-09-14

Following a thread only ever set a flag: nothing ranked, alerted, or filtered
on it in any surface an analyst uses. The column goes with the button.
"""

import sqlalchemy as sa

from alembic import op

revision = "w8y0z2a4c6e8"
down_revision = "v7x9y1z3b5c7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("user_thread_states", "is_following")


def downgrade() -> None:
    op.add_column(
        "user_thread_states",
        sa.Column("is_following", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
