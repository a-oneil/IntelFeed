"""add paused_until/paused_reason to ai_providers for quota auto-pause

Lets the engine self-disable a provider when it hits the Max-plan rate
window (or any other transient quota error) and re-enable it once the
window resets — instead of silently writing provider_error rows.

Revision ID: w1a2b3c4d5f3
Revises: v1a2b3c4d5f2
Create Date: 2026-05-24

"""

import sqlalchemy as sa

from alembic import op

revision = "w1a2b3c4d5f3"
down_revision = "v1a2b3c4d5f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_providers",
        sa.Column("paused_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "ai_providers",
        sa.Column("paused_reason", sa.String(length=500), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ai_providers", "paused_reason")
    op.drop_column("ai_providers", "paused_until")
