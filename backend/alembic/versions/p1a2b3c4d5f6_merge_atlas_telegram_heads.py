"""merge atlas + telegram migration heads

Two parallel branches existed at the time the telegram + atlas + bluesky work
landed: n1a2b3c4d5f4 (atlas heatmap theme vars) and o1a2b3c4d5f5 (telegram
mentions). This is a no-op merge that joins them so `alembic upgrade head`
resolves to a single revision.

Revision ID: p1a2b3c4d5f6
Revises: n1a2b3c4d5f4, o1a2b3c4d5f5
Create Date: 2026-05-03

"""

revision = "p1a2b3c4d5f6"
down_revision = ("n1a2b3c4d5f4", "o1a2b3c4d5f5")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
