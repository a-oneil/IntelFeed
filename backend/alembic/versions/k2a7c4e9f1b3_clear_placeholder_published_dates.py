"""Clear placeholder publish dates: year 1 (stored as -infinity) and the epoch.

Revision ID: k2a7c4e9f1b3
Revises: j8u5y1n4h7z0
Create Date: 2026-11-24

Hugo feeds date undated pages "Mon, 01 Jan 0001"; asyncpg writes that as
-infinity, which reads back as a datetime whose .timestamp() raises and stops
the search index rebuild. Others use the Unix epoch. The adapters now drop
both (app/adapters/base.py); this clears rows stored before that. NULL is what
an entry with no parseable date already holds.
"""

from alembic import op

revision = "k2a7c4e9f1b3"
down_revision = "j8u5y1n4h7z0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE entries SET published_at = NULL WHERE published_at <= '1970-01-01 00:00:00+00'")


def downgrade() -> None:
    # The placeholder values carried no information; nothing to restore.
    pass
