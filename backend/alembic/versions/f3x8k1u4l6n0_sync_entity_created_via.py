"""Give sync-created actors and malware their own created_via.

Revision ID: f3x8k1u4l6n0
Revises: e2w7j0t3k5m9
Create Date: 2026-11-21

The ransomware leak-site and Cybergeist syncs create entities through the
entity resolver, which writes a ``resolution_created`` audit row for every
door. The provenance backfill (f1a3c5e7g9i1) matched those rows by name and
stamped ``created_via = 'ai_extraction'`` on them, so 130 leak-site groups sat
in the AI-created table, and the ones with victims but no articles filled the
orphan lens. A sync-created entity never has a source article: that, plus the
sync's own metadata key, picks them out. The syncs set created_via themselves.
"""

import sqlalchemy as sa

from alembic import op

revision = "f3x8k1u4l6n0"
down_revision = "e2w7j0t3k5m9"
branch_labels = None
depends_on = None

_MISLABELED = "created_via = 'ai_extraction' AND created_from_entry_id IS NULL"


def upgrade() -> None:
    op.execute(
        sa.text(
            f"UPDATE threat_actors SET created_via = 'leak_site' "
            f"WHERE {_MISLABELED} AND metadata_ ->> 'source' = 'ransomware.live'"
        )
    )
    for table in ("threat_actors", "malware_families"):
        op.execute(
            sa.text(
                f"UPDATE {table} SET created_via = 'cybergeist' "
                f"WHERE {_MISLABELED} AND metadata_ ->> 'cybergeist' IS NOT NULL"
            )
        )


def downgrade() -> None:
    for table in ("threat_actors", "malware_families"):
        op.execute(
            sa.text(
                f"UPDATE {table} SET created_via = 'ai_extraction' "
                f"WHERE created_via IN ('leak_site', 'cybergeist') AND created_from_entry_id IS NULL"
            )
        )
