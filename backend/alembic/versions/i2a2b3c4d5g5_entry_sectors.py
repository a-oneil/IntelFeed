"""Entry sector targeting + malware targeted_sectors

Adds:
- entry_sectors: controlled-vocabulary victim-sector links per entry
  (sector holds a canonical slug from app.intelligence.sectors — no
  Sector entity table). Powers the Priority Queue "my sectors" boost
  and actor/malware targeted-sector aggregation.
- malware_families.targeted_sectors: ARRAY(Text), mirrors
  threat_actors.targeted_sectors so malware profiles can show
  victimology chips.

Revision ID: i2a2b3c4d5g5
Revises: h2a2b3c4d5g4
Create Date: 2026-07-04

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, UUID

from alembic import op

revision = "i2a2b3c4d5g5"
down_revision = "h2a2b3c4d5g4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entry_sectors",
        sa.Column(
            "entry_id",
            UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("sector", sa.String(50), primary_key=True),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column(
            "extracted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_entry_sectors_sector", "entry_sectors", ["sector"])

    op.add_column(
        "malware_families",
        sa.Column(
            "targeted_sectors",
            ARRAY(sa.Text),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
    )


def downgrade() -> None:
    op.drop_column("malware_families", "targeted_sectors")
    op.drop_index("ix_entry_sectors_sector", table_name="entry_sectors")
    op.drop_table("entry_sectors")
