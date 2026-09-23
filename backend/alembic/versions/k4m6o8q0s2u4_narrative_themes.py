"""narrative themes — keep the day briefing's own grouping of its articles

The daily briefing sorts a day of reporting into `### Theme` sections and links
every article it cites by entry id. That structure was rendered once and
discarded. These tables keep it so the co-occurrence promotion gate can tell
"re-asserted under headings on different days" from "one reporting wave told
several ways" — the judgement evidence_structure makes from embeddings, here
without them.

Revision ID: k4m6o8q0s2u4
Revises: j3l5n7p9r1t3
Create Date: 2026-09-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "k4m6o8q0s2u4"
down_revision = "j3l5n7p9r1t3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "narrative_briefings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("day_key", sa.String(10), nullable=False),
        sa.Column("theme_count", sa.Integer(), server_default="0"),
        sa.Column("cited_entry_count", sa.Integer(), server_default="0"),
        sa.Column("parsed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("day_key", name="uq_narrative_briefing_day"),
    )
    op.create_index("ix_narrative_briefings_day_key", "narrative_briefings", ["day_key"])

    op.create_table(
        "narrative_theme_members",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("day_key", sa.String(10), nullable=False),
        sa.Column(
            "entry_id",
            UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Empty string rather than NULL for the non-theme sections, so the
        # uniqueness constraint actually constrains them.
        sa.Column("theme", sa.String(200), nullable=False, server_default=""),
        sa.Column("section", sa.String(20), nullable=False, server_default="theme"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("day_key", "entry_id", "theme", name="uq_narrative_theme_member"),
    )
    op.create_index("ix_narrative_theme_members_day_key", "narrative_theme_members", ["day_key"])
    op.create_index("ix_narrative_theme_members_entry_id", "narrative_theme_members", ["entry_id"])
    op.create_index("ix_narrative_theme_members_day_theme", "narrative_theme_members", ["day_key", "theme"])


def downgrade() -> None:
    op.drop_index("ix_narrative_theme_members_day_theme", table_name="narrative_theme_members")
    op.drop_index("ix_narrative_theme_members_entry_id", table_name="narrative_theme_members")
    op.drop_index("ix_narrative_theme_members_day_key", table_name="narrative_theme_members")
    op.drop_table("narrative_theme_members")
    op.drop_index("ix_narrative_briefings_day_key", table_name="narrative_briefings")
    op.drop_table("narrative_briefings")
