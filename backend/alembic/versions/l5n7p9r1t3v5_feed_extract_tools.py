"""Per-feed switch for AI tool-entity creation.

Advisory and detection-content feeds name affected or referenced software, not
software an adversary wielded. Left unscoped they minted most of the tool
catalog's junk — NVD alone produced 230 tools in eleven weeks, 224 of them with
no adversary link. Defaults to true so existing behaviour is unchanged; the
offending feeds are flipped off below.

See planning/tool-extraction-cleanup.md.

Revision ID: l5n7p9r1t3v5
Revises: k4m6o8q0s2u4
Create Date: 2026-09-20
"""

import sqlalchemy as sa

from alembic import op

revision = "l5n7p9r1t3v5"
down_revision = "k4m6o8q0s2u4"
branch_labels = None
depends_on = None

# Feeds whose entries are advisories, bulletins or rule repositories. Matched
# on title so the migration is portable across instances; anything absent is
# simply skipped.
_ADVISORY_FEED_TITLES = (
    "NVD - National Vulnerability Database",
    "Red Hat security updates",
    "AusCERT Security Bulletins",
    "Elastic Detection Rules",
    "Atomic Red Team",
    "Nuclei Templates",
)


def upgrade() -> None:
    op.add_column(
        "feeds",
        sa.Column("extract_tools", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.execute(
        sa.text("UPDATE feeds SET extract_tools = false WHERE title IN :titles").bindparams(
            sa.bindparam("titles", value=_ADVISORY_FEED_TITLES, expanding=True)
        )
    )


def downgrade() -> None:
    op.drop_column("feeds", "extract_tools")
