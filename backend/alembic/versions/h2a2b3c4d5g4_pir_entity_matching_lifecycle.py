"""PIR entity matching + lifecycle fields

Adds to intelligence_requirements:
- linked_entities: JSONB dict of entity refs the PIR tracks
  ({"threat_actors": [{"id", "name"}], "malware": [...], "cves": [...], "ttps": [...]})
- min_relevance: optional per-PIR floor for auto-match relevance
  (NULL = keep all matches, backwards compatible)
- fulfilled_by_report_id: intel report that fulfilled this requirement

Revision ID: h2a2b3c4d5g4
Revises: g2a2b3c4d5g3
Create Date: 2026-07-04

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "h2a2b3c4d5g4"
down_revision = "g2a2b3c4d5g3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "intelligence_requirements",
        sa.Column("linked_entities", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "intelligence_requirements",
        sa.Column("min_relevance", sa.String(10), nullable=True),
    )
    op.add_column(
        "intelligence_requirements",
        sa.Column(
            "fulfilled_by_report_id",
            UUID(as_uuid=True),
            sa.ForeignKey("intel_reports.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("intelligence_requirements", "fulfilled_by_report_id")
    op.drop_column("intelligence_requirements", "min_relevance")
    op.drop_column("intelligence_requirements", "linked_entities")
