"""add_labels_to_automation_rules

Revision ID: 058_automation_labels
Revises: 057_add_preset_type_and_config
Create Date: 2026-04-13 00:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "058_automation_labels"
down_revision: str | None = "057_add_preset_type_and_config"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "automation_rules",
        sa.Column("labels", JSONB, server_default="[]", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("automation_rules", "labels")
