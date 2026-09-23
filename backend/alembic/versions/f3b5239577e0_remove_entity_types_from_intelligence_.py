"""remove entity_types from intelligence_requirements

Revision ID: f3b5239577e0
Revises: 050_report_templates
Create Date: 2026-03-16 04:09:26.086810

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3b5239577e0"
down_revision: str | None = "050_report_templates"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("intelligence_requirements", "entity_types")


def downgrade() -> None:
    op.add_column(
        "intelligence_requirements", sa.Column("entity_types", ARRAY(sa.Text), server_default="{}", nullable=True)
    )
