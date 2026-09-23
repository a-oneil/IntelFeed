"""add preset_type and config to webhook_presets

Revision ID: 057_add_preset_type_and_config
Revises: 056_add_webhook_presets
Create Date: 2026-04-12 13:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "057_add_preset_type_and_config"
down_revision: str | None = "056_add_webhook_presets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("webhook_presets", sa.Column("preset_type", sa.String(30), nullable=False, server_default="webhook"))
    op.add_column("webhook_presets", sa.Column("config", postgresql.JSONB, nullable=False, server_default="{}"))


def downgrade() -> None:
    op.drop_column("webhook_presets", "config")
    op.drop_column("webhook_presets", "preset_type")
