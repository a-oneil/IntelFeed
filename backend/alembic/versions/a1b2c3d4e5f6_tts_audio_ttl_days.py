"""add per-row ttl_days to tts_audio (share-scoped 24h retention)

Revision ID: a1b2c3d4e5f6
Revises: g7i9k1m3o5q7
Create Date: 2026-08-17

Nullable per-row eviction TTL override. Null → the global
settings.tts_cache_ttl_days default; share pre-generated audio sets 1.0 so it
lapses after ~24h without extending reader/summary audio.
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "g7i9k1m3o5q7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tts_audio", sa.Column("ttl_days", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("tts_audio", "ttl_days")
