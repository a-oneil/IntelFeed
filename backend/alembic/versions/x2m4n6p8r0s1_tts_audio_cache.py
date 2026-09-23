"""tts_audio bookkeeping table for server-side (Piper) read-aloud audio.

One row per cached MP3 on the tts_media volume: disambiguates pending/ready/error
status, carries duration for the player, and drives LRU eviction via last_accessed_at.
"""

import sqlalchemy as sa

from alembic import op

revision = "x2m4n6p8r0s1"
down_revision = "w9l1m2n3o4p5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tts_audio",
        sa.Column("cache_key", sa.String(64), primary_key=True),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("ref_id", sa.String(200), nullable=True),
        sa.Column("voice", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("byte_size", sa.BigInteger(), nullable=True),
        sa.Column("error", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "last_accessed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_tts_audio_last_accessed_at", "tts_audio", ["last_accessed_at"])


def downgrade() -> None:
    op.drop_index("ix_tts_audio_last_accessed_at", table_name="tts_audio")
    op.drop_table("tts_audio")
