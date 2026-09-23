"""Story threads

Revision ID: t5u7w9x1y3z5
Revises: s4t6u8w0x2y4
Create Date: 2026-09-13

A thread is one unfolding story: the articles that cover it, the spine of what
was actually new in each wave, and the re-reports folded underneath their
original. Persistent and named, unlike the per-request temporal clusters it
replaces in the reading queue.

``story_thread_entries.entry_id`` is unique on purpose — an article belongs to
at most one story. Two stories that turn out to be one merge; an article that
straddles both belongs to whichever it resembles most.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.models.vector_types import HalfVec

revision = "t5u7w9x1y3z5"
down_revision = "s4t6u8w0x2y4"
branch_labels = None
depends_on = None

EMBEDDING_DIM = 768


def upgrade() -> None:
    op.create_table(
        "story_threads",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(120), nullable=False, unique=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        # open: still accepting articles. dormant: nothing new inside the
        # dormancy window. closed: retired by hand.
        sa.Column("status", sa.String(12), nullable=False, server_default="open"),
        sa.Column("centroid", HalfVec(EMBEDDING_DIM), nullable=True),
        sa.Column("entry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("echo_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("peak_at", sa.DateTime(timezone=True), nullable=True),
        # Cached [{entity_type, entity_id, label, count}] for the row chips and
        # the join guard, refreshed by the sweeper.
        sa.Column("key_entities", postgresql.JSONB(), nullable=False, server_default="[]"),
        # Hash of the member set the current spine was written from.
        sa.Column("narrative_hash", sa.String(64), nullable=True),
        sa.Column("narrated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_story_threads_status_last_seen", "story_threads", ["status", "last_seen"])

    op.create_table(
        "story_thread_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "thread_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("story_threads.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        # origin: the article that opened the thread. beat: carried something
        # new. echo: a re-report, folded under duplicate_of_entry_id.
        sa.Column("role", sa.String(10), nullable=False, server_default="beat"),
        sa.Column("similarity", sa.Float(), nullable=False, server_default="0"),
        sa.Column(
            "duplicate_of_entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # Source domain, not feed id: one outlet published through four feeds is
        # one outlet. Mirrors _source_key in app.intelligence.signals.
        sa.Column("source_key", sa.String(255), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_story_thread_entries_thread", "story_thread_entries", ["thread_id"])

    op.create_table(
        "story_thread_beats",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "thread_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("story_threads.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        # first_disclosure | new_tradecraft | peak | update
        sa.Column("kind", sa.String(20), nullable=False, server_default="update"),
        sa.Column("headline", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column(
            "lead_entry_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("entry_ids", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("collapsed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_ai", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_index("ix_story_thread_beats_thread", "story_thread_beats", ["thread_id", "position"])

    op.create_table(
        "user_thread_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "thread_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("story_threads.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("last_opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_following", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.UniqueConstraint("user_id", "thread_id", name="uq_user_thread_states_user_thread"),
    )
    op.create_index("ix_user_thread_states_user", "user_thread_states", ["user_id"])


def downgrade() -> None:
    op.drop_table("user_thread_states")
    op.drop_table("story_thread_beats")
    op.drop_table("story_thread_entries")
    op.drop_table("story_threads")
