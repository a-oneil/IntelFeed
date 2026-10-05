"""User-defined chips: promotable tags and per-user chip stamps.

Superseded in part by y6q8s0u2w4y6, which makes *every* assignment per-user
and adds `tags.is_global` as the shared exception; the shape this revision
introduces (`entry_tags.id`, nullable `user_id`, the NULLS NOT DISTINCT unique
constraint) is what that revision builds on. The paragraphs below describe the
model as it stood at this revision.

Revision ID: x5p7r9t1v3x5
Revises: w4o6q8s0u2w4
Create Date: 2026-10-04

A tag can now be promoted to a chip (`display_as_chip`), which renders it in
the entry's badge row instead of the quiet meta line, with `description` as
its tooltip.

`entry_tags.user_id` brings back an owner for one kind of assignment: the chip
an automation rule stamps is personal to the rule's owner, so one analyst's
"Customer A exposure" doesn't appear on everyone's cards. NULL means shared —
every existing row, and everything tagged by hand. Migration 059 dropped the
column when tags became shared; this keeps that model and makes ownership the
exception rather than the rule.

The old (entry_id, tag_id) primary key can't hold a shared and a personal
assignment of the same tag, or two analysts' stamps on one entry, so it moves
to a surrogate id with uniqueness on (entry_id, tag_id, user_id), NULLs equal.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "x5p7r9t1v3x5"
down_revision = "w4o6q8s0u2w4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tags", sa.Column("display_as_chip", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("tags", sa.Column("description", sa.String(255), nullable=True))

    op.add_column(
        "entry_tags",
        sa.Column("id", UUID(as_uuid=True), nullable=False, server_default=sa.text("gen_random_uuid()")),
    )
    op.add_column(
        "entry_tags",
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
    )
    op.drop_constraint("entry_tags_pkey", "entry_tags", type_="primary")
    op.create_primary_key("entry_tags_pkey", "entry_tags", ["id"])
    op.create_unique_constraint(
        "uq_entry_tags_entry_tag_user",
        "entry_tags",
        ["entry_id", "tag_id", "user_id"],
        postgresql_nulls_not_distinct=True,
    )
    op.create_index("ix_entry_tags_user_id", "entry_tags", ["user_id"])


def downgrade() -> None:
    # Personal stamps have no home in the shared-only shape; drop them rather
    # than collide with a shared assignment of the same tag.
    op.execute("DELETE FROM entry_tags WHERE user_id IS NOT NULL")
    op.drop_index("ix_entry_tags_user_id", table_name="entry_tags")
    op.drop_constraint("uq_entry_tags_entry_tag_user", "entry_tags", type_="unique")
    op.drop_constraint("entry_tags_pkey", "entry_tags", type_="primary")
    op.drop_column("entry_tags", "user_id")
    op.drop_column("entry_tags", "id")
    op.create_primary_key("entry_tags_pkey", "entry_tags", ["entry_id", "tag_id"])

    op.drop_column("tags", "description")
    op.drop_column("tags", "display_as_chip")
