"""Per-user tag assignments, with a per-tag option to go global.

Revision ID: y6q8s0u2w4y6
Revises: x5p7r9t1v3x5
Create Date: 2026-10-04

The tag list stays shared (one `tags` row per name, with its colour, chip flag
and tooltip). Who sees a tag *on an entry* is now per user: an `entry_tags`
row belongs to the user who applied it, and nobody else sees it. A tag flagged
`is_global` is the exception — one shared row per entry (`user_id` NULL),
visible to everyone — the way every tag behaved before this revision.

Existing shared assignments are copied to every human account, so day one
looks identical to everyone; from then on each analyst's tagging is their own.
Same approach as f7h9k1m3o5q7 took for saved searches. Every existing tag
starts personal; Tag Manager can flip one to global.

The SQL lives in module constants so tests/test_tag_scope.py can run the same
statements against a seeded test database.
"""

import sqlalchemy as sa

from alembic import op

revision = "y6q8s0u2w4y6"
down_revision = "x5p7r9t1v3x5"
branch_labels = None
depends_on = None

# Every human account gets its own copy of each shared assignment. The NOT
# EXISTS guard reads the pre-statement snapshot, so a re-run, or a user who
# already holds a personal row of the same tag on the same entry (x5p7r9t1v3x5's
# chip stamps), cannot trip uq_entry_tags_entry_tag_user.
COPY_SHARED_TO_EACH_USER = """
INSERT INTO entry_tags (id, entry_id, tag_id, user_id)
SELECT gen_random_uuid(), et.entry_id, et.tag_id, u.id
FROM entry_tags et
CROSS JOIN users u
WHERE et.user_id IS NULL
  AND u.role != 'system'
  AND NOT EXISTS (
      SELECT 1 FROM entry_tags x
      WHERE x.entry_id = et.entry_id
        AND x.tag_id = et.tag_id
        AND x.user_id = u.id
  )
"""

DELETE_SHARED_ROWS = "DELETE FROM entry_tags WHERE user_id IS NULL"

# Back to x5p7r9t1v3x5's shape, where NULL means shared: collapse every
# (entry, tag) that anyone holds into one shared row. Lossy on who owned what;
# the alternative — dropping personal rows — loses the tags entirely.
COLLAPSE_TO_SHARED = """
INSERT INTO entry_tags (id, entry_id, tag_id, user_id)
SELECT gen_random_uuid(), d.entry_id, d.tag_id, NULL
FROM (
    SELECT DISTINCT entry_id, tag_id FROM entry_tags WHERE user_id IS NOT NULL
) d
WHERE NOT EXISTS (
    SELECT 1 FROM entry_tags x
    WHERE x.entry_id = d.entry_id AND x.tag_id = d.tag_id AND x.user_id IS NULL
)
"""

DELETE_PERSONAL_ROWS = "DELETE FROM entry_tags WHERE user_id IS NOT NULL"


def upgrade() -> None:
    op.add_column("tags", sa.Column("is_global", sa.Boolean(), nullable=False, server_default="false"))
    # The old (entry_id, tag_id) primary key covered lookups by tag; the
    # surrogate key from x5p7r9t1v3x5 doesn't, and scope flips, merges, renames
    # and deletes all walk a tag's rows.
    op.create_index("ix_entry_tags_tag_id", "entry_tags", ["tag_id"])

    conn = op.get_bind()
    conn.execute(sa.text(COPY_SHARED_TO_EACH_USER))
    conn.execute(sa.text(DELETE_SHARED_ROWS))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text(COLLAPSE_TO_SHARED))
    conn.execute(sa.text(DELETE_PERSONAL_ROWS))

    op.drop_index("ix_entry_tags_tag_id", table_name="entry_tags")
    op.drop_column("tags", "is_global")
