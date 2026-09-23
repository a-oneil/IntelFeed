"""copy_saved_searches_per_user — give every analyst their own copy of the shared searches

Saved searches used to be one shared list every account read. Scoping them by
``created_by`` is correct going forward, but on its own it would have silently
emptied the saved-search sidebar (and the saved-search-hits widget) for every
account except the one d5f7h9j1l3n5 backfilled the rows to.

So the backfill is a copy, not a move — the same convention the feed
subscriptions and the default dashboards use: everyone keeps what they were
seeing on day one, and divergence starts when someone edits or deletes their
own copy. Campaign links stay pointed at the original row; the copies are
independent personal searches.

Revision ID: f7h9k1m3o5q7
Revises: e6g8j0l2n4p6
Create Date: 2026-09-16
"""

import sqlalchemy as sa

from alembic import op

revision = "f7h9k1m3o5q7"
down_revision = "e6g8j0l2n4p6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # Every human account gets a copy of each existing search it does not
    # already own by that name. Name is the identity here: it is what the
    # sidebar shows and what a user would recognise as "the same search".
    #
    # DISTINCT ON collapses same-named searches owned by different people to
    # one source row — the NOT EXISTS guard reads the table's pre-statement
    # snapshot, so it cannot see rows this same INSERT is adding and would
    # otherwise hand one user two copies under the same name.
    conn.execute(
        sa.text(
            """
            INSERT INTO saved_searches (id, created_by, name, display_name, query, filters, created_at)
            SELECT gen_random_uuid(), u.id, s.name, s.display_name, s.query,
                   coalesce(s.filters, '{}'::jsonb), now()
            FROM (
                SELECT DISTINCT ON (name) name, display_name, query, filters, created_by
                FROM saved_searches
                WHERE created_by IS NOT NULL
                ORDER BY name, created_at ASC
            ) s
            CROSS JOIN users u
            WHERE u.role != 'system'
              AND u.id != s.created_by
              AND NOT EXISTS (
                  SELECT 1 FROM saved_searches x
                  WHERE x.created_by = u.id AND x.name = s.name
              )
            """
        )
    )


def downgrade() -> None:
    # Not reversible: once the copies exist they are ordinary per-user rows that
    # their owners may have edited, and nothing distinguishes an untouched copy
    # from a search that user wrote themselves. Same stance as d5f7h9j1l3n5's
    # ownership backfill.
    pass
