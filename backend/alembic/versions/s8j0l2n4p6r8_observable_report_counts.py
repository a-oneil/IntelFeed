"""Corroboration counters on observables: reports vs indicator feeds.

``sighting_count`` counts junction rows, and a curated indicator feed that
re-publishes one list as eighteen CSV variants produced eighteen "sightings"
of a value no article ever reported. Two new counters make the number mean
what analysts read into it:

* ``report_count`` — distinct entries that are NOT indicator-list files
  (articles, advisories, rule repos) carrying the value;
* ``feed_source_count`` — distinct feeds among the indicator-list entries
  carrying it (all of C2IntelFeeds' variants = 1).

``sighting_count`` stays as the raw junction count. Both new columns are
backfilled here from ``entry_observables`` and kept current by
``record_sighting`` / the nightly ``reconcile-observable-counters`` job.

Revision ID: s8j0l2n4p6r8
Revises: r7i9k1m3o5q7
Create Date: 2026-10-01
"""

import sqlalchemy as sa

from alembic import op

revision = "s8j0l2n4p6r8"
down_revision = "r7i9k1m3o5q7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("observables", sa.Column("report_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("observables", sa.Column("feed_source_count", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_observables_report_count", "observables", ["report_count"])
    op.execute(
        """
        WITH agg AS (
            SELECT eo.observable_id,
                   COUNT(DISTINCT eo.entry_id) FILTER (
                       WHERE COALESCE(e.metadata->>'content_type', '') <> 'ioc_list'
                   ) AS reports,
                   COUNT(DISTINCT e.feed_id) FILTER (
                       WHERE COALESCE(e.metadata->>'content_type', '') = 'ioc_list'
                   ) AS feeds
            FROM entry_observables eo
            JOIN entries e ON e.id = eo.entry_id
            GROUP BY eo.observable_id
        )
        UPDATE observables o
           SET report_count = agg.reports,
               feed_source_count = agg.feeds
          FROM agg
         WHERE o.id = agg.observable_id
        """
    )


def downgrade() -> None:
    op.drop_index("ix_observables_report_count", table_name="observables")
    op.drop_column("observables", "feed_source_count")
    op.drop_column("observables", "report_count")
