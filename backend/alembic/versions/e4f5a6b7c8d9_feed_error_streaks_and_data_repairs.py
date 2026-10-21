"""Feed failure streaks, plus three data repairs from the Engine prod review.

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-10-21

Schema:
  feeds.error_since     when the current run of failed fetches began; cleared
                        by the first clean fetch. The health check pauses a
                        feed whose HTTP 4xx streak has outlasted
                        feed_auto_pause_days (default 30).
  feeds.auto_paused_at  set by that pause, so the Feeds view can show a dead
                        feed as dead rather than merely disabled; cleared on
                        resume.

error_since is backfilled for feeds already failing: the streak start is
estimated as error_count polls at the feed's own interval before its last
fetch, floored at the feed's creation. Without this every feed that has been
404 for months would start its 30-day clock at deploy time.

Data repairs:
  cves.exploit_sources  bare strings written by the Metasploit sync become
                        {"source": ...} dicts. `apply_kev_record` called
                        .get() on every element and the string took the KEV
                        sync down with it (2026-10-08 to 10-21).
  system_settings       retired keys dropped from the overrides JSONB —
                        link_validation_* and relationship_adjudication_enabled
                        (the hygiene jobs the adjudicate stage replaced),
                        agent_default_model and max_graph_nodes (read nowhere)
                        — plus the five retired jobs' schedule overrides.
                        Nothing reads them; this just stops them hiding in a
                        row the UI can't show.

Downgrade drops the two columns; the data repairs are one-way by design.
"""

import sqlalchemy as sa

from alembic import op

revision = "e4f5a6b7c8d9"
down_revision = "d3e4f5a6b7c8"
branch_labels = None
depends_on = None

RETIRED_SETTING_KEYS = (
    "link_validation_mode",
    "link_validation_batch_size",
    "link_validation_content_max_chars",
    "relationship_adjudication_enabled",
    "agent_default_model",
    "max_graph_nodes",
)
RETIRED_JOB_KEYS = (
    "validate-entity-links",
    "hygiene-proposal-review",
    "entity-merge-maintenance",
    "relationship-adjudication",
    "stale-entity-review",
)


def upgrade() -> None:
    op.add_column("feeds", sa.Column("error_since", sa.DateTime(timezone=True), nullable=True))
    op.add_column("feeds", sa.Column("auto_paused_at", sa.DateTime(timezone=True), nullable=True))

    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE feeds SET error_since = GREATEST("
            "  created_at,"
            "  COALESCE(last_fetched_at, now())"
            "    - make_interval(mins => error_count * GREATEST(fetch_interval_minutes, 1))"
            ") WHERE error_count > 0 AND error_since IS NULL"
        )
    )

    conn.execute(
        sa.text(
            "UPDATE cves SET exploit_sources = ("
            "  SELECT COALESCE(jsonb_agg("
            "    CASE WHEN jsonb_typeof(e) = 'string' THEN jsonb_build_object('source', e #>> '{}') ELSE e END"
            "  ), '[]'::jsonb)"
            "  FROM jsonb_array_elements(exploit_sources) AS e"
            ") WHERE jsonb_typeof(exploit_sources) = 'array'"
            "  AND EXISTS ("
            "    SELECT 1 FROM jsonb_array_elements(exploit_sources) AS e WHERE jsonb_typeof(e) = 'string'"
            "  )"
        )
    )

    keys = " ".join(f"- '{k}'" for k in RETIRED_SETTING_KEYS)
    jobs = " ".join(f"- '{k}'" for k in RETIRED_JOB_KEYS)
    conn.execute(sa.text(f"UPDATE system_settings SET settings = settings {keys} WHERE id = 1"))
    conn.execute(
        sa.text(
            "UPDATE system_settings SET settings = jsonb_set("
            "  settings, '{_job_schedule_overrides}',"
            f"  (settings -> '_job_schedule_overrides') {jobs}"
            ") WHERE id = 1 AND settings ? '_job_schedule_overrides'"
        )
    )


def downgrade() -> None:
    op.drop_column("feeds", "auto_paused_at")
    op.drop_column("feeds", "error_since")
