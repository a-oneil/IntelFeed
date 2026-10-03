"""Campaign sources can be a typed query.

Standing intake on a campaign was either a *linked saved search* — owned by one
analyst, invisible to their teammates, and only linkable if the search already
existed — or a follow on an entity/story the campaign already held. Neither
could express "also take anything matching this query", which is the only
intake that catches something nobody has named yet.

``kind='query'`` carries the query-language string in the new ``query`` column
and has no ``ref_id``, so that column becomes nullable; the shape of the two
is held together by ``ck_campaign_sources_shape``. The existing unique
constraint keys on ``ref_id``, and Postgres treats NULLs as distinct, so query
rows get their own partial unique index on the text instead.

Revision ID: u2m4o6q8s0u2
Revises: t0k2m4o6q8s0
Create Date: 2026-10-02
"""

import sqlalchemy as sa

from alembic import op

revision = "u2m4o6q8s0u2"
down_revision = "t0k2m4o6q8s0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("campaign_sources", sa.Column("query", sa.Text(), nullable=True))
    op.alter_column("campaign_sources", "ref_id", existing_type=sa.dialects.postgresql.UUID(), nullable=True)
    op.create_index(
        "uq_campaign_sources_query",
        "campaign_sources",
        ["campaign_id", "query"],
        unique=True,
        postgresql_where=sa.text("kind = 'query'"),
    )
    op.create_check_constraint(
        "ck_campaign_sources_shape",
        "campaign_sources",
        "(kind = 'query' AND ref_id IS NULL AND query IS NOT NULL)"
        " OR (kind <> 'query' AND ref_id IS NOT NULL AND query IS NULL)",
    )


def downgrade() -> None:
    # Query sources have no pre-query representation, so they go rather than
    # being left behind as rows with a NULL ref_id the constraint forbids.
    op.execute("DELETE FROM campaign_sources WHERE kind = 'query'")
    op.drop_constraint("ck_campaign_sources_shape", "campaign_sources", type_="check")
    op.drop_index("uq_campaign_sources_query", table_name="campaign_sources")
    op.alter_column("campaign_sources", "ref_id", existing_type=sa.dialects.postgresql.UUID(), nullable=False)
    op.drop_column("campaign_sources", "query")
