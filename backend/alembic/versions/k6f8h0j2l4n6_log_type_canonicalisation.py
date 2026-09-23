"""Canonical log types beside the raw vendor strings

get_available_telemetry() matches a rule's required sources against
telemetry_sources.log_types, which is free text: 864 distinct values across
1,124 assignments, 721 used exactly once. Thirteen identity products are
enabled and all of them log a login, but a rule asking for `authentication`
matches 7 and one asking for `login_success` matches 1.

log_type_alias maps the raw strings onto a ~60-80 id behaviour axis
(auth.login, dns.query, process.creation, net.connection, file.write …),
aligned to the ATT&CK log-source channel names on ttps.data_sources where they
correspond. log_types itself is never rewritten — the vendor strings are what
renders on a source card.

Revision ID: k6f8h0j2l4n6
Revises: j5e7g9i1k3m5
Create Date: 2026-09-02
"""

import sqlalchemy as sa

from alembic import op

revision = "k6f8h0j2l4n6"
down_revision = "j5e7g9i1k3m5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "telemetry_sources",
        sa.Column(
            "log_types_canonical",
            sa.ARRAY(sa.Text()),
            nullable=False,
            server_default="{}",
        ),
    )
    op.create_table(
        "log_type_alias",
        sa.Column("raw", sa.String(120), nullable=False),
        sa.Column("canonical", sa.String(60), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("raw"),
    )
    op.create_index("ix_log_type_alias_canonical", "log_type_alias", ["canonical"])


def downgrade() -> None:
    op.drop_index("ix_log_type_alias_canonical", table_name="log_type_alias")
    op.drop_table("log_type_alias")
    op.drop_column("telemetry_sources", "log_types_canonical")
