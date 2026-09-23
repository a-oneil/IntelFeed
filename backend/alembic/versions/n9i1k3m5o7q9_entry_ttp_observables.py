"""Typed observables on entry_ttps.

Rules are made of observables — the domain pattern, the sideloaded DLL path,
the abused client id. `source_text` carries the sentence; these two columns
carry the artefact the sentence documents, typed so a rule draft can compile it
into a selection clause instead of re-deriving it from prose.

Written by the one-pass entry analysis (which gains the fields in its output
contract); read by the coverage workspace's quotes, the extend checklist and
the board's writable-evidence count.

Revision ID: n9i1k3m5o7q9
Revises: m8h0j2l4n6p8
Create Date: 2026-09-03
"""

import sqlalchemy as sa

from alembic import op

revision = "n9i1k3m5o7q9"
down_revision = "m8h0j2l4n6p8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # domain_pattern | path | cmdline | registry | client_id | header | hash | other
    op.add_column("entry_ttps", sa.Column("observable_type", sa.String(20), nullable=True))
    op.add_column("entry_ttps", sa.Column("observable_value", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("entry_ttps", "observable_value")
    op.drop_column("entry_ttps", "observable_type")
