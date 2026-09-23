"""observables.infra_tag — dual-use infrastructure kept, labeled

VPN exits, residential proxies, RMM endpoints, scanner/phish-sim servers are
real context (an attack *from* a NordVPN exit tells you something) but they
are not malicious indicators. Instead of denying their feed files at the
door, the door now ingests them tagged — and the publish boundary excludes
any tagged row so a VPN exit never lands on a blocklist.

Revision ID: j3l5n7p9r1t3
Revises: i2k4m6o8q0s2
Create Date: 2026-09-19
"""

import sqlalchemy as sa

from alembic import op

revision = "j3l5n7p9r1t3"
down_revision = "i2k4m6o8q0s2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("observables", sa.Column("infra_tag", sa.String(20)))
    op.create_index("ix_observables_infra_tag", "observables", ["infra_tag"])


def downgrade() -> None:
    op.drop_index("ix_observables_infra_tag", table_name="observables")
    op.drop_column("observables", "infra_tag")
