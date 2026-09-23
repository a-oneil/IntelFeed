"""entry_ttps.telemetry — where a defender would see the activity

The non-endpoint bridge: one column so coverage surfaces can slice technique
observables by the telemetry that carries them (dns, netflow, cloudtrail,
identity, ...) instead of assuming everything is an endpoint story.

Revision ID: i2k4m6o8q0s2
Revises: h1j3l5n7p9r1
Create Date: 2026-09-19
"""

import sqlalchemy as sa

from alembic import op

revision = "i2k4m6o8q0s2"
down_revision = "h1j3l5n7p9r1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entry_ttps", sa.Column("telemetry", sa.String(20)))


def downgrade() -> None:
    op.drop_column("entry_ttps", "telemetry")
