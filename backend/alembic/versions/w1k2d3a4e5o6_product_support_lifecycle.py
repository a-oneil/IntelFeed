"""products.support_status and products.next_eol, from endoflife.date.

support_status is maintained, security_only, eol or unknown; next_eol is the
soonest date a maintained release stops getting security fixes. Both stay
empty for products endoflife.date doesn't list.

Revision ID: w1k2d3a4e5o6
Revises: f7s8v9c0d1e2
"""

import sqlalchemy as sa

from alembic import op

revision = "w1k2d3a4e5o6"
down_revision = "f7s8v9c0d1e2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("products", sa.Column("support_status", sa.String(20), nullable=True))
    op.add_column("products", sa.Column("next_eol", sa.Date(), nullable=True))


def downgrade() -> None:
    op.drop_column("products", "next_eol")
    op.drop_column("products", "support_status")
