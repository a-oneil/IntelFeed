"""Enrichment: bigint ASNs, no made-up GreyNoise class, vendor country.

- ``observables.asn`` becomes bigint: 32-bit AS numbers run to 4,294,967,295,
  past int4.
- ``observables.noise_class = 'not_seen'`` was IntelFeed's own word for "GreyNoise
  hasn't seen it scanning", not a GreyNoise class; those rows go to NULL and
  their profile context row is deleted.
- ``vendors.country_id``: the company's country (Wikidata P17), a link to a
  country row like a victim's country.

Downgrade empties ASNs int4 can't hold and drops the vendor column. NULLed GreyNoise classes stay
NULL; the next lookup answers them.

Revision ID: w4k9e2s7v1c3
Revises: c9v4a1l2s3x7
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "w4k9e2s7v1c3"
down_revision = "c9v4a1l2s3x7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("observables", "asn", type_=sa.BigInteger(), existing_type=sa.Integer(), existing_nullable=True)
    op.execute("UPDATE observables SET noise_class = NULL WHERE noise_class = 'not_seen'")
    op.execute(
        "DELETE FROM entity_context WHERE source_type = 'greynoise' AND key = 'noise_class' "
        "AND value = '\"not_seen\"'::jsonb"
    )
    op.add_column("vendors", sa.Column("country_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "vendors_country_id_fkey", "vendors", "countries", ["country_id"], ["id"], ondelete="SET NULL"
    )
    op.create_index("ix_vendors_country_id", "vendors", ["country_id"])


def downgrade() -> None:
    op.drop_index("ix_vendors_country_id", table_name="vendors")
    op.drop_constraint("vendors_country_id_fkey", "vendors", type_="foreignkey")
    op.drop_column("vendors", "country_id")
    op.execute("UPDATE observables SET asn = NULL WHERE asn > 2147483647")
    op.alter_column("observables", "asn", type_=sa.Integer(), existing_type=sa.BigInteger(), existing_nullable=True)
