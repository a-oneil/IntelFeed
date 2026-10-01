"""Reputation summary on observables.

VirusTotal / GreyNoise / Shodan results used to land only in
``enrichment_results`` and never reached an ``Observable`` column, so the
ledger could not say "this IP is a known VPN exit" or "flagged by 12 engines".
``reputation`` holds the compact summary the entity updater writes
(``{asn, country, ports, tags, vt_ratio, gn_classification, gn_riot,
enriched_at}``); the updater also fills ``infra_tag`` from it.

Revision ID: t0k2m4o6q8s0
Revises: s8j0l2n4p6r8
Create Date: 2026-10-01
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "t0k2m4o6q8s0"
down_revision = "s8j0l2n4p6r8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("observables", sa.Column("reputation", postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column("observables", "reputation")
