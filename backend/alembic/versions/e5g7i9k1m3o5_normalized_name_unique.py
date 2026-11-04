"""UNIQUE constraint on normalized_name — threat_actors, vendors, products only

The DB-level backstop that makes F1/F2 duplicate creation impossible
(entity creation guardrails, phase 1.4). Validated against a fresh
prod sync on 2026-08-16: threat_actors, vendors, and products are collision-
free. Deliberately EXCLUDED:

- malware_families: one residual leetspeak dupe (NoEscape vs n0_esc4pe) that
  needs a prod merge first — add the constraint in a follow-up once merged.
- offensive_tools: a *permanent*, legitimate collision (.NET vs Net — the
  cleanup explicitly keeps them separate: net.exe is a different lolbas), so a
  plain UNIQUE on normalized_name is structurally wrong for tools. The
  resolver handles this class as "ambiguous normalized match" instead.

Revision ID: e5g7i9k1m3o5
Revises: d4f6h8j0l2n4
Create Date: 2026-08-16
"""

from alembic import op

revision = "e5g7i9k1m3o5"
down_revision = "d4f6h8j0l2n4"
branch_labels = None
depends_on = None

CONSTRAINED_TABLES = ["threat_actors", "vendors", "products"]


def upgrade() -> None:
    for table in CONSTRAINED_TABLES:
        op.create_unique_constraint(f"uq_{table}_normalized_name", table, ["normalized_name"])


def downgrade() -> None:
    for table in CONSTRAINED_TABLES:
        op.drop_constraint(f"uq_{table}_normalized_name", table, type_="unique")
