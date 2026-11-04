"""ransomware leak-site / victim tracker

Creates ransomware_victims + victim_disclosures, wires ransomware_victims into the alias-index machinery (entity_norm()
computed normalized_name + sync_entity_alias_index trigger — both the function and
the trigger fn already exist from d4f6h8j0l2n4), and adds threat_actors.actor_type
so the dashboard can scope to ransomware groups without heuristics.

Revision ID: c3d5e7f9a1b3
Revises: a1b2c3d4e5f6
Create Date: 2026-08-19
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c3d5e7f9a1b3"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- ransomware_victims (the organization; alias-indexed entity) ---
    op.create_table(
        "ransomware_victims",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column(
            "country_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("countries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("sector", sa.String(50), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("disclosure_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("metadata_", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_ransomware_victims_name", "ransomware_victims", ["name"])
    op.create_index("ix_ransomware_victims_domain", "ransomware_victims", ["domain"])
    op.create_index("ix_ransomware_victims_country_id", "ransomware_victims", ["country_id"])
    op.create_index("ix_ransomware_victims_sector", "ransomware_victims", ["sector"])

    # DB-computed hardened normal form of name (matches vendor/threat_actor pattern).
    # entity_norm() already exists (d4f6h8j0l2n4).
    op.execute(
        "ALTER TABLE ransomware_victims ADD COLUMN normalized_name varchar(255) "
        "GENERATED ALWAYS AS (entity_norm(name)) STORED"
    )
    op.create_index("ix_ransomware_victims_normalized_name", "ransomware_victims", ["normalized_name"])
    op.execute(
        "CREATE INDEX ix_ransomware_victims_normalized_name_trgm ON ransomware_victims "
        "USING gin (normalized_name gin_trgm_ops)"
    )

    # Alias-index trigger (sync_entity_alias_index fn already exists). Backfill is a
    # no-op today but keeps the exact shape the guardrails migration established.
    op.execute(
        "CREATE TRIGGER trg_ransomware_victims_alias_index "
        "AFTER INSERT OR DELETE OR UPDATE OF name, aliases ON ransomware_victims "
        "FOR EACH ROW EXECUTE FUNCTION sync_entity_alias_index('ransomware_victim')"
    )
    op.execute(
        """
        INSERT INTO entity_alias_index (id, entity_type, entity_id, surface, normalized, is_name)
        SELECT gen_random_uuid(), 'ransomware_victim', t.id, f.surface, entity_norm(f.surface), f.is_name
        FROM ransomware_victims t
        CROSS JOIN LATERAL (
            SELECT t.name AS surface, true AS is_name
            UNION ALL
            SELECT a, false FROM unnest(COALESCE(t.aliases, '{}'::text[])) AS a
        ) f
        WHERE f.surface IS NOT NULL AND entity_norm(f.surface) <> ''
        ON CONFLICT (entity_type, entity_id, normalized) DO NOTHING
        """
    )

    # --- victim_disclosures (the posting event; what the feed lists) ---
    op.create_table(
        "victim_disclosures",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "victim_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ransomware_victims.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_actors.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("group_name_raw", sa.String(255), nullable=True),
        sa.Column("leak_site_url", sa.Text(), nullable=True),
        sa.Column("posted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "country_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("countries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("sector", sa.String(50), nullable=True),
        sa.Column("claimed_data", sa.Text(), nullable=True),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("guid", sa.String(64), nullable=False),
        sa.Column("metadata_", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("source", "guid", name="uq_victim_disclosure_source_guid"),
    )
    op.create_index("ix_victim_disclosures_victim_id", "victim_disclosures", ["victim_id"])
    op.create_index("ix_victim_disclosures_group_id", "victim_disclosures", ["group_id"])
    op.create_index("ix_victim_disclosures_posted_at", "victim_disclosures", ["posted_at"])
    op.create_index("ix_victim_disclosures_country_id", "victim_disclosures", ["country_id"])
    op.create_index("ix_victim_disclosures_sector", "victim_disclosures", ["sector"])
    op.create_index("ix_victim_disclosures_source", "victim_disclosures", ["source"])

    # --- ransomware-group discriminator on ThreatActor ---
    op.add_column("threat_actors", sa.Column("actor_type", sa.String(30), nullable=True))
    op.create_index("ix_threat_actors_actor_type", "threat_actors", ["actor_type"])


def downgrade() -> None:
    op.drop_index("ix_threat_actors_actor_type", table_name="threat_actors")
    op.drop_column("threat_actors", "actor_type")

    op.drop_table("victim_disclosures")

    op.execute("DROP TRIGGER IF EXISTS trg_ransomware_victims_alias_index ON ransomware_victims")
    op.execute("DELETE FROM entity_alias_index WHERE entity_type = 'ransomware_victim'")
    op.drop_table("ransomware_victims")
