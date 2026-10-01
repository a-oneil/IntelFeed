"""Promote sector to a first-class entity.

Sectors were a controlled vocabulary with no table: ``entry_sectors.sector``
held a slug, actor/malware ``targeted_sectors`` held free-text labels, and
"who targets healthcare?" could only be asked sideways. This adds the
``sectors`` table (seeded here from the vocabulary so a fresh ``upgrade head``
never has an empty FK target), gives ``entry_sectors`` the ``sector_id`` FK the
correlation engine pivots on, and creates the three target junctions that the
free-text columns will be folded into.

Ids are uuid5(SECTOR_NAMESPACE, slug) — the same ids ``app.intelligence.sectors
.sector_uuid`` mints — so dev, prod and the test schema agree on them. The rows
below are frozen copies: the module is the live source of truth, this file is
what the database looked like on 2026-09-30.

The slug column on ``entry_sectors`` stays as a natural key (closed vocabulary,
never renamed), so every slug-keyed reader keeps working. Off-vocabulary slugs
(none in prod) are dropped rather than left dangling.

Two enum CHECK constraints hard-code the entity-type list and are recreated
with ``sector`` added, otherwise notes and campaign membership 500 on the new
type.

Revision ID: q6h8j0l2n4p6
Revises: p5g7i9k1m3o5
Create Date: 2026-09-30
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

from alembic import op

revision = "q6h8j0l2n4p6"
down_revision = "p5g7i9k1m3o5"
branch_labels = None
depends_on = None

# (id, slug, name, aliases, description)
SECTORS = [
    (
        "1464dbd9-63e5-5366-9cf0-d8b9e43df524",
        "healthcare",
        "Healthcare",
        [
            "hospital",
            "hospitals",
            "medical",
            "health",
            "health care",
            "public health",
            "pharma",
            "pharmaceutical",
            "pharmaceuticals",
            "biotech",
            "life sciences",
            "clinics",
            "healthcare providers",
        ],
        "Hospitals, health systems, clinics, insurers, pharmaceutical and medical-device makers.",
    ),
    (
        "e3e5522c-a6e9-5e48-a554-ea753c5fd100",
        "financial-services",
        "Financial Services",
        [
            "bank",
            "banks",
            "banking",
            "finance",
            "financial",
            "fintech",
            "insurance",
            "investment",
            "financial institutions",
            "credit unions",
            "securities",
            "capital markets",
        ],
        "Banks, payment processors, insurers, asset managers and fintech.",
    ),
    (
        "c6980367-f749-52fd-896b-cadde09015a5",
        "government",
        "Government",
        [
            "gov",
            "public sector",
            "federal",
            "municipal",
            "state government",
            "local government",
            "ministries",
            "public administration",
            "diplomatic",
            "embassies",
            "foreign ministries",
            "law enforcement",
            "government & defense",
        ],
        "National, regional and municipal government bodies, agencies and public administration.",
    ),
    (
        "dbd8ca5b-6e5b-5d1d-a5cb-27be563ac988",
        "defense",
        "Defense",
        [
            "military",
            "defence",
            "defense contractors",
            "defence contractors",
            "armed forces",
            "defense industrial base",
        ],
        "Armed forces, defense ministries and the defense industrial base.",
    ),
    (
        "b354166e-9089-572b-9a9d-19fdf942eb44",
        "energy",
        "Energy",
        [
            "oil and gas",
            "oil & gas",
            "oil",
            "gas",
            "utilities",
            "electric",
            "electricity",
            "power",
            "power grid",
            "nuclear",
            "petroleum",
            "renewables",
            "energy & utilities",
        ],
        "Oil and gas, electric and gas utilities, renewables and power generation.",
    ),
    (
        "f2633183-c413-5e4a-8eaf-14581138d16c",
        "manufacturing",
        "Manufacturing",
        ["industrial manufacturing", "factories", "automotive", "chemical", "chemicals", "heavy industry"],
        "Industrial, automotive, chemical and consumer-goods manufacturing.",
    ),
    (
        "fd748012-980c-5bee-82b3-23a542f17af7",
        "education",
        "Education",
        ["universities", "university", "academia", "academic", "schools", "research institutions", "higher education"],
        "Schools, universities, academic research institutions and education technology.",
    ),
    (
        "c1041f7d-b09c-5f3d-9557-ca2390b9a423",
        "technology",
        "Technology",
        [
            "tech",
            "software",
            "it",
            "information technology",
            "saas",
            "semiconductor",
            "semiconductors",
            "technology companies",
        ],
        "Software, hardware, cloud, semiconductor and IT product companies.",
    ),
    (
        "01a60342-30a3-50fe-a813-2d65087c4547",
        "telecommunications",
        "Telecommunications",
        ["telecom", "telecoms", "telco", "telcos", "isp", "isps", "mobile operators", "carriers"],
        "Carriers, ISPs, mobile operators and network service providers.",
    ),
    (
        "c0c1c3a7-f993-5619-9c8e-2191447d7d13",
        "retail",
        "Retail",
        ["e-commerce", "ecommerce", "retailers", "consumer goods", "wholesale", "retail & e-commerce"],
        "Retailers, e-commerce, consumer goods and wholesale distribution.",
    ),
    (
        "cf567f48-8372-5ea5-99f5-2a4c2444a9ae",
        "transportation",
        "Transportation",
        [
            "logistics",
            "shipping",
            "aviation",
            "airlines",
            "airports",
            "maritime",
            "rail",
            "railways",
            "ports",
            "transport",
            "trucking",
        ],
        "Airlines, airports, shipping, rail, logistics and freight.",
    ),
    (
        "de0af01b-c46b-5f11-a99f-6a17bb2b278a",
        "legal",
        "Legal",
        ["law firms", "legal services", "attorneys", "lawyers"],
        "Law firms, legal services and the courts.",
    ),
    (
        "5d0f972c-58d3-5ffb-b04a-cf03131034e9",
        "media",
        "Media",
        ["news", "journalism", "journalists", "entertainment", "broadcasting", "publishing", "press"],
        "News organizations, broadcasters, publishers and entertainment.",
    ),
    (
        "d519e9ab-477d-5c4b-b3e1-7a776e6d0b7f",
        "hospitality",
        "Hospitality",
        ["hotels", "restaurants", "tourism", "travel", "casinos"],
        "Hotels, restaurants, travel, tourism and gaming venues.",
    ),
    (
        "84f3118f-d14c-53bb-95f8-b091387ed441",
        "agriculture",
        "Agriculture",
        [
            "farming",
            "food",
            "food and agriculture",
            "food production",
            "agribusiness",
            "agriculture and food production",
            "food & beverage",
            "food and beverage",
        ],
        "Farming, food production and the agribusiness supply chain.",
    ),
    (
        "a4b8c242-00e7-5b81-9901-78b7a9c9df7b",
        "aerospace",
        "Aerospace",
        ["space", "satellite", "satellites", "satellite operators"],
        "Aircraft, spacecraft and satellite manufacturers and operators.",
    ),
    (
        "08e6fe39-e0c4-57c0-926c-8eae66c27634",
        "critical-infrastructure",
        "Critical Infrastructure",
        [
            "ics",
            "ot",
            "scada",
            "industrial control systems",
            "operational technology",
            "water",
            "water treatment",
            "wastewater",
            "water utilities",
            "dams",
            "pipelines",
        ],
        "Operational technology and industrial control systems: water, power grids, pipelines and other essential services.",
    ),
    (
        "35661350-6f01-570e-9236-d004fbcdd289",
        "ngo",
        "NGO / Civil Society",
        [
            "ngos",
            "non-profit",
            "non-profits",
            "nonprofit",
            "nonprofits",
            "civil society",
            "activists",
            "dissidents",
            "think tanks",
            "human rights organizations",
            "charities",
        ],
        "Non-profits, charities, think tanks, activists and other civil-society organizations.",
    ),
    (
        "022acfad-2031-5af5-807d-4dc146365745",
        "cryptocurrency",
        "Cryptocurrency / Web3",
        ["crypto", "web3", "blockchain", "defi", "cryptocurrency exchanges", "crypto exchanges", "nft"],
        "Cryptocurrency exchanges, wallets, DeFi protocols and Web3 projects.",
    ),
    (
        "1bfbda55-ade6-5769-b91d-d34fa3ab0204",
        "msp",
        "MSP / IT Services",
        ["msps", "managed service providers", "managed services", "it services", "it providers", "outsourcing"],
        "Managed service providers, IT outsourcers and service desks with privileged access to customer environments.",
    ),
    (
        "72d3fe07-a8b5-5cc7-9493-12598c4d9c94",
        "professional-services",
        "Professional Services",
        ["business services", "consulting", "accounting"],
        "Consulting, accounting, marketing, staffing and other business services.",
    ),
]

_NOTE_ENTITY_TYPES = [
    "ioc",
    "ttp",
    "cve",
    "threat_actor",
    "malware",
    "campaign",
    "country",
    "mitigation",
    "tool",
    "vendor",
    "product",
]
_CAMPAIGN_ENTITY_TYPES = [
    "ioc",
    "ttp",
    "cve",
    "threat_actor",
    "malware",
    "country",
    "mitigation",
    "tool",
    "vendor",
    "product",
]


def _replace_check(table: str, column: str, name: str, values: list[str]) -> None:
    values_sql = ", ".join(f"'{v}'" for v in values)
    op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
    op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({column} IN ({values_sql}))")


def upgrade() -> None:
    op.create_table(
        "sectors",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(50), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("aliases", ARRAY(sa.Text), server_default="{}"),
        sa.Column("description", sa.Text),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("article_count", sa.Integer, server_default="0"),
        sa.Column("metadata_", JSONB, server_default="{}"),
        sa.UniqueConstraint("slug", name="uq_sectors_slug"),
        sa.UniqueConstraint("name", name="uq_sectors_name"),
    )
    op.create_index("ix_sectors_slug", "sectors", ["slug"])

    sectors_tbl = sa.table(
        "sectors",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("slug", sa.String),
        sa.column("name", sa.String),
        sa.column("aliases", ARRAY(sa.Text)),
        sa.column("description", sa.Text),
        sa.column("article_count", sa.Integer),
    )
    op.bulk_insert(
        sectors_tbl,
        [
            {"id": sid, "slug": slug, "name": name, "aliases": aliases, "description": desc, "article_count": 0}
            for sid, slug, name, aliases, desc in SECTORS
        ],
    )

    # --- entry_sectors: slug stays, FK arrives -------------------------------
    op.add_column(
        "entry_sectors",
        sa.Column("sector_id", UUID(as_uuid=True), sa.ForeignKey("sectors.id", ondelete="CASCADE"), nullable=True),
    )
    op.execute("UPDATE entry_sectors es SET sector_id = s.id FROM sectors s WHERE s.slug = es.sector")
    op.execute("DELETE FROM entry_sectors WHERE sector_id IS NULL")
    op.alter_column("entry_sectors", "sector_id", nullable=False)
    op.add_column("entry_sectors", sa.Column("role", sa.String(20), nullable=True))
    op.add_column("entry_sectors", sa.Column("paragraph_indices", ARRAY(sa.SmallInteger), nullable=True))
    op.create_index("ix_entry_sectors_sector_id", "entry_sectors", ["sector_id"])
    op.create_unique_constraint("uq_entry_sectors_entry_sector_id", "entry_sectors", ["entry_id", "sector_id"])

    # Article counts reflect what is already linked, the way the autolinker
    # would have bumped them had the table existed from the start.
    op.execute(
        """
        UPDATE sectors s
        SET article_count = c.n, first_seen_at = c.first_at, last_seen_at = c.last_at
        FROM (
            SELECT sector_id,
                   COUNT(DISTINCT entry_id) AS n,
                   MIN(extracted_at) AS first_at,
                   MAX(extracted_at) AS last_at
            FROM entry_sectors
            GROUP BY sector_id
        ) c
        WHERE c.sector_id = s.id
        """
    )

    # --- target junctions -----------------------------------------------------
    op.create_table(
        "threat_actor_target_sectors",
        sa.Column(
            "threat_actor_id",
            UUID(as_uuid=True),
            sa.ForeignKey("threat_actors.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("sector_id", UUID(as_uuid=True), sa.ForeignKey("sectors.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("source", sa.String(20), nullable=False, server_default="analyst"),
        sa.Column("article_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_threat_actor_target_sectors_sector_id", "threat_actor_target_sectors", ["sector_id"])

    op.create_table(
        "malware_target_sectors",
        sa.Column(
            "malware_family_id",
            UUID(as_uuid=True),
            sa.ForeignKey("malware_families.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("sector_id", UUID(as_uuid=True), sa.ForeignKey("sectors.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("source", sa.String(20), nullable=False, server_default="analyst"),
        sa.Column("article_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_malware_target_sectors_sector_id", "malware_target_sectors", ["sector_id"])

    op.create_table(
        "campaign_sectors",
        sa.Column(
            "campaign_id", UUID(as_uuid=True), sa.ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("sector_id", UUID(as_uuid=True), sa.ForeignKey("sectors.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_campaign_sectors_sector_id", "campaign_sectors", ["sector_id"])

    # --- enum CHECKs that enumerate entity types ------------------------------
    _replace_check("entity_notes", "entity_type", "ck_entity_notes_entity_type", [*_NOTE_ENTITY_TYPES, "sector"])
    _replace_check(
        "campaign_entities", "entity_type", "ck_campaign_entities_entity_type", [*_CAMPAIGN_ENTITY_TYPES, "sector"]
    )


def downgrade() -> None:
    op.execute("DELETE FROM entity_notes WHERE entity_type = 'sector'")
    op.execute("DELETE FROM campaign_entities WHERE entity_type = 'sector'")
    _replace_check("entity_notes", "entity_type", "ck_entity_notes_entity_type", _NOTE_ENTITY_TYPES)
    _replace_check("campaign_entities", "entity_type", "ck_campaign_entities_entity_type", _CAMPAIGN_ENTITY_TYPES)

    op.drop_table("campaign_sectors")
    op.drop_table("malware_target_sectors")
    op.drop_table("threat_actor_target_sectors")

    op.drop_constraint("uq_entry_sectors_entry_sector_id", "entry_sectors", type_="unique")
    op.drop_index("ix_entry_sectors_sector_id", table_name="entry_sectors")
    op.drop_column("entry_sectors", "paragraph_indices")
    op.drop_column("entry_sectors", "role")
    op.drop_column("entry_sectors", "sector_id")

    op.drop_index("ix_sectors_slug", table_name="sectors")
    op.drop_table("sectors")
