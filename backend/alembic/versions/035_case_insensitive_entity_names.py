"""case-insensitive unique indexes on entity name columns

Merges case-duplicate rows (keeping the one with highest article_count),
drops old case-sensitive unique constraints, and adds LOWER() unique indexes
on threat_actors.name, malware_families.name, and countries.name.

Revision ID: 035_ci_entity_names
Revises: 034_campaign_saved_searches
Create Date: 2026-03-13

"""

from collections.abc import Sequence

from sqlalchemy import text

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "035_ci_entity_names"
down_revision: str | None = "034_campaign_saved_searches"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Tables and their entry-link tables for dedup
ENTITY_TABLES = [
    {
        "table": "threat_actors",
        "link_table": "entry_threat_actors",
        "link_fk": "threat_actor_id",
        "rel_entity_type": "threat_actor",
    },
    {
        "table": "malware_families",
        "link_table": "entry_malware",
        "link_fk": "malware_family_id",
        "rel_entity_type": "malware",
    },
    {
        "table": "countries",
        "link_table": "entry_countries",
        "link_fk": "country_id",
        "rel_entity_type": "country",
    },
]


def _merge_case_duplicates(conn, cfg: dict) -> None:
    """Find groups of rows whose names differ only by case, merge into one."""
    table = cfg["table"]
    link_table = cfg["link_table"]
    link_fk = cfg["link_fk"]
    entity_type = cfg["rel_entity_type"]

    # Find groups with case-duplicate names
    dups = conn.execute(
        text(
            f"SELECT LOWER(name) AS lname, array_agg(id ORDER BY article_count DESC, first_seen_at ASC) AS ids "
            f"FROM {table} GROUP BY LOWER(name) HAVING COUNT(*) > 1"
        )
    ).fetchall()

    for row in dups:
        ids = row.ids
        keeper_id = ids[0]  # highest article_count
        loser_ids = ids[1:]

        for loser_id in loser_ids:
            # Sum article_count into keeper
            conn.execute(
                text(
                    f"UPDATE {table} SET article_count = article_count + "
                    f"(SELECT article_count FROM {table} WHERE id = :loser) "
                    f"WHERE id = :keeper"
                ),
                {"keeper": keeper_id, "loser": loser_id},
            )

            # Reassign entry links (skip if link already exists for keeper)
            conn.execute(
                text(
                    f"UPDATE {link_table} SET {link_fk} = :keeper "
                    f"WHERE {link_fk} = :loser "
                    f"AND entry_id NOT IN (SELECT entry_id FROM {link_table} WHERE {link_fk} = :keeper)"
                ),
                {"keeper": keeper_id, "loser": loser_id},
            )

            # Delete remaining duplicate entry links
            conn.execute(text(f"DELETE FROM {link_table} WHERE {link_fk} = :loser"), {"loser": loser_id})

            # Reassign entity_relationships (source)
            conn.execute(
                text(
                    "UPDATE entity_relationships SET source_id = :keeper "
                    "WHERE source_type = :etype AND source_id = :loser"
                ),
                {"keeper": keeper_id, "loser": loser_id, "etype": entity_type},
            )

            # Reassign entity_relationships (target)
            conn.execute(
                text(
                    "UPDATE entity_relationships SET target_id = :keeper "
                    "WHERE target_type = :etype AND target_id = :loser"
                ),
                {"keeper": keeper_id, "loser": loser_id, "etype": entity_type},
            )

            # Delete the duplicate row
            conn.execute(text(f"DELETE FROM {table} WHERE id = :loser"), {"loser": loser_id})


def upgrade() -> None:
    conn = op.get_bind()

    # Step 1: Merge case-duplicates
    for cfg in ENTITY_TABLES:
        _merge_case_duplicates(conn, cfg)

    # Step 2: Drop old case-sensitive unique constraints/indexes, add LOWER() unique indexes
    # threat_actors — has unique constraint "threat_actors_name_key"
    op.drop_constraint("threat_actors_name_key", "threat_actors", type_="unique")
    op.create_index("ix_threat_actors_name", "threat_actors", ["name"])
    op.execute("CREATE UNIQUE INDEX uq_threat_actors_name_ci ON threat_actors (LOWER(name))")

    # malware_families — has unique constraint "malware_families_name_key"
    op.drop_constraint("malware_families_name_key", "malware_families", type_="unique")
    op.create_index("ix_malware_families_name", "malware_families", ["name"])
    op.execute("CREATE UNIQUE INDEX uq_malware_families_name_ci ON malware_families (LOWER(name))")

    # countries — has unique index "ix_countries_name"
    op.drop_index("ix_countries_name", table_name="countries")
    op.create_index("ix_countries_name", "countries", ["name"])
    op.execute("CREATE UNIQUE INDEX uq_countries_name_ci ON countries (LOWER(name))")


def downgrade() -> None:
    # threat_actors — restore unique constraint
    op.execute("DROP INDEX uq_threat_actors_name_ci")
    op.drop_index("ix_threat_actors_name", table_name="threat_actors")
    op.create_unique_constraint("threat_actors_name_key", "threat_actors", ["name"])

    # malware_families — restore unique constraint
    op.execute("DROP INDEX uq_malware_families_name_ci")
    op.drop_index("ix_malware_families_name", table_name="malware_families")
    op.create_unique_constraint("malware_families_name_key", "malware_families", ["name"])

    # countries — restore unique index
    op.execute("DROP INDEX uq_countries_name_ci")
    op.drop_index("ix_countries_name", table_name="countries")
    op.create_index("ix_countries_name", "countries", ["name"], unique=True)
