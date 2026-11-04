"""offensive_tools → tools: table rename + persisted slug migration

Layers 2+3 of the tool-category rename (broad software-tool scope).
The frontend already spoke 'tool'; this makes storage match:

- ALTER TABLE offensive_tools RENAME TO tools (FKs reference the table by oid,
  so entry_tools.tool_id is unaffected); indexes and the alias-index trigger
  renamed to match what metadata.create_all produces on fresh installs.
- The alias-index trigger is recreated with the canonical 'tool' slug argument.
- Every persisted 'offensive_tool' slug becomes 'tool' (surveyed against a
  fresh prod sync 2026-08-16: entity_alias_index 1,865 rows, denylist 149,
  maintenance log 355, tombstones 76+14, entity_relationships 43; zero
  unique-constraint collisions in any of them). pending_autolink_matches,
  watchlists, dismissals, enrichment_results and all jsonb configs already
  used 'tool' or carry no tool rows.
- Meilisearch: code now writes entities_tool; the legacy entities_offensive_tool
  index is dropped by _ensure_entity_indexes on the next entity sync.
- API keeps a one-release read-shim (canonical_entity_type) plus the legacy
  /offensive-tools/{id}/merge route and merge_tools CLI handler alias.

Revision ID: g7i9k1m3o5q7
Revises: f6h8j0l2n4p6
Create Date: 2026-08-16
"""

from alembic import op

revision = "g7i9k1m3o5q7"
down_revision = "f6h8j0l2n4p6"
branch_labels = None
depends_on = None

INDEX_RENAMES = [
    ("offensive_tools_pkey", "tools_pkey"),
    ("ix_offensive_tools_name", "ix_tools_name"),
    ("ix_offensive_tools_tool_type", "ix_tools_tool_type"),
    ("ix_offensive_tools_normalized_name", "ix_tools_normalized_name"),
    ("ix_offensive_tools_normalized_trgm", "ix_tools_normalized_trgm"),
]

# (table, columns) that persist the entity-type slug
SLUG_COLUMNS = [
    ("entity_alias_index", ["entity_type"]),
    ("entity_name_denylist", ["entity_type"]),
    ("entity_maintenance_log", ["entity_type"]),
    ("entity_reclassify_tombstones", ["source_type", "target_type"]),
    ("entity_relationships", ["source_type", "target_type"]),
]


def upgrade() -> None:
    op.execute("ALTER TABLE offensive_tools RENAME TO tools")
    for old, new in INDEX_RENAMES:
        op.execute(f"ALTER INDEX IF EXISTS {old} RENAME TO {new}")

    op.execute("DROP TRIGGER IF EXISTS trg_offensive_tools_alias_index ON tools")
    op.execute(
        "CREATE OR REPLACE TRIGGER trg_tools_alias_index "
        "AFTER INSERT OR DELETE OR UPDATE OF name, aliases ON tools "
        "FOR EACH ROW EXECUTE FUNCTION sync_entity_alias_index('tool')"
    )

    for table, columns in SLUG_COLUMNS:
        for col in columns:
            op.execute(f"UPDATE {table} SET {col} = 'tool' WHERE {col} = 'offensive_tool'")


def downgrade() -> None:
    # entity_relationships is intentionally NOT reversed: it carried a majority
    # of 'tool'-slug rows before this migration, so a blanket reverse-update
    # would corrupt rows that never said 'offensive_tool'.
    for table, columns in SLUG_COLUMNS:
        if table == "entity_relationships":
            continue
        for col in columns:
            op.execute(f"UPDATE {table} SET {col} = 'offensive_tool' WHERE {col} = 'tool'")
    op.execute("DROP TRIGGER IF EXISTS trg_tools_alias_index ON tools")
    op.execute(
        "CREATE OR REPLACE TRIGGER trg_offensive_tools_alias_index "
        "AFTER INSERT OR DELETE OR UPDATE OF name, aliases ON tools "
        "FOR EACH ROW EXECUTE FUNCTION sync_entity_alias_index('offensive_tool')"
    )
    for old, new in INDEX_RENAMES:
        op.execute(f"ALTER INDEX IF EXISTS {new} RENAME TO {old}")
    op.execute("ALTER TABLE tools RENAME TO offensive_tools")
