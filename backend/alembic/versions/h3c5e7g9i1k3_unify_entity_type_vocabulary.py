"""Unify the entity_type vocabulary: malware_family -> malware

The merge/dedup/resolution stack keyed entity_type off the model class
(``malware_family``) while the autolinker, correlation, search and the API all
said ``malware``. Both spellings reached the same columns, so rows written by
one half of the app were invisible to the other — most visibly in
``entity_relationships``, where 213 source rows and 3 target rows sat orphaned
next to 36k that used the canonical slug.

This converts every ``entity_type``-style column to the canonical vocabulary
(see app/entity_types.py) and re-points the alias-index trigger, which carries
the slug as a trigger argument.

Not touched, deliberately: the ``malware_families`` table, the
``malware_family_id`` foreign keys, and the ``MalwareFamily`` model. Only the
discriminator string changes.

``offensive_tool`` and ``actor`` needed no data step — the 2026-08 tools rename
already cleared the former and the latter only ever lived in the search index.

Revision ID: h3c5e7g9i1k3
Revises: g2b4d6f8h0j2
"""

import sqlalchemy as sa

from alembic import op

revision = "h3c5e7g9i1k3"
down_revision = "g2b4d6f8h0j2"
branch_labels = None
depends_on = None


# (table, column) pairs holding an entity_type discriminator. Verified against a
# prod-synced database: every one of these carried 'malware_family' rows.
_TYPE_COLUMNS = [
    ("entity_alias_index", "entity_type"),
    ("entity_name_denylist", "entity_type"),
    ("entity_maintenance_log", "entity_type"),
    ("entity_reclassify_tombstones", "source_type"),
    ("entity_reclassify_tombstones", "target_type"),
    ("entity_relationships", "source_type"),
    ("entity_relationships", "target_type"),
    ("enrichment_results", "entity_type"),
    ("entity_link_validation_log", "entity_type"),
    ("entity_link_validation_log", "suggested_entity_type"),
    ("entity_merge_suggestion_dismissals", "entity_type_a"),
    ("entity_merge_suggestion_dismissals", "entity_type_b"),
]

# Tables with a uniqueness constraint that spans the type column, so a blind
# UPDATE can collide with a row that already uses the canonical slug. Each entry
# lists the other columns in the constraint.
_UNIQUE_PEERS = {
    ("entity_alias_index", "entity_type"): ["entity_id", "normalized"],
    ("entity_name_denylist", "entity_type"): ["normalized_name"],
    ("entity_reclassify_tombstones", "source_type"): ["normalized_name"],
    ("entity_merge_suggestion_dismissals", "entity_type_a"): [
        "entity_id_a",
        "entity_type_b",
        "entity_id_b",
    ],
    ("entity_merge_suggestion_dismissals", "entity_type_b"): [
        "entity_type_a",
        "entity_id_a",
        "entity_id_b",
    ],
    ("entity_relationships", "source_type"): [
        "source_id",
        "target_type",
        "target_id",
        "relationship_type",
    ],
    ("entity_relationships", "target_type"): [
        "source_type",
        "source_id",
        "target_id",
        "relationship_type",
    ],
}

_ALIAS_TRIGGER = (
    "CREATE OR REPLACE TRIGGER trg_malware_families_alias_index "
    "AFTER INSERT OR DELETE OR UPDATE OF name, aliases ON malware_families "
    "FOR EACH ROW EXECUTE FUNCTION sync_entity_alias_index('{slug}')"
)


def _convert(old: str, new: str) -> None:
    """Rewrite one slug to another across every type column, collisions first."""
    conn = op.get_bind()
    for table, column in _TYPE_COLUMNS:
        peers = _UNIQUE_PEERS.get((table, column))
        if peers:
            # Drop rows whose converted form would duplicate an existing row —
            # they are the same fact under two spellings, so the survivor is
            # already correct. Deleted rather than merged: these columns carry
            # no payload beyond the tuple itself.
            match = " AND ".join(f"dup.{c} = orig.{c}" for c in peers)
            deleted = conn.execute(
                sa.text(
                    f"DELETE FROM {table} orig WHERE orig.{column} = :old "
                    f"AND EXISTS (SELECT 1 FROM {table} dup "
                    f"WHERE dup.{column} = :new AND {match})"
                ),
                {"old": old, "new": new},
            ).rowcount
            if deleted:
                print(f"  {table}.{column}: dropped {deleted} row(s) already present as '{new}'")

        updated = conn.execute(
            sa.text(f"UPDATE {table} SET {column} = :new WHERE {column} = :old"),
            {"old": old, "new": new},
        ).rowcount
        if updated:
            print(f"  {table}.{column}: {updated} row(s) {old} -> {new}")


def upgrade() -> None:
    print("Unifying entity_type vocabulary: malware_family -> malware")
    _convert("malware_family", "malware")

    # The alias-index trigger stamps the slug into every row it writes, so it
    # has to be re-created or the next name/alias edit reintroduces the old one.
    op.execute(_ALIAS_TRIGGER.format(slug="malware"))

    # Stored prompts are user-editable rows, so the defaults.py edit alone does
    # not reach them. Same for the tool name: the pre-rename 'merge_offensive_tools'
    # alias was dead (it registered onto itself), so prompts calling it were
    # invoking a tool that no longer existed.
    for table, columns in (
        ("ai_prompt_templates", ("template_text", "system_text")),
        ("ai_tasks", ("default_prompt_template",)),
    ):
        for column in columns:
            op.execute(
                sa.text(
                    f"UPDATE {table} SET {column} = "
                    f"replace(replace(replace({column}, "
                    "'merge_offensive_tools', 'merge_tools'), "
                    "'malware_family', 'malware'), "
                    "'offensive_tool', 'tool') "
                    f"WHERE {column} IS NOT NULL"
                )
            )


def downgrade() -> None:
    # Lossy by nature: rows dropped as duplicates above cannot be recreated, and
    # a blanket reverse rename would also rewrite rows that always said
    # 'malware'. Restore the trigger so writes match the pre-migration spelling
    # and leave the data alone.
    op.execute(_ALIAS_TRIGGER.format(slug="malware_family"))
