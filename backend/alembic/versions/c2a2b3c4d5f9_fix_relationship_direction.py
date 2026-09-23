"""fix inverted co-occurrence relationship direction

The co-occurrence engine ordered entity pairs alphabetically by type name and
then looked the relationship verb up in either direction, so 5 of the 8
directional (source, target, verb) patterns persisted semantically backwards
(e.g. "cve exploits threat_actor"). The engine now stores semantic direction
(threat_actor -exploits-> cve); this migration flips existing rows to match.

Where both directions of the same pair+verb exist, evidence merges into the
correctly-directed row (keeping the stronger confidence) and the inverted row
is deleted before the flip, so the unique constraint can't collide.

Revision ID: c2a2b3c4d5f9
Revises: b2a2b3c4d5f8
Create Date: 2026-07-03

"""

from alembic import op

revision = "c2a2b3c4d5f9"
down_revision = "b2a2b3c4d5f8"
branch_labels = None
depends_on = None


# (stored_source_type, stored_target_type, relationship_type) patterns that are
# semantically inverted; upgrade flips each row to (target, source).
INVERTED_PATTERNS = (
    ("malware", "threat_actor", "uses"),
    ("cve", "threat_actor", "exploits"),
    ("country", "threat_actor", "targets"),
    ("cve", "malware", "exploits"),
    ("country", "malware", "targets"),
)


def _patterns_sql(patterns) -> str:
    return ", ".join(f"('{s}', '{t}', '{r}')" for s, t, r in patterns)


def _flip(patterns) -> None:
    pat = _patterns_sql(patterns)
    # 1. Where the opposite-direction row already exists, merge evidence into it
    #    and keep the stronger confidence.
    op.execute(f"""
        UPDATE entity_relationships AS ok
        SET evidence_entry_ids = ARRAY(
                SELECT DISTINCT e FROM unnest(
                    coalesce(ok.evidence_entry_ids, '{{}}'::uuid[]) ||
                    coalesce(inv.evidence_entry_ids, '{{}}'::uuid[])
                ) AS e
            ),
            confidence = CASE
                WHEN 'confirmed' IN (ok.confidence, inv.confidence) THEN 'confirmed'
                WHEN 'probable' IN (ok.confidence, inv.confidence) THEN 'probable'
                ELSE ok.confidence
            END
        FROM entity_relationships AS inv
        WHERE inv.source_type = ok.target_type AND inv.source_id = ok.target_id
          AND inv.target_type = ok.source_type AND inv.target_id = ok.source_id
          AND inv.relationship_type = ok.relationship_type
          AND (inv.source_type, inv.target_type, inv.relationship_type) IN ({pat})
    """)
    # 2. Drop the now-merged inverted duplicates.
    op.execute(f"""
        DELETE FROM entity_relationships AS inv
        USING entity_relationships AS ok
        WHERE inv.source_type = ok.target_type AND inv.source_id = ok.target_id
          AND inv.target_type = ok.source_type AND inv.target_id = ok.source_id
          AND inv.relationship_type = ok.relationship_type
          AND (inv.source_type, inv.target_type, inv.relationship_type) IN ({pat})
    """)
    # 3. Flip the remaining rows in place. Postgres evaluates the RHS against
    #    the old row values, so the swap is safe in one statement.
    op.execute(f"""
        UPDATE entity_relationships
        SET source_type = target_type, source_id = target_id,
            target_type = source_type, target_id = source_id
        WHERE (source_type, target_type, relationship_type) IN ({pat})
    """)


def upgrade() -> None:
    _flip(INVERTED_PATTERNS)


def downgrade() -> None:
    # Restore the pre-fix (alphabetically canonical) storage direction.
    _flip(tuple((t, s, r) for s, t, r in INVERTED_PATTERNS))
