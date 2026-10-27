"""detection_rules.rule_type allows nuclei and panther; enrichment overrides are per user.

ck_detection_rules_rule_type (a3b7c9d2e4f1) lists seven rule types, so a
database migrated from scratch rejects every Nuclei and Panther rule. It is
rebuilt with all nine where it exists. Databases that predate it never got
it, and still don't: adding it there could fail on rows it never checked.

user_enrichment_overrides is unique on source_id alone (059), from when
overrides were instance-wide. Overrides are per user now (pipeline.py looks
them up by created_by), so the second user to save a key for a source got an
IntegrityError. The key becomes (created_by, source_id).

user_enrichment_overrides.trigger_mode_override is dropped: it was saved and
shown but nothing read it, and enrichment results are shared, so a per-user
auto/manual switch has nothing to act on.

Revision ID: i6d7e8f9a0b1
Revises: h5c6d7e8f9a0
"""

import sqlalchemy as sa

from alembic import op

revision = "i6d7e8f9a0b1"
down_revision = "h5c6d7e8f9a0"
branch_labels = None
depends_on = None

RULE_TYPES = ["sigma", "splunk_spl", "crowdstrike_ql", "elastic_ql", "kql", "snort_suricata", "yara"]
NEW_RULE_TYPES = [*RULE_TYPES, "nuclei", "panther"]


def _constraint_exists(name: str) -> bool:
    return (
        op.get_bind().execute(sa.text("SELECT 1 FROM pg_constraint WHERE conname = :n"), {"n": name}).first()
        is not None
    )


def _set_rule_types(values: list[str], *, not_valid: bool = False) -> None:
    if not _constraint_exists("ck_detection_rules_rule_type"):
        return
    allowed = ", ".join(f"'{v}'" for v in values)
    op.execute("ALTER TABLE detection_rules DROP CONSTRAINT ck_detection_rules_rule_type")
    op.execute(
        "ALTER TABLE detection_rules ADD CONSTRAINT ck_detection_rules_rule_type "
        f"CHECK (rule_type IN ({allowed})){' NOT VALID' if not_valid else ''}"
    )


def upgrade() -> None:
    _set_rule_types(NEW_RULE_TYPES)

    if _constraint_exists("uq_enrichment_overrides_source_id"):
        op.drop_constraint("uq_enrichment_overrides_source_id", "user_enrichment_overrides", type_="unique")
    if not _constraint_exists("uq_enrichment_overrides_user_source"):
        op.create_unique_constraint(
            "uq_enrichment_overrides_user_source", "user_enrichment_overrides", ["created_by", "source_id"]
        )
    op.drop_column("user_enrichment_overrides", "trigger_mode_override")


def downgrade() -> None:
    op.add_column("user_enrichment_overrides", sa.Column("trigger_mode_override", sa.String(20), nullable=True))
    # NOT VALID: existing nuclei/panther rows stay; only new ones are refused.
    _set_rule_types(RULE_TYPES, not_valid=True)

    op.drop_constraint("uq_enrichment_overrides_user_source", "user_enrichment_overrides", type_="unique")
    op.create_unique_constraint("uq_enrichment_overrides_source_id", "user_enrichment_overrides", ["source_id"])
