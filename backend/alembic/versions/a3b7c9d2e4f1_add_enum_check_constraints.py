"""add_enum_check_constraints

Revision ID: a3b7c9d2e4f1
Revises: 51c00f977a8d
Create Date: 2026-04-10 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3b7c9d2e4f1"
down_revision: str | None = "51c00f977a8d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, column, allowed_values, constraint_name)
CONSTRAINTS = [
    (
        "campaigns",
        "status",
        ["active", "monitoring", "closed", "historical"],
        "ck_campaigns_status",
    ),
    (
        "campaigns",
        "tlp_marking",
        ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"],
        "ck_campaigns_tlp_marking",
    ),
    (
        "campaign_entities",
        "entity_type",
        ["ioc", "ttp", "cve", "threat_actor", "malware", "country", "mitigation", "tool", "vendor", "product"],
        "ck_campaign_entities_entity_type",
    ),
    (
        "campaign_entities",
        "role",
        ["primary", "secondary", "related"],
        "ck_campaign_entities_role",
    ),
    (
        "iocs",
        "status",
        ["active", "expired", "false_positive", "revoked"],
        "ck_iocs_status",
    ),
    (
        "iocs",
        "source",
        ["regex", "ai"],
        "ck_iocs_source",
    ),
    (
        "detection_rules",
        "rule_type",
        ["sigma", "splunk_spl", "crowdstrike_ql", "elastic_ql", "kql", "snort_suricata", "yara"],
        "ck_detection_rules_rule_type",
    ),
    (
        "intel_reports",
        "status",
        ["draft", "published", "archived"],
        "ck_intel_reports_status",
    ),
    (
        "intel_reports",
        "tlp_marking",
        ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"],
        "ck_intel_reports_tlp_marking",
    ),
    (
        "automation_logs",
        "status",
        ["success", "error", "skipped"],
        "ck_automation_logs_status",
    ),
    (
        "intelligence_requirements",
        "priority",
        ["critical", "high", "medium", "low"],
        "ck_intelligence_requirements_priority",
    ),
    (
        "intelligence_requirements",
        "status",
        ["active", "fulfilled", "expired", "draft"],
        "ck_intelligence_requirements_status",
    ),
    (
        "intelligence_requirements",
        "category",
        ["strategic", "operational", "tactical", "technical"],
        "ck_intelligence_requirements_category",
    ),
    (
        "entity_relationships",
        "confidence",
        ["confirmed", "probable", "possible"],
        "ck_entity_relationships_confidence",
    ),
    (
        "entity_relationships",
        "source",
        ["auto_extracted", "analyst_confirmed", "analyst_created", "external_feed", "mitre_attack"],
        "ck_entity_relationships_source",
    ),
    (
        "entity_notes",
        "entity_type",
        [
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
        ],
        "ck_entity_notes_entity_type",
    ),
    (
        "entity_notes",
        "note_type",
        ["annotation", "analysis", "action_taken", "false_positive", "context"],
        "ck_entity_notes_note_type",
    ),
    (
        "entry_media",
        "media_type",
        ["audio", "video", "image", "document"],
        "ck_entry_media_media_type",
    ),
    (
        "cves",
        "exploit_availability",
        ["none", "poc", "weaponized", "active_exploitation"],
        "ck_cves_exploit_availability",
    ),
    (
        "entry_countries",
        "role",
        ["origin", "target", "infrastructure", "mentioned"],
        "ck_entry_countries_role",
    ),
    (
        "campaign_countries",
        "role",
        ["origin", "target"],
        "ck_campaign_countries_role",
    ),
    (
        "requirement_matches",
        "match_type",
        ["keyword", "entity", "manual"],
        "ck_requirement_matches_match_type",
    ),
    (
        "requirement_matches",
        "relevance",
        ["high", "medium", "low"],
        "ck_requirement_matches_relevance",
    ),
    (
        "podcasts",
        "podcast_type",
        ["episodic", "serial"],
        "ck_podcasts_podcast_type",
    ),
    (
        "ai_task_assignments",
        "execution_mode",
        ["api", "agent"],
        "ck_ai_task_assignments_execution_mode",
    ),
    (
        "users",
        "role",
        ["user", "admin"],
        "ck_users_role",
    ),
]


def upgrade() -> None:
    conn = op.get_bind()
    for table, column, values, name in CONSTRAINTS:
        # Skip if table doesn't exist or constraint already present
        tbl_exists = conn.execute(
            sa.text("SELECT 1 FROM information_schema.tables WHERE table_name=:t"), {"t": table}
        ).fetchone()
        if not tbl_exists:
            continue
        con_exists = conn.execute(sa.text("SELECT 1 FROM pg_constraint WHERE conname=:n"), {"n": name}).fetchone()
        if con_exists:
            continue
        values_sql = ", ".join(f"'{v}'" for v in values)
        op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({column} IN ({values_sql}))")


def downgrade() -> None:
    for table, _column, _values, name in CONSTRAINTS:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
