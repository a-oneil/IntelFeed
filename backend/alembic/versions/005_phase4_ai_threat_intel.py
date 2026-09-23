"""Phase 4: AI providers, tasks, prompts, IOCs, TTPs, CVEs, threat actors, malware, detection rules

Revision ID: 005
Revises: 004
Create Date: 2026-03-03
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

from alembic import op

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # AI Providers
    op.create_table(
        "ai_providers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("provider_type", sa.String(30), nullable=False),
        sa.Column("base_url", sa.Text, nullable=True),
        sa.Column("api_key_encrypted", sa.Text, nullable=True),
        sa.Column("models", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("TRUE"), nullable=False),
        sa.Column("config", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # AI Tasks
    op.create_table(
        "ai_tasks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("category", sa.String(50), nullable=True),
        sa.Column("default_prompt_template", sa.Text, nullable=False),
        sa.Column("output_schema", JSONB, nullable=True),
        sa.Column("is_system", sa.Boolean, server_default=sa.text("TRUE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # AI Prompt Templates
    op.create_table(
        "ai_prompt_templates",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("task_id", UUID(as_uuid=True), sa.ForeignKey("ai_tasks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("template_text", sa.Text, nullable=False),
        sa.Column("variables", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("TRUE"), nullable=False),
        sa.Column("version", sa.Integer, server_default=sa.text("1"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_prompts_task", "ai_prompt_templates", ["task_id"])
    op.create_index("idx_prompts_user", "ai_prompt_templates", ["user_id"])
    op.create_index(
        "idx_prompts_active",
        "ai_prompt_templates",
        ["task_id", "user_id", "is_active"],
        postgresql_where=sa.text("is_active = TRUE"),
    )

    # AI Task Assignments
    op.create_table(
        "ai_task_assignments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("task_id", UUID(as_uuid=True), sa.ForeignKey("ai_tasks.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "provider_id", UUID(as_uuid=True), sa.ForeignKey("ai_providers.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("model_name", sa.String(100), nullable=False),
        sa.Column("is_enabled", sa.Boolean, server_default=sa.text("TRUE"), nullable=False),
        sa.Column("config", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.UniqueConstraint("user_id", "task_id", name="uq_task_assignments_user_task"),
    )

    # AI Results
    op.create_table(
        "ai_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=True),
        sa.Column("task_id", UUID(as_uuid=True), sa.ForeignKey("ai_tasks.id"), nullable=False),
        sa.Column("provider_id", UUID(as_uuid=True), sa.ForeignKey("ai_providers.id"), nullable=True),
        sa.Column("model_name", sa.String(100), nullable=True),
        sa.Column("prompt_used", sa.Text, nullable=True),
        sa.Column("raw_response", sa.Text, nullable=True),
        sa.Column("parsed_result", JSONB, nullable=True),
        sa.Column("tokens_input", sa.Integer, nullable=True),
        sa.Column("tokens_output", sa.Integer, nullable=True),
        sa.Column("cost_estimate", sa.Numeric(10, 6), nullable=True),
        sa.Column("processing_time_ms", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_ai_results_entry", "ai_results", ["entry_id"])
    op.create_index("idx_ai_results_task", "ai_results", ["task_id"])
    op.create_index("idx_ai_results_date", "ai_results", ["created_at"])

    # IOCs
    op.create_table(
        "iocs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("ioc_type", sa.String(30), nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("context", sa.Text, nullable=True),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column("source_text", sa.Text, nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("enrichment", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.UniqueConstraint("ioc_type", "value", name="uq_iocs_type_value"),
    )
    op.create_index("idx_iocs_type", "iocs", ["ioc_type"])
    op.create_index("idx_iocs_value", "iocs", ["value"])
    op.create_index("idx_iocs_confidence", "iocs", ["confidence"])
    op.create_index("idx_iocs_first_seen", "iocs", ["first_seen_at"])

    # Entry-IOCs junction
    op.create_table(
        "entry_iocs",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ioc_id", UUID(as_uuid=True), sa.ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("entry_id", "ioc_id"),
    )
    op.create_index("idx_entry_iocs_ioc", "entry_iocs", ["ioc_id"])

    # TTPs
    op.create_table(
        "ttps",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("technique_id", sa.String(20), nullable=False, unique=True),
        sa.Column("technique_name", sa.String(255), nullable=False),
        sa.Column("tactic", sa.String(100), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("article_count", sa.Integer, server_default=sa.text("1"), nullable=False),
    )
    op.create_index("idx_ttps_technique", "ttps", ["technique_id"])
    op.create_index("idx_ttps_tactic", "ttps", ["tactic"])

    # Entry-TTPs junction
    op.create_table(
        "entry_ttps",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ttp_id", UUID(as_uuid=True), sa.ForeignKey("ttps.id", ondelete="CASCADE"), nullable=False),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("source_text", sa.Text, nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("entry_id", "ttp_id"),
    )
    op.create_index("idx_entry_ttps_ttp", "entry_ttps", ["ttp_id"])

    # CVEs
    op.create_table(
        "cves",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cve_id", sa.String(20), nullable=False, unique=True),
        sa.Column("cvss_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("affected_products", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("exploit_status", sa.String(30), nullable=True),
        sa.Column("exploit_sources", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("references_", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("nvd_data", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("timeline", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_cves_severity", "cves", ["severity"])
    op.create_index("idx_cves_score", "cves", ["cvss_score"])
    op.create_index("idx_cves_first_seen", "cves", ["first_seen_at"])

    # Entry-CVEs junction
    op.create_table(
        "entry_cves",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", UUID(as_uuid=True), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("entry_id", "cve_id"),
    )
    op.create_index("idx_entry_cves_cve", "entry_cves", ["cve_id"])

    # Threat Actors
    op.create_table(
        "threat_actors",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("aliases", ARRAY(sa.Text), server_default=sa.text("'{}'::text[]"), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("mitre_id", sa.String(20), nullable=True),
        sa.Column("country", sa.String(100), nullable=True),
        sa.Column("motivation", sa.String(100), nullable=True),
        sa.Column("associated_ttps", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("article_count", sa.Integer, server_default=sa.text("1"), nullable=False),
        sa.Column("metadata_", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.create_index("idx_actors_name", "threat_actors", ["name"])

    # Entry-Threat Actors junction
    op.create_table(
        "entry_threat_actors",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "threat_actor_id", UUID(as_uuid=True), sa.ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("entry_id", "threat_actor_id"),
    )
    op.create_index("idx_entry_actors_actor", "entry_threat_actors", ["threat_actor_id"])

    # Malware Families
    op.create_table(
        "malware_families",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("aliases", ARRAY(sa.Text), server_default=sa.text("'{}'::text[]"), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("malpedia_url", sa.Text, nullable=True),
        sa.Column("malware_type", sa.String(50), nullable=True),
        sa.Column("associated_actors", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("article_count", sa.Integer, server_default=sa.text("1"), nullable=False),
        sa.Column("metadata_", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.create_index("idx_malware_name", "malware_families", ["name"])
    op.create_index("idx_malware_type", "malware_families", ["malware_type"])

    # Entry-Malware junction
    op.create_table(
        "entry_malware",
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "malware_family_id",
            UUID(as_uuid=True),
            sa.ForeignKey("malware_families.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("confidence", sa.String(10), nullable=True),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("entry_id", "malware_family_id"),
    )
    op.create_index("idx_entry_malware_family", "entry_malware", ["malware_family_id"])

    # Detection Rules
    op.create_table(
        "detection_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_type", sa.String(30), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("rule_content", sa.Text, nullable=False),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("tags", ARRAY(sa.Text), server_default=sa.text("'{}'::text[]"), nullable=False),
        sa.Column("source_iocs", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("source_ttps", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_rules_user", "detection_rules", ["user_id"])
    op.create_index("idx_rules_type", "detection_rules", ["rule_type"])
    op.create_index("idx_rules_entry", "detection_rules", ["entry_id"])


def downgrade() -> None:
    op.drop_table("entry_malware")
    op.drop_table("malware_families")
    op.drop_table("entry_threat_actors")
    op.drop_table("threat_actors")
    op.drop_table("detection_rules")
    op.drop_table("entry_cves")
    op.drop_table("cves")
    op.drop_table("entry_ttps")
    op.drop_table("ttps")
    op.drop_table("entry_iocs")
    op.drop_table("iocs")
    op.drop_table("ai_results")
    op.drop_table("ai_task_assignments")
    op.drop_table("ai_prompt_templates")
    op.drop_table("ai_tasks")
    op.drop_table("ai_providers")
