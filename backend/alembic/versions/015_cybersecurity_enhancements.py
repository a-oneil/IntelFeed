"""Cybersecurity enhancements: campaigns, intel reports, entity relationships,
entity notes, telemetry sources, comments, enrichment, detection rule extensions,
IOC lifecycle, CVE EPSS/exploit tracking, feed reliability.

Revision ID: 015
Revises: 014
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

from alembic import op

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade():
    # --- New tables ---

    # Campaigns
    op.create_table(
        "campaigns",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("tlp_marking", sa.String(20), server_default="TLP:GREEN"),
        sa.Column("start_date", sa.Date),
        sa.Column("end_date", sa.Date),
        sa.Column("tags", ARRAY(sa.Text), server_default="{}"),
        sa.Column("metadata", JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_campaigns_user_id", "campaigns", ["user_id"])
    op.create_index("ix_campaigns_status", "campaigns", ["status"])

    op.create_table(
        "campaign_entries",
        sa.Column(
            "campaign_id", UUID(as_uuid=True), sa.ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("added_by", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("notes", sa.Text),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "campaign_entities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("campaign_id", UUID(as_uuid=True), sa.ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(20), server_default="related"),
        sa.Column("added_by", UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("added_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_campaign_entities_campaign_id", "campaign_entities", ["campaign_id"])

    # Intelligence Requirements
    op.create_table(
        "intelligence_requirements",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("priority", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("category", sa.String(20), server_default="operational"),
        sa.Column("keywords", ARRAY(sa.Text), server_default="{}"),
        sa.Column("entity_types", ARRAY(sa.Text), server_default="{}"),
        sa.Column("linked_feed_ids", ARRAY(UUID(as_uuid=True)), server_default="{}"),
        sa.Column("auto_match", sa.Boolean, server_default="true"),
        sa.Column("match_count", sa.Integer, server_default="0"),
        sa.Column("last_matched_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_intel_req_user_id", "intelligence_requirements", ["user_id"])
    op.create_index("ix_intel_req_status", "intelligence_requirements", ["status"])

    op.create_table(
        "requirement_matches",
        sa.Column(
            "requirement_id",
            UUID(as_uuid=True),
            sa.ForeignKey("intelligence_requirements.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("entry_id", UUID(as_uuid=True), sa.ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("match_type", sa.String(20), nullable=False),
        sa.Column("matched_on", sa.String(500), nullable=False),
        sa.Column("matched_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("relevance", sa.String(10)),
    )

    # Intel Reports
    op.create_table(
        "intel_reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("template_type", sa.String(30), nullable=False),
        sa.Column("tlp_marking", sa.String(20), server_default="TLP:GREEN"),
        sa.Column("status", sa.String(20), server_default="draft"),
        sa.Column("content", JSONB, server_default="{}"),
        sa.Column("summary", sa.Text),
        sa.Column("version", sa.Integer, server_default="1"),
        sa.Column("entry_ids", ARRAY(UUID(as_uuid=True)), server_default="{}"),
        sa.Column("entity_ids", JSONB, server_default="{}"),
        sa.Column("tags", ARRAY(sa.Text), server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("published_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_intel_reports_user_id", "intel_reports", ["user_id"])
    op.create_index("ix_intel_reports_status", "intel_reports", ["status"])

    op.create_table(
        "intel_report_versions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "report_id", UUID(as_uuid=True), sa.ForeignKey("intel_reports.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("content", JSONB, nullable=False),
        sa.Column("change_description", sa.Text),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_intel_report_versions_report_id", "intel_report_versions", ["report_id"])

    # Detection Rule Versions
    op.create_table(
        "detection_rule_versions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "rule_id", UUID(as_uuid=True), sa.ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("version_number", sa.Integer, nullable=False),
        sa.Column("rule_content", sa.Text, nullable=False),
        sa.Column("rule_type", sa.String(30)),
        sa.Column("change_description", sa.Text),
        sa.Column("changed_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_detection_rule_versions_rule_id", "detection_rule_versions", ["rule_id"])

    # Entity Relationships
    op.create_table(
        "entity_relationships",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("source_id", UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), nullable=False),
        sa.Column("relationship_type", sa.String(30), nullable=False),
        sa.Column("confidence", sa.String(20), server_default="possible"),
        sa.Column("source", sa.String(20), server_default="analyst_created"),
        sa.Column("description", sa.Text),
        sa.Column("evidence_entry_ids", ARRAY(UUID(as_uuid=True)), server_default="{}"),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("source_type", "source_id", "target_type", "target_id", "relationship_type"),
    )
    op.create_index("ix_entity_rel_source", "entity_relationships", ["source_type", "source_id"])
    op.create_index("ix_entity_rel_target", "entity_relationships", ["target_type", "target_id"])

    # Entity Notes
    op.create_table(
        "entity_notes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("note_type", sa.String(20), server_default="annotation"),
        sa.Column("tags", ARRAY(sa.Text), server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_entity_notes_entity", "entity_notes", ["entity_type", "entity_id"])
    op.create_index("ix_entity_notes_user_id", "entity_notes", ["user_id"])

    # Telemetry Sources
    op.create_table(
        "telemetry_sources",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("vendor", sa.String(100)),
        sa.Column("product", sa.String(100)),
        sa.Column("log_types", ARRAY(sa.Text), server_default="{}"),
        sa.Column("ingested_into", sa.String(50)),
        sa.Column("enabled", sa.Boolean, server_default="true"),
        sa.Column("notes", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_telemetry_sources_user_id", "telemetry_sources", ["user_id"])

    # Comments (polymorphic threaded)
    op.create_table(
        "comments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("commentable_type", sa.String(30), nullable=False),
        sa.Column("commentable_id", UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("parent_id", UUID(as_uuid=True), sa.ForeignKey("comments.id", ondelete="CASCADE")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_comments_commentable", "comments", ["commentable_type", "commentable_id"])
    op.create_index("ix_comments_user_id", "comments", ["user_id"])
    op.create_index("ix_comments_parent_id", "comments", ["parent_id"])

    op.create_table(
        "comment_mentions",
        sa.Column("comment_id", UUID(as_uuid=True), sa.ForeignKey("comments.id", ondelete="CASCADE"), primary_key=True),
        sa.Column(
            "mentioned_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
        ),
    )

    # Enrichment Sources
    op.create_table(
        "enrichment_sources",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_type", sa.String(30), unique=True, nullable=False),
        sa.Column("display_name", sa.String(100), nullable=False),
        sa.Column("is_enabled", sa.Boolean, server_default="false"),
        sa.Column("trigger_mode", sa.String(20), server_default="manual"),
        sa.Column("api_key_encrypted", sa.Text),
        sa.Column("rate_limit_config", JSONB, server_default="{}"),
        sa.Column("last_synced_at", sa.DateTime(timezone=True)),
        sa.Column("health_status", sa.String(20), server_default="unknown"),
        sa.Column("config", JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "user_enrichment_overrides",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "source_id", UUID(as_uuid=True), sa.ForeignKey("enrichment_sources.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("api_key_encrypted", sa.Text),
        sa.Column("trigger_mode_override", sa.String(20)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "source_id"),
    )

    op.create_table(
        "enrichment_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("raw_response", JSONB, nullable=False),
        sa.Column("parsed_data", JSONB, nullable=False),
        sa.Column("enriched_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), server_default="success"),
    )
    op.create_index("ix_enrichment_entity", "enrichment_results", ["entity_type", "entity_id"])
    op.create_index("ix_enrichment_source_entity", "enrichment_results", ["source_type", "entity_type", "entity_id"])

    # --- Alter existing tables ---

    # DetectionRule extensions
    op.add_column("detection_rules", sa.Column("is_draft", sa.Boolean, server_default="true"))
    op.add_column("detection_rules", sa.Column("log_sources", JSONB))
    op.add_column("detection_rules", sa.Column("mitre_tactics", ARRAY(sa.Text), server_default="{}"))
    op.add_column("detection_rules", sa.Column("data_sources", ARRAY(sa.Text), server_default="{}"))
    op.add_column("detection_rules", sa.Column("notes", sa.Text))
    op.add_column("detection_rules", sa.Column("source_entries", ARRAY(UUID(as_uuid=True)), server_default="{}"))
    op.add_column("detection_rules", sa.Column("source_actors", ARRAY(UUID(as_uuid=True)), server_default="{}"))
    op.add_column("detection_rules", sa.Column("source_campaigns", ARRAY(UUID(as_uuid=True)), server_default="{}"))

    # IOC lifecycle extensions
    op.add_column("iocs", sa.Column("status", sa.String(20), server_default="active"))
    op.add_column("iocs", sa.Column("base_confidence", sa.Float))
    op.add_column("iocs", sa.Column("current_confidence", sa.Float))
    op.add_column("iocs", sa.Column("confidence_pinned", sa.Boolean, server_default="false"))
    op.add_column("iocs", sa.Column("confidence_override", sa.Float))
    op.add_column("iocs", sa.Column("decay_profile", sa.String(20)))
    op.add_column("iocs", sa.Column("is_false_positive", sa.Boolean, server_default="false"))
    op.add_column("iocs", sa.Column("false_positive_reason", sa.Text))
    op.add_column(
        "iocs",
        sa.Column("false_positive_marked_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
    )
    op.add_column("iocs", sa.Column("false_positive_marked_at", sa.DateTime(timezone=True)))
    op.create_index("ix_iocs_status", "iocs", ["status"])

    # CVE EPSS + exploit tracking
    op.add_column("cves", sa.Column("epss_score", sa.Float))
    op.add_column("cves", sa.Column("epss_percentile", sa.Float))
    op.add_column("cves", sa.Column("epss_updated_at", sa.DateTime(timezone=True)))
    op.add_column("cves", sa.Column("exploit_availability", sa.String(25)))
    op.add_column("cves", sa.Column("github_poc_count", sa.Integer))
    op.add_column("cves", sa.Column("github_poc_urls", ARRAY(sa.Text), server_default="{}"))
    op.add_column("cves", sa.Column("metasploit_module", sa.String(255)))

    # Feed reliability
    op.add_column("feeds", sa.Column("reliability_rating", sa.String(1)))
    op.add_column("feeds", sa.Column("timeliness_rating", sa.String(10)))
    op.add_column("feeds", sa.Column("relevance_rating", sa.String(10)))
    op.add_column("feeds", sa.Column("analyst_notes", sa.Text))
    op.add_column("feeds", sa.Column("last_reviewed_at", sa.DateTime(timezone=True)))


def downgrade():
    # Feed reliability
    op.drop_column("feeds", "last_reviewed_at")
    op.drop_column("feeds", "analyst_notes")
    op.drop_column("feeds", "relevance_rating")
    op.drop_column("feeds", "timeliness_rating")
    op.drop_column("feeds", "reliability_rating")

    # CVE EPSS
    op.drop_column("cves", "metasploit_module")
    op.drop_column("cves", "github_poc_urls")
    op.drop_column("cves", "github_poc_count")
    op.drop_column("cves", "exploit_availability")
    op.drop_column("cves", "epss_updated_at")
    op.drop_column("cves", "epss_percentile")
    op.drop_column("cves", "epss_score")

    # IOC lifecycle
    op.drop_index("ix_iocs_status", "iocs")
    op.drop_column("iocs", "false_positive_marked_at")
    op.drop_column("iocs", "false_positive_marked_by")
    op.drop_column("iocs", "false_positive_reason")
    op.drop_column("iocs", "is_false_positive")
    op.drop_column("iocs", "decay_profile")
    op.drop_column("iocs", "confidence_override")
    op.drop_column("iocs", "confidence_pinned")
    op.drop_column("iocs", "current_confidence")
    op.drop_column("iocs", "base_confidence")
    op.drop_column("iocs", "status")

    # DetectionRule extensions
    op.drop_column("detection_rules", "source_campaigns")
    op.drop_column("detection_rules", "source_actors")
    op.drop_column("detection_rules", "source_entries")
    op.drop_column("detection_rules", "notes")
    op.drop_column("detection_rules", "data_sources")
    op.drop_column("detection_rules", "mitre_tactics")
    op.drop_column("detection_rules", "log_sources")
    op.drop_column("detection_rules", "is_draft")

    # Drop new tables (reverse order)
    op.drop_table("enrichment_results")
    op.drop_table("user_enrichment_overrides")
    op.drop_table("enrichment_sources")
    op.drop_table("comment_mentions")
    op.drop_table("comments")
    op.drop_table("telemetry_sources")
    op.drop_table("entity_notes")
    op.drop_table("entity_relationships")
    op.drop_table("detection_rule_versions")
    op.drop_table("intel_report_versions")
    op.drop_table("intel_reports")
    op.drop_table("requirement_matches")
    op.drop_table("intelligence_requirements")
    op.drop_table("campaign_entities")
    op.drop_table("campaign_entries")
    op.drop_table("campaigns")
