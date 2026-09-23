import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.database import Base
from app.intelligence.tactics import canonical_tactics


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), index=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    rule_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    # sigma, splunk_spl, crowdstrike_ql, elastic_ql, kql, snort_suricata, yara
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    rule_content: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str | None] = mapped_column(String(20))
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    source_ttps: Mapped[list] = mapped_column(JSONB, default=list)
    source_cves: Mapped[list] = mapped_column(JSONB, default=list)
    is_draft: Mapped[bool] = mapped_column(Boolean, default=True)
    log_sources: Mapped[dict | None] = mapped_column(JSONB)
    mitre_tactics: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    data_sources: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    notes: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB)
    source_entries: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    source_actors: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    source_campaigns: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    # Provenance / reuse (research redesign, phase 1)
    license: Mapped[str | None] = mapped_column(String(60))  # upstream repo license (MIT/DRL/CC0/...)
    upstream_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # source commit date
    references: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)  # advisory/blog URLs the rule cites
    source_products: Mapped[list] = mapped_column(JSONB, default=list)  # product names the rule detects against
    # A conversion of this rule into another format is a sibling row, not a
    # blob on the parent — searchable, versioned and exportable on its own.
    derived_from: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @validates("mitre_tactics")
    def _canonicalize_tactics(self, _key: str, value):
        """Fold tactic spellings on the way in, whoever is writing.

        Six paths set this column — metadata extraction, the Sigma and Elastic
        parsers, the API, the tool registry and the workbench — and each used to
        pick its own casing, so the `rule.tactic` facet listed `Persistence`
        and `persistence` as separate values and a query for one missed the
        other. Normalizing at the attribute rather than at the callers is what
        keeps the seventh writer from reintroducing the split.
        """
        return canonical_tactics(value)

    # Relationships
    entry = relationship("Entry", back_populates="detection_rules", lazy="joined")
    creator = relationship("User", back_populates="detection_rules")
    versions = relationship("DetectionRuleVersion", back_populates="rule", cascade="all, delete-orphan")

    @property
    def entry_title(self) -> str | None:
        return self.entry.title if self.entry else None

    @property
    def entry_url(self) -> str | None:
        return self.entry.url if self.entry else None

    # --- Derived provenance (research redesign, phase 1) ---
    @property
    def source_repo(self) -> str | None:
        """Upstream repo name (e.g. 'nuclei-templates'), if this rule was mirrored."""
        return (self.metadata_ or {}).get("repo")

    @property
    def source_author(self) -> str | None:
        """Original author of the upstream rule, if known."""
        meta = self.metadata_ or {}
        return meta.get("commit_author") or meta.get("owner")

    @property
    def is_authored_local(self) -> bool:
        """True when the rule originated in-app rather than mirrored from a repo."""
        return not bool((self.metadata_ or {}).get("repo"))

    @property
    def linked_entry_count(self) -> int:
        return len(self.source_entries or [])

    @property
    def linked_actor_count(self) -> int:
        return len(self.source_actors or [])
