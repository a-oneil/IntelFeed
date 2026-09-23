import uuid
from datetime import datetime

from sqlalchemy import Boolean, Computed, DateTime, ForeignKey, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.database import Base
from app.intelligence.platforms import canonical_platforms

# Controlled tool_type vocabulary. STIX 2.1 tool types + offensive security
# categories, extended 2026-08 for the broad tools scope (any software tool:
# offensive, defensive, general software, services, LLMs). Free-text values
# are coerced to this vocab on write (see entity_resolution.coerce_tool_type);
# the raw string is preserved in metadata_["raw_tool_type"].
TOOL_TYPES = [
    "c2_framework",  # Cobalt Strike, Sliver, Havoc, Brute Ratel
    "credential_access",  # Mimikatz, LaZagne, secretsdump
    "lateral_movement",  # PsExec, WMIExec, Impacket suite
    "reconnaissance",  # BloodHound, SharpHound, ADRecon
    "exploitation",  # Metasploit, SQLmap, Exploit kits
    "persistence",  # SharPersist, Scheduled Task tools
    "defense_evasion",  # Process hollowing tools, packers
    "lolbas",  # Living-off-the-land binaries (certutil, mshta, etc.)
    "framework",  # Multi-purpose: Impacket, PowerSploit, Empire
    "phishing_kit",  # Tycoon 2FA, Evilginx, PhaaS kits
    "tunneling",  # ngrok, Cloudflare Tunnel, proxies, VPNs
    "remote_access",  # RMM/remote-desktop software (AnyDesk, NetSupport)
    "ai_model",  # LLMs, AI agents/assistants
    "defensive",  # EDR/AV/SIEM/forensics/security products
    "observability",  # Monitoring, logging, telemetry, network analysis
    "cloud",  # Cloud platforms/services and container tooling
    "identity",  # IAM/SSO/MFA/directory products
    "dev_tool",  # Runtimes, compilers, SDKs, package managers, CLIs
    "service",  # Hosted platforms/marketplaces/…-as-a-service
    "software",  # General-purpose software not covered above
    "other",
]


class Tool(Base):
    __tablename__ = "tools"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    # Hardened normal form of ``name`` (see entity_norm() in models/entity_index.py
    # and normalize_entity_name() in intelligence/entity_resolution.py).
    normalized_name: Mapped[str | None] = mapped_column(
        String(255), Computed("entity_norm(name)", persisted=True), nullable=True, index=True
    )
    description: Mapped[str | None] = mapped_column(Text)
    mitre_id: Mapped[str | None] = mapped_column(String(20), index=True)
    tool_type: Mapped[str | None] = mapped_column(String(50), index=True)
    platforms: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    # Windows, Linux, macOS, IaaS, Containers, ... (see intelligence/platforms.py)
    malpedia_url: Mapped[str | None] = mapped_column(Text)
    github_url: Mapped[str | None] = mapped_column(Text)
    # Artifacts used for detection (named pipes, process names, PE metadata, etc.)
    detection_artifacts: Mapped[dict] = mapped_column(JSONB, default=dict)
    article_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata_", JSONB, default=dict)
    # --- AI-extraction provenance (Engine → Extraction management tab) ---
    created_via: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    created_from_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    created_confidence: Mapped[str | None] = mapped_column(String(10), nullable=True)
    needs_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    @validates("platforms")
    def _canonicalize_platforms(self, _key: str, value):
        """Fold platform spellings on the way in, the way tool_type already is.

        AI extraction answered this column with distro names, CPU
        architectures and language runtimes, so the `tool.platform` facet grew
        to 304 values. Folding here rather than at the extraction callers is
        what keeps the next writer from reintroducing the spread.
        """
        return canonical_platforms(value)

    # Relationships
    entry_tools = relationship("EntryTool", back_populates="tool", cascade="all, delete-orphan")


class EntryTool(Base):
    __tablename__ = "entry_tools"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    tool_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tools.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))  # ai
    matched_names: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)

    # Relationships
    entry = relationship("Entry")
    tool = relationship("Tool", back_populates="entry_tools")
