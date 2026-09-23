"""CWE — the MITRE weakness catalog, and the two tables that attach it.

The catalog is seeded whole from ``cwec_latest.xml`` (see
``scripts/seed/seed_cwe_catalog.py``), so — unlike CVE and TTP — the autolinker
never creates stub rows: an id that isn't in the catalog is a typo, not a new
weakness. That is the one structural difference from the TTP model this file
otherwise mirrors.

Two kinds of row live in ``cwes``. *Weaknesses* are the real entries, arranged
on the Pillar → Class → Base → Variant abstraction ladder via ``parent_cwe_id``
(the ``ChildOf`` edge in MITRE's research view 1000). *Categories* are an
orthogonal grouping MITRE publishes alongside them; they carry no abstraction
and no parent, and their ``mapping_usage`` is always ``Prohibited`` — MITRE's
own guidance is that a CVE should never be tagged with one. Both kinds are
seeded because NVD tagged CVEs with categories for years, and a link to a row
that says "this was never a valid mapping target" is far more useful than a
dangling string.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, SmallInteger, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

#: ``kind`` values. Categories are seeded so prohibited NVD mappings resolve.
KIND_WEAKNESS = "weakness"
KIND_CATEGORY = "category"

#: ``mapping_usage`` values, straight from the catalog's Mapping_Notes/Usage.
#: Anything other than Allowed means NVD tagging a CVE with this id is at best
#: imprecise; Prohibited means MITRE says it is not a mapping target at all.
USAGE_ALLOWED = "Allowed"
USAGE_ALLOWED_WITH_REVIEW = "Allowed-with-Review"
USAGE_DISCOURAGED = "Discouraged"
USAGE_PROHIBITED = "Prohibited"


class CWE(Base):
    __tablename__ = "cwes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    #: Canonical external id, always the full "CWE-416" form (never a bare int),
    #: so it matches what NVD stores and what the autolinker finds in prose.
    cwe_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default=KIND_WEAKNESS, index=True)
    #: Pillar | Class | Base | Variant | Compound. NULL for categories.
    abstraction: Mapped[str | None] = mapped_column(String(20), index=True)
    #: Stable | Draft | Incomplete | Deprecated | Obsolete
    status: Mapped[str | None] = mapped_column(String(20))
    mapping_usage: Mapped[str | None] = mapped_column(String(24), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    extended_description: Mapped[str | None] = mapped_column(Text)
    #: ChildOf edge in view 1000, as the parent's "CWE-825" string rather than a
    #: self-FK — the seeder can then insert in any order (same reason
    #: TTP.parent_technique_id is a string).
    parent_cwe_id: Mapped[str | None] = mapped_column(String(20), index=True)
    likelihood_of_exploit: Mapped[str | None] = mapped_column(String(20))
    #: Catalog "Alternate Terms" (e.g. UAF, Dangling pointer). Stored for display
    #: and search only — deliberately NOT fed to the autolinker dictionary, which
    #: matches the id pattern alone.
    alternate_terms: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    capec_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    #: [{"scope": "Integrity", "impacts": ["Modify Memory", ...]}, ...]
    consequences: Mapped[list] = mapped_column(JSONB, default=list)
    #: [{"phase": "Implementation", "description": "..."}, ...]
    mitigations: Mapped[list] = mapped_column(JSONB, default=list)
    #: [{"method": "Automated Static Analysis", "description": "..."}, ...]
    detection_methods: Mapped[list] = mapped_column(JSONB, default=list)
    cwe_url: Mapped[str | None] = mapped_column(Text)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    #: Replacement id when the catalog names one for a deprecated entry.
    superseded_by: Mapped[str | None] = mapped_column(String(20))
    article_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    wikipedia_url: Mapped[str | None] = mapped_column(Text)
    wikipedia_content: Mapped[str | None] = mapped_column(Text)
    wikipedia_image_url: Mapped[str | None] = mapped_column(Text)
    # --- AI-extraction provenance (Engine → Extraction management tab) ---
    # CWEs only ever arrive from the seeded catalog, so created_via stays
    # "catalog" and needs_review stays false. The columns exist so the shared
    # extraction-management queries don't need a per-type exception.
    created_via: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    created_from_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    created_confidence: Mapped[str | None] = mapped_column(String(10), nullable=True)
    needs_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    # Relationships
    entry_cwes = relationship("EntryCWE", back_populates="cwe", cascade="all, delete-orphan")
    cve_links = relationship("CVEWeakness", back_populates="cwe")


class EntryCWE(Base):
    __tablename__ = "entry_cwes"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    cwe_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cwes.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    source: Mapped[str | None] = mapped_column(String(20))  # auto_link | ai | manual
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)

    # Relationships
    entry = relationship("Entry", back_populates="entry_cwes")
    cwe = relationship("CWE", back_populates="entry_cwes")


class CVEWeakness(Base):
    """Authoritative CVE -> weakness link parsed from the NVD ``weaknesses`` block.

    Deliberately shaped like ``CVEAffected`` rather than ``EntityRelationship``:
    this is catalog fact from NVD, not an adjudicated claim, and the relationship
    matrix docstring already draws that line for CPE affects-links.

    One row per (cve, cwe_ref). The raw string is always kept — including the
    ``NVD-CWE-noinfo`` / ``NVD-CWE-Other`` sentinels, which are the honest record
    that NVD declined to classify — and ``cwe_id`` is filled only when the string
    resolves to a catalog row, so unresolved refs persist and can resolve
    retroactively after a catalog refresh.

    Several CNAs can each assign a weakness to the same CVE, so the same id can
    arrive twice with different ``type`` values. The unique key collapses those:
    ``is_primary`` is true when *any* assigner called it Primary.
    """

    __tablename__ = "cve_weaknesses"
    __table_args__ = (UniqueConstraint("cve_id", "cwe_ref", name="uq_cve_weakness_pair"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: Raw value as NVD published it: "CWE-416", "NVD-CWE-noinfo", "NVD-CWE-Other".
    cwe_ref: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    cwe_id_fk: Mapped[uuid.UUID | None] = mapped_column(
        "cwe_id", UUID(as_uuid=True), ForeignKey("cwes.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    #: The assigning CNA's identifier from the NVD block (e.g. "nvd@nist.gov").
    assigner: Mapped[str | None] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="nvd", server_default="nvd")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    cve = relationship("CVE", back_populates="weakness_links")
    cwe = relationship("CWE", back_populates="cve_links")
