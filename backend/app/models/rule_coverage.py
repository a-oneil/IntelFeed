import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class RuleCoverage(Base):
    """Materialised rule → entity resolution.

    The tag columns on ``detection_rules`` (``source_cves`` / ``source_ttps`` /
    ``source_actors``) are only ever written by in-app authoring and by the two
    importers whose upstream format happens to carry the field, so they resolve
    3,996 of 11,517 rules and zero actors. This table is the answer to "has an
    open-source engineer already written something for this?" — rebuilt by the
    resolver rather than hoped for at import time.

    ``via`` records which writer produced the row so the UI can show *why* a rule
    matched instead of laundering a body-text hit into a green check.
    """

    __tablename__ = "rule_coverage"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), primary_key=True
    )
    # One of app.entity_types.* — import the constants, never type the strings.
    entity_type: Mapped[str] = mapped_column(String(30), primary_key=True)
    # cve_id ("CVE-2026-1731"), technique_id ("T1059.001"), or an entity uuid as text.
    entity_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    via: Mapped[str] = mapped_column(String(10), nullable=False)  # tag | meta | text
    confidence: Mapped[str] = mapped_column(String(10), nullable=False)  # high | medium | low
    # The literal that matched, so every text-derived row stays auditable.
    matched_on: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
