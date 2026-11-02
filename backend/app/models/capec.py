"""CAPEC — MITRE's catalog of attack patterns, synced weekly by the ``capec``
enrichment source (``app/enrichment/capec.py``).

A lookup table, not an entity: nothing links to its rows by key. CWEs name
their patterns in ``cwes.capec_ids`` (from the CWE catalog), which resolve
against ``capec_id`` here; techniques get theirs from ``technique_ids``.
"""

from datetime import datetime

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CAPECPattern(Base):
    __tablename__ = "capec_patterns"

    #: "CAPEC-248", the form ``cwes.capec_ids`` holds.
    capec_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    #: Meta | Standard | Detailed
    abstraction: Mapped[str | None] = mapped_column(String(20))
    #: Stable | Usable | Draft | Obsolete | Deprecated
    status: Mapped[str | None] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text)
    #: Related weaknesses as "CWE-77".
    cwe_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list, server_default="{}")
    #: ATT&CK taxonomy mappings as "T1574.010".
    technique_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list, server_default="{}")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
