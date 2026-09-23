import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CVEAffected(Base):
    """Authoritative CVE -> vendor/product affects-link parsed from NVD CPE data.

    One row per (cve, cpe_vendor, cpe_product) pair. Raw CPE strings are always
    kept; vendor_id/product_id are filled in only when the strings resolve to
    canonical entities, so unmatched pairs persist and can resolve retroactively
    when entities or cpe_names aliases are added later.
    """

    __tablename__ = "cve_affected"
    __table_args__ = (UniqueConstraint("cve_id", "cpe_vendor", "cpe_product", name="uq_cve_affected_pair"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Raw lowercase CPE 2.3 vendor/product segments (e.g. "vmware", "vcenter_server")
    cpe_vendor: Mapped[str] = mapped_column(Text, nullable=False)
    cpe_product: Mapped[str] = mapped_column(Text, nullable=False)
    vendor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    product_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("products.id", ondelete="SET NULL"), nullable=True, index=True
    )
    version_start: Mapped[str | None] = mapped_column(Text)
    version_end: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="nvd", server_default="nvd")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    cve = relationship("CVE", back_populates="affected_links")
    vendor = relationship("Vendor")
    product = relationship("Product")
