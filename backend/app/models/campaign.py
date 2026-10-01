import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    # active, monitoring, closed, historical
    tlp_marking: Mapped[str] = mapped_column(String(20), default="TLP:GREEN")
    # TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    creator = relationship("User", back_populates="campaigns")
    entries = relationship("CampaignEntry", back_populates="campaign", cascade="all, delete-orphan")
    entities = relationship("CampaignEntity", back_populates="campaign", cascade="all, delete-orphan")
    saved_searches = relationship("CampaignSavedSearch", back_populates="campaign", cascade="all, delete-orphan")
    country_links = relationship("CampaignCountry", back_populates="campaign", cascade="all, delete-orphan")
    sector_links = relationship("CampaignSector", back_populates="campaign", cascade="all, delete-orphan")
    sources = relationship("CampaignSource", back_populates="campaign", cascade="all, delete-orphan")


class CampaignEntry(Base):
    __tablename__ = "campaign_entries"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True
    )
    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    added_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    notes: Mapped[str | None] = mapped_column(Text)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    campaign = relationship("Campaign", back_populates="entries")
    entry = relationship("Entry", back_populates="campaign_entries")


class CampaignEntity(Base):
    __tablename__ = "campaign_entities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), index=True
    )
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # ttp, cve, threat_actor, malware
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="related")
    # primary, secondary, related
    added_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    campaign = relationship("Campaign", back_populates="entities")


class CampaignSavedSearch(Base):
    __tablename__ = "campaign_saved_searches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    saved_search_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("saved_searches.id", ondelete="CASCADE"), nullable=False, index=True
    )
    auto_sync: Mapped[bool] = mapped_column(Boolean, default=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    entries_added: Mapped[int] = mapped_column(Integer, default=0)
    added_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    campaign = relationship("Campaign", back_populates="saved_searches")
    saved_search = relationship("SavedSearch", back_populates="campaign_links")


class CampaignSource(Base):
    """Something a campaign feeds on, beyond a linked saved search.

    A saved search is a query kept in parallel with the campaign, and it drifts:
    the campaign's subject changes and the query doesn't. These sources are the
    campaign feeding on what it has already declared —

    * ``entity`` — the actor or malware it names as its subject. New articles
      mentioning it join, which is what makes curating the primary role worth
      doing.
    * ``story`` — a thread it has already accepted part of. Later waves of a
      story you are already tracking are the clearest case of "obviously yes",
      and before this they arrived as a suggestion to re-accept every time.

    ``label`` is frozen at link time so a source still reads after its target is
    renamed or merged away.
    """

    __tablename__ = "campaign_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # entity | story
    entity_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ref_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    label: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    auto_sync: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    entries_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    added_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    campaign = relationship("Campaign", back_populates="sources")

    __table_args__ = (
        UniqueConstraint("campaign_id", "kind", "entity_type", "ref_id", name="uq_campaign_sources_target"),
    )
