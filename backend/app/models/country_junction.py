"""Junction tables linking countries to threat actors and campaigns."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ThreatActorTargetCountry(Base):
    __tablename__ = "threat_actor_target_countries"

    threat_actor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_actors.id", ondelete="CASCADE"),
        primary_key=True,
    )
    country_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("countries.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    threat_actor = relationship("ThreatActor", back_populates="target_country_links")
    country = relationship("Country", back_populates="targeted_by_actor_links")


class CampaignCountry(Base):
    __tablename__ = "campaign_countries"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        primary_key=True,
    )
    country_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("countries.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(20), default="target")
    # origin, target
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    campaign = relationship("Campaign", back_populates="country_links")
    country = relationship("Country", back_populates="campaign_links")
