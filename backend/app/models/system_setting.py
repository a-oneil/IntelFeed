from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SystemSettings(Base):
    __tablename__ = "system_settings"
    __table_args__ = (CheckConstraint("id = 1", name="singleton_row"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False, server_default="{}")
    secrets: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False, server_default="{}")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
