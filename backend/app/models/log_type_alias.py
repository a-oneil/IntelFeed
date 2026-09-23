from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LogTypeAlias(Base):
    """Raw vendor log-type string → canonical behaviour id.

    ``telemetry_sources.log_types`` is free text: 864 distinct values across
    1,124 assignments, 721 of them used exactly once. One idea has eleven
    spellings (``authentication``, ``authentication_event``, ``login_event``,
    ``login_success`` …), so a rule asking for one of them matches a fraction of
    the products that actually emit it.

    This table normalises without destroying: the raw strings stay on
    ``telemetry_sources.log_types`` because they are what renders on a source
    card, and ``log_types_canonical`` carries the mapped ids alongside them.
    """

    __tablename__ = "log_type_alias"

    raw: Mapped[str] = mapped_column(String(120), primary_key=True)
    # Behaviour axis: auth.login, dns.query, process.creation, net.connection, …
    # Aligned to ATT&CK log-source channel names where they correspond.
    canonical: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    note: Mapped[str | None] = mapped_column(Text)
