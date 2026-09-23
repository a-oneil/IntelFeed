from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class TTSAudio(Base):
    """Bookkeeping for server-side (Piper) read-aloud audio.

    One row per cached MP3 on the ``tts_media`` volume. The row exists so status
    polling is a fast DB read (pending vs ready vs error — a missing file alone
    is ambiguous), carries the duration for the player, and drives LRU eviction
    via ``last_accessed_at``. The audio bytes live on disk, keyed by cache_key.
    """

    __tablename__ = "tts_audio"

    # sha256 of (source + ref_id + content-hash + voice); also the mp3 filename stem.
    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False)  # "entry" | "summary"
    ref_id: Mapped[str | None] = mapped_column(String(200))  # entry_id / day_key, for debugging
    voice: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")  # pending|ready|error
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    byte_size: Mapped[int | None] = mapped_column(BigInteger)
    error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_accessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Per-row eviction TTL override, in days since last access. Null → the global
    # tts_cache_ttl_days setting. Share pre-generation sets this to 1.0 so audio
    # made just for a share link lapses after ~24h (and regenerates on demand),
    # without extending it to reader/summary audio.
    ttl_days: Mapped[float | None] = mapped_column(Float)
