from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,
    pool_recycle=3600,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        # Warm the system-settings cache so synchronous settings.get() reads
        # see DB overrides in every API worker (TTL-guarded: one cheap
        # singleton-row SELECT at most every few seconds). Workers do the
        # same via their task wrappers.
        from app.services.system_settings import _ensure_cache

        await _ensure_cache(session)
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
