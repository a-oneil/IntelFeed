import itertools
import os
from collections.abc import AsyncGenerator
from unittest.mock import patch

import bcrypt
import meilisearch
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.config import settings
from app.core.security import create_access_token, hash_password
from app.database import Base, get_db
from app.main import app
from app.models.category import Category
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP
from app.models.user import User

_real_gensalt = bcrypt.gensalt

# Each xdist worker gets its own database so parallel runs never share schema.
# Two pytest processes started independently (e.g. two agent sessions sharing
# this checkout) would still land on the same names, so PYTEST_DB_SUFFIX lets
# one of them claim a separate set.
_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")
_SUFFIX = os.environ.get("PYTEST_DB_SUFFIX", "")
TEST_DB_NAME = settings.postgres_db + "_test" + (f"_{_SUFFIX}" if _SUFFIX else "") + (f"_{_WORKER}" if _WORKER else "")


def _db_url(name: str) -> str:
    return (
        f"postgresql+asyncpg://{settings.postgres_user}:{settings.postgres_password}"
        f"@{settings.postgres_host}:{settings.postgres_port}/{name}"
    )


TEST_DATABASE_URL = _db_url(TEST_DB_NAME)


async def _ensure_test_database() -> None:
    """Create this worker's test database if it does not exist yet."""
    admin_url = _db_url("postgres")
    admin = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        async with admin.connect() as conn:
            exists = await conn.scalar(text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": TEST_DB_NAME})
            if not exists:
                await conn.execute(text(f'CREATE DATABASE "{TEST_DB_NAME}"'))
    finally:
        await admin.dispose()


@pytest_asyncio.fixture(scope="session")
async def _engine():
    """One engine and one schema build for the whole session.

    Building the 95-table schema costs ~0.6s, so doing it per test (as this
    fixture used to) dominated the runtime of the suite. Per-test isolation is
    handled by transaction rollback in ``db_session`` instead.
    """
    await _ensure_test_database()
    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
        # pgvector lives in the schema we just dropped; entry_embeddings and
        # story_threads declare halfvec columns, so it has to come back first.
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _cheap_bcrypt():
    """Drop the bcrypt work factor for the suite.

    ``hash_password`` costs ~0.35s at the default 12 rounds, and it runs in the
    ``test_user`` / ``admin_user`` fixtures plus ~30 test modules, which made it
    the single largest per-test cost after schema setup. 4 rounds is ~250x
    cheaper. ``verify_password`` reads the cost factor out of the hash, so
    round-tripping still works.
    """
    with patch.object(bcrypt, "gensalt", lambda rounds=4, **kw: _real_gensalt(4)):
        yield


@pytest.fixture(autouse=True)
def _reset_redis():
    """Reset Redis singletons between tests to avoid stale event-loop references."""
    from app.services.redis_client import reset_pools

    reset_pools()
    yield
    reset_pools()


@pytest.fixture(autouse=True)
def _offline_meilisearch():
    """Keep tests off the network.

    Meilisearch's client has no timeout, so when the container is down (or
    merely paused, which still completes the TCP handshake) any code path that
    indexes a document blocks forever. Tests that exercise the client patch
    ``meilisearch.Client`` themselves, and that inner patch wins over this one.
    """
    from app.services import meilisearch_client

    meilisearch_client._client = None
    with patch.object(meilisearch, "Client", side_effect=ConnectionError("Meilisearch disabled in tests")):
        yield
    meilisearch_client._client = None


async def _truncate_all(engine) -> None:
    async with engine.begin() as conn:
        tables = await conn.scalar(
            text(
                "SELECT string_agg(format('%I.%I', schemaname, tablename), ', ') "
                "FROM pg_tables WHERE schemaname = 'public'"
            )
        )
        if tables:
            await conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))


@pytest_asyncio.fixture
async def db_session(request, _engine) -> AsyncGenerator[AsyncSession, None]:
    """Run each test inside a transaction that is rolled back afterwards.

    ``join_transaction_mode="create_savepoint"`` turns any ``commit()`` made by
    the code under test into a savepoint release, so the outer transaction stays
    open and the rollback below still restores a clean database.

    Tests marked ``@pytest.mark.committed_db`` opt out: they spin up their own
    engines to imitate Celery workers, and a second connection cannot see data
    that is still sitting in an uncommitted transaction. Those commit for real
    and pay for a TRUNCATE afterwards.
    """
    if request.node.get_closest_marker("committed_db"):
        session = AsyncSession(bind=_engine, expire_on_commit=False)
        try:
            yield session
        finally:
            await session.close()
            await _truncate_all(_engine)
        return

    conn = await _engine.connect()
    trans = await conn.begin()
    session = AsyncSession(bind=conn, expire_on_commit=False, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        await session.close()
        await trans.rollback()
        await conn.close()


_client_ips = itertools.count(1)


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    # Unauthenticated requests are rate limited per client IP over a sliding
    # window. Now that tests run in milliseconds rather than seconds, a shared
    # IP makes later tests fail with 429 on the login/register routes, so give
    # every test its own address.
    n = next(_client_ips)
    peer = (f"10.{n >> 16 & 0xFF}.{n >> 8 & 0xFF}.{n & 0xFF}", 50000)
    transport = ASGITransport(app=app, client=peer)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    user = User(
        username="testuser",
        password_hash=hash_password("testpassword"),
        role="user",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def auth_headers(test_user: User) -> dict:
    token = create_access_token(test_user.id, test_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    user = User(
        username="adminuser",
        password_hash=hash_password("adminpassword"),
        role="admin",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def admin_headers(admin_user: User) -> dict:
    token = create_access_token(admin_user.id, admin_user.role)
    return {"Authorization": f"Bearer {token}"}


# ── Common entity fixtures ──────────────────────────────────────────


@pytest_asyncio.fixture
async def test_feed(db_session: AsyncSession) -> Feed:
    feed = Feed(title="Test Feed", url="https://example.com/feed.xml", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    return feed


@pytest_asyncio.fixture
async def test_category(db_session: AsyncSession, test_user: User) -> Category:
    cat = Category(created_by=test_user.id, name="Test Category")
    db_session.add(cat)
    await db_session.flush()
    return cat


@pytest_asyncio.fixture
async def test_entry(db_session: AsyncSession, test_feed: Feed) -> Entry:
    entry = Entry(
        feed_id=test_feed.id,
        title="Test Entry",
        guid="test-guid-001",
        url="https://example.com/entry/1",
        content_text="This is test content about APT29 and CVE-2024-1234.",
        summary="A test entry for unit testing.",
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest_asyncio.fixture
async def test_threat_actor(db_session: AsyncSession) -> ThreatActor:
    actor = ThreatActor(name="APT29", aliases=["Cozy Bear", "The Dukes"])
    db_session.add(actor)
    await db_session.flush()
    return actor


@pytest_asyncio.fixture
async def test_ttp(db_session: AsyncSession) -> TTP:
    ttp = TTP(
        technique_id="T1566.001",
        technique_name="Spearphishing Attachment",
        tactic="initial-access",
    )
    db_session.add(ttp)
    await db_session.flush()
    return ttp
