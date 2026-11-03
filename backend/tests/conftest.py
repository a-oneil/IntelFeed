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
        await _seed_vocabularies(conn)
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
def _single_tenant_feed_visibility(monkeypatch):
    """Run the suite with the legacy every-feed-visible behaviour.

    ``per_user_subscriptions_enabled`` ships on (issue #15), under which a
    user sees only the feeds they are subscribed to. Most tests create feeds
    straight in the database with no subscription rows and then list them as
    some user, so they assume the flag is off. The subscription tests flip it
    on themselves through the DB override, which beats this field default.
    """
    from app.config import settings as env_settings

    monkeypatch.setattr(env_settings, "per_user_subscriptions_enabled", False)


@pytest.fixture(autouse=True)
def _no_actor_malware_evidence_gate(monkeypatch):
    """Run the suite with the actor/malware evidence door open.

    ``ai_entity_evidence_required`` ships on: a new actor or malware family
    needs an evidence sentence naming it. Most tests build analysis payloads
    with just a name to exercise something else (relationships, resolution,
    tombstones). The evidence tests switch it back on themselves.
    """
    from app.config import settings as env_settings

    monkeypatch.setattr(env_settings, "ai_entity_evidence_required", False)


@pytest.fixture(autouse=True)
def _fresh_settings_cache():
    """Forget the in-process system_settings cache between tests.

    The cache lives 5 s, longer than most tests, so a code or flag one test
    stored (the generated invite code, say) would still be served to the
    next test after its own schema is gone.
    """
    from app.services.system_settings import invalidate_cache

    invalidate_cache()
    yield
    invalidate_cache()


@pytest.fixture(autouse=True)
def _reset_redis():
    """Reset Redis singletons between tests to avoid stale event-loop references."""
    from app.services.redis_client import reset_pools

    reset_pools()
    yield
    reset_pools()


@pytest.fixture(autouse=True)
def _private_scale_cutoffs(monkeypatch):
    """Give each test its own Redis key for the 0–10 scale's cutoffs.

    Scoring reads the cutoffs from Redis and, on a miss, computes them from the
    database and caches them. Against the shared key a test would score with the
    dev stack's real cutoffs, and one that seeded enough scored entries would
    write cutoffs derived from the test database into dev Redis. A cached-on-miss
    value expires (SCALE_CUTOFFS_MISS_TTL), so the per-test keys don't pile up.
    """
    import uuid

    from app.intelligence import signals

    monkeypatch.setattr(signals, "SCALE_CUTOFFS_REDIS_KEY", f"intelfeed:test:{uuid.uuid4().hex}:scale_cutoffs")


@pytest.fixture(autouse=True)
def _private_gateway_keys(monkeypatch):
    """Give each test its own Redis namespace for the enrichment gateways'
    buckets, budgets and breakers, so no test drains another's (or dev's)
    allowance. The keys expire on their own."""
    import uuid

    from app.enrichment import gateway

    monkeypatch.setattr(gateway, "KEY_PREFIX", f"intelfeed:test:{uuid.uuid4().hex}:gw:")


@pytest.fixture(autouse=True)
def _engine_switch_reads_test_db(monkeypatch):
    """The engine switch reads its setting on a connection of its own; point
    it at the test database, not dev's, and forget the last read."""
    from app.services import engine_switch

    monkeypatch.setattr(engine_switch, "_dsn", lambda: TEST_DATABASE_URL.replace("+asyncpg", "", 1))
    monkeypatch.setattr(engine_switch, "_cached", None)


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


async def _seed_vocabularies(conn) -> None:
    """Rows the app assumes exist that ``create_all`` cannot provide.

    Sectors are a seeded closed vocabulary, not extracted data: entry_sectors
    carries an FK onto the 21 rows, so the test schema seeds them the way the
    Alembic migration does. Idempotent, because ``_truncate_all`` wipes them
    along with everything else after a ``committed_db`` test.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.intelligence.sectors import seed_rows
    from app.models.sector import Sector

    await conn.execute(pg_insert(Sector).values(seed_rows()).on_conflict_do_nothing())


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
        await _seed_vocabularies(conn)


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


@pytest.fixture
def pause_enrichment(db_session: AsyncSession):
    """Pause enrichment the way the Settings page does: store the
    ``enrichment_paused`` setting and sync the gateways' Redis flag from it.

    Writing only the Redis flag doesn't pause a source job: ``source_job``
    re-asserts the flag from the stored setting before the body runs, and the
    test schema has no system_settings row until one is made here.
    """
    from app.enrichment.pause import set_paused
    from app.models.system_setting import SystemSettings

    async def pause(paused: bool = True) -> None:
        if await db_session.get(SystemSettings, 1) is None:
            db_session.add(SystemSettings(id=1, settings={}, secrets={}))
            await db_session.flush()
        await set_paused(db_session, paused)

    return pause
