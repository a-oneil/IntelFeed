"""The queued vocabulary rebuild: request handlers ask the worker for one build
instead of each compiling the 34k-form automaton on the event loop."""

import asyncio

import pytest

from app.intelligence import autolinker


class FakeRedis:
    """Just enough of redis.asyncio for the debounce key and the version check."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def get(self, key):
        return self.store.get(key)

    async def delete(self, key):
        self.store.pop(key, None)


@pytest.fixture
def fake_redis(monkeypatch):
    r = FakeRedis()

    async def _get_redis():
        return r

    monkeypatch.setattr(autolinker, "get_redis", _get_redis)
    return r


@pytest.fixture
def sent(monkeypatch):
    """Capture the Celery dispatch instead of publishing to a broker."""
    from app.workers import intel_feed_tasks

    calls: list[dict] = []
    monkeypatch.setattr(intel_feed_tasks.refresh_autolinker_vocabulary, "apply_async", lambda **kw: calls.append(kw))
    return calls


@pytest.mark.asyncio
async def test_burst_of_changes_queues_one_rebuild(fake_redis, sent):
    first = await autolinker.schedule_vocabulary_refresh(None)
    second = await autolinker.schedule_vocabulary_refresh(None)
    third = await autolinker.schedule_vocabulary_refresh(None)

    assert (first, second, third) == ("queued", "pending", "pending")
    assert len(sent) == 1
    assert sent[0]["countdown"] == autolinker.VOCAB_REFRESH_DEBOUNCE_SECONDS


@pytest.mark.asyncio
async def test_change_after_the_build_starts_queues_the_next_one(fake_redis, sent):
    await autolinker.schedule_vocabulary_refresh(None)
    # The worker clears the key when its build begins, so a later change is
    # not folded into a build that cannot see it.
    await autolinker._clear_vocabulary_refresh_pending()
    assert await autolinker.schedule_vocabulary_refresh(None) == "queued"
    assert len(sent) == 2


@pytest.mark.asyncio
async def test_unreachable_broker_falls_back_to_an_inline_rebuild(fake_redis, monkeypatch):
    from app.workers import intel_feed_tasks

    def _boom(**kw):
        raise ConnectionError("broker down")

    monkeypatch.setattr(intel_feed_tasks.refresh_autolinker_vocabulary, "apply_async", _boom)
    rebuilt: list[object] = []

    async def _refresh(db):
        rebuilt.append(db)
        return 0

    monkeypatch.setattr(autolinker, "refresh_vocabulary", _refresh)

    assert await autolinker.schedule_vocabulary_refresh("db") == "inline"
    assert rebuilt == ["db"]
    # The failed dispatch must not leave the debounce key behind, or the next
    # change would be told a rebuild is pending that nobody is going to run.
    assert autolinker.VOCAB_REFRESH_PENDING_KEY not in fake_redis.store


@pytest.mark.asyncio
async def test_concurrent_scans_share_one_rebuild(fake_redis, monkeypatch):
    """Three scans that all see a stale version wait for one build, not three."""
    built = autolinker.EntityVocabulary()
    built.built = True
    built.version = "old"
    monkeypatch.setattr(autolinker, "_vocabulary", built)
    monkeypatch.setattr(autolinker, "_vocab_version", "old")
    fake_redis.store[autolinker.VOCAB_VERSION_KEY] = "new"

    builds = 0

    async def _refresh(db):
        nonlocal builds
        builds += 1
        await asyncio.sleep(0.01)
        # What a real build does: publish the version it compiled.
        monkeypatch.setattr(autolinker, "_vocab_version", "new")
        return 1

    monkeypatch.setattr(autolinker, "refresh_vocabulary", _refresh)

    await asyncio.gather(*(autolinker._ensure_vocabulary(None) for _ in range(3)))
    assert builds == 1


@pytest.mark.asyncio
async def test_current_vocabulary_is_not_rebuilt(fake_redis, monkeypatch):
    built = autolinker.EntityVocabulary()
    built.built = True
    monkeypatch.setattr(autolinker, "_vocabulary", built)
    monkeypatch.setattr(autolinker, "_vocab_version", "same")
    fake_redis.store[autolinker.VOCAB_VERSION_KEY] = "same"

    async def _refresh(db):
        raise AssertionError("must not rebuild")

    monkeypatch.setattr(autolinker, "refresh_vocabulary", _refresh)
    await autolinker._ensure_vocabulary(None)
