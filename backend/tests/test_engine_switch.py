"""The engine switch: the setting, the API, and how workers, tasks and beat
obey it.

Real database and Redis. The switch reads its setting on a connection of its
own, so the tests that change it commit for real (``committed_db``).
"""

import asyncio
from types import SimpleNamespace

import pytest
from celery.exceptions import Ignore

from app.enrichment import gateway as gw
from app.enrichment.pause import set_paused
from app.models.system_setting import SystemSettings
from app.services import engine_switch
from app.services.redis_client import get_redis_bytes
from app.services.system_settings import CONFIGURABLE_KEYS, SETTING_METADATA
from app.workers import engine_gate


@pytest.fixture(autouse=True)
async def _settings_row(db_session):
    if await db_session.get(SystemSettings, 1) is None:
        db_session.add(SystemSettings(id=1, settings={}, secrets={}))
        await db_session.flush()


def test_setting_is_registered():
    assert CONFIGURABLE_KEYS[engine_switch.SETTING] is bool
    assert SETTING_METADATA[engine_switch.SETTING]["label"]


@pytest.mark.committed_db
async def test_stop_and_start(db_session):
    r = await get_redis_bytes()
    await engine_switch.set_stopped(db_session, True)
    assert await engine_switch.is_stopped_async(fresh=True)
    # Workers and beat call it with no loop running.
    assert await asyncio.to_thread(engine_switch.is_stopped, fresh=True)
    assert await r.exists(gw.paused_key()), "a stopped engine pauses enrichment"

    await engine_switch.set_stopped(db_session, False)
    assert not await engine_switch.is_stopped_async(fresh=True)
    assert not await r.exists(gw.paused_key())


@pytest.mark.committed_db
async def test_start_leaves_an_enrichment_pause_in_place(db_session):
    r = await get_redis_bytes()
    await set_paused(db_session, True)
    await engine_switch.set_stopped(db_session, True)
    await engine_switch.set_stopped(db_session, False)
    assert await r.exists(gw.paused_key())
    await set_paused(db_session, False)


@pytest.mark.committed_db
async def test_unreadable_database_keeps_the_last_answer(db_session, monkeypatch):
    await engine_switch.set_stopped(db_session, True)
    assert await engine_switch.is_stopped_async(fresh=True)
    monkeypatch.setattr(engine_switch, "_dsn", lambda: "postgresql://nobody@127.0.0.1:1/none")
    engine_switch.disconnect()
    assert await engine_switch.is_stopped_async(fresh=True)


async def test_unreachable_database_with_no_answer_yet_means_running(monkeypatch):
    monkeypatch.setattr(engine_switch, "_cached", None)
    monkeypatch.setattr(engine_switch, "_dsn", lambda: "postgresql://nobody@127.0.0.1:1/none")
    engine_switch.disconnect()
    assert await engine_switch.is_stopped_async(fresh=True) is False
    # The answer is cached like any other.
    assert engine_switch._cached is not None and engine_switch._cached[1] is False


async def test_reads_reuse_one_connection(monkeypatch):
    opened = []
    real_connect = engine_switch.asyncpg.connect

    async def counting_connect(*args, **kwargs):
        opened.append(args)
        return await real_connect(*args, **kwargs)

    monkeypatch.setattr(engine_switch.asyncpg, "connect", counting_connect)
    engine_switch.disconnect()
    for _ in range(3):
        await engine_switch.is_stopped_async(fresh=True)
    assert len(opened) == 1


async def test_queue_depths_are_unknown_without_redis(monkeypatch):
    import redis.asyncio as aioredis

    dead = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.5)

    async def broken():
        return dead

    monkeypatch.setattr(engine_switch, "get_redis_bytes", broken)
    depths = await engine_switch.queue_depths()
    assert set(depths) == set(engine_switch.worker_queues())
    assert set(depths.values()) == {None}


@pytest.mark.committed_db
async def test_run_now_is_refused_while_stopped(client, admin_headers, db_session, monkeypatch):
    from app.api import job_schedules
    from app.workers.job_registry import JOB_REGISTRY

    job_name = next(iter(JOB_REGISTRY))
    sent = []
    monkeypatch.setattr(
        job_schedules.celery_app, "send_task", lambda name: sent.append(name) or SimpleNamespace(id="t1")
    )
    await engine_switch.set_stopped(db_session, True)
    resp = await client.post(f"/api/job-schedules/{job_name}/run", headers=admin_headers)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "engine_stopped"
    assert sent == []

    await engine_switch.set_stopped(db_session, False)
    resp = await client.post(f"/api/job-schedules/{job_name}/run", headers=admin_headers)
    assert resp.status_code == 200
    assert sent == [JOB_REGISTRY[job_name]["task"]]


@pytest.mark.committed_db
async def test_state_endpoints(client, admin_headers, auth_headers, db_session):
    resp = await client.put("/api/engine/state", json={"stopped": True}, headers=auth_headers)
    assert resp.status_code == 403

    resp = await client.put("/api/engine/state", json={"stopped": True}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["stopped"] is True
    assert set(resp.json()["queued"]) == set(engine_switch.worker_queues())
    assert await engine_switch.is_stopped_async(fresh=True)

    resp = await client.get("/api/engine/state", headers=auth_headers)
    assert resp.json()["stopped"] is True

    resp = await client.put("/api/engine/state", json={"stopped": False}, headers=admin_headers)
    assert resp.json()["stopped"] is False
    assert not await engine_switch.is_stopped_async(fresh=True)


def test_worker_queues_include_every_routed_queue():
    from app.workers.celery_app import celery_app

    routed = {r["queue"] for r in celery_app.conf.task_routes.values()}
    assert {"celery", *routed} == set(engine_switch.worker_queues())


@pytest.mark.committed_db
async def test_settings_page_toggle_stops_the_engine(client, admin_headers, db_session):
    r = await get_redis_bytes()
    await client.patch("/api/system-settings", json={"settings": {engine_switch.SETTING: True}}, headers=admin_headers)
    assert await engine_switch.is_stopped_async(fresh=True)
    assert await r.exists(gw.paused_key())
    await client.delete(f"/api/system-settings/{engine_switch.SETTING}", headers=admin_headers)
    assert not await engine_switch.is_stopped_async(fresh=True)


# --- the worker -------------------------------------------------------------


class _FakePool:
    def __init__(self, size, busy=0):
        self.num_processes = size
        self.busy = busy

    def shrink(self, n):
        if self.num_processes - n < self.busy:
            raise ValueError("Can't shrink pool. All processes busy!")
        self.num_processes -= n

    def grow(self, n):
        self.num_processes += n


class _FakeConsumer:
    def __init__(self, queues, pool_size=1):
        self.task_consumer = SimpleNamespace(queues=[SimpleNamespace(name=q) for q in queues])
        self.timer = SimpleNamespace(call_repeatedly=lambda *a, **k: SimpleNamespace(cancel=lambda: None))
        self.pool = _FakePool(pool_size)
        self.prefetch = pool_size
        self.calls = []

    def cancel_task_queue(self, q):
        self.calls.append(("cancel", q))

    def add_task_queue(self, q):
        self.calls.append(("add", q))

    def _update_prefetch_count(self, n):
        self.prefetch += n


def test_worker_stops_and_resumes_only_its_own_queues(monkeypatch):
    state = {"stopped": False}
    monkeypatch.setattr(engine_switch, "is_stopped", lambda fresh=False: state["stopped"])
    step = engine_gate.EngineSwitchStep(parent=None)
    c = _FakeConsumer(["ai", "claude_code"])

    step.start(c)
    assert c.calls == []

    state["stopped"] = True
    step.check(c)
    step.check(c)  # no change, no calls
    assert c.calls == [("cancel", "ai"), ("cancel", "claude_code")]

    # A reconnect while stopped: the consumer's queue list is empty.
    c.task_consumer.queues = []
    step.start(c)
    state["stopped"] = False
    step.check(c)
    assert c.calls[-2:] == [("add", "ai"), ("add", "claude_code")]


def test_start_brings_processes_back_one_at_a_time(monkeypatch):
    state = {"stopped": False}
    clock = [1000.0]
    monkeypatch.setattr(engine_switch, "is_stopped", lambda fresh=False: state["stopped"])
    monkeypatch.setattr(engine_gate.time, "monotonic", lambda: clock[0])
    step = engine_gate.EngineSwitchStep(parent=None)
    c = _FakeConsumer(["celery"], pool_size=4)
    step.start(c)

    state["stopped"] = True
    step.check(c)
    assert c.pool.num_processes == 4, "a stop leaves the pool alone"

    state["stopped"] = False
    step.check(c)
    assert (c.pool.num_processes, c.prefetch) == (1, 1)

    sizes = []
    for _ in range(4):
        clock[0] += engine_gate.RAMP_SECONDS / 2
        step.check(c)  # too soon: no change
        clock[0] += engine_gate.RAMP_SECONDS / 2
        step.check(c)
        sizes.append(c.pool.num_processes)
    assert sizes == [2, 3, 4, 4]
    assert c.prefetch == 4


def test_start_keeps_processes_that_are_still_busy(monkeypatch):
    state = {"stopped": True}
    monkeypatch.setattr(engine_switch, "is_stopped", lambda fresh=False: state["stopped"])
    step = engine_gate.EngineSwitchStep(parent=None)
    c = _FakeConsumer(["celery"], pool_size=4)
    step.start(c)
    c.pool.busy = 2

    state["stopped"] = False
    step.check(c)
    assert c.pool.num_processes == 2
    assert ("add", "celery") in c.calls


class _FixedPool:
    """The solo and threads pools: a size that can't change."""

    num_processes = 4

    def shrink(self, n):
        raise NotImplementedError

    def grow(self, n):
        raise NotImplementedError


def test_a_pool_that_cannot_resize_is_left_alone(monkeypatch):
    state = {"stopped": True}
    monkeypatch.setattr(engine_switch, "is_stopped", lambda fresh=False: state["stopped"])
    step = engine_gate.EngineSwitchStep(parent=None)
    c = _FakeConsumer(["celery"], pool_size=4)
    c.pool = _FixedPool()
    step.start(c)

    state["stopped"] = False
    step.check(c)
    step.check(c)
    assert (c.pool.num_processes, c.prefetch) == (4, 4)
    assert ("add", "celery") in c.calls


@pytest.fixture
def gated(monkeypatch):
    """A registered task, as a worker would call it, with its run and its
    re-send faked. Returns (task, sent)."""
    from app.workers.celery_app import celery_app

    pushed = []

    def make(name, stopped=True):
        monkeypatch.setattr(engine_switch, "is_stopped", lambda fresh=False: stopped)
        celery_app.loader.import_default_modules()
        task = celery_app.tasks[name]
        sent = []
        monkeypatch.setattr(task, "run", lambda *a, **k: "ran")
        monkeypatch.setattr(
            task, "signature_from_request", lambda: SimpleNamespace(apply_async=lambda: sent.append(name))
        )
        task.push_request(called_directly=False, is_eager=False, args=[], kwargs={})
        pushed.append(task)
        return task, sent

    yield make
    for task in pushed:
        task.pop_request()


def test_prefetched_task_goes_back_on_its_queue(gated):
    task, sent = gated("app.workers.feed_tasks.fetch_feed")
    with pytest.raises(Ignore):
        task(1)
    assert sent == ["app.workers.feed_tasks.fetch_feed"]


def test_prefetched_scheduled_job_is_dropped(gated):
    from app.workers.task_tracking import KNOWN_JOB_TASKS

    task, sent = gated(next(iter(KNOWN_JOB_TASKS)))
    with pytest.raises(Ignore):
        task()
    assert sent == []


def test_task_runs_while_the_engine_runs(gated):
    task, sent = gated("app.workers.feed_tasks.fetch_feed", stopped=False)
    assert task(1) == "ran"
    assert sent == []


def test_beat_sends_nothing_while_stopped(monkeypatch):
    sent = []
    monkeypatch.setattr(
        engine_gate.PersistentScheduler, "apply_entry", lambda self, entry, producer=None: sent.append(entry)
    )
    from app.workers.celery_app import celery_app

    sched = engine_gate.EngineScheduler(app=celery_app, lazy=True, schedule_filename="unused")
    monkeypatch.setattr(engine_switch, "is_stopped", lambda fresh=False: True)
    sched.apply_entry(SimpleNamespace(name="poll-feeds"))
    assert sent == []
    monkeypatch.setattr(engine_switch, "is_stopped", lambda fresh=False: False)
    sched.apply_entry(SimpleNamespace(name="poll-feeds"))
    assert len(sent) == 1


def test_every_registered_task_is_gated():
    from app.workers.celery_app import celery_app

    celery_app.loader.import_default_modules()
    tasks = [t for name, t in celery_app.tasks.items() if name.startswith("app.")]
    assert tasks
    assert all(isinstance(t, engine_gate.GatedTask) for t in tasks)


async def test_telegram_listener_leaves_a_burst_to_the_feeds_own_poll_while_stopped(monkeypatch):
    """The listener runs outside Celery, so it asks the switch itself before
    dispatching a fetch; a stopped engine gets no task, a running one does."""
    from app.workers import feed_tasks
    from app.workers.telegram_listener import _ChannelDispatcher

    state = {"stopped": True}
    sent: list[str] = []

    async def stopped(fresh: bool = False) -> bool:
        return state["stopped"]

    monkeypatch.setattr(engine_switch, "is_stopped_async", stopped)
    monkeypatch.setattr(feed_tasks.fetch_feed, "delay", lambda feed_id: sent.append(feed_id))

    dispatcher = _ChannelDispatcher()
    await dispatcher._dispatch("feed-1")
    assert sent == []

    state["stopped"] = False
    await dispatcher._dispatch("feed-1")
    assert sent == ["feed-1"]
