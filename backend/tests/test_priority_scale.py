"""The 0–10 priority scale: raw signal sums ranked onto a fixed scale.

Entry.priority_raw keeps the engine's unbounded sum (and the ordering);
Entry.priority_score is that sum placed by rank against the trailing 30 days.
"""

import importlib.util
import json
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.intelligence import signals
from app.intelligence.signals import (
    DEFAULT_SCALE_CUTOFFS,
    SCALE_ANCHORS,
    compute_scale_cutoffs,
    scale_score,
    scale_score_sql,
)
from app.models.entry import Entry

NOW = datetime.now(UTC)
CUTS = [float(i) for i in range(1, 11)]  # scale reads back the raw sum between 1 and 10


class FakeRedis:
    def __init__(self, data: dict | None = None):
        self.data = dict(data or {})
        self.ttl: dict = {}

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, value, ex=None):
        self.data[key] = value
        if ex is not None:
            self.ttl[key] = ex

    async def delete(self, *keys):
        for key in keys:
            self.data.pop(key, None)


@pytest.fixture
def fake_redis(monkeypatch):
    redis = FakeRedis()

    async def _get():
        return redis

    monkeypatch.setattr(signals, "get_redis", _get)
    monkeypatch.setattr("app.services.redis_client.get_redis", _get)
    return redis


async def _entry(db_session, feed, raw: float | None, *, score: float | None = None, scored_at=NOW) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title="Report",
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://example.com/{uuid.uuid4()}",
        content_text="content",
        published_at=NOW,
        priority_raw=raw,
        priority_score=score,
        scored_at=scored_at if raw is not None else None,
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


class TestScaleScore:
    def test_nothing_fired_is_zero(self):
        assert scale_score(0.0, CUTS) == 0.0
        assert scale_score(-0.5, CUTS) == 0.0  # an echo that cancelled the rest out

    def test_unscored_stays_unscored(self):
        assert scale_score(None, CUTS) is None

    def test_any_signal_is_at_least_one(self):
        assert scale_score(0.0001, CUTS) == 1.0

    def test_interpolates_between_anchors_to_one_decimal(self):
        assert scale_score(4.24, CUTS) == 4.2
        assert scale_score(4.25, CUTS) == 4.3  # half away from zero, as Postgres rounds
        assert scale_score(7.0, CUTS) == 7.0

    def test_clamps_at_ten(self):
        assert scale_score(10.0, CUTS) == 10.0
        assert scale_score(250.0, CUTS) == 10.0

    def test_monotonic_on_real_cutoffs(self):
        raws = [i / 100 for i in range(0, 700)]
        scaled = [scale_score(r, DEFAULT_SCALE_CUTOFFS) for r in raws]
        assert scaled == sorted(scaled)

    def test_tied_cutoffs_do_not_divide_by_zero(self):
        tied = [0.1, 0.2, 0.2, 0.2, 0.5, 0.8, 1.0, 1.5, 2.0, 3.0]
        assert scale_score(0.2, tied) == 4.0  # the highest of the tied anchors
        assert scale_score(0.15, tied) == 1.5

    def test_top_heavy(self):
        """A 9 starts at the 95th percentile and a 10 at the 99th."""
        anchors = dict(SCALE_ANCHORS)
        assert anchors[9.0] == 0.95
        assert anchors[10.0] == 0.99


@pytest.mark.asyncio
async def test_sql_mapping_matches_python(db_session, test_feed):
    cuts = list(DEFAULT_SCALE_CUTOFFS)
    cuts[2] = cuts[1]  # include a tied pair, as real cutoffs have
    raws = [-1.0, 0.0, 0.001, 0.002, 0.19, 0.191, 0.3, 0.9, 1.55, 2.0, 3.3, 4.89, 4.9, 12.0]
    for raw in raws:
        await _entry(db_session, test_feed, raw)
    rows = (await db_session.execute(select(Entry.priority_raw, scale_score_sql(Entry.priority_raw, cuts)))).all()
    for raw, sql_value in rows:
        assert sql_value == pytest.approx(scale_score(raw, cuts)), raw


@pytest.mark.asyncio
async def test_sql_and_python_round_exact_halves_alike(db_session, test_feed):
    """An exact half must round the same both ways, or the nightly job rewrites it every night."""
    raws = [1.05, 2.15, 2.25, 3.35, 4.25, 4.45, 5.55, 6.65, 7.75, 8.85, 9.95]
    for raw in raws:
        await _entry(db_session, test_feed, raw)
    rows = (await db_session.execute(select(Entry.priority_raw, scale_score_sql(Entry.priority_raw, CUTS)))).all()
    assert len(rows) == len(raws)
    for raw, sql_value in rows:
        assert sql_value == scale_score(raw, CUTS), raw


@pytest.mark.asyncio
async def test_cutoffs_need_a_real_sample(db_session, test_feed):
    for i in range(10):
        await _entry(db_session, test_feed, 0.1 * (i + 1))
    assert await compute_scale_cutoffs(db_session) is None


@pytest.mark.asyncio
async def test_cutoffs_come_from_positive_recent_scores(db_session, test_feed):
    for i in range(100):
        await _entry(db_session, test_feed, float(i + 1))
    for _ in range(50):
        await _entry(db_session, test_feed, 0.0)  # zeros don't drag the scale down
    await _entry(db_session, test_feed, 999.0, scored_at=NOW - timedelta(days=45))  # outside the window
    cuts = await compute_scale_cutoffs(db_session)
    assert cuts is not None and len(cuts) == len(SCALE_ANCHORS)
    assert cuts[0] == 1.0
    assert cuts[-1] == pytest.approx(99.01)
    assert cuts == sorted(cuts)


@pytest.mark.asyncio
async def test_cached_cutoffs_win(fake_redis):
    fake_redis.data[signals.SCALE_CUTOFFS_REDIS_KEY] = json.dumps(CUTS)
    assert await signals.get_scale_cutoffs() == CUTS


@pytest.mark.asyncio
async def test_cutoffs_miss_computes_and_caches(db_session, test_feed, fake_redis):
    for i in range(60):
        await _entry(db_session, test_feed, float(i + 1))
    cuts = await signals.get_scale_cutoffs(db_session)
    assert cuts != list(DEFAULT_SCALE_CUTOFFS)
    assert json.loads(fake_redis.data[signals.SCALE_CUTOFFS_REDIS_KEY]) == cuts
    # Only a stopgap until the nightly job writes the durable copy.
    assert fake_redis.ttl[signals.SCALE_CUTOFFS_REDIS_KEY] == signals.SCALE_CUTOFFS_MISS_TTL


@pytest.mark.asyncio
async def test_cutoffs_miss_without_session_uses_defaults(fake_redis):
    assert await signals.get_scale_cutoffs() == list(DEFAULT_SCALE_CUTOFFS)


@pytest.mark.asyncio
async def test_score_entry_stores_raw_and_scaled(db_session, test_feed, fake_redis, monkeypatch):
    from app.intelligence.signals import SignalHit
    from app.workers.signal_tasks import score_entry

    fake_redis.data[signals.SCALE_CUTOFFS_REDIS_KEY] = json.dumps(CUTS)

    async def two_hits(db, entry):
        return [SignalHit("kev_added", 1.0, "KEV"), SignalHit("scoop", 1.0, "first")]

    monkeypatch.setattr(signals, "compute_entry_signals", two_hits)
    entry = await _entry(db_session, test_feed, None)

    score = await score_entry(db_session, entry.id)
    await db_session.flush()

    await db_session.refresh(entry)
    assert entry.priority_raw > 0
    assert entry.priority_score == score == scale_score(entry.priority_raw, CUTS)
    assert 0 < score <= 10


@pytest.fixture
def worker_session_is_test_session(db_session, monkeypatch):
    from app.workers import signal_tasks

    @asynccontextmanager
    async def same_session():
        yield db_session

    monkeypatch.setattr(signal_tasks, "_get_worker_session", same_session)


@pytest.mark.asyncio
async def test_nightly_job_rescales_stored_scores(
    db_session, test_feed, fake_redis, monkeypatch, worker_session_is_test_session
):
    from app.workers import signal_tasks

    monkeypatch.setattr(signal_tasks, "RESCALE_BATCH_SIZE", 7)  # several batches
    fake_redis.data[signals.LEGACY_THRESHOLD_REDIS_KEY] = "2.8"
    for i in range(100):
        # Stored against stale cutoffs: every score is wrong for today's spread.
        await _entry(db_session, test_feed, float(i + 1), score=1.0)
    unscored = await _entry(db_session, test_feed, None)
    # Scored long ago: outside the re-scale window, keeps the scale it was given.
    old = await _entry(db_session, test_feed, 50.0, score=1.0, scored_at=NOW - timedelta(days=120))
    await db_session.commit()

    await signal_tasks._recompute_signal_rates()

    cuts = json.loads(fake_redis.data[signals.SCALE_CUTOFFS_REDIS_KEY])
    rows = (
        (await db_session.execute(select(Entry).where(Entry.priority_raw.isnot(None), Entry.id != old.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 100
    for row in rows:
        await db_session.refresh(row)
        assert row.priority_score == pytest.approx(scale_score(row.priority_raw, cuts))
    top = max(rows, key=lambda r: r.priority_raw)
    assert top.priority_score == 10.0
    await db_session.refresh(unscored)
    assert unscored.priority_score is None
    await db_session.refresh(old)
    assert old.priority_score == 1.0
    # The auto radar threshold is read off the re-scaled column.
    assert 0 <= float(fake_redis.data[signals.THRESHOLD_REDIS_KEY]) <= 10
    assert signals.LEGACY_THRESHOLD_REDIS_KEY not in fake_redis.data


@pytest.mark.asyncio
async def test_nightly_rescale_writes_only_rows_that_move(db_session, test_feed, worker_session_is_test_session):
    from app.workers.signal_tasks import _rescale_priority_scores

    for i in range(10):
        await _entry(db_session, test_feed, float(i + 1), score=scale_score(float(i + 1), CUTS))
    stale = await _entry(db_session, test_feed, 5.0, score=1.0)
    await db_session.commit()

    assert await _rescale_priority_scores(db_session, CUTS) == 1
    await db_session.refresh(stale)
    assert stale.priority_score == 5.0


@pytest.mark.asyncio
async def test_cutoffs_are_cached_before_anything_later_can_fail(
    db_session, test_feed, fake_redis, monkeypatch, worker_session_is_test_session
):
    from app.workers import signal_tasks

    for i in range(60):
        await _entry(db_session, test_feed, float(i + 1), score=1.0)
    await db_session.commit()

    async def boom(*_args, **_kwargs):
        raise RuntimeError("feedback lookup failed")

    monkeypatch.setattr("app.services.system_settings.get_setting", boom)
    with pytest.raises(RuntimeError):
        await signal_tasks._recompute_signal_rates()

    # The stored scores were re-scaled, and new scoring already sees the same cutoffs.
    assert signals.SCALE_CUTOFFS_REDIS_KEY in fake_redis.data


@pytest.mark.asyncio
async def test_legacy_raw_override_is_converted_once(fake_redis):
    fake_redis.data[signals.SCALE_CUTOFFS_REDIS_KEY] = json.dumps(CUTS)
    fake_redis.data[signals.LEGACY_THRESHOLD_OVERRIDE_REDIS_KEY] = "4.5"

    assert await signals.get_radar_threshold() == (4.5, False)
    assert signals.LEGACY_THRESHOLD_OVERRIDE_REDIS_KEY not in fake_redis.data
    assert fake_redis.data[signals.THRESHOLD_OVERRIDE_REDIS_KEY] == "4.5"


@pytest.mark.asyncio
async def test_legacy_override_waits_for_real_cutoffs(fake_redis):
    """Right after deploy nothing has cached the cutoffs; converting with the defaults would stick."""
    fake_redis.data[signals.LEGACY_THRESHOLD_OVERRIDE_REDIS_KEY] = "4.5"

    assert await signals.get_radar_threshold() == (signals.DEFAULT_RADAR_THRESHOLD, True)
    assert fake_redis.data[signals.LEGACY_THRESHOLD_OVERRIDE_REDIS_KEY] == "4.5"
    assert signals.THRESHOLD_OVERRIDE_REDIS_KEY not in fake_redis.data

    fake_redis.data[signals.SCALE_CUTOFFS_REDIS_KEY] = json.dumps(CUTS)
    assert await signals.get_radar_threshold() == (4.5, False)


@pytest.mark.asyncio
async def test_threshold_default_is_on_the_scale(fake_redis):
    value, is_auto = await signals.get_radar_threshold()
    assert is_auto and 0 < value <= 10


# ── The migration's rule conversion ────────────────────────────────

_MIGRATION = next(Path(__file__).resolve().parents[1].glob("alembic/versions/z7r9t1v3x5z7_*.py"))
_spec = importlib.util.spec_from_file_location("scale_migration", _MIGRATION)
migration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(migration)


def test_migration_mapping_matches_live_mapping():
    for raw in [-1, 0, 0.001, 0.19, 0.5, 1.4, 2.0, 4.0, 4.9, 30]:
        assert migration.scale(raw, list(DEFAULT_SCALE_CUTOFFS)) == scale_score(raw, DEFAULT_SCALE_CUTOFFS)
    for raw in [2.25, 4.25, 8.85]:  # exact halves round alike too
        assert migration.scale(raw, CUTS) == scale_score(raw, CUTS)
    assert migration.ANCHORS == SCALE_ANCHORS
    assert migration.DEFAULT_CUTOFFS == DEFAULT_SCALE_CUTOFFS


def test_migration_converts_conditions_wherever_they_sit():
    conditions = {"operator": "AND", "conditions": [{"type": "priority_score_above", "config": {"min": 5.0}}]}
    actions = [
        {
            "type": "branch",
            "config": {
                "condition": {"type": "priority_score_above", "config": {"min": 6.0}},
                "then_actions": [{"type": "send_notification", "config": {"min": 99}}],
            },
        }
    ]
    convert = lambda raw: migration.scale(raw, CUTS)  # noqa: E731
    assert migration.convert_rule_json(conditions, convert)
    assert migration.convert_rule_json(actions, convert)
    assert conditions["conditions"][0]["config"]["min"] == 5.0
    assert actions[0]["config"]["condition"]["config"]["min"] == 6.0
    # Not a score condition — left alone.
    assert actions[0]["config"]["then_actions"][0]["config"]["min"] == 99

    big = {"type": "priority_score_above", "config": {"min": 40}}
    migration.convert_rule_json(big, convert)
    assert big["config"]["min"] == 10.0


def test_migration_leaves_rules_without_score_conditions_alone():
    rule = {"operator": "AND", "conditions": [{"type": "has_signal", "config": {"signal_types": ["kev_added"]}}]}
    assert not migration.convert_rule_json(rule, lambda raw: 0.0)


def test_tests_never_share_the_live_cutoffs_key():
    """conftest swaps the key per test, so no test reads or writes dev's real cutoffs."""
    assert signals.SCALE_CUTOFFS_REDIS_KEY != "intelfeed:signal_engine:scale_cutoffs"
    assert signals.SCALE_CUTOFFS_REDIS_KEY.startswith("intelfeed:test:")
