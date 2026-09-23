"""Per-user learned Radar weights: the fit, the read-time lift, and the toggles.

The global feedback nudge (test_signal_engine) pools every analyst's thumbs into
one multiplier baked into Entry.priority_score. These tests cover the per-analyst
half: weights fitted from one user's own verdicts and applied at read time, with
the stored score left alone.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.intelligence.signals import (
    ECHO_WEIGHT,
    PERSONAL_WEIGHT_MAX,
    PERSONAL_WEIGHT_MIN,
    SIGNAL_FAMILIES,
    SignalHit,
    compute_priority_score,
    fit_personal_weight,
    personal_signal_coefficients,
)
from app.models.entry import Entry
from app.models.entry_signal import EntrySignal
from app.models.feed import Feed
from app.models.user_signal_weight import UserSignalWeight
from app.services.radar_personalization import (
    enrich_personal,
    get_personal_coefficients,
    get_user_weights,
    is_personalization_opted_in,
)

NOW = datetime.now(UTC)


@pytest_asyncio.fixture
async def feed(db_session) -> Feed:
    row = Feed(title="Vendor Blog", url="https://vendor.example/feed", feed_type="rss", reliability_rating="A")
    db_session.add(row)
    await db_session.flush()
    return row


async def _scored_entry(db_session, feed, *, score: float, signals: list[tuple[str, float]]) -> Entry:
    entry = Entry(
        feed_id=feed.id,
        title="Report",
        guid=f"guid-{uuid.uuid4()}",
        url=f"https://example.com/{uuid.uuid4()}",
        content_text="content",
        published_at=NOW,
        priority_score=score,
        scored_at=NOW,
    )
    db_session.add(entry)
    await db_session.flush()
    for signal_type, raw in signals:
        db_session.add(
            EntrySignal(
                entry_id=entry.id,
                signal_type=signal_type,
                score=raw,
                explanation=f"{signal_type} fired",
                payload={},
            )
        )
    await db_session.flush()
    return entry


# ── the fit ───────────────────────────────────────────────────────


def test_fit_is_neutral_without_votes():
    assert fit_personal_weight([]) == 1.0


def test_fit_moves_with_verdict_direction():
    assert fit_personal_weight([1] * 20) > 1.0
    assert fit_personal_weight([-1] * 20) < 1.0


def test_fit_shrinks_small_samples_toward_neutral():
    """Three thumbs must not move a family as far as thirty identical ones."""
    few = fit_personal_weight([1, 1, 1])
    many = fit_personal_weight([1] * 30)
    assert 1.0 < few < many


def test_fit_respects_bounds():
    assert fit_personal_weight([1] * 10_000) <= PERSONAL_WEIGHT_MAX
    assert fit_personal_weight([-1] * 10_000) >= PERSONAL_WEIGHT_MIN


def test_fit_cancels_on_split_verdicts():
    assert fit_personal_weight([1, -1, 1, -1, 1, -1]) == 1.0


# ── coefficients reproduce the engine's own arithmetic ────────────


def test_coefficients_skip_neutral_families():
    coeffs = personal_signal_coefficients({"severity": 1.0, "novelty": 1.0})
    assert coeffs == {}


def test_coefficients_cover_only_the_diverging_family():
    coeffs = personal_signal_coefficients({"severity": 1.2})
    assert set(coeffs) == {t for t, f in SIGNAL_FAMILIES.items() if f == "severity"}


def test_coefficients_keep_echo_negative_weighting():
    """feed_echo sinks entries; up-weighting coverage must sink them harder."""
    coeffs = personal_signal_coefficients({"coverage": 1.2})
    assert coeffs["feed_echo"] == pytest.approx(ECHO_WEIGHT * 0.2)


def test_lift_reproduces_a_full_rescore():
    """score + personal_lift must equal what the engine would produce with the
    user's multipliers — that equality is the whole contract of the feature."""
    hits = [SignalHit("kev_added", 0.8, ""), SignalHit("novel_entity", 0.5, ""), SignalHit("feed_echo", 0.6, "")]
    weights = {"severity": 1.25, "novelty": 0.8, "coverage": 1.1}

    global_score = compute_priority_score(hits)
    rescored = compute_priority_score(hits, multipliers=weights)

    coeffs = personal_signal_coefficients(weights)
    lift = sum(h.score * coeffs.get(h.signal_type, 0.0) for h in hits)

    # compute_priority_score rounds to 4dp and the coefficients to 6dp, so the
    # two paths can differ in the last place — a real arithmetic divergence
    # would be off by tenths, not by 1e-4.
    assert global_score + lift == pytest.approx(rescored, abs=1e-3)


# ── read-time application ─────────────────────────────────────────


async def test_no_weights_means_no_coefficients(db_session, test_user):
    assert await get_personal_coefficients(db_session, test_user.id) == {}


async def test_enrich_reports_lift_and_the_families_behind_it(db_session, feed, test_user):
    entry = await _scored_entry(db_session, feed, score=5.0, signals=[("kev_added", 0.9), ("pir_match", 0.4)])
    weights = {"severity": 1.3, "interest": 0.7}
    coeffs = personal_signal_coefficients(weights)

    detail = await enrich_personal(db_session, [entry.id], coeffs, weights)

    assert entry.id in detail
    families = {f["family"]: f for f in detail[entry.id]["families"]}
    assert families["severity"]["delta"] > 0
    assert families["interest"]["delta"] < 0
    # The reported lift is the sum of the parts it shows.
    assert detail[entry.id]["lift"] == pytest.approx(sum(f["delta"] for f in detail[entry.id]["families"]), abs=1e-3)


async def test_enrich_skips_entries_the_weights_do_not_move(db_session, feed, test_user):
    """An entry whose only signal belongs to a neutral family gets no row — the
    reader must not show a 'tuned for you' note that explains nothing."""
    entry = await _scored_entry(db_session, feed, score=3.0, signals=[("research_depth", 0.5)])
    coeffs = personal_signal_coefficients({"severity": 1.3})

    assert await enrich_personal(db_session, [entry.id], coeffs, {"severity": 1.3}) == {}


def test_opt_in_defaults_on_and_respects_an_explicit_no():
    assert is_personalization_opted_in(None) is True
    assert is_personalization_opted_in({}) is True
    assert is_personalization_opted_in({"radar_personalized": False}) is False


# ── the nightly job ───────────────────────────────────────────────


async def test_fit_job_writes_weights_and_clears_stale_ones(db_session, feed, test_user, monkeypatch):
    from app.models.entry_signal_feedback import EntrySignalFeedback
    from app.workers import signal_tasks

    entries = [await _scored_entry(db_session, feed, score=5.0, signals=[("kev_added", 0.9)]) for _ in range(6)]
    for entry in entries:
        db_session.add(EntrySignalFeedback(entry_id=entry.id, created_by=test_user.id, verdict=1, created_at=NOW))
    # A weight with no surviving evidence — the job must drop it.
    db_session.add(UserSignalWeight(user_id=test_user.id, family="content", weight=1.3, sample_count=9, up_votes=9))
    await db_session.commit()

    monkeypatch.setattr(signal_tasks, "_get_worker_session", lambda: _SessionHandle(db_session))
    result = await signal_tasks._fit_user_signal_weights()

    rows = {
        r.family: r
        for r in (await db_session.execute(select(UserSignalWeight).where(UserSignalWeight.user_id == test_user.id)))
        .scalars()
        .all()
    }
    assert "severity" in rows and rows["severity"].weight > 1.0
    assert rows["severity"].up_votes == 6
    assert "content" not in rows  # stale row cleared
    assert result["cleared"] == 1


async def test_fit_job_honours_the_sample_floor(db_session, feed, test_user, monkeypatch):
    """Below the floor a family stays neutral — no row, no lift."""
    from app.models.entry_signal_feedback import EntrySignalFeedback
    from app.workers import signal_tasks

    entry = await _scored_entry(db_session, feed, score=5.0, signals=[("kev_added", 0.9)])
    db_session.add(EntrySignalFeedback(entry_id=entry.id, created_by=test_user.id, verdict=1, created_at=NOW))
    await db_session.commit()

    monkeypatch.setattr(signal_tasks, "_get_worker_session", lambda: _SessionHandle(db_session))
    await signal_tasks._fit_user_signal_weights()

    assert await get_user_weights(db_session, test_user.id) == {}


async def test_fit_job_ignores_votes_outside_the_window(db_session, feed, test_user, monkeypatch):
    from app.models.entry_signal_feedback import EntrySignalFeedback
    from app.workers import signal_tasks

    stale = NOW - timedelta(days=400)
    for _ in range(8):
        entry = await _scored_entry(db_session, feed, score=5.0, signals=[("kev_added", 0.9)])
        db_session.add(EntrySignalFeedback(entry_id=entry.id, created_by=test_user.id, verdict=1, created_at=stale))
    await db_session.commit()

    monkeypatch.setattr(signal_tasks, "_get_worker_session", lambda: _SessionHandle(db_session))
    await signal_tasks._fit_user_signal_weights()

    assert await get_user_weights(db_session, test_user.id) == {}


class _SessionHandle:
    """Async-context shim so the worker's `async with _get_worker_session()` runs
    on the test's session without committing it away."""

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc):
        return False


# ── API surface ───────────────────────────────────────────────────


async def test_my_radar_reports_learned_families(client, db_session, test_user, auth_headers):
    db_session.add(
        UserSignalWeight(
            user_id=test_user.id, family="severity", weight=1.22, up_votes=30, down_votes=4, sample_count=34
        )
    )
    await db_session.commit()

    res = await client.get("/api/engine/my-radar", headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    families = {f["family"]: f for f in body["families"]}
    assert families["severity"]["learned"] is True
    assert families["severity"]["weight"] == pytest.approx(1.22)
    # Every family is listed, learned or not, so the panel can show the floor.
    assert families["content"]["learned"] is False
    assert families["content"]["weight"] == 1.0


async def test_toggle_round_trips(client, auth_headers):
    off = await client.put("/api/engine/my-radar", json={"personalized": False}, headers=auth_headers)
    assert off.status_code == 200
    assert (await client.get("/api/engine/my-radar", headers=auth_headers)).json()["personalized"] is False

    await client.put("/api/engine/my-radar", json={"personalized": True}, headers=auth_headers)
    assert (await client.get("/api/engine/my-radar", headers=auth_headers)).json()["personalized"] is True


async def test_reset_clears_only_this_users_weights(client, db_session, test_user, admin_user, auth_headers):
    db_session.add(UserSignalWeight(user_id=test_user.id, family="severity", weight=1.2, sample_count=10))
    db_session.add(UserSignalWeight(user_id=admin_user.id, family="severity", weight=0.8, sample_count=10))
    await db_session.commit()

    res = await client.delete("/api/engine/my-radar", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["cleared"] == 1

    survivors = (await db_session.execute(select(UserSignalWeight))).scalars().all()
    assert [s.user_id for s in survivors] == [admin_user.id]
