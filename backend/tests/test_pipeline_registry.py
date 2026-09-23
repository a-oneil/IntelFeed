"""Registry-driven chord assembly must be structurally identical to the old hand-built dispatch."""

import uuid
from unittest.mock import patch

import pytest

from app.pipeline.plans import _merge, synthesize_from_feed
from app.pipeline.registry import PIPELINE_STAGES, stages_of_kind


class _CapturedChord:
    def __init__(self, header, callback):
        self.header = header
        self.callback = callback

    def apply_async(self):
        return None


def _capture_dispatch(entry_id: str, **kwargs):
    captured = {}

    def fake_chord(header, callback):
        captured["header"] = list(header.tasks) if hasattr(header, "tasks") else list(header)
        captured["callback"] = callback
        return _CapturedChord(captured["header"], callback)

    with patch("app.workers.feed_tasks.chord", side_effect=fake_chord):
        from app.workers.feed_tasks import dispatch_entry_pipeline

        dispatch_entry_pipeline(entry_id, **kwargs)
    return captured


def _sig_names(signatures) -> list[str]:
    return [s.task for s in signatures]


def test_dispatch_without_extraction_matches_legacy_structure():
    eid = str(uuid.uuid4())
    captured = _capture_dispatch(eid, run_extraction=False)
    # Legacy: [autolink, telegram_links] → entry_post_processing(entry_id=…);
    # the observables stage joined the parallel header in the ledger build.
    assert _sig_names(captured["header"]) == [
        "app.workers.intel_feed_tasks.autolink_entry_task",
        "app.workers.intel_feed_tasks.observables_entry_task",
        "app.workers.telegram_link_tasks.scan_telegram_links_task",
    ]
    for sig in captured["header"]:
        assert list(sig.args) == [eid]
        assert sig.immutable
    assert captured["callback"].task == "app.workers.feed_tasks.entry_post_processing"
    assert captured["callback"].kwargs == {"entry_id": eid}


def test_dispatch_with_extraction_matches_legacy_structure():
    eid = str(uuid.uuid4())
    captured = _capture_dispatch(eid, run_extraction=True)
    assert _sig_names(captured["header"]) == [
        "app.workers.intel_feed_tasks.autolink_entry_task",
        "app.workers.intel_feed_tasks.observables_entry_task",
        "app.workers.telegram_link_tasks.scan_telegram_links_task",
        "app.workers.intel_feed_tasks.extract_entry_intel_task",
    ]


def test_dispatch_with_plan_overrides():
    eid = str(uuid.uuid4())
    plan = {
        "autolink": {"enabled": True, "config": {}},
        "observables": {"enabled": False, "config": {}},
        "telegram_links": {"enabled": False, "config": {}},
        "extract": {"enabled": True, "config": {}},
    }
    captured = _capture_dispatch(eid, plan=plan)
    assert _sig_names(captured["header"]) == [
        "app.workers.intel_feed_tasks.autolink_entry_task",
        "app.workers.intel_feed_tasks.extract_entry_intel_task",
    ]


def test_dispatch_plan_never_empties_header():
    eid = str(uuid.uuid4())
    plan = {name: {"enabled": False, "config": {}} for name in PIPELINE_STAGES}
    captured = _capture_dispatch(eid, plan=plan)
    # Autolink is the floor — post-processing depends on entity links existing
    assert _sig_names(captured["header"]) == ["app.workers.intel_feed_tasks.autolink_entry_task"]


def test_dispatch_with_translate_prologue():
    """auto_translate feeds chain translate ahead of the chord so every later
    stage (autolink/extract/relevance/score) sees the translated text."""
    eid = str(uuid.uuid4())
    captured = {}

    def fake_chord(header, callback):
        captured["header"] = list(header.tasks) if hasattr(header, "tasks") else list(header)
        captured["callback"] = callback
        return _CapturedChord(captured["header"], callback)

    class _CapturedChain:
        def __init__(self, *sigs):
            captured["chain"] = list(sigs)

        def apply_async(self):
            return None

    with (
        patch("app.workers.feed_tasks.chord", side_effect=fake_chord),
        patch("app.workers.feed_tasks.chain", side_effect=lambda *sigs: _CapturedChain(*sigs)),
    ):
        from app.workers.feed_tasks import dispatch_entry_pipeline

        dispatch_entry_pipeline(eid, run_extraction=False, translate_target="en")

    prologue, chord_obj = captured["chain"]
    assert prologue.task == "app.workers.translation_tasks.translate_entry_task"
    assert list(prologue.args) == [eid, "en"]
    assert prologue.kwargs == {"requeue_autolink": False}
    assert prologue.immutable
    assert isinstance(chord_obj, _CapturedChord)
    # The chord itself is unchanged by the prologue
    assert _sig_names(captured["header"]) == [
        "app.workers.intel_feed_tasks.autolink_entry_task",
        "app.workers.intel_feed_tasks.observables_entry_task",
        "app.workers.telegram_link_tasks.scan_telegram_links_task",
    ]


def test_post_processing_chord_structure():
    eid = str(uuid.uuid4())
    captured = {}

    def fake_chord(header, callback):
        captured["header"] = list(header.tasks) if hasattr(header, "tasks") else list(header)
        captured["callback"] = callback
        return _CapturedChord(captured["header"], callback)

    with patch("app.workers.feed_tasks.chord", side_effect=fake_chord):
        from app.workers.feed_tasks import entry_post_processing

        entry_post_processing(entry_id=eid)

    assert _sig_names(captured["header"]) == [
        "app.workers.intel_feed_tasks.create_cooccurrence_relationships_task",
        "app.workers.automation_tasks.detect_correlation_events",
        "app.workers.intel_feed_tasks.match_requirements_task",
    ]
    assert captured["callback"].task == "app.workers.signal_tasks.score_entry_task"
    assert captured["callback"].kwargs == {"entry_id": eid}


def test_registry_kinds_cover_expected_stages():
    assert [s.name for s in stages_of_kind("pre")] == ["translate"]
    assert [s.name for s in stages_of_kind("parallel")] == ["autolink", "observables", "telegram_links", "extract"]
    assert [s.name for s in stages_of_kind("post")] == ["cooccurrence", "correlation", "requirements"]
    assert [s.name for s in stages_of_kind("final")] == ["score"]


def test_plan_synthesis_and_merge():
    class FakeFeed:
        auto_extract_on_ingest = False
        extract_detection_rules = True
        intel_extraction_mode = "selective"

    plan = synthesize_from_feed(FakeFeed())
    assert plan["extract"]["enabled"] is True  # detection rules imply extraction
    assert plan["extract"]["config"]["detection_rules"] is True
    assert plan["autolink"]["enabled"] is True

    merged = _merge(plan, {"extract": {"enabled": False}, "unknown_stage": {"enabled": True}})
    assert merged["extract"]["enabled"] is False
    assert "unknown_stage" not in merged


@pytest.mark.asyncio
async def test_plan_resolution_layers(db_session, monkeypatch):
    from app.config import settings as env_settings
    from app.models.feed import Feed
    from app.models.pipeline_plan import PipelinePlan
    from app.pipeline import plans as plans_mod

    feed = Feed(title="Plan Feed", url="https://plan.example/feed", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()

    # Engine off → None (legacy path)
    assert await plans_mod.resolve_feed_plan(db_session, feed) is None

    monkeypatch.setattr(env_settings, "pipeline_engine_enabled", True)

    # Disable redis caching for the test
    async def no_redis():
        raise RuntimeError("no redis in test")

    monkeypatch.setattr(plans_mod, "get_redis", no_redis, raising=False)

    db_session.add(
        PipelinePlan(name="Global", scope_type="global", scope_id=None, stages={"extract": {"enabled": True}})
    )
    db_session.add(
        PipelinePlan(
            name="This feed", scope_type="feed", scope_id=feed.id, stages={"telegram_links": {"enabled": False}}
        )
    )
    await db_session.flush()

    resolved = await plans_mod.resolve_feed_plan(db_session, feed)
    assert resolved is not None
    assert resolved["extract"]["enabled"] is True  # global overlay
    assert resolved["telegram_links"]["enabled"] is False  # feed overlay wins
    assert resolved["autolink"]["enabled"] is True  # synthesized base


@pytest.mark.asyncio
async def test_plans_api_crud(client, admin_headers, db_session):
    # Global plan exists via migration in dev, but the test DB starts empty — create it
    body = {
        "name": "Global default",
        "scope_type": "global",
        "scope_id": None,
        "stages": {"extract": {"enabled": True}},
    }
    resp = await client.put("/api/engine/plans", json=body, headers=admin_headers)
    assert resp.status_code == 200, resp.text

    resp = await client.get("/api/engine/plans", headers=admin_headers)
    plans = resp.json()["plans"]
    assert any(p["scope_type"] == "global" and p["stages"]["extract"]["enabled"] for p in plans)

    # Unknown stage rejected
    bad = {"name": "x", "scope_type": "global", "scope_id": None, "stages": {"nope": {"enabled": True}}}
    resp = await client.put("/api/engine/plans", json=bad, headers=admin_headers)
    assert resp.status_code == 422

    # Global plan cannot be deleted
    global_id = next(p["id"] for p in plans if p["scope_type"] == "global")
    resp = await client.delete(f"/api/engine/plans/{global_id}", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_pipeline_overview_endpoint(client, auth_headers):
    resp = await client.get("/api/engine/pipeline", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    names = [s["name"] for s in data["stages"]]
    assert "autolink" in names and "score" in names and "enrich" in names
    assert data["pipeline_engine_enabled"] is False
