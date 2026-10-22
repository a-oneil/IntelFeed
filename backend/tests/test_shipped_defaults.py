"""The shipped defaults are the values production settled on (issue #15).

A fresh install should behave like the tuned instance, not like the platform
did months before the tuning. Each assertion here is a knob that was promoted
from prod's `system_settings` override row into the code default; if one of
them drifts back, this is the test that says so. Keys deliberately left
instance-specific (content char budget, public RSS, the FP-name list, the
user agent) are not here on purpose.
"""

from app.ai.prompts.defaults import SYSTEM_TASKS
from app.ai.providers.ollama_provider import DEFAULT_TIMEOUT_SECONDS, OllamaProvider
from app.config import Settings
from app.services.system_settings import find_redundant_overrides
from app.workers.job_registry import JOB_REGISTRY

FIELD_DEFAULTS = {name: field.default for name, field in Settings.model_fields.items()}

PROMOTED = {
    "ai_one_pass_enabled": True,
    "signal_engine_shadow": True,
    "signal_engine_surface": True,
    "per_user_subscriptions_enabled": True,
    "my_stack_exposure_enabled": True,
    "exposure_attack_visibility_enabled": True,
    "entity_creation_gates": "on",
    "autolinker_min_name_length": 3,
    "observables_ai_capture_mode": "capture",
    "embeddings_enabled": True,
    "relationship_evidence_structure": True,
    "adjudication_mode": "apply",
}


def test_engine_defaults_match_production_tuning():
    drift = {k: FIELD_DEFAULTS.get(k) for k, v in PROMOTED.items() if FIELD_DEFAULTS.get(k) != v}
    assert not drift, f"shipped defaults drifted from the promoted values: {drift}"


def test_instance_specific_keys_were_not_promoted():
    """The keys the issue lists as never-promote keep their conservative defaults."""
    assert FIELD_DEFAULTS["public_rss_enabled"] is False
    assert FIELD_DEFAULTS["observables_publish_enabled"] is False
    assert FIELD_DEFAULTS["ai_analysis_content_max_chars"] == 12000
    assert FIELD_DEFAULTS["autolinker_blocked_surface_forms"] == ""
    assert FIELD_DEFAULTS["registration_enabled"] is True
    assert "Mozilla/5.0" in FIELD_DEFAULTS["user_agent"]


def test_job_cadences_match_production():
    assert JOB_REGISTRY["story-threads"]["default_schedule"] == {"type": "interval", "seconds": 7200}
    assert JOB_REGISTRY["refresh-correlation-cache"]["default_schedule"] == {"type": "crontab", "minute": "10"}


def test_ollama_timeout_default():
    assert DEFAULT_TIMEOUT_SECONDS == 900
    assert OllamaProvider(base_url="http://x", config={}).timeout == 900


def _task(name: str) -> dict:
    return next(t for t in SYSTEM_TASKS if t["name"] == name)


def test_prompt_splits_keep_the_variables_in_the_user_block():
    """The cacheable instruction moved to the system block; every variable stayed in the user block."""
    for name in ("article_summary", "actor_profile_refresh"):
        task = _task(name)
        assert task["default_system_template"], name
        for var in task["variables"]:
            root = var.split(".")[0]
            assert root in task["default_prompt_template"], f"{name}: {var} left the user template"
            assert "{{" not in task["default_system_template"], f"{name}: system block must be static"


def test_batch_tasks_hide_from_article_and_entity_actions():
    for name in ("daily_summary", "intelligence_briefing"):
        task = _task(name)
        assert task["show_in_entry_actions"] is False, name
        assert task["show_in_entity_actions"] is False, name
    for name in ("article_summary", "detection_rules", "video_transcript_summary"):
        assert _task(name)["show_in_entity_actions"] is False, name
        assert _task(name).get("show_in_entry_actions", True) is True, name


def test_find_redundant_overrides_classifies_the_prod_shape():
    registry = {
        "story-threads": {"default_schedule": {"type": "interval", "seconds": 7200}},
        "actor-profile-refresh": {"default_schedule": {"type": "crontab", "minute": "0", "hour": "3"}},
        "signal-rescore-all": {"default_schedule": {"type": "crontab", "minute": "0"}, "enabled_by_default": False},
    }
    row = {
        "registration_enabled": True,  # equals default
        "entity_maintenance_mode": "shadow",  # equals default
        "ai_analysis_content_max_chars": 24000,  # real override
        "max_graph_nodes": 1000,  # nothing reads it
        "nvd_api_key": "x",  # secret: never listed
        "_public_rss_token": "tok",
        "_default_theme_id": "uuid",
        "_job_schedule_overrides": {
            "story-threads": {"schedule": {"type": "interval", "seconds": 7200}},  # now the default
            "actor-profile-refresh": {"enabled": True},  # already enabled
            "signal-rescore-all": {"enabled": True},  # a real flip
            "validate-entity-links": {"enabled": False},  # job is gone
        },
    }
    report = find_redundant_overrides(row, job_registry=registry)
    assert report["equal_to_default"] == ["entity_maintenance_mode", "registration_enabled"]
    assert report["unknown"] == ["max_graph_nodes"]
    assert report["job_overrides_orphaned"] == ["validate-entity-links"]
    assert report["job_overrides_equal_to_default"] == ["actor-profile-refresh", "story-threads"]


# ---------------------------------------------------------------------------
# Bulk apply (the background "Apply all" behind the Proposals lens)
# ---------------------------------------------------------------------------


def test_adjudication_maint_actions_scope():
    from app.services.entry_adjudication import ACTION_ASSESSMENT, ADJUDICATION_PROPOSAL_ACTIONS
    from app.services.proposal_apply import adjudication_maint_actions

    everything = adjudication_maint_actions(None)
    assert ACTION_ASSESSMENT not in everything
    assert set(everything) == ADJUDICATION_PROPOSAL_ACTIONS - {ACTION_ASSESSMENT}
    assert adjudication_maint_actions("shadow_remove") == []
    only = everything[0]
    assert adjudication_maint_actions(only) == [only]
