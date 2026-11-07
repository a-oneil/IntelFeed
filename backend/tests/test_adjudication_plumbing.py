"""Adjudicate stage plumbing (commit 1 of the adjudication PR): registry row,
settings registration, matrix column. The task itself lands in commit 2."""

from app.api.engine import PIPELINE_STAGE_LABELS, PROCESSING_STAGE_ORDER
from app.pipeline.registry import PIPELINE_STAGES
from app.services.system_settings import (
    _ENGINE_SECTION_GROUPS,
    CONFIGURABLE_KEYS,
    GROUP_LABELS,
    SETTING_METADATA,
)

ADJUDICATION_SETTINGS: dict[str, type] = {
    "adjudication_mode": str,
    "adjudication_trigger": str,
    "adjudication_max_per_hour": int,
    "adjudication_min_priority_score": float,
    "adjudication_apply_min_confidence": str,
    "adjudication_circuit_breaker_pct": float,
    "adjudication_circuit_breaker_min_items": int,
    "adjudication_content_max_chars": int,
    "adjudication_scope": str,
}


def test_registry_row():
    stage = PIPELINE_STAGES["adjudicate"]
    assert stage.kind == "post_analysis"
    assert stage.task_path == "app.workers.adjudication_tasks.adjudicate_entry_task"
    # Plans are off in prod: the mode setting is the master switch, so the
    # registry default must not be a second gate.
    assert stage.default_enabled is True
    assert stage.config_schema["mode"]["setting"] == "adjudication_mode"


def test_matrix_columns_follow_score():
    # score enqueues the AI analysis; the review follows the analysis.
    assert PROCESSING_STAGE_ORDER.index("analyze") == PROCESSING_STAGE_ORDER.index("score") + 1
    assert PROCESSING_STAGE_ORDER.index("adjudicate") == PROCESSING_STAGE_ORDER.index("analyze") + 1
    assert PIPELINE_STAGE_LABELS["analyze"] and PIPELINE_STAGE_LABELS["adjudicate"]


def test_settings_registered_with_metadata_and_group():
    """An unregistered key is permanently inert (settings.get falls through to
    the env default and the UI never renders it) — guard every key."""
    assert GROUP_LABELS["adjudication"]
    for key, kind in ADJUDICATION_SETTINGS.items():
        assert CONFIGURABLE_KEYS.get(key) is kind, f"{key} missing from CONFIGURABLE_KEYS"
        meta = SETTING_METADATA[key]
        assert meta["label"] and meta["description"]
        assert meta["group"] == "adjudication"
        assert _ENGINE_SECTION_GROUPS[key] == "adjudication"


def test_enum_settings_render_as_selects():
    assert SETTING_METADATA["adjudication_mode"]["options"] == ["off", "shadow", "apply"]
    assert SETTING_METADATA["adjudication_trigger"]["options"] == ["all", "created"]
    assert SETTING_METADATA["adjudication_apply_min_confidence"]["options"] == ["high", "medium", "low"]
    assert SETTING_METADATA["entity_creation_gates"]["options"] == ["off", "shadow", "on"]


def test_defaults_are_apply_all_and_no_ceilings():
    """Every dial that could quietly hold the stage back ships neutral: the
    master switch on (apply — what production settled on, see issue #15),
    every analysed entry in scope, and no floor or ceiling. A rate ceiling is
    worth setting on a metered provider or to protect the shared `ai` queue —
    neither is true of every install, so neither is a default."""
    from app.config import Settings

    fields = Settings.model_fields
    assert fields["adjudication_mode"].default == "apply"
    assert fields["adjudication_trigger"].default == "all"
    assert fields["adjudication_min_priority_score"].default == 0.0
    assert fields["adjudication_max_per_hour"].default == 0
