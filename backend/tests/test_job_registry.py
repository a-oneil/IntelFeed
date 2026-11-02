"""Guards on the job registry ↔ system settings contract.

Every knob a job advertises has to be a real, settable setting with a UI-worthy
label, and every setting has to live in a group some admin surface renders.
These broke silently before: `settings.get()` returns None for an unregistered
key, so the job just kept using its inline default forever.
"""

from app.services.system_settings import (
    CONFIGURABLE_KEYS,
    GROUP_LABELS,
    SETTING_METADATA,
)
from app.workers.job_registry import JOB_REGISTRY


def test_job_settings_keys_are_configurable():
    """A job may only advertise keys the settings API can actually write."""
    unknown = {
        (name, key)
        for name, job in JOB_REGISTRY.items()
        for key in job.get("settings_keys", [])
        if key not in CONFIGURABLE_KEYS
    }
    assert not unknown, f"jobs reference unsettable keys: {sorted(unknown)}"


def test_job_settings_keys_are_unique_per_job():
    for name, job in JOB_REGISTRY.items():
        keys = job.get("settings_keys", [])
        assert len(keys) == len(set(keys)), f"{name} repeats a settings key"


def test_every_configurable_key_has_metadata():
    missing = [k for k in CONFIGURABLE_KEYS if k not in SETTING_METADATA]
    assert not missing, f"settings with no label/description/group: {missing}"


def test_every_setting_group_is_labelled():
    """An unlabelled group is a setting that renders on no admin surface."""
    unknown = {
        (key, SETTING_METADATA[key].get("group"))
        for key in CONFIGURABLE_KEYS
        if SETTING_METADATA[key].get("group") not in GROUP_LABELS
    }
    assert not unknown, f"settings in unknown groups: {sorted(unknown)}"


def _weekly_slot(job: dict) -> tuple[str, str, str] | None:
    sched = job["default_schedule"]
    if sched["type"] != "crontab" or sched.get("day_of_week", "*") == "*":
        return None
    return sched["day_of_week"], sched["hour"], sched["minute"]


def test_weekly_enrichment_syncs_start_in_their_own_slots():
    """Weekly catalog syncs write the same entity tables; two started together deadlocked."""
    slots: dict[tuple, str] = {}
    for name, job in JOB_REGISTRY.items():
        slot = _weekly_slot(job)
        if job["category"] != "enrichment" or slot is None:
            continue
        assert slot not in slots, f"{name} shares its weekly slot with {slots[slot]}"
        slots[slot] = name


def test_malpedia_sync_has_its_weekly_hour_to_itself():
    day, hour, _ = _weekly_slot(JOB_REGISTRY["malpedia-sync"])
    neighbours = [
        name
        for name, job in JOB_REGISTRY.items()
        if name != "malpedia-sync" and (slot := _weekly_slot(job)) and slot[:2] == (day, hour)
    ]
    assert not neighbours


def test_job_registry_entries_are_complete():
    for name, job in JOB_REGISTRY.items():
        assert job.get("task"), f"{name} has no task path"
        assert job.get("description"), f"{name} has no description"
        assert job.get("category"), f"{name} has no category"
        assert job.get("default_schedule"), f"{name} has no default schedule"
