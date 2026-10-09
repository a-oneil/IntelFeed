"""Offline half of the observables extraction fixture: the hand-curated expected
values must agree with the kind validators, and validator-flagged garbage must
be rejected by them. The model-calling half is scripts/dev/eval_observable_extraction.py."""

import json
from pathlib import Path

import pytest

from app.intelligence.observables import normalize_value, validate_kind_value
from app.models.observable import ALL_KINDS

CASES = sorted((Path(__file__).parent / "fixtures" / "observables" / "cases").glob("*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


@pytest.mark.parametrize("path", CASES, ids=[p.stem for p in CASES])
def test_fixture_expected_values_are_canonical_and_valid(path: Path):
    case = _load(path)
    assert case.get("slug") == path.stem
    assert case.get("kind") in ("positive", "negative")
    for item in case.get("expected", []):
        kind, value = item["kind"], item["value"]
        assert kind in ALL_KINDS, f"{path.stem}: unknown kind {kind}"
        assert normalize_value(kind, value) == value, f"{path.stem}: {kind} {value!r} is not canonical"
        assert validate_kind_value(kind, value) == value, f"{path.stem}: validator rejects expected {kind} {value!r}"
    if case["kind"] == "negative":
        assert not case.get("expected"), f"{path.stem}: a negative case expects nothing"


@pytest.mark.parametrize("path", CASES, ids=[p.stem for p in CASES])
def test_fixture_flagged_garbage_is_rejected_by_validators(path: Path):
    case = _load(path)
    for item in case.get("must_not", []):
        if not item.get("validator"):
            continue
        assert validate_kind_value(item["kind"], item["value"]) is None, (
            f"{path.stem}: validator accepts garbage {item['kind']} {item['value']!r} ({item.get('why')})"
        )
