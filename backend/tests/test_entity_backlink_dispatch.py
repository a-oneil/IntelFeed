"""Entity-type normalization for the retro match-scan dispatcher.

dispatch_entity_backlink() is called from every layer that creates or widens an
entity, and those layers don't share one entity_type vocabulary. These tests pin
the translation and the drift between the mirrored type set and the autolinker.
"""

import inspect
import re
import uuid

import pytest

from app import entity_types
from app.entity_types import normalize_entity_type
from app.services.entity_backlink import (
    dispatch_backlink_for_added_aliases,
    dispatch_entity_backlink,
)


@pytest.fixture
def queued(monkeypatch):
    """Capture apply_async kwargs instead of hitting Celery."""
    from app.workers import intel_feed_tasks

    calls: list[dict] = []
    monkeypatch.setattr(
        intel_feed_tasks.link_new_entity_to_entries,
        "apply_async",
        lambda *a, **kw: calls.append(kw.get("kwargs", {})),
    )
    return calls


def test_autolinkable_set_matches_autolinker():
    """entity_types.AUTOLINKABLE must cover exactly what the autolinker branches on."""
    from app.intelligence import autolinker

    source = inspect.getsource(autolinker._link_entity_to_existing_entries_inner)
    # The loader block is the first if/elif chain; it ends at the unsupported-type else.
    loader = source.split("unsupported_entity_type")[0]
    branched = set(re.findall(r'entity_type == "(\w+)"', loader))
    assert branched == set(entity_types.AUTOLINKABLE)


@pytest.mark.parametrize(
    "given,expected",
    [
        ("malware", "malware"),  # maintenance / entity-resolution registry
        ("offensive_tool", "tool"),  # pre-2026-08 rename
        ("actor", "threat_actor"),  # search vocabulary
        ("threat_actor", "threat_actor"),  # already canonical
        ("mitigation", "mitigation"),
    ],
)
def test_normalize_entity_type(given, expected):
    assert normalize_entity_type(given) == expected


@pytest.mark.parametrize("entity_type", sorted(entity_types.AUTOLINKABLE))
def test_every_supported_type_dispatches(entity_type, queued):
    entity_id = uuid.uuid4()
    assert dispatch_entity_backlink(entity_type, entity_id) is True
    assert queued == [{"entity_type": entity_type, "entity_id": str(entity_id)}]


@pytest.mark.parametrize(
    "given,canonical",
    [("malware", "malware"), ("offensive_tool", "tool"), ("actor", "threat_actor")],
)
def test_legacy_slugs_dispatch_under_canonical_type(given, canonical, queued):
    assert dispatch_entity_backlink(given, uuid.uuid4()) is True
    assert queued[0]["entity_type"] == canonical


@pytest.mark.parametrize("entity_type", ["campaign", "victim", "detection_rule", "nonsense"])
def test_unscannable_types_are_skipped_not_queued(entity_type, queued):
    assert dispatch_entity_backlink(entity_type, uuid.uuid4()) is False
    assert queued == []


def test_alias_helper_reports_false_when_type_unscannable(queued):
    assert dispatch_backlink_for_added_aliases("campaign", uuid.uuid4(), [], ["New Name"]) is False
    assert queued == []


def test_alias_helper_dispatches_for_legacy_slug(queued):
    assert dispatch_backlink_for_added_aliases("malware", uuid.uuid4(), ["A"], ["A", "B"]) is True
    assert queued[0]["entity_type"] == "malware"


def test_alias_helper_ignores_recased_aliases(queued):
    assert dispatch_backlink_for_added_aliases("malware", uuid.uuid4(), ["Alpha"], ["ALPHA"]) is False
    assert queued == []
