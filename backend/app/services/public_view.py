"""What a visitor (public read-only mode) sees of shared data.

Two things are hidden from visitors at the data layer rather than route by
route, because they would otherwise leak through every entry list in the app
— profiles, timelines, pivots, threads, widgets, similar-entries:

* the Manual Uploads feed and every entry in it (an analyst's own documents),
* feed internals: URL, errors, health, pause reasons, adapter config, notes.

AI output is a third: no ``AIResult`` row loads during a visitor's request,
so no route can hand a visitor a saved summary, analysis or briefing.
Entity assessments live on the entity row, not in ``AIResult``, and stay.

The first is a SQLAlchemy global filter: while the request's viewer is
anonymous (core/public_access.py), every ORM select of ``Feed`` or ``Entry``
gets the hidden-feed criterion added, subqueries and relationship loads
included. The second is a response shaping step the feed routes call.
"""

import uuid
from typing import Any

from sqlalchemy import event, false
from sqlalchemy.orm import Session, with_loader_criteria

from app.core.public_access import viewer_is_anonymous
from app.dashboard_defaults import DEFAULT_BOARDS
from app.models.ai_result import AIResult
from app.models.entry import Entry
from app.models.feed import Feed
from app.schemas.dashboard import DashboardResponse, WidgetResponse
from app.schemas.feed import FeedResponse

#: Feed types a visitor never sees, with their entries.
HIDDEN_FEED_TYPES: frozenset[str] = frozenset({"manual"})


def _hidden_feed_ids():
    from sqlalchemy import select

    return select(Feed.id).where(Feed.feed_type.in_(HIDDEN_FEED_TYPES))


@event.listens_for(Session, "do_orm_execute")
def _hide_from_visitors(state) -> None:
    if not state.is_select or not viewer_is_anonymous():
        return
    state.statement = state.statement.options(
        with_loader_criteria(Feed, Feed.feed_type.not_in(HIDDEN_FEED_TYPES), include_aliases=True),
        with_loader_criteria(Entry, Entry.feed_id.not_in(_hidden_feed_ids()), include_aliases=True),
        with_loader_criteria(AIResult, false(), include_aliases=True),
    )


def strip_feed_for_visitor(resp: FeedResponse) -> FeedResponse:
    """A feed as a visitor sees it: a name in a category, nothing operational."""
    resp.url = ""
    resp.site_url = None
    resp.last_error = None
    resp.error_count = 0
    resp.error_since = None
    resp.auto_paused_at = None
    resp.pause_reason = None
    resp.health_warning = None
    resp.adapter_config = {}
    resp.analyst_notes = None
    resp.exclude_title_patterns = None
    resp.unread_count = 0
    return resp


# ── Dashboards ─────────────────────────────────────────────────────────
#
# Dashboards belong to a person. A visitor gets the built-in boards a new
# account would be seeded with, minus the tabs and widgets about hidden areas
# (rules, campaigns, ransomware) or about one person's activity.

VISITOR_BOARDS: tuple[str, ...] = ("__triage__/Triage", "__triage__/Intel", "__triage__/CVE")
HIDDEN_WIDGET_TYPES: frozenset[str] = frozenset(
    {
        "morning_briefing",
        "saved_search_hits",
        "watchlist_pulse",
        "ai_usage",
        "feed_health",
        "campaign_momentum",
        "active_campaigns",
        "telegram_mentions",
        "playbook_drift",
        "worker_queue",
        "automation_logs",
        "ransomware_pulse",
        "targeting_grid",
        "relationship_inbox",
        "rules_attention",
        "new_detections",
        "detection_format_breakdown",
        "detection_coverage",
        "attack_coverage_gap",
        "observables",
        "ioc_ledger",
    }
)

_VISITOR_NS = uuid.UUID("7a2f0c0e-5b1e-4d3a-9f6c-000000000001")


def _stable_id(*parts: Any) -> uuid.UUID:
    return uuid.uuid5(_VISITOR_NS, "/".join(str(p) for p in parts))


def visitor_dashboards() -> list[DashboardResponse]:
    """The read-only boards served to a visitor, with stable synthetic ids."""
    from datetime import UTC, datetime

    created = datetime(2024, 1, 1, tzinfo=UTC)
    boards: list[DashboardResponse] = []
    for sort_order, board in enumerate(DEFAULT_BOARDS):
        if board["name"] not in VISITOR_BOARDS:
            continue
        board_id = _stable_id("board", board["name"])
        widgets = [
            WidgetResponse(
                id=_stable_id("widget", board["name"], i, w["widget_type"]),
                dashboard_id=board_id,
                widget_type=w["widget_type"],
                title=w["title"],
                config=w["config"],
                position_x=w["position_x"],
                position_y=w["position_y"],
                width=w["width"],
                height=w["height"],
            )
            for i, w in enumerate(board["widgets"])
            if w["widget_type"] not in HIDDEN_WIDGET_TYPES
        ]
        boards.append(
            DashboardResponse(
                id=board_id,
                created_by=None,
                name=board["name"],
                is_default=sort_order == 0,
                sort_order=sort_order,
                created_at=created,
                widgets=widgets,
            )
        )
    return boards


# ── Response scrubbing ─────────────────────────────────────────────────
#
# The routes a visitor may read were written for analysts, and many carry a
# few fields about areas a visitor doesn't get: who edited a field, rule
# counts and coverage on a badge, a campaign node in a graph. Rather than
# fork each route, the visitor's JSON is scrubbed on the way out: keys about
# hidden areas are dropped, objects that *are* a hidden-area entity are
# removed from their list, and graph edges left pointing at a removed node go
# with it. Article fields (``author`` is the article's byline) are untouched.

#: Keys naming a person on this instance.
_USER_KEYS = frozenset(
    {"username", "analyst", "owner_username", "creator_username", "created_by_username", "updated_by_username"}
)
#: A key containing one of these is about an area visitors don't get.
_HIDDEN_KEY_PARTS = ("rule", "campaign", "observable", "requirement", "coverage_gap", "ioc", "translat")
#: An object whose type is one of these is removed outright.
HIDDEN_ENTITY_TYPES = frozenset(
    {"campaign", "campaigns", "observable", "observables", "detection_rule", "rule", "ioc", "requirement"}
)
_REMOVED = object()


def _hidden_key(key: str) -> bool:
    k = key.lower()
    return k in _USER_KEYS or any(part in k for part in _HIDDEN_KEY_PARTS)


def _scrub(value: Any, removed_ids: set[str]) -> Any:
    if isinstance(value, dict):
        kind = value.get("type", value.get("entity_type"))
        if isinstance(kind, str) and kind.lower() in HIDDEN_ENTITY_TYPES:
            if "id" in value:
                removed_ids.add(str(value["id"]))
            return _REMOVED
        out = {}
        for key, item in value.items():
            if _hidden_key(key):
                continue
            item = _scrub(item, removed_ids)
            if item is not _REMOVED:
                out[key] = item
        return out
    if isinstance(value, list):
        return [item for item in (_scrub(v, removed_ids) for v in value) if item is not _REMOVED]
    return value


def _drop_dangling_edges(value: Any, removed_ids: set[str]) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("edges", "links") and isinstance(item, list):
                value[key] = [
                    e
                    for e in item
                    if not (
                        isinstance(e, dict)
                        and (str(e.get("source")) in removed_ids or str(e.get("target")) in removed_ids)
                    )
                ]
            else:
                _drop_dangling_edges(item, removed_ids)
    elif isinstance(value, list):
        for item in value:
            _drop_dangling_edges(item, removed_ids)
    return value


def scrub_for_visitor(payload: Any) -> Any:
    """``payload`` (decoded JSON) as a visitor may see it."""
    removed_ids: set[str] = set()
    cleaned = _scrub(payload, removed_ids)
    if cleaned is _REMOVED:
        return None
    return _drop_dangling_edges(cleaned, removed_ids) if removed_ids else cleaned
