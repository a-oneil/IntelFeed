"""What a visitor (public read-only mode) sees of shared data.

Two things are hidden from visitors at the data layer rather than route by
route, because they would otherwise leak through every entry list in the app
— profiles, timelines, pivots, threads, widgets, similar-entries:

* every feed an admin has not marked ``visible_to_visitors``, with its
  entries, and the Manual Uploads feed (an analyst's own documents) always,
* feed internals: URL, errors, health, pause reasons, adapter config, notes.

AI output is a third: no ``AIResult`` row loads during a visitor's request,
so no route can hand a visitor a saved summary, analysis or briefing.
Entity assessments live on the entity row, not in ``AIResult``, and stay.

The first is a SQLAlchemy global filter: while the request's viewer is
anonymous (core/public_access.py), every ORM select of ``Feed`` or ``Entry``
gets the hidden-feed criterion added, subqueries and relationship loads
included. The second is a response shaping step the feed routes call.

The filter runs on SQL the ORM emits, so ``session.get()`` answered from the
identity map skips it. That is safe because a request's session starts empty
and everything a visitor's request loads passed the filter; code must not
hand a visitor's request a session that already holds other rows.
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

#: Feed types a visitor never sees, with their entries, whatever the flag says.
HIDDEN_FEED_TYPES: frozenset[str] = frozenset({"manual"})


def _feed_shown_to_visitors():
    return Feed.visible_to_visitors.is_(True) & Feed.feed_type.not_in(HIDDEN_FEED_TYPES)


def _shown_feed_ids():
    from sqlalchemy import select

    return select(Feed.id).where(_feed_shown_to_visitors())


def visible_entries_only(stmt, entry_id_column):
    """``stmt`` restricted to entries a visitor may see, when the viewer is one.

    A query over a junction table (EntryCVE, EntryThreatActor, ...) that never
    names ``Entry`` slips past the ORM filter: its rows, counts and entry ids
    include hidden feeds. Joining ``Entry`` brings the filter in. An inner
    join, deliberately: on an outer join the criteria land in the ON clause and
    the row survives with NULL entry columns.
    """
    if not viewer_is_anonymous():
        return stmt
    return stmt.join(Entry, Entry.id == entry_id_column)


#: Correlation event types a visitor may see: an allowlist, so a new type
#: stays hidden until someone reads what its context text says. Left out:
#: coverage gaps and rule events (detection), campaign and requirement
#: matches (their context names the campaign or PIR), feed health.
VISITOR_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "new_ttp_for_known_actor",
        "new_ttp_for_known_malware",
        "new_malware_for_known_actor",
        "actor_malware_cooccurrence",
        "exploit_status_change",
        "cve_score_change",
        "new_exploit_discovered",
        "kev_addition",
        "trending_entity",
    }
)


def visitor_events_only(stmt):
    """A correlation-event query cut to what a visitor may see: allowed types,
    about an article they can see or about none (CVE score, exploit and KEV
    events carry no article). No-op for a signed-in viewer."""
    from sqlalchemy import or_, select

    from app.models.correlation_event import CorrelationEventRecord

    if not viewer_is_anonymous():
        return stmt
    return stmt.where(
        CorrelationEventRecord.event_type.in_(VISITOR_EVENT_TYPES),
        or_(
            CorrelationEventRecord.entry_id.is_(None),
            # Through the visitor filter: visible articles only.
            CorrelationEventRecord.entry_id.in_(select(Entry.id)),
        ),
    )


async def entities_shown(db, refs) -> set[tuple[str, Any]]:
    """Which ``(entity_type, id)`` pairs a visitor sees. Types the visitor
    filter doesn't cover pass; article-derived ones are looked up through it."""
    from sqlalchemy import select

    from app.intelligence.correlation import ENTITY_CONFIG

    refs = set(refs)
    shown = {(t, i) for t, i in refs if t not in ARTICLE_DERIVED_TYPES}
    by_type: dict[str, set] = {}
    for t, i in refs:
        if t in ARTICLE_DERIVED_TYPES:
            by_type.setdefault(t, set()).add(i)
    for t, ids in by_type.items():
        model = ENTITY_CONFIG[t][0]
        found = (await db.execute(select(model.id).where(model.id.in_(ids)))).scalars()
        shown |= {(t, i) for i in found}
    return shown


async def visitor_feed_ids(db) -> list[str] | None:
    """The feeds a visitor may read, as search-index ``feed_id`` values; None
    for a signed-in viewer. The search index sits outside the visitor filter,
    so every search a visitor reaches must be limited to these."""
    from sqlalchemy import select

    if not viewer_is_anonymous():
        return None
    return [str(i) for i in (await db.execute(select(Feed.id))).scalars()]


def meili_feed_filter(feed_ids: list[str] | None) -> str | None:
    """``feed_ids`` as a Meilisearch filter. No feeds matches nothing."""
    if feed_ids is None:
        return None
    if not feed_ids:
        return 'feed_id = "00000000-0000-0000-0000-000000000000"'
    return "feed_id IN [" + ", ".join(f'"{i}"' for i in feed_ids) + "]"


#: The same rule as _feed_shown_to_visitors, for raw SQL with ``feeds`` joined
#: as ``f``. Raw SQL never passes through the ORM filter, so every raw query a
#: visitor reaches has to state it.
VISIBLE_FEED_SQL = "(f.visible_to_visitors AND f.feed_type NOT IN ({}))".format(
    ", ".join(f"'{t}'" for t in sorted(HIDDEN_FEED_TYPES))
)


async def visitor_thread_view(db, thread_ids) -> dict:
    """What a visitor may see of each story thread: the visible members only.

    Thread rows, beats and titles are raw SQL built from every member, so a
    thread can carry a hidden feed's headline or an AI spine written from
    hidden articles. Per thread id this returns its visible member ids
    (publication order), the earliest visible member's title, the
    highest-ranked visible member and its scores, and the counts and dates
    over visible members. A thread with no visible member is absent:
    a visitor never sees it.
    """
    from sqlalchemy import text

    ids = list({tid for tid in thread_ids if tid})
    if not ids:
        return {}
    rows = await db.execute(
        text(
            f"""
            SELECT ste.thread_id,
                   ARRAY_AGG(e.id ORDER BY e.published_at ASC NULLS LAST) AS entry_ids,
                   (ARRAY_AGG(e.title ORDER BY e.published_at ASC NULLS LAST))[1] AS first_title,
                   (ARRAY_AGG(e.id ORDER BY e.priority_raw DESC NULLS LAST)
                       FILTER (WHERE ste.role <> 'echo'))[1] AS top_entry_id,
                   MAX(e.priority_score) FILTER (WHERE ste.role <> 'echo') AS top_score,
                   MAX(e.priority_raw) FILTER (WHERE ste.role <> 'echo') AS top_raw,
                   COUNT(DISTINCT e.feed_id) AS source_count,
                   COUNT(*) FILTER (WHERE ste.role = 'echo') AS echo_count,
                   MIN(e.published_at) AS first_seen,
                   MAX(e.published_at) AS last_seen
            FROM story_thread_entries ste
            JOIN entries e ON e.id = ste.entry_id
            JOIN feeds f ON f.id = e.feed_id
            WHERE ste.thread_id = ANY(:ids) AND {VISIBLE_FEED_SQL}
            GROUP BY ste.thread_id
            """
        ),
        {"ids": ids},
    )
    return {row.thread_id: dict(row._mapping) for row in rows}


#: Entity types a visitor sees only through visible articles. Each is
#: extracted from articles, so one known only from a hidden feed (a Manual
#: Upload's actor, say) would otherwise name that feed's content. The
#: reference catalogs (CVE, TTP, CWE, mitigation, country, sector) are public
#: whatever mentions them; observables and campaigns are hidden outright.
ARTICLE_DERIVED_TYPES: tuple[str, ...] = ("threat_actor", "malware", "tool", "vendor", "product")


def _entity_shown_to_visitors(model, junction, fk_col):
    """Visible with no article link at all (a catalog import), or with at
    least one link into a visible article.

    The subqueries use aliases of their own: an outer query that already
    joins the junction or ``entries`` would otherwise auto-correlate them
    away and leave a subquery with no FROM.
    """
    from sqlalchemy import exists, or_, select
    from sqlalchemy.orm import aliased, join

    any_link = aliased(junction)
    shown_link = aliased(junction)
    entries = Entry.__table__.alias()
    feeds = Feed.__table__.alias()
    hidden_types = tuple(HIDDEN_FEED_TYPES)

    def criteria(cls):
        linked = exists(select(1).select_from(any_link).where(getattr(any_link, fk_col.key) == cls.id))
        shown = exists(
            select(1)
            .select_from(
                join(shown_link, entries, entries.c.id == shown_link.entry_id).join(
                    feeds, feeds.c.id == entries.c.feed_id
                )
            )
            .where(
                getattr(shown_link, fk_col.key) == cls.id,
                feeds.c.visible_to_visitors.is_(True),
                feeds.c.feed_type.not_in(hidden_types),
            )
        )
        return or_(~linked, shown)

    # track_closure_variables=True: SQLAlchemy caches a lambda criteria by
    # its code object, and all five entity types share this one. Without
    # tracking, every type reused the first one's SQL (threat actors'
    # junction), and the rule never applied to malware, tools, vendors or
    # products.
    return with_loader_criteria(model, criteria, include_aliases=True, track_closure_variables=True)


def _junction_shown_to_visitors(junction):
    """Rows of an article-link table (EntryTTP, EntryCVE, StoryThreadEntry...)
    about visible articles only. The counts, trends, heatmaps and per-article
    lists read these tables without loading Entry, so without this they
    count and list hidden feeds. Not applied to aliases: the entity rule
    above needs an unfiltered alias to tell "no links at all" from "no
    visible links"."""
    from sqlalchemy import select

    entries = Entry.__table__.alias()
    feeds = Feed.__table__.alias()
    # An explicit Join in select_from: Select.join() re-derives its left side
    # when embedded, and fails once the outer statement also joins the junction.
    shown_entries = (
        select(entries.c.id)
        .select_from(entries.join(feeds, feeds.c.id == entries.c.feed_id))
        .where(feeds.c.visible_to_visitors.is_(True), feeds.c.feed_type.not_in(tuple(HIDDEN_FEED_TYPES)))
    )
    # A lambda, so the criteria attach to the junction wherever the statement
    # puts it (a join's ON clause included); a bare column expression made the
    # table an extra FROM and broke select(TTP, EntryTTP.x).join(EntryTTP).
    return with_loader_criteria(
        junction, lambda cls: cls.entry_id.in_(shown_entries), include_aliases=False, track_closure_variables=False
    )


def _private_models() -> list:
    """Tables no visitor reads a row of: analysts' work products (campaigns,
    observables, detection rules, intelligence requirements, intel profiles),
    their notes and comments, and the ransomware victim tracker. Hiding them at the data layer, not route by
    route, means a campaign id or an observable passed as a parameter (to a
    pivot, a list filter, a timeline) finds nothing."""
    from app.models.campaign import Campaign, CampaignEntity, CampaignEntry, CampaignSavedSearch, CampaignSource
    from app.models.comment import Comment
    from app.models.detection_rule import DetectionRule
    from app.models.entity_note import EntityNote
    from app.models.intel_profile import IntelProfile
    from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
    from app.models.note import Note
    from app.models.observable import EntryObservable, Observable
    from app.models.ransomware import RansomwareVictim, VictimDisclosure

    return [
        Campaign,
        CampaignEntity,
        CampaignEntry,
        CampaignSavedSearch,
        CampaignSource,
        Comment,
        DetectionRule,
        EntityNote,
        IntelProfile,
        IntelligenceRequirement,
        Note,
        RequirementMatch,
        EntryObservable,
        Observable,
        # Leak-site victims: the ransomware area is signed-in only.
        RansomwareVictim,
        VictimDisclosure,
    ]


_entity_options: list | None = None


def _entity_criteria() -> list:
    global _entity_options
    if _entity_options is None:
        from app.intelligence.correlation import ENTITY_CONFIG
        from app.models.story_thread import StoryThreadEntry

        _entity_options = [_entity_shown_to_visitors(*ENTITY_CONFIG[t]) for t in ARTICLE_DERIVED_TYPES]
        junctions = {junction for _model, junction, _fk in ENTITY_CONFIG.values()} | {StoryThreadEntry}
        _entity_options += [_junction_shown_to_visitors(j) for j in sorted(junctions, key=lambda j: j.__name__)]
        _entity_options += [with_loader_criteria(m, false(), include_aliases=True) for m in _private_models()]
    return _entity_options


@event.listens_for(Session, "do_orm_execute")
def _hide_from_visitors(state) -> None:
    if not state.is_select or not viewer_is_anonymous():
        return
    state.statement = state.statement.options(
        with_loader_criteria(Feed, _feed_shown_to_visitors(), include_aliases=True),
        with_loader_criteria(Entry, Entry.feed_id.in_(_shown_feed_ids()), include_aliases=True),
        with_loader_criteria(AIResult, false(), include_aliases=True),
        *_entity_criteria(),
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


_GRID_COLS = 12  # DashboardPage's react-grid-layout width


def _repack(widgets: list[dict]) -> list[dict]:
    """Close the holes the hidden widgets leave.

    The grid compacts upward but never sideways, so a removed left-hand
    widget leaves an empty column beside its neighbours. Each remaining
    widget, in reading order, takes the first spot its size fits, then
    widens into any free columns to its right.
    """
    taken: set[tuple[int, int]] = set()

    def free(x: int, y: int, w: int, h: int) -> bool:
        return all((cx, cy) not in taken for cx in range(x, x + w) for cy in range(y, y + h))

    placed = []
    for w in sorted(widgets, key=lambda w: (w["position_y"], w["position_x"])):
        width, height = min(w["width"], _GRID_COLS), w["height"]
        y = 0
        while True:
            x = next((x for x in range(_GRID_COLS - width + 1) if free(x, y, width, height)), None)
            if x is not None:
                break
            y += 1
        taken.update((cx, cy) for cx in range(x, x + width) for cy in range(y, y + height))
        placed.append({**w, "position_x": x, "position_y": y, "width": width})
    for w in sorted(placed, key=lambda w: -w["position_x"]):
        x, y, height = w["position_x"], w["position_y"], w["height"]
        while x + w["width"] < _GRID_COLS and free(x + w["width"], y, 1, height):
            taken.update((x + w["width"], cy) for cy in range(y, y + height))
            w["width"] += 1
    return placed


def visitor_dashboards() -> list[DashboardResponse]:
    """The read-only boards served to a visitor, with stable synthetic ids."""
    from datetime import UTC, datetime

    created = datetime(2024, 1, 1, tzinfo=UTC)
    boards: list[DashboardResponse] = []
    for sort_order, board in enumerate(DEFAULT_BOARDS):
        if board["name"] not in VISITOR_BOARDS:
            continue
        board_id = _stable_id("board", board["name"])
        shown = _repack(
            [{**w, "index": i} for i, w in enumerate(board["widgets"]) if w["widget_type"] not in HIDDEN_WIDGET_TYPES]
        )
        widgets = [
            WidgetResponse(
                id=_stable_id("widget", board["name"], w["index"], w["widget_type"]),
                dashboard_id=board_id,
                widget_type=w["widget_type"],
                title=w["title"],
                config=w["config"],
                position_x=w["position_x"],
                position_y=w["position_y"],
                width=w["width"],
                height=w["height"],
            )
            for w in sorted(shown, key=lambda w: w["index"])
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
    {
        "username",
        "analyst",
        "owner_username",
        "creator_username",
        "created_by_username",
        "updated_by_username",
        # User ids: they name a person on this instance as surely as a username.
        "created_by",
        "changed_by",
        "updated_by",
    }
)
#: A key containing one of these is about an area visitors don't get: detection
#: (rules, coverage, gap hints), intel work products, IOCs, translations.
_HIDDEN_KEY_PARTS = (
    "rule",
    # Intel profiles are analysts' customer or portfolio scopes.
    "intel_profile",
    # AI-written article metadata (entry.metadata.article_intel).
    "article_intel",
    "campaign",
    "observable",
    "requirement",
    "pir_",
    "coverage",
    "detection",
    "ioc",
    "translat",
)
#: Exact keys: counts of private analyst work and of saved AI output.
_HIDDEN_KEYS = frozenset(
    {"notes", "note_count", "ai_results", "ai_result_count", "comments", "comment_count", "unread"}
)
#: An object whose type is one of these is removed outright.
HIDDEN_ENTITY_TYPES = frozenset(
    {"campaign", "campaigns", "observable", "observables", "detection_rule", "rule", "ioc", "requirement"}
)
#: Keys that say what an object is, or what it points at: a relationship to a
#: campaign, a timeline event about a rule, a correlation naming an observable.
_TYPE_KEYS = (
    "type",
    "entity_type",
    "event_type",
    "source_type",
    "target_type",
    "source_entity_type",
    "related_entity_type",
    "other_type",
)
#: Priority signals whose stored explanation names private work (a PIR's
#: title, the campaign or requirement behind a correlation, rule counts). A
#: visitor keeps the signal and its score, so the ranking still adds up, with
#: a generic explanation.
_SIGNAL_TEXT_FOR_VISITORS = {
    "pir_match": "Matches an intelligence requirement",
    "correlation_event": "Linked to related intelligence",
    "detection_content": "Contains detection content",
}
_REMOVED = object()
_EMPTY_LIKE: dict[type, Any] = {list: list, int: int, float: float, bool: bool}


def _hidden_key(key: str) -> bool:
    k = key.lower()
    return k in _USER_KEYS or k in _HIDDEN_KEYS or any(part in k for part in _HIDDEN_KEY_PARTS)


def _scrub(value: Any, removed_ids: set[str]) -> Any:
    if isinstance(value, dict):
        if "explanation" in value and (generic := _SIGNAL_TEXT_FOR_VISITORS.get(value.get("type"))):
            value = {**value, "explanation": generic}
        kinds = (value.get(k) for k in _TYPE_KEYS)
        if any(isinstance(kind, str) and kind.lower() in HIDDEN_ENTITY_TYPES for kind in kinds):
            if "id" in value:
                removed_ids.add(str(value["id"]))
            return _REMOVED
        out = {}
        for key, item in value.items():
            if _hidden_key(key):
                # Keep the shape the page expects: a hidden list reads as
                # empty and a hidden count as zero, since dropping them made
                # pages that read campaigns.length crash for visitors. A
                # hidden object is dropped: pages test for its presence
                # (headline.detections && ...), which an empty one would pass.
                if (empty := _EMPTY_LIKE.get(type(item))) is not None:
                    out[key] = empty()
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
