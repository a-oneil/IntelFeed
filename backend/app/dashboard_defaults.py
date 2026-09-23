"""Default dashboard boards seeded for a user who has none.

Mirrors the board set the instance owner curated in the UI: five tabs, each a
`__triage__/`-prefixed dashboard the frontend renders as a tab, captured verbatim
from a live instance. A user who edits, renames, or deletes any of them keeps
their own version — seeding only ever runs for a user with zero dashboards.

Re-capture with `GET /api/dashboards` against the reference instance.
"""

from typing import Any, TypedDict


class DefaultWidget(TypedDict):
    widget_type: str
    title: str
    position_x: int
    position_y: int
    width: int
    height: int
    config: dict[str, Any]


class DefaultBoard(TypedDict):
    name: str
    widgets: list[DefaultWidget]


#: Board names carry the `__triage__/` prefix the dashboard page filters tabs on.
DEFAULT_BOARDS: list[DefaultBoard] = [
    {
        "name": "__triage__/Triage",
        "widgets": [
            {
                "widget_type": "overview_row",
                "title": "Overview",
                "position_x": 0,
                "position_y": 0,
                "width": 12,
                "height": 3,
                "config": {},
            },
            {
                "widget_type": "morning_briefing",
                "title": "Morning Briefing",
                "position_x": 0,
                "position_y": 3,
                "width": 5,
                "height": 9,
                "config": {},
            },
            {
                "widget_type": "triage_flow",
                "title": "Triage Flow",
                "position_x": 5,
                "position_y": 3,
                "width": 7,
                "height": 4,
                "config": {"days": 20},
            },
            {
                "widget_type": "under_reported",
                "title": "Under the Radar",
                "position_x": 5,
                "position_y": 7,
                "width": 7,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "correlation_browser",
                "title": "Correlation Events",
                "position_x": 5,
                "position_y": 11,
                "width": 7,
                "height": 6,
                "config": {},
            },
            {
                "widget_type": "saved_search_hits",
                "title": "Saved Search Hits",
                "position_x": 0,
                "position_y": 12,
                "width": 2,
                "height": 5,
                "config": {},
            },
            {
                "widget_type": "watchlist_pulse",
                "title": "Watchlist Pulse",
                "position_x": 2,
                "position_y": 12,
                "width": 3,
                "height": 5,
                "config": {},
            },
            {
                "widget_type": "ai_usage",
                "title": "AI Usage",
                "position_x": 0,
                "position_y": 17,
                "width": 6,
                "height": 3,
                "config": {},
            },
            {
                "widget_type": "top_tags",
                "title": "Top Tags",
                "position_x": 6,
                "position_y": 17,
                "width": 6,
                "height": 3,
                "config": {},
            },
            {
                "widget_type": "feed_health",
                "title": "Feed Health",
                "position_x": 0,
                "position_y": 20,
                "width": 12,
                "height": 6,
                "config": {},
            },
        ],
    },
    {
        "name": "__triage__/Intel",
        "widgets": [
            {
                "widget_type": "actor_activity_timeline",
                "title": "Actor Activity",
                "position_x": 0,
                "position_y": 0,
                "width": 4,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "new_actors",
                "title": "New Actors",
                "position_x": 4,
                "position_y": 0,
                "width": 4,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "trending_actors",
                "title": "Trending Actors",
                "position_x": 8,
                "position_y": 0,
                "width": 4,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "hot_correlations",
                "title": "Hot Correlations",
                "position_x": 0,
                "position_y": 4,
                "width": 4,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "campaign_momentum",
                "title": "Campaign Momentum",
                "position_x": 4,
                "position_y": 4,
                "width": 4,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "telegram_mentions",
                "title": "Telegram Mentions",
                "position_x": 8,
                "position_y": 4,
                "width": 4,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "playbook_drift",
                "title": "Playbook Drift",
                "position_x": 0,
                "position_y": 8,
                "width": 5,
                "height": 6,
                "config": {},
            },
            {
                "widget_type": "products_trending",
                "title": "Trending Products",
                "position_x": 5,
                "position_y": 8,
                "width": 4,
                "height": 6,
                "config": {},
            },
            {
                "widget_type": "vendors_trending",
                "title": "Trending Vendors",
                "position_x": 9,
                "position_y": 8,
                "width": 3,
                "height": 6,
                "config": {},
            },
        ],
    },
    {
        "name": "__triage__/CVE",
        "widgets": [
            {
                "widget_type": "cve_severity",
                "title": "CVE Severity",
                "position_x": 0,
                "position_y": 0,
                "width": 4,
                "height": 3,
                "config": {},
            },
            {
                "widget_type": "kev_matches",
                "title": "Actively Exploited CVEs",
                "position_x": 4,
                "position_y": 0,
                "width": 4,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "kev_deadlines",
                "title": "KEV Deadlines",
                "position_x": 8,
                "position_y": 0,
                "width": 4,
                "height": 9,
                "config": {},
            },
            {
                "widget_type": "new_cves",
                "title": "New CVEs",
                "position_x": 0,
                "position_y": 3,
                "width": 4,
                "height": 6,
                "config": {},
            },
            {
                "widget_type": "trending_cves",
                "title": "Trending CVEs",
                "position_x": 4,
                "position_y": 4,
                "width": 4,
                "height": 5,
                "config": {},
            },
        ],
    },
    {
        "name": "__triage__/DE",
        "widgets": [
            {
                "widget_type": "new_detections",
                "title": "New Detections",
                "position_x": 0,
                "position_y": 0,
                "width": 6,
                "height": 9,
                "config": {},
            },
            {
                "widget_type": "detection_format_breakdown",
                "title": "Detection Format Breakdown",
                "position_x": 6,
                "position_y": 0,
                "width": 6,
                "height": 3,
                "config": {},
            },
            {
                "widget_type": "rules_attention",
                "title": "Rules Needing Attention",
                "position_x": 6,
                "position_y": 3,
                "width": 6,
                "height": 6,
                "config": {},
            },
            {
                "widget_type": "trending_ttps",
                "title": "Trending TTPs",
                "position_x": 0,
                "position_y": 9,
                "width": 12,
                "height": 4,
                "config": {},
            },
        ],
    },
    {
        "name": "__triage__/Ransomware Ops",
        "widgets": [
            {
                "widget_type": "ransomware_pulse",
                "title": "Ransomware Pulse",
                "position_x": 0,
                "position_y": 0,
                "width": 8,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "watchlist_pulse",
                "title": "Watchlist Pulse",
                "position_x": 8,
                "position_y": 0,
                "width": 4,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "targeting_grid",
                "title": "Targeting Grid",
                "position_x": 0,
                "position_y": 4,
                "width": 6,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "playbook_drift",
                "title": "Playbook Drift",
                "position_x": 6,
                "position_y": 4,
                "width": 6,
                "height": 4,
                "config": {},
            },
            {
                "widget_type": "campaign_momentum",
                "title": "Campaign Momentum",
                "position_x": 0,
                "position_y": 8,
                "width": 6,
                "height": 3,
                "config": {},
            },
            {
                "widget_type": "active_campaigns",
                "title": "Active Campaigns",
                "position_x": 6,
                "position_y": 8,
                "width": 6,
                "height": 3,
                "config": {},
            },
        ],
    },
]
