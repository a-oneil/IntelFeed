"""Single source of truth for the template variables automation actions inject.

The runtime injectors in ``actions.py`` build their payloads by selecting keys
from the field lists below, and the builder UI reads the same definitions via
``GET /api/automation/variable-contexts``. Because both sides derive from here,
the documented "available variables" can't drift from what is actually provided
at runtime — the exact problem that made prompt-building confusing.

Two distinct variable systems exist, and they are easy to conflate:

1. **AI-prompt variables** (Jinja ``{{ }}``) — consumed by the *Run AI Task*
   action. The available set depends on the rule's execution mode
   (``per_entry`` vs ``batch``). See :func:`ai_prompt_variable_contexts`.

2. **Notification/template variables** (single-brace ``{ }``) — consumed by
   *Send Notification*, *Run Webhook*, *Create Note*, etc. via
   ``_render_template``. A fixed, mode-independent set. See
   :func:`notification_template_variables`.
"""

# --- AI-prompt variables (Jinja {{ }}, Run AI Task) -------------------------

# Entry fields injected per entry. `_action_run_ai_task` exposes these under
# `entry`; `_action_run_ai_task_batch` exposes them on each item of `entries`
# (plus `feed_title`) and on the first-entry alias `entry`.
PER_ENTRY_FIELDS: list[str] = [
    "id",
    "title",
    "content_text",
    "content_html",
    "summary",
    "author",
    "url",
    "app_url",
    "published_at",
]
# Batch prompts also see the story each article belongs to: the batch is folded
# to one article per story before it reaches the model (see
# _fold_batch_by_thread), and these carry what was folded away.
BATCH_ENTRY_FIELDS: list[str] = [
    *PER_ENTRY_FIELDS,
    "feed_title",
    "thread_title",
    "outlet_count",
    "also_reported_by",
]

_FIELD_DESCRIPTIONS: dict[str, str] = {
    "id": "Entry UUID",
    "title": "Article title",
    "content_text": "Plain-text article body",
    "content_html": "Sanitized HTML article body",
    "summary": "Existing short summary, if any",
    "author": "Article author",
    "url": "Canonical (external) article URL",
    "app_url": "In-app reader deep link (absolute if PUBLIC_BASE_URL is set)",
    "published_at": "Publication timestamp (string)",
    "feed_title": "Source feed name",
    "thread_title": "Name of the unfolding story this article belongs to (empty if none)",
    "outlet_count": "Independent outlets covering that story",
    "also_reported_by": "Articles in this batch folded into this one as the same story",
}


def _entry_field_vars(fields: list[str]) -> list[dict]:
    # Display the actual Jinja accessor (`entry.title`), while the bare field
    # names above drive runtime injection.
    return [{"name": f"entry.{f}", "description": _FIELD_DESCRIPTIONS.get(f, "")} for f in fields]


def ai_prompt_variable_contexts() -> dict:
    """Variables available to a Run AI Task prompt, keyed by execution mode."""
    return {
        "per_entry": {
            "label": "Per-entry",
            "note": ("The prompt runs once per matching entry. Reference entry.* fields directly."),
            "groups": [
                {"group": "entry", "variables": _entry_field_vars(PER_ENTRY_FIELDS)},
            ],
        },
        "batch": {
            "label": "Batch",
            "note": (
                "The prompt runs once over all matching entries. Note: "
                "date_label / scope_label are NOT injected by automation — "
                "they exist only in the feed-UI daily summary."
            ),
            "groups": [
                {
                    "group": "batch",
                    "variables": [
                        {
                            "name": "entries",
                            "description": "List of all matching entries — loop with {% for entry in entries %}",
                        },
                        {
                            "name": "entry_count",
                            "description": "Number of entries in the batch (one per story once folded)",
                        },
                        {
                            "name": "article_count",
                            "description": "Articles the batch held before same-story folding",
                        },
                    ],
                },
                {
                    "group": "entry (each item / first-entry alias)",
                    "variables": _entry_field_vars(BATCH_ENTRY_FIELDS),
                },
            ],
        },
    }


# --- Notification/template variables (single-brace { }) ---------------------

# Consumed by `_render_template` for send_notification / run_webhook /
# create_note / create_intel_report message and payload templates.
NOTIFICATION_TEMPLATE_FIELDS: list[str] = [
    "title",
    "url",
    "author",
    "summary",
    "published_at",
    "ai_summary",
    "feed_name",
]

_NOTIFICATION_DESCRIPTIONS: dict[str, str] = {
    "title": "Entry title",
    "url": "Entry URL",
    "author": "Entry author",
    "summary": "Entry summary (truncated)",
    "published_at": "Publication timestamp",
    "ai_summary": "Output of a preceding Run AI Task or Use Daily Summary action (briefing/summary)",
    "feed_name": "Source feed name",
}


def notification_template_variables() -> list[dict]:
    """Variables available to single-brace ({ }) notification/webhook templates."""
    return [{"name": f, "description": _NOTIFICATION_DESCRIPTIONS.get(f, "")} for f in NOTIFICATION_TEMPLATE_FIELDS]
