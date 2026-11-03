"""Provider/task tool-capability model.

Some AI tasks are agentic: they only produce their effect by calling tools.
Assigning one to a provider with no tool path silently produces tool-less
output — worst case the entity merge task reports merges that were never
applied.

This module is the single source of truth for both sides of that contract.
It must stay free of app.* imports so ORM models, API routers, and workers
can all import it without cycles.
"""

# Tasks that cannot function without tool execution. Tasks whose tools are
# optional verification aids (e.g. actor_profile_refresh) are deliberately
# excluded — they degrade acceptably on a tool-less provider.
TOOL_REQUIRED_TASKS: frozenset[str] = frozenset(
    {
        "copilot",
        "entity_enrichment_research",
    }
)

# Provider types whose runtime can execute tool calls against the backend tool
# registry. The Claude Code CLI is a full agent harness (IntelFeed tools over
# MCP). The others run an in-process function-calling loop (``stream_agent``
# with an injected tool executor): Ollama's ``/api/chat``, the Anthropic
# Messages API, and ``/v1/chat/completions`` for OpenAI-compatible servers.
TOOL_CAPABLE_PROVIDER_TYPES: frozenset[str] = frozenset({"claude_code", "ollama", "claude", "openai_compatible"})

# Types whose tool calling a provider row can switch off with
# ``config.tools_enabled = false``: OpenAI-compatible servers range from OpenAI
# itself to local servers that handle tools badly or not at all.
TOOLS_TOGGLEABLE_PROVIDER_TYPES: frozenset[str] = frozenset({"openai_compatible"})


def task_requires_tools(task_name: str | None) -> bool:
    return task_name in TOOL_REQUIRED_TASKS


def provider_type_supports_tools(provider_type: str | None, config: dict | None = None) -> bool:
    """Whether a provider (its type, and for some types its row config) runs tools."""
    if provider_type not in TOOL_CAPABLE_PROVIDER_TYPES:
        return False
    if provider_type in TOOLS_TOGGLEABLE_PROVIDER_TYPES and (config or {}).get("tools_enabled") is False:
        return False
    return True


# Tasks a person's own AI key may answer. One test decides membership: does
# the result belong to the person who clicked? Copilot turns, rule drafts,
# summaries and reports do. Entity links, adjudication verdicts, briefs and
# story spines are read by everyone and stay on the instance's providers,
# whoever started them. The migration that added ai_tasks.allows_user_provider
# seeded the flag from this set; the startup seeder applies it to tasks it
# creates later; the admin can turn it off per task, and on for custom tasks,
# but can't open a task outside this set.
USER_PROVIDER_ELIGIBLE_TASKS: frozenset[str] = frozenset(
    {
        "copilot",
        "detection_rules",
        "article_summary",
        "threat_assessment",
        "intelligence_briefing",
        "detection_engineering_summary",
        "video_transcript_summary",
        "report_section",
        "report_section_exposure",
        "report_section_flash_alert",
        "report_section_actor_profile",
        "report_section_campaign_tracker",
        "report_section_landscape",
        "report_section_detection",
    }
)

# Provider types a person may register as their own. claude_code is never
# one: it runs a single CLI sign-in shared by the whole instance.
PERSONAL_PROVIDER_TYPES: frozenset[str] = frozenset({"claude", "ollama", "openai_compatible"})

# Provider types whose client falls back to the server's own localhost when
# the row has no address. A personal key of one of these must say where it
# points, or it would run on the instance's GPU under a personal key.
LOCALHOST_DEFAULT_TYPES: frozenset[str] = frozenset({"ollama", "openai_compatible"})
