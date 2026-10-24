"""Provider/task tool-capability model.

Some AI tasks are agentic: they only produce their effect by calling tools
(IntelFeed's read-only tools and web search on the Claude Code CLI). Providers
that run a single-shot chat completion (Ollama, Anthropic API) have no tool
execution path, so assigning an agentic task to them silently produces
tool-less output — worst case the entity merge task reports merges that were
never applied.

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

# Provider types whose runtime can execute tool calls. The Claude Code CLI is a
# full agent harness; Ollama runs a native ``/api/chat`` function-calling loop
# (OllamaProvider.stream_agent / complete with an injected in-process
# tool_executor) against the backend tool registry.
#
# ``openai_compatible`` is deliberately NOT here yet: local OpenAI-compatible
# servers (LM Studio, llama.cpp, vLLM) vary too much in tool-calling quality
# for a blanket type-level capability. Tool support for it is tracked as a
# follow-up behind a per-provider config opt-in, not a type-level flag.
TOOL_CAPABLE_PROVIDER_TYPES: frozenset[str] = frozenset({"claude_code", "ollama"})


def task_requires_tools(task_name: str | None) -> bool:
    return task_name in TOOL_REQUIRED_TASKS


def provider_type_supports_tools(provider_type: str | None) -> bool:
    return provider_type in TOOL_CAPABLE_PROVIDER_TYPES


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
