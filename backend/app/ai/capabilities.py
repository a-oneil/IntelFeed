"""Provider/task tool-capability model.

Some AI tasks are agentic: they only produce their effect by calling tools
(the Claude Code CLI's Bash/Read/Skill/WebFetch/WebSearch surface). Providers
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
