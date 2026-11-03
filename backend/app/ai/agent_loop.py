"""Pieces shared by the in-process tool loops (Anthropic API, OpenAI-compatible).

Each provider's ``stream_agent`` speaks its own wire format but yields the same
events, so the copilot handles every provider with one loop:

  {"kind": "text", "text": <str>}
  {"kind": "tool_call", "id", "name", "args"}
  {"kind": "tool_result", "id", "status", "summary"}
  {"kind": "done", "usage": {tokens_input, tokens_output, total_cost_usd}}

``complete_with_agent`` collapses a ``stream_agent`` run into an AIResponse
for engine tasks, re-asking for schema-valid JSON at the end when the task
has an output schema.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from app.ai.providers.base import AIResponse

ToolExecutor = Callable[[str, dict], Awaitable[str]]

# Hard cap on tool round-trips per turn: a model that keeps calling tools
# without answering must not loop forever.
DEFAULT_MAX_TOOL_ITERATIONS = 8

# Cap on one tool result fed back to the model, so a huge payload can't crowd
# out the system prompt and the question.
TOOL_RESULT_MAX_CHARS = 30_000


def clip_tool_result(text: str) -> str:
    if len(text) <= TOOL_RESULT_MAX_CHARS:
        return text
    return (
        text[:TOOL_RESULT_MAX_CHARS] + f"... [truncated {len(text) - TOOL_RESULT_MAX_CHARS} chars"
        " — narrow the query (lower limit, tighter filters) for full results]"
    )


def summarize_result(result: str) -> str:
    return " ".join(str(result).split())[:200]


async def run_tool(executor: ToolExecutor, name: str, args: dict) -> tuple[str, str]:
    """Run one call; returns (status, result text). A failure goes back to the model."""
    try:
        result = await executor(name, args)
    except Exception as e:  # noqa: BLE001 — surface tool failure to the model
        return "error", json.dumps({"error": str(e)})
    status = "error" if str(result).startswith('{"error"') else "success"
    return status, str(result)


def coerce_args(raw: object) -> dict:
    """Tool-call arguments: usually a dict or a JSON string; anything else is empty."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


async def complete_with_agent(
    provider,
    *,
    prompt: str,
    system: str | None,
    model: str | None,
    tools: list[dict],
    tool_executor: ToolExecutor,
    temperature: float,
    max_tokens: int,
    timeout_seconds: float | None,
    response_format: dict | None,
) -> AIResponse:
    """Run a tool loop to its answer; with a schema, re-express it as JSON."""
    import time

    start = time.monotonic()
    parts: list[str] = []
    findings: list[str] = []
    usage: dict = {}
    calls: dict[str, str] = {}
    async for ev in provider.stream_agent(
        prompt=prompt,
        system=system,
        model=model,
        tools=tools,
        tool_executor=_recording(tool_executor, findings),
        temperature=temperature,
        max_tokens=max_tokens,
        timeout_seconds=timeout_seconds,
    ):
        kind = ev.get("kind")
        if kind == "text":
            parts.append(ev.get("text") or "")
        elif kind == "tool_call":
            calls[ev.get("id") or ""] = ev.get("name") or ""
        elif kind == "done":
            usage = ev.get("usage") or {}
    content = "".join(parts).strip()
    tokens_input = int(usage.get("tokens_input") or 0)
    tokens_output = int(usage.get("tokens_output") or 0)
    cost = usage.get("total_cost_usd")
    resolved_model = model or ""

    if response_format is not None:
        # Structured output and tool calling don't mix on every API, so the
        # loop runs free and one last constrained call restates its answer.
        evidence = "\n\n".join(findings)[-60_000:]
        final_prompt = (
            f"{prompt}\n\n## What your tool calls returned\n{evidence or '(no tool calls)'}"
            f"\n\n## Your answer so far\n{content or '(none)'}\n\n"
            "Now produce your final answer as a single JSON object matching the required schema, "
            "based on the above."
        )
        final = await provider.complete(
            prompt=final_prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            model=model,
            timeout_seconds=timeout_seconds,
        )
        content = final.content or content
        tokens_input += final.tokens_input
        tokens_output += final.tokens_output
        resolved_model = final.model or resolved_model
        if cost is not None or final.cost_usd is not None:
            cost = (cost or 0.0) + (final.cost_usd or 0.0)

    return AIResponse(
        content=content,
        raw_response={"model": resolved_model, "usage": usage, "tool_calls": list(calls.values())},
        tokens_input=tokens_input,
        tokens_output=tokens_output,
        model=resolved_model,
        latency_ms=int((time.monotonic() - start) * 1000),
        cost_usd=cost,
    )


def _recording(executor: ToolExecutor, findings: list[str]) -> ToolExecutor:
    async def _run(name: str, args: dict) -> str:
        result = await executor(name, args)
        findings.append(f"### {name}({json.dumps(args, default=str)[:300]})\n{clip_tool_result(str(result))[:8000]}")
        return result

    return _run
