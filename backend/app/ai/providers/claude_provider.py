"""Anthropic Claude API provider.

Uses the official ``anthropic`` Python SDK (``AsyncAnthropic``) with:

* Dual auth: ``sk-ant-api03-*`` (API-key billing) and ``sk-ant-oat01-*``
  (OAuth subscription / Agent SDK credit pool, launches June 15, 2026).
  Selected by token prefix; unknown prefixes default to API-key billing
  for forwards compatibility.
* Prompt caching: when a ``system`` prompt is supplied to ``complete()`` it
  is sent as a text block with ``cache_control={"type": "ephemeral"}`` —
  subsequent calls within the 5-minute TTL are billed at ~10% of the input
  rate. This is the highest-leverage feature for the link-validator
  workload (~22k entries sharing one ~3 KB system prompt).
* Typed error mapping: ``anthropic.RateLimitError`` is converted to
  :class:`app.ai.providers.claude_code_provider.QuotaExhaustedError` so
  ``engine.run_task`` auto-pauses the provider via the same code path the
  CLI provider uses. Other SDK errors propagate.
* Structured output: when ``response_format`` (a JSON schema dict) is
  passed, it is forwarded to the SDK as
  ``output_config={"format": {"type": "json_schema", "schema": ...}}``.

* Tools: ``stream_agent`` runs the Messages API tool-use loop with an
  injected executor (the copilot passes app.tools.gate.ToolGate), and
  ``complete(tools=..., tool_executor=...)`` collapses that loop for agentic
  engine tasks. The tool list is cached along with the system prompt.

Cache hit/miss token counts are surfaced via ``AIResponse.raw_response``
under the keys ``cache_read_input_tokens`` and
``cache_creation_input_tokens`` for downstream observability without
broadening the :class:`AIResponse` schema.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncGenerator
from typing import ClassVar

import anthropic
from anthropic import AsyncAnthropic, DefaultAsyncHttpxClient

from app.ai.agent_loop import (
    DEFAULT_MAX_TOOL_ITERATIONS,
    ToolExecutor,
    clip_tool_result,
    complete_with_agent,
    run_tool,
    summarize_result,
)
from app.ai.providers.base import AIProvider, AIResponse
from app.ai.providers.claude_code_provider import QuotaExhaustedError
from app.ai.providers.schema_utils import enforce_no_additional_properties as _enforce_no_additional_properties

logger = logging.getLogger(__name__)

OAUTH_BETA_HEADER = "oauth-2025-04-20"
OAUTH_TOKEN_PREFIX = "sk-ant-oat"


def _parse_retry_after(headers: object) -> None:
    """Reserved hook for future retry-after parsing.

    Today we return ``None`` — the engine defaults to a +1 hour pause when
    ``reset_at`` is ``None``. We intentionally don't try to parse the
    ``retry-after`` header here because (a) the SDK exposes it on the
    response object in different shapes across versions, and (b) a wrong
    parse leaks into the auto-pause window. Conservative: hand back None
    and let the engine apply its default backoff.
    """
    return None


class ClaudeProvider(AIProvider):
    """Anthropic Claude API via the official Python SDK."""

    # Must agree with capabilities.TOOL_CAPABLE_PROVIDER_TYPES.
    supports_tools: ClassVar[bool] = True

    def render_tools(self, defs: list[dict]) -> list[dict]:
        from app.tools.gate import anthropic_specs

        return anthropic_specs(defs)

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        config: dict | None = None,
    ):
        super().__init__(base_url=base_url, api_key=api_key, config=config)
        self.timeout: float = float(self.config.get("timeout_seconds", 120))
        self._client: AsyncAnthropic | None = None

    # ---------------------------------------------------------------- helpers

    def _build_client(self) -> AsyncAnthropic:
        """Lazily build (and cache) the SDK client with the right auth.

        ``sk-ant-oat01-*`` tokens are OAuth subscription tokens (Agent SDK
        credit pool, June 15 2026 launch) and require ``auth_token=`` plus
        the ``anthropic-beta: oauth-2025-04-20`` header. Anything else
        defaults to API-key auth.
        """
        if self._client is not None:
            return self._client

        kwargs: dict = {"timeout": self.timeout}
        if self.config.get("follow_redirects") is False:
            # A personal key's base_url was vetted as public; a 307 could lead
            # the SDK's default client past that host to an internal address,
            # so the engine turns redirects off for those rows (see
            # _get_provider_instance). The instance's own provider keeps the
            # SDK default, since a gateway it points at may legitimately redirect.
            kwargs["http_client"] = DefaultAsyncHttpxClient(follow_redirects=False)
        if self.base_url:
            kwargs["base_url"] = self.base_url

        token = self.api_key or ""
        if token.startswith(OAUTH_TOKEN_PREFIX):
            kwargs["auth_token"] = token
            kwargs["default_headers"] = {"anthropic-beta": OAUTH_BETA_HEADER}
        else:
            # Forwards-compat default: treat anything else as an API key.
            # AsyncAnthropic accepts api_key=None and will read from
            # ANTHROPIC_API_KEY env, which preserves existing behavior for
            # provider rows that haven't had a key configured yet.
            kwargs["api_key"] = token or None

        self._client = AsyncAnthropic(**kwargs)
        return self._client

    @staticmethod
    def _build_system(system: str | None) -> list[dict] | None:
        """Wrap the system prompt as a cacheable text block.

        Returning ``None`` (rather than ``[]``) lets the caller omit the
        ``system`` kwarg entirely — the SDK rejects empty system blocks.
        """
        if not system:
            return None
        return [
            {
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    @staticmethod
    def _enforce_no_additional_properties(schema: dict) -> dict:
        """Recursively set ``additionalProperties: false`` on every object node.

        Anthropic's structured-output API rejects schemas where an ``object``
        node doesn't explicitly forbid additional properties. Thin wrapper
        over the shared helper in ``schema_utils`` kept for backward-compat
        call sites.
        """
        return _enforce_no_additional_properties(schema)

    @classmethod
    def _build_output_config(cls, response_format: dict | None) -> dict | None:
        """Build the JSON-schema-constrained output config, if requested."""
        if not response_format:
            return None
        return {
            "format": {
                "type": "json_schema",
                "schema": cls._enforce_no_additional_properties(response_format),
            }
        }

    # ---------------------------------------------------------------- API

    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format: dict | None = None,
        model: str = "claude-sonnet-4-6",
        timeout_seconds: float | None = None,
        heartbeat_label: str | None = None,
        tools: list[dict] | None = None,
        tool_executor: ToolExecutor | None = None,
    ) -> AIResponse:
        if tools and tool_executor is not None:
            # An agentic task: run the tool loop instead of answering blind.
            return await complete_with_agent(
                self,
                prompt=prompt,
                system=system,
                model=model,
                tools=tools,
                tool_executor=tool_executor,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout_seconds=timeout_seconds,
                response_format=response_format,
            )
        # timeout_seconds / heartbeat_label are claude_code-provider specific
        # (subprocess wait). Accepted here for interface compatibility, ignored
        # — the anthropic SDK applies its own per-request timeout.
        # temperature is gone from the current models (and from the SDK's
        # messages.create signature since 1.0); accepted, never sent.
        del timeout_seconds, heartbeat_label, temperature
        client = self._build_client()
        kwargs: dict = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

        system_blocks = self._build_system(system)
        if system_blocks is not None:
            kwargs["system"] = system_blocks

        output_config = self._build_output_config(response_format)
        if output_config is not None:
            kwargs["output_config"] = output_config

        start = time.monotonic()
        try:
            message = await client.messages.create(**kwargs)
        except anthropic.RateLimitError as e:
            # Engine catches QuotaExhaustedError and auto-pauses the provider.
            # reset_at=None → engine applies its +1hr default backoff.
            headers = e.response.headers if e.response else None
            raise QuotaExhaustedError(str(e)[:500], reset_at=_parse_retry_after(headers))
        except anthropic.APIStatusError:
            # 5xx → Celery retry policy picks it up. 4xx → engine.run_task's
            # generic except logs it as a provider_error. Either way, propagate.
            raise
        # Other anthropic.APIError subclasses (APIConnectionError,
        # APITimeoutError, etc.) propagate as-is — Celery retries handle
        # them at the task level.

        latency_ms = int((time.monotonic() - start) * 1000)

        # Concatenate all text blocks (Claude usually returns one but the
        # API contract is a list).
        content_parts: list[str] = []
        for block in message.content:
            text = getattr(block, "text", None)
            if text:
                content_parts.append(text)
        content = "".join(content_parts)

        usage = message.usage
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0

        # raw_response carries cache stats for downstream observability
        # (engine.py logs/stores raw_response; we don't widen AIResponse).
        raw_response = {
            "id": message.id,
            "model": message.model,
            "stop_reason": message.stop_reason,
            "usage": {
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": cache_creation,
            },
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_creation,
        }

        return AIResponse(
            content=content,
            raw_response=raw_response,
            tokens_input=usage.input_tokens,
            tokens_output=usage.output_tokens,
            model=message.model,
            latency_ms=latency_ms,
        )

    async def stream_complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        model: str = "claude-sonnet-4-6",
    ):
        """Yield text chunks via the SDK's streaming helper."""
        # temperature accepted for interface compatibility only — see complete().
        del temperature
        client = self._build_client()
        kwargs: dict = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        system_blocks = self._build_system(system)
        if system_blocks is not None:
            kwargs["system"] = system_blocks

        self.last_stream_usage = None
        try:
            async with client.messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    yield text
                final = await stream.get_final_message()
                self.last_stream_usage = {
                    "tokens_input": final.usage.input_tokens,
                    "tokens_output": final.usage.output_tokens,
                    "cost_usd": None,
                }
        except anthropic.RateLimitError as e:
            headers = e.response.headers if e.response else None
            raise QuotaExhaustedError(str(e)[:500], reset_at=_parse_retry_after(headers))

    @staticmethod
    def _cached_tools(tools: list[dict]) -> list[dict]:
        """Mark the last tool cacheable: the tool list rarely changes between turns."""
        if not tools:
            return tools
        return [*tools[:-1], {**tools[-1], "cache_control": {"type": "ephemeral"}}]

    @staticmethod
    def _assistant_blocks(message) -> list[dict]:
        """The reply's text and tool_use blocks, replayed as the next request's assistant turn."""
        blocks: list[dict] = []
        for block in message.content:
            btype = getattr(block, "type", None)
            if btype == "text" and block.text:
                blocks.append({"type": "text", "text": block.text})
            elif btype == "tool_use":
                blocks.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input or {}})
        return blocks

    async def stream_agent(
        self,
        prompt: str,
        system: str | None = None,
        model: str | None = None,
        tools: list[dict] | None = None,
        tool_executor: ToolExecutor | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        timeout_seconds: float | None = None,
        heartbeat_label: str | None = None,
    ) -> AsyncGenerator[dict, None]:
        """Run one agent turn over the Messages API, yielding typed events.

        Text streams as it arrives; each ``tool_use`` block is run through
        ``tool_executor`` and its result sent back, until the model answers
        without calling a tool or the iteration cap is hit. Event shapes are
        the ones in app.ai.agent_loop. Cost is left to the engine's token
        table (``total_cost_usd`` None).
        """
        del temperature, heartbeat_label
        client = self._build_client()
        if timeout_seconds:
            client = client.with_options(timeout=timeout_seconds)
        model = model or "claude-sonnet-4-6"
        max_iterations = int(self.config.get("max_tool_iterations", DEFAULT_MAX_TOOL_ITERATIONS))
        messages: list[dict] = [{"role": "user", "content": prompt}]
        kwargs: dict = {"model": model, "max_tokens": max_tokens}
        system_blocks = self._build_system(system)
        if system_blocks is not None:
            kwargs["system"] = system_blocks
        if tools and tool_executor is not None:
            kwargs["tools"] = self._cached_tools(tools)

        tokens_input = 0
        tokens_output = 0

        def _done() -> dict:
            return {
                "kind": "done",
                "usage": {"tokens_input": tokens_input, "tokens_output": tokens_output, "total_cost_usd": None},
            }

        for _ in range(max_iterations):
            emitted_text = False
            try:
                async with client.messages.stream(messages=messages, **kwargs) as stream:
                    async for text in stream.text_stream:
                        if text:
                            emitted_text = True
                            yield {"kind": "text", "text": text}
                    final = await stream.get_final_message()
            except anthropic.RateLimitError as e:
                headers = e.response.headers if e.response else None
                raise QuotaExhaustedError(str(e)[:500], reset_at=_parse_retry_after(headers))

            usage = final.usage
            # Cached input is still input: a dollar cap must see it.
            tokens_input += (
                (usage.input_tokens or 0)
                + (getattr(usage, "cache_read_input_tokens", 0) or 0)
                + (getattr(usage, "cache_creation_input_tokens", 0) or 0)
            )
            tokens_output += usage.output_tokens or 0

            tool_uses = [b for b in final.content if getattr(b, "type", None) == "tool_use"]
            if final.stop_reason != "tool_use" or not tool_uses or tool_executor is None:
                if final.stop_reason == "max_tokens":
                    yield {"kind": "text", "text": "\n\n_[answer truncated — model hit its output limit]_"}
                yield _done()
                return

            if emitted_text:
                yield {"kind": "text", "text": "\n\n"}
            messages.append({"role": "assistant", "content": self._assistant_blocks(final)})
            results: list[dict] = []
            for block in tool_uses:
                args = block.input if isinstance(block.input, dict) else {}
                yield {"kind": "tool_call", "id": block.id, "name": block.name, "args": args}
                status, result = await run_tool(tool_executor, block.name, args)
                yield {"kind": "tool_result", "id": block.id, "status": status, "summary": summarize_result(result)}
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": clip_tool_result(result),
                        "is_error": status == "error",
                    }
                )
            messages.append({"role": "user", "content": results})

        logger.warning("claude agent loop hit max_iterations=%d without a final answer", max_iterations)
        yield _done()

    async def check_health(self) -> bool:
        if not self.api_key:
            return False
        try:
            client = self._build_client()
            await client.with_options(timeout=15).messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
            return True
        except Exception as e:  # noqa: BLE001 — health probe is best-effort
            logger.warning("claude provider health check failed: %s", e)
            return False

    async def list_models(self) -> list[str]:
        # Claude has no models-list endpoint — return the curated set the
        # AI Configuration UI dropdown expects. Keep in sync with
        # COST_TABLE in app/ai/engine.py.
        return [
            "claude-opus-4-6",
            "claude-sonnet-4-6",
            "claude-haiku-4-5-20251001",
        ]
