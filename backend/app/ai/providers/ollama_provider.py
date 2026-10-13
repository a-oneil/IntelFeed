"""Ollama provider — self-hosted models via the Ollama HTTP API.

Talks to an Ollama server (local or remote, e.g. behind a reverse proxy)
using the native ``/api/chat`` endpoint:

* Structured output: when ``response_format`` (a JSON schema dict) is
  passed, it is forwarded as Ollama's ``format`` field, which constrains
  generation to the schema (supported since Ollama 0.5).
* Auth: Ollama itself is unauthenticated, but proxied instances often
  gate access with a bearer token — when an ``api_key`` is configured it
  is sent as ``Authorization: Bearer <key>``.
* 429 responses (from a proxy or an overloaded server) are mapped to
  :class:`QuotaExhaustedError` so ``engine.run_task`` auto-pauses the
  provider via the same code path the Claude providers use.
* ``cost_usd`` is reported as ``0.0`` (not ``None``) so the engine
  records zero cost instead of falling back to its token-table estimate.

Config keys (``ai_providers.config`` / assignment config):

* ``timeout_seconds`` — per-request timeout (default 300; local models
  can be slow, especially on cold load).
* ``keep_alive`` — forwarded to Ollama verbatim (e.g. ``"30m"`` keeps
  the model resident between calls; unset uses the server default).
* ``num_ctx`` — FIXED context window forwarded via ``options``; disables
  auto-sizing. Without it the provider estimates the prompt's token count
  and requests a window that fits (min 4096, capped by ``num_ctx_max``,
  default 32768). This matters: Ollama's server default is 4096 and it
  SILENTLY truncates oversized prompts from the front — long articles
  vanish and the model answers from whatever tail survives.
* ``num_ctx_max`` — cap for auto-sizing (default 32768). Raise for
  long-context models with RAM to spare; prompts beyond the cap still
  truncate (a warning is logged).
* ``model_overrides`` — per-model config map layered over the keys above
  at request time, keyed by exact model name (as passed on the task
  assignment). E.g. ``{"qwen3.5:9b": {"think": true, "num_ctx_max":
  65536}}``. Edited via the provider card's Configure panel in
  Settings → AI Configuration.
* ``think`` — default ``False``: thinking is explicitly disabled per
  request. Reasoning models (qwen3.5, deepseek-r1) otherwise burn the
  whole ``num_predict`` budget on chain-of-thought for long prompts and
  return an EMPTY ``content`` (surfaced as blank AI results). Set
  ``true`` to re-enable if a task benefits and the budget allows.
* ``min_temperature`` — floor applied to the engine's temperature
  (default 0.2). The engine defaults extraction tasks to 0.0, but greedy
  decoding under a grammar constraint sends local models into repetition
  loops: qwen3.5:9b emitted the SAME technique_id 182 times across 16k
  tokens on an entry_analysis prompt, never closing the JSON, where the
  identical prompt at 0.2 finished cleanly in 1138 tokens. Sending an
  explicit ``temperature`` also overrides the model's own Modelfile
  sampling defaults (qwen3.5 ships temperature 1 + presence_penalty 1.5
  precisely to suppress this), so the floor restores a safe margin.
  Set ``0`` to opt out per provider or per model via ``model_overrides``.

Structured-output hardening: every object node in the forwarded schema
gets ``required`` filled with all of its properties (preserving any
explicit ``required``). With thinking off, Ollama's grammar-constrained
decoding otherwise accepts the degenerate-but-valid ``{}``.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import ClassVar

import httpx

from app.ai.providers.base import AIProvider, AIResponse
from app.ai.providers.claude_code_provider import QuotaExhaustedError
from app.ai.providers.schema_utils import enforce_required as _enforce_required_schema

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://localhost:11434"

# Type of the injected in-process tool dispatcher: (tool_name, args) -> JSON str.
# The caller (copilot endpoint / engine) builds this as a closure over the
# request's db session + user id so the provider never imports app models.
ToolExecutor = Callable[[str, dict], Awaitable[str]]

# Hard cap on tool round-trips per agent turn — a runaway model that keeps
# calling tools without answering is bounded here. Override via provider config
# ``max_tool_iterations``.
_DEFAULT_MAX_TOOL_ITERATIONS = 8

# Cap on a single tool result fed back into the conversation. Ollama truncates
# an over-long context from the FRONT, so an unbounded tool result (e.g. a huge
# search payload) would silently evict the system prompt and question. ~30k
# chars ≈ 10k tokens at our 3-chars/token estimate.
_TOOL_RESULT_MAX_CHARS = 30_000


async def _noop_tool_executor(name: str, args: dict) -> str:
    """Fallback executor when tools are declared but no dispatcher is injected."""
    return json.dumps({"error": f"No tool executor configured; cannot run '{name}'"})


class OllamaProvider(AIProvider):
    """Ollama HTTP API (``/api/chat``, ``/api/tags``, ``/api/version``)."""

    # Native ``/api/chat`` function calling: when a ``tools`` spec + a
    # ``tool_executor`` are supplied, ``complete()``/``stream_agent()`` run an
    # in-process tool loop. Must agree with capabilities.TOOL_CAPABLE_PROVIDER_TYPES.
    supports_tools: ClassVar[bool] = True

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        config: dict | None = None,
    ):
        super().__init__(base_url=base_url, api_key=api_key, config=config)
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout: float = float(self.config.get("timeout_seconds", 300))

    # ---------------------------------------------------------------- helpers

    def _headers(self) -> dict[str, str]:
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

    def _resolve_model(self, model: str | None) -> str:
        resolved = model or self.config.get("default_model")
        if not resolved:
            raise ValueError("Ollama provider requires a model name (set one on the task assignment)")
        return resolved

    def _model_config(self, resolved_model: str) -> dict:
        """Provider config with this model's ``model_overrides`` entry layered on top."""
        overrides = (self.config.get("model_overrides") or {}).get(resolved_model) or {}
        return {**self.config, **overrides}

    @staticmethod
    def _enforce_required(schema: dict) -> dict:
        """Recursively require every declared property on object nodes.

        Explicit ``required`` lists are preserved. Thin wrapper over the
        shared helper in ``schema_utils`` (also used by the OpenAI-compatible
        provider) kept for backward-compat call sites.
        """
        return _enforce_required_schema(schema)

    @staticmethod
    def _effective_temperature(cfg: dict, temperature: float) -> float:
        """Apply the ``min_temperature`` floor (see module docstring).

        Greedy decoding (0.0) under grammar-constrained JSON drives local
        models into repetition loops that never emit the closing brace.
        """
        floor = float(cfg.get("min_temperature", 0.2))
        return max(float(temperature), floor)

    def _build_payload(
        self,
        prompt: str,
        system: str | None,
        temperature: float,
        max_tokens: int,
        response_format: dict | None,
        model: str | None,
        stream: bool,
    ) -> dict:
        resolved_model = self._resolve_model(model)
        cfg = self._model_config(resolved_model)

        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        options: dict = {
            "temperature": self._effective_temperature(cfg, temperature),
            "num_predict": max_tokens,
        }
        if cfg.get("num_ctx"):
            options["num_ctx"] = int(cfg["num_ctx"])
        else:
            # Auto-size the context window. ~3 chars/token deliberately
            # overestimates (English runs ~4) so the margin absorbs tokenizer
            # variance and chat-template overhead.
            est_prompt_tokens = (len(prompt) + len(system or "")) // 3 + 256
            needed = est_prompt_tokens + max_tokens
            cap = int(cfg.get("num_ctx_max", 32768))
            options["num_ctx"] = min(max(4096, needed), cap)
            if needed > cap:
                logger.warning(
                    "ollama prompt (~%d tokens + %d output) exceeds num_ctx_max=%d — "
                    "Ollama will silently truncate the prompt from the front",
                    est_prompt_tokens,
                    max_tokens,
                    cap,
                )

        payload: dict = {
            "model": resolved_model,
            "messages": messages,
            "stream": stream,
            "think": bool(cfg.get("think", False)),
            "options": options,
        }
        if response_format:
            payload["format"] = self._enforce_required(response_format)
        if cfg.get("keep_alive") is not None:
            payload["keep_alive"] = cfg["keep_alive"]
        return payload

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.status_code == 429:
            raise QuotaExhaustedError(f"Ollama returned 429: {resp.text[:400]}")
        resp.raise_for_status()

    # ---------------------------------------------------------------- API

    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format: dict | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        heartbeat_label: str | None = None,
        tools: list[dict] | None = None,
        tool_executor: ToolExecutor | None = None,
    ) -> AIResponse:
        del heartbeat_label  # subprocess-provider concept; not applicable

        # Agentic path: with a tool spec + an in-process dispatcher, run the tool
        # loop and return the final text. Used by engine.run_task for agentic
        # tasks (entity_merge_maintenance etc.) so Ollama genuinely executes
        # tools instead of silently producing tool-less output.
        if tools and tool_executor is not None:
            return await self._complete_with_tools(
                prompt,
                system,
                temperature,
                max_tokens,
                model,
                timeout_seconds,
                tools,
                tool_executor,
                response_format=response_format,
            )

        payload = self._build_payload(prompt, system, temperature, max_tokens, response_format, model, stream=False)
        cfg = self._model_config(payload["model"])
        timeout = timeout_seconds or float(cfg.get("timeout_seconds", 300))

        start = time.monotonic()
        async with httpx.AsyncClient(timeout=timeout, headers=self._headers()) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            if resp.status_code == 400 and "think" in payload and "think" in resp.text.lower():
                # Older servers / some models reject the think toggle — retry without.
                payload.pop("think")
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            self._raise_for_status(resp)
            data = resp.json()
        latency_ms = int((time.monotonic() - start) * 1000)

        content = (data.get("message") or {}).get("content") or ""
        return AIResponse(
            content=content,
            raw_response={
                "model": data.get("model"),
                "done_reason": data.get("done_reason"),
                "total_duration": data.get("total_duration"),
                "prompt_eval_count": data.get("prompt_eval_count"),
                "eval_count": data.get("eval_count"),
            },
            tokens_input=data.get("prompt_eval_count") or 0,
            tokens_output=data.get("eval_count") or 0,
            model=data.get("model") or payload["model"],
            latency_ms=latency_ms,
            cost_usd=0.0,  # self-hosted: no per-token cost
        )

    # ----------------------------------------------------------- agent / tools

    def _agent_options(self, cfg: dict, char_len: int, max_tokens: int, temperature: float = 0.0) -> dict:
        """Sizing ``options`` for an agent round, mirroring _build_payload's auto-ctx.

        The message history grows each round, so context is sized off the
        current concatenated length rather than a single prompt.
        """
        options: dict = {
            "temperature": self._effective_temperature(cfg, temperature),
            "num_predict": max_tokens,
        }
        if cfg.get("num_ctx"):
            options["num_ctx"] = int(cfg["num_ctx"])
            return options
        est_prompt_tokens = char_len // 3 + 256
        needed = est_prompt_tokens + max_tokens
        cap = int(cfg.get("num_ctx_max", 32768))
        options["num_ctx"] = min(max(4096, needed), cap)
        if needed > cap:
            logger.warning(
                "ollama agent context (~%d tokens + %d output) exceeds num_ctx_max=%d — "
                "history may be truncated from the front",
                est_prompt_tokens,
                max_tokens,
                cap,
            )
        return options

    @staticmethod
    def _coerce_args(raw: object) -> dict:
        """Ollama tool-call arguments are usually a dict; tolerate a JSON string."""
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}

    async def _agent_events(
        self,
        messages: list[dict],
        model: str,
        tools: list[dict],
        tool_executor: ToolExecutor,
        temperature: float,
        max_tokens: int,
        timeout: float,
        max_iterations: int,
    ) -> AsyncGenerator[dict, None]:
        """Drive the Ollama tool loop, yielding ClaudeCode-compatible events.

        Event shapes mirror ``ClaudeCodeProvider.stream_agent`` so the copilot
        endpoint's handling loop is identical across providers:
          {"kind": "text", "text": <str>}
          {"kind": "tool_call", "id", "name", "args"}
          {"kind": "tool_result", "id", "status", "summary"}
          {"kind": "done", "usage": {tokens_input, tokens_output, total_cost_usd}}

        v1: tool rounds run non-streamed; the final (no-tool-call) answer is
        emitted as a single text event. Cost is always 0.0 (self-hosted).
        """
        resolved_model = self._resolve_model(model)
        cfg = self._model_config(resolved_model)
        tokens_input = 0
        tokens_output = 0
        call_counter = 0
        # Dropped to None for the rest of the turn if the model rejects tools
        # (Ollama 400s with "... does not support tools") — the turn then
        # degrades to a plain text answer instead of erroring out.
        effective_tools: list[dict] | None = tools or None

        async with httpx.AsyncClient(timeout=timeout, headers=self._headers()) as client:
            for iteration in range(max_iterations):
                # Context sizing must count the tool schemas too — Ollama's chat
                # template renders them into the prompt (dozens of tools ≈
                # thousands of tokens). Undercounting makes generation hit
                # num_ctx mid-answer and stop silently.
                char_len = sum(len(str(m.get("content") or "")) for m in messages)
                if effective_tools:
                    char_len += len(json.dumps(effective_tools))
                payload = {
                    "model": resolved_model,
                    "messages": messages,
                    "stream": False,
                    "think": bool(cfg.get("think", False)),
                    "options": self._agent_options(cfg, char_len, max_tokens, temperature),
                }
                if effective_tools:
                    payload["tools"] = effective_tools
                if cfg.get("keep_alive") is not None:
                    payload["keep_alive"] = cfg["keep_alive"]

                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                if resp.status_code == 400 and "think" in payload and "think" in resp.text.lower():
                    payload.pop("think", None)
                    resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                if resp.status_code == 400 and effective_tools and "tool" in resp.text.lower():
                    # Model has no tool support — degrade to text-only for the
                    # whole turn rather than failing it.
                    logger.warning(
                        "ollama model %s rejected tools (%s); continuing without tool calling",
                        resolved_model,
                        resp.text[:200],
                    )
                    effective_tools = None
                    payload.pop("tools", None)
                    resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                self._raise_for_status(resp)
                data = resp.json()

                tokens_input += data.get("prompt_eval_count") or 0
                tokens_output += data.get("eval_count") or 0
                message = data.get("message") or {}
                tool_calls = message.get("tool_calls") or []
                content = message.get("content") or ""

                if not tool_calls:
                    # Final answer for this turn.
                    if content:
                        yield {"kind": "text", "text": content}
                    if data.get("done_reason") == "length":
                        # Generation stopped at the token/context ceiling — say
                        # so instead of ending mid-sentence with no explanation.
                        logger.warning(
                            "ollama agent answer truncated (done_reason=length, num_ctx=%s, num_predict=%s)",
                            payload["options"].get("num_ctx"),
                            payload["options"].get("num_predict"),
                        )
                        yield {"kind": "text", "text": "\n\n_[answer truncated — model hit its output limit]_"}
                    yield {
                        "kind": "done",
                        "usage": {
                            "tokens_input": tokens_input,
                            "tokens_output": tokens_output,
                            "total_cost_usd": 0.0,
                        },
                    }
                    return

                # Surface intermediate narration ("Let me search for that…") the
                # model emitted alongside its tool calls — the CLI provider
                # streams this too, and it keeps the trace readable.
                if content.strip():
                    yield {"kind": "text", "text": content.rstrip() + "\n\n"}

                # Record the assistant turn (with its tool_calls) then execute each.
                messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})
                for tc in tool_calls:
                    fn = tc.get("function") or {}
                    name = fn.get("name") or ""
                    args = self._coerce_args(fn.get("arguments"))
                    call_counter += 1
                    call_id = f"ollama-{iteration}-{call_counter}"
                    yield {"kind": "tool_call", "id": call_id, "name": name, "args": args}
                    try:
                        result = await tool_executor(name, args)
                        status = "success"
                    except Exception as e:  # noqa: BLE001 — surface tool failure to the model
                        result = json.dumps({"error": str(e)})
                        status = "error"
                    yield {
                        "kind": "tool_result",
                        "id": call_id,
                        "status": status,
                        "summary": " ".join(str(result).split())[:200],
                    }
                    # Feed the result back, capped so a huge payload can't evict
                    # the system prompt (Ollama truncates context from the FRONT).
                    # ``tool_name`` is honored by newer Ollama builds and harmless
                    # on older ones.
                    result_text = str(result)
                    if len(result_text) > _TOOL_RESULT_MAX_CHARS:
                        result_text = (
                            result_text[:_TOOL_RESULT_MAX_CHARS]
                            + f"... [truncated {len(result_text) - _TOOL_RESULT_MAX_CHARS} chars"
                            " — narrow the query (lower limit, tighter filters) for full results]"
                        )
                    messages.append({"role": "tool", "tool_name": name, "content": result_text})

        # Iteration budget exhausted without a final answer.
        logger.warning("ollama agent loop hit max_iterations=%d without a final answer", max_iterations)
        yield {
            "kind": "done",
            "usage": {
                "tokens_input": tokens_input,
                "tokens_output": tokens_output,
                "total_cost_usd": 0.0,
            },
        }

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
        history: list[dict] | None = None,
    ) -> AsyncGenerator[dict, None]:
        """Run one agent turn and yield typed streaming events (see _agent_events).

        ``history`` is an optional prior message list (role/content dicts) replayed
        before the current ``prompt``. Without ``tools``/``tool_executor`` this
        degrades to a single non-tool round (text-only).
        """
        del heartbeat_label
        cfg = self._model_config(self._resolve_model(model))
        timeout = timeout_seconds or float(cfg.get("timeout_seconds", 300))
        max_iterations = int(cfg.get("max_tool_iterations", _DEFAULT_MAX_TOOL_ITERATIONS))

        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        for m in history or []:
            role = m.get("role")
            if role in ("user", "assistant") and m.get("content"):
                messages.append({"role": role, "content": m["content"]})
        messages.append({"role": "user", "content": prompt})

        async for event in self._agent_events(
            messages,
            model or "",
            tools or [],
            tool_executor or _noop_tool_executor,
            temperature,
            max_tokens,
            timeout,
            max_iterations,
        ):
            yield event

    async def _complete_with_tools(
        self,
        prompt: str,
        system: str | None,
        temperature: float,
        max_tokens: int,
        model: str | None,
        timeout_seconds: float | None,
        tools: list[dict],
        tool_executor: ToolExecutor,
        response_format: dict | None = None,
    ) -> AIResponse:
        """Non-streaming agent turn: run the tool loop and collapse to an AIResponse.

        When ``response_format`` is set (engine tasks always pass their output
        schema), the tool loop runs UNCONSTRAINED — grammar-constrained decoding
        and tool calling don't mix — and a final ``format``-constrained round
        (no tools) then re-expresses the answer as schema-valid JSON over the
        full tool-informed conversation.
        """
        start = time.monotonic()
        resolved_model = self._resolve_model(model)
        cfg = self._model_config(resolved_model)
        timeout = timeout_seconds or float(cfg.get("timeout_seconds", 300))
        max_iterations = int(cfg.get("max_tool_iterations", _DEFAULT_MAX_TOOL_ITERATIONS))

        # Own the message list so the final constrained round (below) sees the
        # whole tool-informed conversation — _agent_events mutates it in place.
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        parts: list[str] = []
        usage: dict = {}
        async for event in self._agent_events(
            messages, model or "", tools, tool_executor, temperature, max_tokens, timeout, max_iterations
        ):
            if event.get("kind") == "text":
                parts.append(event.get("text") or "")
            elif event.get("kind") == "done":
                usage = event.get("usage") or {}
        content = "".join(parts)
        tokens_input = int(usage.get("tokens_input") or 0)
        tokens_output = int(usage.get("tokens_output") or 0)

        if response_format is not None:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Now produce your final answer as a single JSON object matching "
                        "the required schema. Base it on the conversation and tool results above. "
                        "Output only JSON."
                    ),
                }
            )
            char_len = sum(len(str(m.get("content") or "")) for m in messages)
            payload: dict = {
                "model": resolved_model,
                "messages": messages,
                "stream": False,
                "think": bool(cfg.get("think", False)),
                "format": self._enforce_required(response_format),
                "options": self._agent_options(cfg, char_len, max_tokens, temperature),
            }
            if cfg.get("keep_alive") is not None:
                payload["keep_alive"] = cfg["keep_alive"]
            async with httpx.AsyncClient(timeout=timeout, headers=self._headers()) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                if resp.status_code == 400 and "think" in payload and "think" in resp.text.lower():
                    payload.pop("think")
                    resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                self._raise_for_status(resp)
                data = resp.json()
            tokens_input += data.get("prompt_eval_count") or 0
            tokens_output += data.get("eval_count") or 0
            formatted = (data.get("message") or {}).get("content") or ""
            if formatted:
                content = formatted

        latency_ms = int((time.monotonic() - start) * 1000)
        return AIResponse(
            content=content,
            raw_response={
                "model": resolved_model,
                "usage": {"tokens_input": tokens_input, "tokens_output": tokens_output},
            },
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            model=resolved_model,
            latency_ms=latency_ms,
            cost_usd=0.0,
        )

    async def stream_complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        model: str | None = None,
    ):
        """Yield text chunks from Ollama's NDJSON streaming response."""
        payload = self._build_payload(
            prompt, system, temperature, max_tokens, response_format=None, model=model, stream=True
        )
        async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers()) as client:
            async with client.stream("POST", f"{self.base_url}/api/chat", json=payload) as resp:
                if resp.status_code >= 400:
                    body = (await resp.aread()).decode(errors="replace")
                    if resp.status_code == 429:
                        raise QuotaExhaustedError(f"Ollama returned 429: {body[:400]}")
                    resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("ollama stream: skipping unparseable line: %.200s", line)
                        continue
                    text = (chunk.get("message") or {}).get("content")
                    if text:
                        yield text
                    if chunk.get("done"):
                        break

    async def embed(self, texts: list[str], model: str) -> list[list[float]]:
        """``POST /api/embed`` — one vector per input, in input order.

        Batched by the caller. A partial or reordered response is an error
        rather than something to paper over: a vector silently attached to the
        wrong entry would poison every thread it lands in.
        """
        if not texts:
            return []
        payload = {"model": model, "input": texts}
        keep_alive = self.config.get("keep_alive")
        if keep_alive:
            payload["keep_alive"] = keep_alive
        async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers()) as client:
            resp = await client.post(f"{self.base_url}/api/embed", json=payload)
            self._raise_for_status(resp)
            data = resp.json()
        vectors = data.get("embeddings") or []
        if len(vectors) != len(texts):
            raise ValueError(f"ollama returned {len(vectors)} embeddings for {len(texts)} inputs")
        return vectors

    async def check_health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=15, headers=self._headers()) as client:
                resp = await client.get(f"{self.base_url}/api/version")
                return resp.status_code == 200
        except Exception as e:  # noqa: BLE001 — health probe is best-effort
            logger.warning("ollama provider health check failed: %s", e)
            return False

    async def list_models(self) -> list[str]:
        async with httpx.AsyncClient(timeout=30, headers=self._headers()) as client:
            resp = await client.get(f"{self.base_url}/api/tags")
            self._raise_for_status(resp)
            data = resp.json()
        return sorted(m["name"] for m in data.get("models", []) if m.get("name"))
