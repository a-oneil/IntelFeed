"""OpenAI-compatible provider — OpenAI, LM Studio, vLLM, llama.cpp, LiteLLM, OpenRouter, Groq.

Talks the `/v1/chat/completions` dialect every one of those servers shares.
They differ only in base URL, whether an API key is required, and how much
of the spec they actually implement — this provider is written defensively
around those gaps rather than assuming a fully-compliant OpenAI server.

Config keys (``ai_providers.config`` / assignment config):

* ``timeout_seconds`` — per-request timeout (default 300).
* ``structured_output`` — one of ``json_schema`` (default), ``json_schema_strict``,
  ``json_object``, ``prompt``. See module-level ``_STRUCTURED_OUTPUT_MODES``.
  On a 400 that looks like a ``response_format`` rejection, ``complete()``
  retries once, stepping down the chain strict → json_schema → json_object →
  prompt, and logs a warning naming the mode that worked.
* ``schema_name`` — ``json_schema.name`` sent to the server (must match
  ``^[A-Za-z0-9_-]{1,64}$``); default ``"intelfeed_output"``.
* ``strict_strip_keywords`` — keywords stripped from the schema before strict
  mode; default ``["minLength", "maxLength"]``.
* ``system_role`` — ``"system"`` (default) or ``"developer"`` (OpenAI's
  reasoning-model convention).
* ``max_tokens_param`` — ``"max_tokens"`` (default) or
  ``"max_completion_tokens"`` (required by OpenAI's reasoning models, which
  reject ``max_tokens``).
* ``send_temperature`` — default ``True``. Set ``False`` for reasoning models
  that reject a non-default temperature.
* ``min_temperature`` — floor applied to the engine's temperature, same
  rationale as ``OllamaProvider`` (grammar-constrained local decoding at 0.0
  can loop). Default ``0.0`` (no floor) since hosted APIs don't have this
  problem; set e.g. ``0.2`` for local servers.
* ``extra_headers`` — merged into every request (e.g. OpenRouter's
  ``HTTP-Referer`` / ``X-Title``).
* ``extra_body`` — merged into the request payload last, after everything
  else this provider sets. Escape hatch for vendor options such as
  ``chat_template_kwargs`` (Qwen3 thinking toggle on vLLM/llama.cpp) or
  OpenRouter's ``provider`` routing block.
* ``model_filter`` — regex; when set, ``list_models()`` drops any model id
  that doesn't match (hides non-chat models like tts/whisper/dall-e/embedding
  from a provider's full catalog).
* ``model_overrides`` — per-model config map layered over the keys above,
  keyed by exact model name, same shape as ``OllamaProvider``.
* Cost (``cost_usd`` on the returned ``AIResponse``), tried in this order:
  1. ``report_cost: true`` — read a provider-reported figure: OpenRouter's
     ``usage.cost`` (requires sending ``usage.include: true``) or a LiteLLM
     proxy's ``x-litellm-response-cost`` response header.
  2. ``pricing: {"input_per_mtok": x, "output_per_mtok": y}`` (optionally
     layered via ``model_overrides[model].pricing``).
  3. ``None`` — the engine falls back to its own ``COST_TABLE`` (0.0 for an
     unknown model), which is correct for genuinely free local servers.
* ``embedding_dimensions`` — forwarded as ``dimensions`` on ``embed()``
  requests (OpenAI's ``text-embedding-3-*`` support truncating to a smaller
  vector). Omitted entirely unless set — sending it unconditionally breaks
  servers that don't support the parameter.

Not implemented in v1: tool calling. ``supports_tools`` is ``False`` and this
type is intentionally excluded from
``app.ai.capabilities.TOOL_CAPABLE_PROVIDER_TYPES`` — local servers vary too
much in tool-calling quality for a blanket capability (tracked for a
follow-up behind a per-provider opt-in).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import ClassVar
from urllib.parse import urlparse

import httpx

from app.ai.providers.base import AIProvider, AIResponse
from app.ai.providers.claude_code_provider import QuotaExhaustedError
from app.ai.providers.schema_utils import enforce_required, to_openai_strict

logger = logging.getLogger(__name__)

# Ordered fallback chain for the auto-downgrade in `complete()`.
_STRUCTURED_OUTPUT_MODES = ("json_schema_strict", "json_schema", "json_object", "prompt")

_SCHEMA_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_MODEL_FILTER_LEN = 256

# Pause after a 429 that names no window: long enough to let a per-minute
# limit clear, short enough that work resumes on its own.
_DEFAULT_RATE_LIMIT_PAUSE_SECONDS = 60


def _validate_provider_base_url(raw_url: str) -> str:
    """Ensure base_url is http(s) and does not target cloud metadata link-local addresses."""
    cleaned = raw_url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("OpenAI-compatible provider base_url must be an http:// or https:// URL")
    try:
        addr = ipaddress.ip_address(parsed.hostname)
        if addr.is_link_local:
            raise ValueError("OpenAI-compatible provider base_url cannot target link-local addresses")
    except ValueError as e:
        if "link-local" in str(e):
            raise
    return cleaned


def _parse_retry_after(value: str | None) -> datetime | None:
    """``Retry-After`` is either delta-seconds or an HTTP-date (RFC 9110 §10.2.3)."""
    if not value:
        return None
    value = value.strip()
    try:
        return datetime.now(UTC) + timedelta(seconds=max(float(value), 0.0))
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class OpenAICompatibleProvider(AIProvider):
    """OpenAI `/v1/chat/completions` dialect (OpenAI, LM Studio, vLLM, llama.cpp, LiteLLM, OpenRouter, Groq)."""

    # No in-process tool-calling loop in v1 — see module docstring.
    supports_tools: ClassVar[bool] = False

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        config: dict | None = None,
    ):
        super().__init__(base_url=base_url, api_key=api_key, config=config)
        if not base_url or not base_url.strip():
            raise ValueError("OpenAI-compatible provider requires a base_url")
        self.base_url = _validate_provider_base_url(base_url)
        self.timeout: float = float(self.config.get("timeout_seconds", 300))

    # ---------------------------------------------------------------- helpers

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.config.get("extra_headers") or {})
        return headers

    def _resolve_model(self, model: str | None) -> str:
        resolved = model or self.config.get("default_model")
        if not resolved:
            raise ValueError("OpenAI-compatible provider requires a model name (set one on the task assignment)")
        return resolved

    def _model_config(self, resolved_model: str) -> dict:
        overrides = (self.config.get("model_overrides") or {}).get(resolved_model) or {}
        return {**self.config, **overrides}

    @staticmethod
    def _effective_temperature(cfg: dict, temperature: float) -> float:
        floor = float(cfg.get("min_temperature", 0.0))
        return max(float(temperature), floor)

    def _schema_name(self, cfg: dict) -> str:
        name = str(cfg.get("schema_name") or "intelfeed_output")
        return name if _SCHEMA_NAME_RE.match(name) else "intelfeed_output"

    def _response_format(self, cfg: dict, response_format: dict | None, mode: str) -> dict | None:
        """Build the `response_format` payload for one structured-output mode."""
        if not response_format or mode == "prompt":
            return None
        if mode == "json_object":
            return {"type": "json_object"}
        if mode == "json_schema_strict":
            strip = tuple(cfg.get("strict_strip_keywords") or ("minLength", "maxLength"))
            schema = to_openai_strict(response_format, strip=strip)
            return {
                "type": "json_schema",
                "json_schema": {"name": self._schema_name(cfg), "strict": True, "schema": schema},
            }
        # json_schema (non-strict default)
        schema = enforce_required(response_format)
        return {
            "type": "json_schema",
            "json_schema": {"name": self._schema_name(cfg), "strict": False, "schema": schema},
        }

    def _schema_instruction(self, response_format: dict | None, mode: str) -> str | None:
        """Textual fallback for servers that can't be told to emit JSON structurally."""
        if not response_format or mode not in ("json_object", "prompt"):
            return None
        return (
            "Respond with a single JSON object only — no prose, no markdown code fences — "
            f"matching this JSON schema:\n{json.dumps(response_format)}"
        )

    def _build_payload(
        self,
        prompt: str,
        system: str | None,
        temperature: float,
        max_tokens: int,
        response_format: dict | None,
        model: str | None,
        stream: bool,
        mode: str,
    ) -> tuple[dict, dict]:
        resolved_model = self._resolve_model(model)
        cfg = self._model_config(resolved_model)

        system_role = cfg.get("system_role") or "system"
        schema_instruction = self._schema_instruction(response_format, mode)

        messages: list[dict] = []
        system_content = system or ""
        if schema_instruction:
            system_content = f"{system_content}\n\n{schema_instruction}" if system_content else schema_instruction
        if system_content:
            messages.append({"role": system_role, "content": system_content})
        messages.append({"role": "user", "content": prompt})

        payload: dict = {
            "model": resolved_model,
            "messages": messages,
            "stream": stream,
        }

        max_tokens_param = cfg.get("max_tokens_param") or "max_tokens"
        payload[max_tokens_param] = max_tokens

        if cfg.get("send_temperature", True):
            payload["temperature"] = self._effective_temperature(cfg, temperature)

        rf = self._response_format(cfg, response_format, mode)
        if rf:
            payload["response_format"] = rf

        if cfg.get("report_cost") and "openrouter.ai" in self.base_url:
            payload["usage"] = {"include": True}

        extra_body = cfg.get("extra_body")
        if isinstance(extra_body, dict):
            payload.update(extra_body)
        elif extra_body:
            logger.warning("%s: ignoring extra_body that isn't a JSON object", self.base_url)

        return payload, cfg

    @staticmethod
    def _rate_limit_error(status_code: int, headers: httpx.Headers, body: str) -> QuotaExhaustedError:
        """Turn a 429 into a pause with the shortest window the server allows.

        The engine pauses the whole provider for ``reset_at`` (an hour when it is
        ``None``), so the default matters: most 429s from these servers are
        per-minute rate limits that clear in seconds. Only a spent balance
        (OpenAI's ``insufficient_quota``) earns the long pause.
        """
        message = f"{status_code} from provider: {body[:400]}"
        reset_at = _parse_retry_after(headers.get("retry-after"))
        if reset_at is None and "insufficient_quota" not in body:
            reset_at = datetime.now(UTC) + timedelta(seconds=_DEFAULT_RATE_LIMIT_PAUSE_SECONDS)
        return QuotaExhaustedError(message, reset_at=reset_at)

    @classmethod
    def _raise_for_status(cls, resp: httpx.Response) -> None:
        if resp.status_code == 429:
            raise cls._rate_limit_error(resp.status_code, resp.headers, resp.text)
        resp.raise_for_status()

    @staticmethod
    def _looks_like_response_format_rejection(resp: httpx.Response) -> bool:
        if resp.status_code != 400:
            return False
        body = resp.text.lower()
        return any(term in body for term in ("response_format", "json_schema", "json_object"))

    def _resolve_cost(self, cfg: dict, usage: dict, headers: httpx.Headers) -> float | None:
        if cfg.get("report_cost"):
            reported = usage.get("cost")
            if isinstance(reported, (int, float)):
                return float(reported)
            header_cost = headers.get("x-litellm-response-cost")
            if header_cost:
                try:
                    return float(header_cost)
                except ValueError:
                    pass

        pricing = cfg.get("pricing")
        if pricing:
            tokens_in = usage.get("prompt_tokens") or 0
            tokens_out = usage.get("completion_tokens") or 0
            cost = (tokens_in / 1_000_000) * float(pricing.get("input_per_mtok", 0.0)) + (
                tokens_out / 1_000_000
            ) * float(pricing.get("output_per_mtok", 0.0))
            return round(cost, 6)

        if cfg.get("local"):
            return 0.0
        return None

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
    ) -> AIResponse:
        del heartbeat_label  # subprocess-provider concept; not applicable

        resolved_model = self._resolve_model(model)
        cfg = self._model_config(resolved_model)
        timeout = timeout_seconds or float(cfg.get("timeout_seconds", 300))

        modes = _STRUCTURED_OUTPUT_MODES
        start_mode = cfg.get("structured_output") or "json_schema"
        if start_mode not in modes:
            start_mode = "json_schema"
        mode_chain = modes[modes.index(start_mode) :] if response_format else ("prompt",)

        start = time.monotonic()
        last_resp: httpx.Response | None = None
        used_mode = mode_chain[0]
        async with httpx.AsyncClient(timeout=timeout, headers=self._headers()) as client:
            for mode in mode_chain:
                payload, cfg = self._build_payload(
                    prompt, system, temperature, max_tokens, response_format, model, stream=False, mode=mode
                )
                resp = await client.post(f"{self.base_url}/chat/completions", json=payload)
                used_mode = mode
                if self._looks_like_response_format_rejection(resp) and mode != mode_chain[-1]:
                    logger.warning(
                        "%s rejected response_format mode %r (%s); downgrading",
                        self.base_url,
                        mode,
                        resp.text[:200],
                    )
                    last_resp = resp
                    continue
                if mode != mode_chain[0]:
                    logger.info("%s accepted response_format mode %r after downgrade", self.base_url, mode)
                last_resp = resp
                break
        assert last_resp is not None
        self._raise_for_status(last_resp)
        data = last_resp.json()
        latency_ms = int((time.monotonic() - start) * 1000)

        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        content = message.get("content") or ""
        finish_reason = choice.get("finish_reason")
        if finish_reason == "length":
            logger.warning("%s completion truncated (finish_reason=length)", self.base_url)
        if not content and (message.get("reasoning_content") or message.get("reasoning")):
            logger.warning(
                "%s returned empty content with a reasoning block set — the model may have spent its "
                "entire token budget on chain-of-thought",
                self.base_url,
            )

        usage = data.get("usage") or {}
        tokens_input = usage.get("prompt_tokens") or 0
        tokens_output = usage.get("completion_tokens") or 0

        return AIResponse(
            content=content,
            raw_response={
                "model": data.get("model"),
                "finish_reason": finish_reason,
                "refusal": message.get("refusal"),
                "usage": usage,
                "structured_output_mode_used": used_mode,
            },
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            model=data.get("model") or resolved_model,
            latency_ms=latency_ms,
            cost_usd=self._resolve_cost(cfg, usage, last_resp.headers),
        )

    async def stream_complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        model: str | None = None,
    ):
        """Yield text chunks from the server's SSE stream (no structured output)."""
        payload, cfg = self._build_payload(
            prompt, system, temperature, max_tokens, response_format=None, model=model, stream=True, mode="prompt"
        )
        timeout = float(cfg.get("timeout_seconds", self.timeout))
        async with httpx.AsyncClient(timeout=timeout, headers=self._headers()) as client:
            async with client.stream("POST", f"{self.base_url}/chat/completions", json=payload) as resp:
                if resp.status_code >= 400:
                    body = (await resp.aread()).decode(errors="replace")
                    if resp.status_code == 429:
                        raise self._rate_limit_error(resp.status_code, resp.headers, body)
                    resp.raise_for_status()
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line or line.startswith(":"):
                        continue
                    if not line.startswith("data:"):
                        continue
                    data_str = line[len("data:") :].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        logger.warning("%s stream: skipping unparseable line: %.200s", self.base_url, data_str)
                        continue
                    if chunk.get("error"):
                        raise RuntimeError(f"{self.base_url} stream error: {chunk['error']}")
                    choices = chunk.get("choices") or []
                    if not choices:
                        continue
                    text = (choices[0].get("delta") or {}).get("content")
                    if text:
                        yield text

    async def embed(self, texts: list[str], model: str) -> list[list[float]]:
        """``POST /embeddings`` — one vector per input, in input order.

        A partial or reordered response is an error rather than something to
        paper over (same rule as ``OllamaProvider.embed``): a vector silently
        attached to the wrong entry would poison every thread it lands in.
        """
        if not texts:
            return []
        payload: dict = {"model": model, "input": texts}
        dimensions = self.config.get("embedding_dimensions")
        if dimensions:
            payload["dimensions"] = int(dimensions)
        async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers()) as client:
            resp = await client.post(f"{self.base_url}/embeddings", json=payload)
            self._raise_for_status(resp)
            data = resp.json()
        rows = data.get("data") or []
        if len(rows) != len(texts):
            raise ValueError(f"provider returned {len(rows)} embeddings for {len(texts)} inputs")
        ordered = sorted(rows, key=lambda r: r.get("index", 0))
        indices = [r.get("index") for r in ordered]
        if indices != list(range(len(texts))):
            raise ValueError(f"provider returned non-contiguous embedding indices: {indices}")
        return [r["embedding"] for r in ordered]

    async def check_health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=15, headers=self._headers()) as client:
                resp = await client.get(f"{self.base_url}/models")
                return resp.status_code == 200
        except Exception as e:  # noqa: BLE001 — health probe is best-effort
            logger.warning("openai_compatible provider health check failed: %s", e)
            return False

    async def list_models(self) -> list[str]:
        async with httpx.AsyncClient(timeout=30, headers=self._headers()) as client:
            resp = await client.get(f"{self.base_url}/models")
            self._raise_for_status(resp)
            data = resp.json()
        ids = sorted(m["id"] for m in data.get("data", []) if m.get("id"))
        model_filter = self.config.get("model_filter")
        if model_filter:
            if not isinstance(model_filter, str) or len(model_filter) > _MAX_MODEL_FILTER_LEN:
                raise ValueError(f"model_filter must be a regex string of at most {_MAX_MODEL_FILTER_LEN} characters")
            try:
                pattern = re.compile(model_filter)
            except re.error as e:
                raise ValueError(f"Invalid model_filter regex: {e}") from e
            ids = [m for m in ids if pattern.search(m)]
        return ids
