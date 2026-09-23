from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel


class AIResponse(BaseModel):
    content: str
    raw_response: dict
    tokens_input: int
    tokens_output: int
    model: str
    latency_ms: int
    # Provider-reported dollar cost for this call, when the provider surfaces
    # one (the Claude Code CLI reports total_cost_usd per run). None means
    # "unknown" — the engine falls back to its own token-based estimate.
    cost_usd: float | None = None


class AIProvider(ABC):
    """Base class for all AI providers."""

    # Whether this provider's runtime can execute tool calls (agent harness).
    # Must agree with app.ai.capabilities.TOOL_CAPABLE_PROVIDER_TYPES.
    supports_tools: ClassVar[bool] = False

    def __init__(self, base_url: str | None = None, api_key: str | None = None, config: dict | None = None):
        self.base_url = base_url
        self.api_key = api_key
        self.config = config or {}

    @abstractmethod
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
    ) -> AIResponse: ...

    async def stream_complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        model: str | None = None,
    ):
        """Yield text chunks from streaming response. Default falls back to non-streaming."""
        resp = await self.complete(
            prompt=prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
            model=model,
        )
        yield resp.content

    async def embed(self, texts: list[str], model: str) -> list[list[float]]:
        """Embed a batch of texts, one vector per input, in input order.

        Optional: only providers backing the embedding sweeper implement it.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support embeddings")

    @abstractmethod
    async def check_health(self) -> bool:
        """Verify the provider is reachable and credentials are valid."""
        ...

    @abstractmethod
    async def list_models(self) -> list[str]:
        """List available models from this provider."""
        ...
