"""Base class for all enrichment adapters."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class EnrichmentData:
    """Normalized enrichment result from any adapter."""

    raw_response: dict
    parsed_data: dict
    ttl_hours: int = 24


class EnrichmentAdapter(ABC):
    """Base class for all enrichment adapters."""

    source_type: str
    display_name: str
    supported_entity_types: list[str]
    requires_api_key: bool = False
    default_trigger_mode: str = "manual"
    default_rate_limit: dict = field(default_factory=lambda: {"requests_per_period": 100, "period_seconds": 86400})
    shared_key_group: str | None = None  # Adapters sharing an API key set this (e.g. "abuse_ch")

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        self.api_key = api_key
        self.config = config or {}

    @abstractmethod
    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        """Enrich a single entity. Returns normalized data."""
        ...

    async def bulk_sync(self) -> list[EnrichmentData]:
        """For scheduled sources that support bulk operations. Override in subclasses."""
        return []

    async def check_health(self) -> bool:
        """Verify the source is reachable and API key is valid."""
        try:
            return True
        except Exception:
            return False

    def supports_entity(self, entity_type: str) -> bool:
        """Check if this adapter can enrich the given entity type."""
        return entity_type in self.supported_entity_types

    def get_cache_ttl(self) -> timedelta:
        """Return cache TTL for this source's results."""
        return timedelta(hours=self.config.get("ttl_hours", 24))
