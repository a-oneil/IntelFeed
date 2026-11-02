"""Base classes for enrichment sources and their adapters."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx
from sqlalchemy import and_

from app import entity_types
from app.enrichment.gateway import THROTTLE_STATUSES, SourceGateway
from app.enrichment.manifest import (
    Column,
    Context,
    Egress,
    Job,
    Key,
    License,
    Match,
    Quota,
    Relation,
)

#: The column each entity type is looked up by when a manifest doesn't say.
LOOKUP_COLUMNS = {
    entity_types.CVE: "cve_id",
    entity_types.CWE: "cwe_id",
    entity_types.TTP: "technique_id",
    entity_types.OBSERVABLE: "value",
    entity_types.RANSOMWARE_VICTIM: "domain",
}

#: Hours a result is kept when the adapter doesn't say.
DEFAULT_TTL_HOURS = 24


@dataclass
class EnrichmentData:
    """Normalized enrichment result from any adapter. Without ``ttl_hours``
    an adapter's result is kept for 24 hours."""

    raw_response: dict
    parsed_data: dict
    ttl_hours: int = DEFAULT_TTL_HOURS


class _derived:
    """A read-only attribute computed from the class's manifest, on the class
    and its instances alike."""

    def __init__(self, fn):
        self.fn = fn

    def __get__(self, obj, cls):
        return self.fn(cls)


class Source:
    """A source's manifest (``app/enrichment/manifest.py``). A catalog source
    only has scheduled jobs; an ``EnrichmentAdapter`` also looks up one entity
    at a time."""

    source_type: str
    display_name: str
    kind: str = "catalog"
    #: entity_type → the observable kinds it handles (None = every value).
    applies_to: dict[str, tuple[str, ...] | None]
    #: Column → the values an entity must hold for the source to look it up on
    #: its own (every queue lane but manual), e.g. {"status": ("active",)}. A
    #: person's request looks up anything the source applies to.
    scope: dict[str, tuple[str, ...]] = {}
    #: The ``Match`` entries of ``applies_to``, by entity type.
    match: dict[str, Match] = {}
    #: Keys the source can't work without: ``Key()`` (its own API key),
    #: ``Key("abuse_ch")`` (a shared one).
    requires: tuple[Key, ...] = ()
    #: One sentence on what the source is, for the console.
    about: str = ""
    #: Takes an API key it doesn't need (GreyNoise: a key raises its limit).
    optional_key: bool = False
    #: System settings that configure the source itself (not one of its
    #: jobs), edited on the source's Limits tab.
    settings_keys: tuple[str, ...] = ()
    quota: Quota
    egress: Egress
    license: License
    jobs: tuple[Job, ...] = ()
    outputs: tuple[Column | Context | Relation, ...] = ()
    default_trigger_mode: str = "manual"
    #: Whether a new install starts with the source on. None: on when it has
    #: jobs (and then its per-entity lookups start manual: it is on only so
    #: its jobs run).
    default_enabled: bool | None = None
    shared_key_group: str | None = None  # Sources sharing an API key set this (e.g. "abuse_ch")
    #: Instance setting holding a key to use when neither the person nor the
    #: source row has one, e.g. "nvd_api_key". Every path resolves keys the same
    #: way, so a job and a per-entity lookup always share one bucket.
    key_setting: str | None = None
    throttle_statuses: tuple[int, ...] = THROTTLE_STATUSES  # Statuses the gateway treats as "slow down"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        applies_to = cls.__dict__.get("applies_to")
        if applies_to is not None:
            # Match entries become plain kinds; the Match itself moves to
            # ``match``, so every reader of applies_to sees one shape.
            cls.applies_to = {t: (m.kinds if isinstance(m, Match) else m) for t, m in applies_to.items()}
            declared = {t: m for t, m in applies_to.items() if isinstance(m, Match)}
            cls.match = {**{t: m for t, m in cls.match.items() if t in cls.applies_to}, **declared}

    @classmethod
    def lookup_column(cls, entity_type: str) -> str:
        """The entity column whose value the source looks up: the
        ``Match.column`` its manifest declares, else the type's identifier
        (``LOOKUP_COLUMNS``), else ``name``."""
        m = cls.match.get(entity_type)
        if m and m.column:
            return m.column
        return LOOKUP_COLUMNS.get(entity_type, "name")

    @classmethod
    def required_keys(cls) -> tuple[Key, ...]:
        return tuple(r for r in cls.requires if isinstance(r, Key))

    @classmethod
    def columns(cls) -> tuple[Column, ...]:
        return tuple(o for o in cls.outputs if isinstance(o, Column))

    @classmethod
    def relations(cls) -> tuple[Relation, ...]:
        return tuple(o for o in cls.outputs if isinstance(o, Relation))

    @classmethod
    def scope_filter(cls, entity_type: str, model):
        """SQL: the entity is one the source looks up on its own — of a kind it
        takes, holding its ``scope`` values. None when every entity is."""
        clauses = []
        kinds = cls.applies_to.get(entity_type)
        if kinds and hasattr(model, "kind"):
            clauses.append(model.kind.in_(kinds))
        clauses += [getattr(model, col).in_(values) for col, values in cls.scope.items() if hasattr(model, col)]
        return and_(*clauses) if clauses else None

    @_derived
    def supported_entity_types(cls) -> list[str]:
        return list(cls.applies_to)

    @_derived
    def requires_api_key(cls) -> bool:
        return bool(cls.required_keys())


class EnrichmentAdapter(Source, ABC):
    """A source that enriches one entity per ``enrich()`` call."""

    kind = "lookup"

    def __init__(self, api_key: str | None = None, config: dict | None = None, gateway: SourceGateway | None = None):
        self.api_key = api_key
        self.config = config or {}
        self.gateway = gateway

    def http(self, timeout: float = 10, **kwargs) -> httpx.AsyncClient:
        """An httpx client for this source. Adapters make every outbound
        request through it, so the source's gateway rate-limits, budgets and
        circuit-breaks each one."""
        if self.gateway is None:
            raise RuntimeError(f"{self.source_type} adapter has no SourceGateway")
        return self.gateway.client(timeout=timeout, **kwargs)

    def http_transport(self) -> httpx.AsyncBaseTransport:
        """The gateway transport alone, for libraries that build their own
        httpx client but accept a transport (wikipediaapi)."""
        if self.gateway is None:
            raise RuntimeError(f"{self.source_type} adapter has no SourceGateway")
        return self.gateway.transport()

    @abstractmethod
    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        """Enrich a single entity. Returns normalized data."""
        ...

    async def check_health(self) -> bool:
        """Verify the source is reachable and API key is valid."""
        try:
            return True
        except Exception:
            return False

    def supports_entity(self, entity_type: str) -> bool:
        """Check if this adapter can enrich the given entity type."""
        return entity_type in self.applies_to
