"""Adapter registry for enrichment sources."""

from app.enrichment.adapters import (
    CISAKEVAdapter,
    CVEDetailsAdapter,
    EPSSAdapter,
    GitHubPoCAdapter,
    GreyNoiseAdapter,
    MalpediaAdapter,
    MITREAttackAdapter,
    NVDAdapter,
    OSVAdapter,
    ShodanAdapter,
    VirusTotalAdapter,
    VulnCheckAdapter,
    WikipediaAdapter,
)
from app.enrichment.base import EnrichmentAdapter
from app.enrichment.gateway import SourceGateway
from app.models.enrichment import EnrichmentSource

ADAPTER_REGISTRY: dict[str, type[EnrichmentAdapter]] = {
    "epss": EPSSAdapter,
    "nvd": NVDAdapter,
    "cisa_kev": CISAKEVAdapter,
    "mitre_attack": MITREAttackAdapter,
    "vulncheck": VulnCheckAdapter,
    "osv": OSVAdapter,
    "malpedia": MalpediaAdapter,
    "github_poc": GitHubPoCAdapter,
    "cvedetails": CVEDetailsAdapter,
    "wikipedia": WikipediaAdapter,
    # Observable (IOC ledger) reputation — restored from the v1-era adapters.
    "virustotal": VirusTotalAdapter,
    "greynoise": GreyNoiseAdapter,
    "shodan": ShodanAdapter,
}

# Default source definitions for seeding the database. default_daily_budget is
# requests per UTC day per credential, about twice what the jobs and per-entity
# lookups send on a busy day (migration j7e8f9a0b1c2 has the breakdown).
DEFAULT_SOURCES = [
    {
        "source_type": "epss",
        "display_name": "FIRST EPSS",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 100, "period_seconds": 60},
        "default_daily_budget": 500,
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "nvd",
        "display_name": "NVD API 2.0",
        "default_trigger_mode": "auto",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 50, "period_seconds": 30},
        "default_daily_budget": 5000,
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "cisa_kev",
        "display_name": "CISA KEV",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 100, "period_seconds": 60},
        "default_daily_budget": 500,
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "mitre_attack",
        "display_name": "MITRE ATT&CK",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 10, "period_seconds": 3600},
        "default_daily_budget": 100,
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "vulncheck",
        "display_name": "VulnCheck KEV",
        "default_trigger_mode": "scheduled",
        "requires_api_key": True,
        "default_rate_limit": {"requests_per_period": 1000, "period_seconds": 60},
        "default_daily_budget": 1000,
        "default_min_confidence_threshold": "medium",
    },
    {
        "source_type": "osv",
        "display_name": "OSV",
        "default_trigger_mode": "auto",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 100, "period_seconds": 60},
        "default_daily_budget": 2000,
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "malpedia",
        "display_name": "Malpedia",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 30, "period_seconds": 60},
        "default_daily_budget": 1000,
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "github_poc",
        "display_name": "GitHub PoC",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 10, "period_seconds": 60},
        "default_daily_budget": 1000,
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "cvedetails",
        "display_name": "CVEDetails",
        "default_trigger_mode": "auto",
        "requires_api_key": True,
        "default_rate_limit": {"requests_per_period": 60, "period_seconds": 60},
        "default_daily_budget": 1000,
        "default_min_confidence_threshold": "medium",
    },
    {
        "source_type": "wikipedia",
        "display_name": "Wikipedia",
        "default_trigger_mode": "auto",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 10, "period_seconds": 60},
        "default_daily_budget": 2000,
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "virustotal",
        "display_name": "VirusTotal v3",
        "default_trigger_mode": "manual",
        "requires_api_key": True,
        # Free tier: 4 req/min, 500/day.
        "default_rate_limit": {"requests_per_period": 4, "period_seconds": 60},
        "default_daily_budget": 500,
        "default_min_confidence_threshold": "medium",
    },
    {
        "source_type": "greynoise",
        "display_name": "GreyNoise Community",
        "default_trigger_mode": "manual",
        # The Community endpoint answers without a key; one raises the allowance.
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 10, "period_seconds": 3600},
        "default_daily_budget": 100,
        "default_min_confidence_threshold": "medium",
    },
    {
        "source_type": "shodan",
        "display_name": "Shodan InternetDB",
        # Keyless and cheap: run automatically for freshly judged IPs. (Existing
        # installs keep their row's trigger_mode — flip it under Settings →
        # Engine → Enrichment.)
        "default_trigger_mode": "auto",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 30, "period_seconds": 60},
        "default_daily_budget": 1000,
        "default_min_confidence_threshold": "medium",
    },
]


# Map shared_key_group → list of source_types that share that key
SHARED_KEY_GROUPS: dict[str, list[str]] = {}
for _st, _cls in ADAPTER_REGISTRY.items():
    group = getattr(_cls, "shared_key_group", None)
    if group:
        SHARED_KEY_GROUPS.setdefault(group, []).append(_st)


def get_adapter(
    source_type: str,
    api_key: str | None = None,
    config: dict | None = None,
    gateway: SourceGateway | None = None,
) -> EnrichmentAdapter:
    """Instantiate an adapter by source type. Without a gateway it can't make
    HTTP requests."""
    adapter_class = ADAPTER_REGISTRY.get(source_type)
    if not adapter_class:
        raise ValueError(f"Unknown enrichment source type: {source_type}")
    return adapter_class(api_key=api_key, config=config, gateway=gateway)


def source_gateway(source: EnrichmentSource, api_key: str | None, **kwargs) -> SourceGateway:
    """The gateway for a source row and the key it will use."""
    adapter_class = ADAPTER_REGISTRY.get(source.source_type) or EnrichmentAdapter
    return SourceGateway.for_source(
        source,
        api_key,
        shared_key_group=adapter_class.shared_key_group,
        throttle_statuses=adapter_class.throttle_statuses,
        **kwargs,
    )


def adapter_for_source(source: EnrichmentSource, api_key: str | None) -> EnrichmentAdapter:
    """The source's adapter, wired to its gateway."""
    return get_adapter(
        source.source_type, api_key=api_key, config=source.config, gateway=source_gateway(source, api_key)
    )
