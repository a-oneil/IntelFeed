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

# Default source definitions for seeding the database
DEFAULT_SOURCES = [
    {
        "source_type": "epss",
        "display_name": "FIRST EPSS",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 100, "period_seconds": 60},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "nvd",
        "display_name": "NVD API 2.0",
        "default_trigger_mode": "auto",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 50, "period_seconds": 30},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "cisa_kev",
        "display_name": "CISA KEV",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 100, "period_seconds": 60},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "mitre_attack",
        "display_name": "MITRE ATT&CK",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 10, "period_seconds": 3600},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "vulncheck",
        "display_name": "VulnCheck KEV",
        "default_trigger_mode": "scheduled",
        "requires_api_key": True,
        "default_rate_limit": {"requests_per_period": 1000, "period_seconds": 60},
        "default_min_confidence_threshold": "medium",
    },
    {
        "source_type": "osv",
        "display_name": "OSV",
        "default_trigger_mode": "auto",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 100, "period_seconds": 60},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "malpedia",
        "display_name": "Malpedia",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 30, "period_seconds": 60},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "github_poc",
        "display_name": "GitHub PoC",
        "default_trigger_mode": "scheduled",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 10, "period_seconds": 60},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "cvedetails",
        "display_name": "CVEDetails",
        "default_trigger_mode": "auto",
        "requires_api_key": True,
        "default_rate_limit": {"requests_per_period": 60, "period_seconds": 60},
        "default_min_confidence_threshold": "medium",
    },
    {
        "source_type": "wikipedia",
        "display_name": "Wikipedia",
        "default_trigger_mode": "auto",
        "requires_api_key": False,
        "default_rate_limit": {"requests_per_period": 10, "period_seconds": 60},
        "default_min_confidence_threshold": "low",
    },
    {
        "source_type": "virustotal",
        "display_name": "VirusTotal v3",
        "default_trigger_mode": "manual",
        "requires_api_key": True,
        # Free tier: 4 req/min, 500/day — set daily_budget on the source row too.
        "default_rate_limit": {"requests_per_period": 4, "period_seconds": 60},
        "default_min_confidence_threshold": "medium",
    },
    {
        "source_type": "greynoise",
        "display_name": "GreyNoise Community",
        "default_trigger_mode": "manual",
        "requires_api_key": True,
        "default_rate_limit": {"requests_per_period": 10, "period_seconds": 3600},
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
        "default_min_confidence_threshold": "medium",
    },
]


# Map shared_key_group → list of source_types that share that key
SHARED_KEY_GROUPS: dict[str, list[str]] = {}
for _st, _cls in ADAPTER_REGISTRY.items():
    group = getattr(_cls, "shared_key_group", None)
    if group:
        SHARED_KEY_GROUPS.setdefault(group, []).append(_st)


def get_adapter(source_type: str, api_key: str | None = None, config: dict | None = None) -> EnrichmentAdapter:
    """Instantiate an adapter by source type."""
    adapter_class = ADAPTER_REGISTRY.get(source_type)
    if not adapter_class:
        raise ValueError(f"Unknown enrichment source type: {source_type}")
    return adapter_class(api_key=api_key, config=config)
