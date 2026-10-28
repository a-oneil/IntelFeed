"""Registry of enrichment sources, and what their manifests generate: seed rows,
job registry entries and gateways."""

from app.enrichment.adapters import (
    CISAKEVAdapter,
    CVEDetailsAdapter,
    CVEListAdapter,
    CymruAdapter,
    EPSSAdapter,
    GitHubPoCAdapter,
    GreyNoiseAdapter,
    MalpediaAdapter,
    MITREAttackAdapter,
    NVDAdapter,
    OSVAdapter,
    RDAPAdapter,
    ShodanAdapter,
    VirusTotalAdapter,
    VulnCheckAdapter,
    WikipediaAdapter,
)
from app.enrichment.base import EnrichmentAdapter, Source
from app.enrichment.capec import CAPECSource
from app.enrichment.catalogs import (
    CybergeistSource,
    MetasploitSource,
    MISPGalaxySource,
    MITRECWESource,
    RansomwareLiveSource,
    TrancoSource,
)
from app.enrichment.ctid import CTIDSource
from app.enrichment.d3fend import D3FENDSource
from app.enrichment.endoflife import EndOfLifeSource
from app.enrichment.etda import ETDASource
from app.enrichment.gateway import SourceGateway
from app.enrichment.wikidata import WikidataSource
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
    "cvelist": CVEListAdapter,
    "wikipedia": WikipediaAdapter,
    # Observable (IOC ledger) reputation — restored from the v1-era adapters.
    "virustotal": VirusTotalAdapter,
    "greynoise": GreyNoiseAdapter,
    "shodan": ShodanAdapter,
    # Observable network context: routing (Team Cymru) and registration (RDAP).
    "cymru": CymruAdapter,
    "rdap": RDAPAdapter,
}

# Catalog sources: scheduled jobs only, no per-entity lookup.
CATALOG_REGISTRY: dict[str, type[Source]] = {
    cls.source_type: cls
    for cls in (
        MISPGalaxySource,
        MetasploitSource,
        MITRECWESource,
        RansomwareLiveSource,
        CybergeistSource,
        WikidataSource,
        EndOfLifeSource,
        TrancoSource,
        CAPECSource,
        CTIDSource,
        D3FENDSource,
        ETDASource,
    )
}

#: Every source, lookup or catalog, by source_type.
SOURCE_REGISTRY: dict[str, type[Source]] = {**ADAPTER_REGISTRY, **CATALOG_REGISTRY}


def _seed_row(cls: type[Source]) -> dict:
    return {
        "source_type": cls.source_type,
        "display_name": cls.display_name,
        "default_trigger_mode": cls.default_trigger_mode,
        "default_rate_limit": cls.quota.rate_limit_config,
        "default_daily_budget": cls.quota.daily_budget,
        # A source with jobs starts on: its jobs skip while it is off.
        "default_enabled": bool(cls.jobs),
    }


#: Seed rows for the enrichment_sources table, from the manifests.
DEFAULT_SOURCES = [_seed_row(cls) for cls in SOURCE_REGISTRY.values()]


# Map shared_key_group → list of source_types that share that key
SHARED_KEY_GROUPS: dict[str, list[str]] = {}
for _st, _cls in SOURCE_REGISTRY.items():
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
    """The gateway for a source row and the key it will use. With a key, a
    source whose manifest has a ``keyed`` quota gets that rate, unless an admin
    has changed the row's rate from the keyless default."""
    cls = SOURCE_REGISTRY.get(source.source_type, Source)
    rate_limit_config = source.rate_limit_config
    quota = getattr(cls, "quota", None)
    if api_key and quota and quota.keyed and rate_limit_config == quota.rate_limit_config:
        rate_limit_config = quota.keyed.rate_limit_config
    return SourceGateway(
        source.source_type,
        rate_limit_config=rate_limit_config,
        daily_budget=source.daily_budget,
        api_key=api_key,
        shared_key_group=cls.shared_key_group,
        throttle_statuses=cls.throttle_statuses,
        **kwargs,
    )


def enrichment_jobs() -> dict[str, dict]:
    """JOB_REGISTRY entries for every source's scheduled jobs."""
    jobs = {}
    for cls in SOURCE_REGISTRY.values():
        for job in cls.jobs:
            entry = {
                "task": job.task,
                "description": job.description,
                "category": "enrichment",
                "source": cls.source_type,
                "default_schedule": job.schedule,
            }
            if job.settings_keys:
                entry["settings_keys"] = list(job.settings_keys)
            jobs[job.key] = entry
    return jobs


def adapter_for_source(source: EnrichmentSource, api_key: str | None) -> EnrichmentAdapter:
    """The source's adapter, wired to its gateway."""
    return get_adapter(
        source.source_type, api_key=api_key, config=source.config, gateway=source_gateway(source, api_key)
    )
