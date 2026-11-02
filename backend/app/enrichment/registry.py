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
    MalwareBazaarAdapter,
    MITREAttackAdapter,
    NVDAdapter,
    OSVAdapter,
    RDAPAdapter,
    ShodanAdapter,
    ThreatFoxAdapter,
    URLhausAdapter,
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
from app.enrichment.github_repo import GitHubRepoSource
from app.enrichment.manifest import Quota
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
    # abuse.ch, on one shared Auth-Key: IOC export matching, manual lookups.
    "threatfox": ThreatFoxAdapter,
    "urlhaus": URLhausAdapter,
    "malwarebazaar": MalwareBazaarAdapter,
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
        GitHubRepoSource,
    )
}

#: Every source, lookup or catalog, by source_type.
SOURCE_REGISTRY: dict[str, type[Source]] = {**ADAPTER_REGISTRY, **CATALOG_REGISTRY}


def seed_enabled(cls: type[Source]) -> bool:
    """Whether a new row starts on: what the manifest says, else on when the
    source has jobs (its jobs skip while it is off)."""
    return bool(cls.jobs) if cls.default_enabled is None else cls.default_enabled


def seed_trigger_mode(cls: type[Source]) -> str:
    """The trigger mode a new row starts in: the manifest's. A source that is
    on only so its jobs run starts ``manual``, so a fresh install makes no
    per-entity lookups for it until an admin chooses auto. A source that sends
    an observable to a third party (``Egress.SHARES_IOC``) inherits the base
    class's ``manual`` unless its manifest names ``auto`` itself."""
    if cls.jobs and cls.default_enabled is None:
        return "manual"
    return cls.default_trigger_mode


def _seed_row(cls: type[Source]) -> dict:
    return {
        "source_type": cls.source_type,
        "display_name": cls.display_name,
        "default_trigger_mode": seed_trigger_mode(cls),
        "default_rate_limit": cls.quota.rate_limit_config,
        "default_daily_budget": cls.quota.daily_budget,
        "default_enabled": seed_enabled(cls),
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


def _within_ceiling(rate_limit_config: dict, quota: Quota) -> dict:
    """The row's rate, lowered to the quota's ceiling when it is above it: the
    ceiling's rate over the row's own period, or the ceiling itself when that
    period is too short to allow one request."""
    requested = rate_limit_config.get("requests_per_period")
    if quota.ceiling_per_period is None or requested is None:
        return rate_limit_config
    period = rate_limit_config.get("period_seconds") or quota.period_seconds
    allowed = quota.ceiling_per_period * period // quota.period_seconds
    if requested <= allowed:
        return rate_limit_config
    if allowed < 1:
        return {"requests_per_period": quota.ceiling_per_period, "period_seconds": quota.period_seconds}
    return {"requests_per_period": allowed, "period_seconds": period}


def quota_in_use(cls: type[Source], api_key: str | None) -> Quota | None:
    """The manifest quota that applies: ``keyed`` with a key, when it has one."""
    quota = getattr(cls, "quota", None)
    if quota is None:
        return None
    return quota.keyed if api_key and quota.keyed else quota


def source_gateway(source: EnrichmentSource, api_key: str | None, **kwargs) -> SourceGateway:
    """The gateway for a source row and the key it will use. With a key, a
    source whose manifest has a ``keyed`` quota gets that rate, unless an admin
    has changed the row's rate from the keyless default. Either way the rate
    never exceeds the ceiling of the quota in use (keyed with a key, keyless
    without), so a stored rate can't outrun the source, and the quota in use
    sets the concurrency cap. Without a key, a source that requires one gets a
    gateway that sends nothing."""
    cls = SOURCE_REGISTRY.get(source.source_type, Source)
    rate_limit_config = source.rate_limit_config
    quota = getattr(cls, "quota", None)
    in_use = quota_in_use(cls, api_key)
    if in_use:
        if in_use is quota.keyed and rate_limit_config == quota.rate_limit_config:
            rate_limit_config = in_use.rate_limit_config
        rate_limit_config = _within_ceiling(rate_limit_config or {}, in_use)
        kwargs.setdefault("concurrency", in_use.concurrency)
    return SourceGateway(
        source.source_type,
        rate_limit_config=rate_limit_config,
        daily_budget=source.daily_budget,
        api_key=api_key,
        shared_key_group=cls.shared_key_group,
        throttle_statuses=cls.throttle_statuses,
        requires_key=cls.requires_api_key,
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
            if not job.counts:
                entry["counts"] = False
            jobs[job.key] = entry
    return jobs


def adapter_for_source(source: EnrichmentSource, api_key: str | None) -> EnrichmentAdapter:
    """The source's adapter, wired to its gateway."""
    return get_adapter(
        source.source_type, api_key=api_key, config=source.config, gateway=source_gateway(source, api_key)
    )
