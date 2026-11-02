"""Catalog sources: no per-entity lookup, only scheduled jobs that download a
whole file or feed. Each has an enrichment_sources row for its gateway (rate,
budget, breaker) and its on/off switch."""

import uuid
from datetime import datetime, timedelta

from sqlalchemy import all_, bindparam, delete, func, select
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.enrichment.base import Source
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Match, Policy, Quota, Relation


class MISPGalaxySource(Source):
    source_type = "misp_galaxy"
    display_name = "MISP Galaxy"
    about = "The MISP community's threat-actor catalog: countries, motives and targeted sectors."
    applies_to = {entity_types.THREAT_ACTOR: None}
    # One file a week from raw.githubusercontent.com.
    quota = Quota(10, 3600, daily_budget=50)
    egress = Egress.NONE
    license = License("CC0 1.0 or BSD 2-Clause", attribution="MISP Galaxy")
    jobs = (
        Job(
            "misp-galaxy-sync",
            "app.workers.enrichment_tasks.run_misp_galaxy_sync",
            {"type": "crontab", "minute": "30", "hour": "3", "day_of_week": "0"},
            "Refresh the reference alias knowledge from the MISP Galaxy threat-actor cluster",
        ),
    )
    # A cluster fills only what an actor's profile leaves blank; its synonyms
    # stay resolution knowledge (known_alias_map), never profile aliases.
    outputs = (
        Column("country", "threat_actor.country", resolve="country"),
        Column("motivation", "threat_actor.motivation", filter="motivation"),
        # Below Wikipedia, ATT&CK and Malpedia: it fills a blank and yields to them.
        Column("description", "threat_actor.description", Policy.RANK, rank=4),
        Relation("sectors", "targets", (entity_types.SECTOR,)),
    )


class MetasploitSource(Source):
    source_type = "metasploit"
    display_name = "Metasploit modules"
    about = "Which CVEs have a Metasploit module: shipped, weaponized exploit code."
    applies_to = {entity_types.CVE: None}
    # One file a week from raw.githubusercontent.com.
    quota = Quota(10, 3600, daily_budget=50)
    egress = Egress.NONE
    license = License("BSD 3-Clause", attribution="Rapid7 Metasploit Framework")
    jobs = (
        Job(
            "metasploit-sync",
            "app.workers.enrichment_tasks.run_metasploit_sync",
            {"type": "crontab", "minute": "45", "hour": "3", "day_of_week": "0"},
            "Map tracked CVEs to Metasploit modules and escalate weaponized exploit status",
        ),
    )
    outputs = (
        Column("module", "cve.metasploit_module", Policy.NEWER_WINS),
        Context("modules", "Metasploit modules", Display.CHIPS),
    )

    @staticmethod
    async def apply_record(db, entity_type: str, entity_id, data, cache: dict) -> None:
        """Adds Metasploit to the CVE's ``exploit_sources`` list, once."""
        from app.intelligence.external_feeds import coerce_exploit_sources
        from app.models.cve import CVE

        module = (data.parsed_data or {}).get("module")
        cve = await db.get(CVE, entity_id) if entity_type == entity_types.CVE and module else None
        if cve is None:
            return
        sources = coerce_exploit_sources(cve.exploit_sources)
        if not any(s.get("source") == "metasploit" for s in sources):
            sources.append({"source": "metasploit", "module": module})
        if sources != list(cve.exploit_sources or []):
            # Rows stored as bare strings are rewritten as dicts.
            cve.exploit_sources = sources


class MITRECWESource(Source):
    source_type = "mitre_cwe"
    display_name = "MITRE CWE"
    about = "MITRE's catalog of software weakness types."
    applies_to = {entity_types.CWE: None}
    # One 2 MB zip a week.
    quota = Quota(10, 3600, daily_budget=50)
    egress = Egress.NONE
    license = License("CWE terms of use", attribution="CWE™ is a trademark of The MITRE Corporation")
    jobs = (
        Job(
            "refresh-cwe-catalog",
            "app.workers.intel_feed_tasks.refresh_cwe_catalog",
            {"type": "crontab", "minute": "45", "hour": "3", "day_of_week": "1"},
            "Re-pull the MITRE CWE catalog and re-resolve unmatched NVD weakness refs",
        ),
    )


class RansomwareLiveSource(Source):
    source_type = "ransomware_live"
    display_name = "ransomware.live"
    about = "ransomware.live's profiles of ransomware groups: tools, leak sites and notes."
    applies_to = {entity_types.THREAT_ACTOR: None}
    # ransomware.live allows about one call a minute per endpoint. The victim
    # sync makes two (/groups, /recentvictims) every 30 minutes, 96 a day; the
    # group profiles at most 10 every four hours, 60 a day.
    quota = Quota(2, 60, daily_budget=200, ceiling_per_period=2)
    egress = Egress.NONE
    # Free for research, awareness and open-source use with attribution;
    # commercial use needs the owner's written approval:
    # https://www.ransomware.live/t&c
    license = License("ransomware.live API terms", attribution="ransomware.live", commercial_ok=False)
    jobs = (
        Job(
            "sync-ransomware-victims",
            "app.workers.intel_feed_tasks.sync_ransomware_victims",
            {"type": "interval", "seconds": 1800},
            "Collect ransomware leak-site victim postings",
            counts=False,
        ),
        Job(
            "ransomware-group-profiles",
            "app.workers.enrichment_tasks.run_ransomware_group_profiles",
            {"type": "crontab", "minute": "50", "hour": "*/4"},
            "Refresh tracked ransomware groups' techniques, tools and leak-site status from ransomware.live",
        ),
    )
    outputs = (
        Relation(
            "techniques",
            "uses",
            (entity_types.TTP,),
            item={"name": "technique_id", "evidence": "technique_details"},
        ),
        Relation("tools", "uses", (entity_types.TOOL,), item={"name": "name"}),
        Context("description", "Description", Display.FACT),
        Context("tools_by_category", "Tools", Display.TABLE, item={"Category": "category", "Tools": "tools"}),
        Context("leak_sites", "Leak sites", Display.TABLE, item={"Type": "type", "Status": "status"}),
        Context("page", "Group page", Display.LINK),
    )


class CybergeistSource(Source):
    source_type = "cybergeist"
    display_name = "Cybergeist"
    about = "Cybergeist's public threat-actor and malware feeds."
    applies_to = {entity_types.THREAT_ACTOR: None, entity_types.MALWARE: None}
    # Two files a day.
    quota = Quota(10, 3600, daily_budget=50)
    egress = Egress.NONE
    # The public feed (pubbucket.cybergeist.io) publishes no license or terms,
    # and cybergeist.io serves none (checked 2026-10-28), so nothing grants
    # commercial reuse.
    license = License("Cybergeist public feed (no published license)", attribution="Cybergeist", commercial_ok=False)
    jobs = (
        Job(
            "sync-cybergeist-feeds",
            "app.workers.intel_feed_tasks.sync_cybergeist_feeds",
            {"type": "crontab", "minute": "30", "hour": "2"},
            "Sync threat actor and malware feeds from Cybergeist",
        ),
    )


class TrancoSource(Source):
    source_type = "tranco"
    display_name = "Tranco"
    about = "A daily ranking of the top million domains. A top-10k domain is likely benign."
    # A victim's site rank is a rough size signal: context only.
    applies_to = {entity_types.OBSERVABLE: ("domain",), entity_types.RANSOMWARE_VICTIM: Match(column="domain")}
    # A daily sync makes two requests: the latest list's id, then its CSV. The
    # API allows one query a second (https://tranco-list.eu/api_documentation).
    quota = Quota(1, 1, daily_budget=20, ceiling_per_period=1)
    egress = Egress.NONE
    # Tranco asks to be cited (Le Pochat et al., NDSS 2019); its inputs are
    # Cisco Umbrella (free), Majestic (CC BY 3.0), Farsight, the Chrome UX
    # Report (CC BY-SA 4.0) and Cloudflare Radar (CC BY 4.0) (https://tranco-list.eu/).
    license = License(
        "Tranco list; inputs under CC BY 3.0, CC BY-SA 4.0 and CC BY 4.0",
        attribution="Tranco (Le Pochat et al., NDSS 2019)",
    )
    jobs = (
        Job(
            "tranco-sync",
            "app.workers.enrichment_tasks.run_tranco_sync",
            {"type": "crontab", "minute": "20", "hour": "4"},
            "Rank tracked domains against the daily Tranco top-1M list and flag top-10k ones for review",
        ),
    )
    outputs = (
        # A domain that drops out of the list is answered "not found": the rank clears.
        Column("rank", "observable.popularity_rank", Policy.NEWER_WINS, clears=True),
        Context("rank", "Tranco rank", Display.FACT),
    )


# ── Tranco: victims ──────────────────────────────────────────────────
# The daily Tranco job ranks the ledger's domains; these rank ransomware
# victims' domains from the same streamed list, as profile context only (no
# column, no review flag: a popular victim is no reason to doubt it).


async def tranco_victim_matches(db: AsyncSession, batch: dict[str, int]) -> dict[uuid.UUID, int]:
    """The victims whose domain (``www.`` aside, any case) is among ``batch``
    (domain → rank), as id → rank."""
    from app.models.ransomware import RansomwareVictim

    host = func.regexp_replace(func.lower(RansomwareVictim.domain), r"^www\.", "")
    rows = await db.execute(select(RansomwareVictim.id, host).where(host.in_(list(batch))))
    return {vid: batch[domain] for vid, domain in rows}


async def write_tranco_victim_ranks(
    db: AsyncSession, matched: dict[uuid.UUID, int], now: datetime, ttl: timedelta
) -> int:
    """Store today's rank for each matched victim and drop the rank of victims
    no longer listed. Returns the victims ranked."""
    from app.models.enrichment import EntityContext

    stale = delete(EntityContext).where(
        EntityContext.entity_type == entity_types.RANSOMWARE_VICTIM,
        EntityContext.source_type == TrancoSource.source_type,
    )
    if matched:
        # One array bind however many victims rank (an IN list binds each).
        ids = bindparam(None, list(matched), type_=ARRAY(UUID(as_uuid=True)))
        stale = stale.where(EntityContext.entity_id != all_(ids))
    await db.execute(stale)
    rows = [
        {
            "entity_type": entity_types.RANSOMWARE_VICTIM,
            "entity_id": vid,
            "source_type": TrancoSource.source_type,
            "key": "rank",
            "value": rank,
            "observed_at": now,
            "expires_at": now + ttl,
        }
        for vid, rank in matched.items()
    ]
    for start in range(0, len(rows), 5000):
        insert = pg_insert(EntityContext).values(rows[start : start + 5000])
        await db.execute(
            insert.on_conflict_do_update(
                index_elements=["entity_type", "entity_id", "source_type", "key"],
                set_={
                    "value": insert.excluded.value,
                    "observed_at": insert.excluded.observed_at,
                    "expires_at": insert.excluded.expires_at,
                },
            )
        )
    return len(rows)
