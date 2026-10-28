"""Catalog sources: no per-entity lookup, only scheduled jobs that download a
whole file or feed. Each has an enrichment_sources row for its gateway (rate,
budget, breaker) and its on/off switch."""

from app import entity_types
from app.enrichment.base import Source
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota, Relation


class MISPGalaxySource(Source):
    source_type = "misp_galaxy"
    display_name = "MISP Galaxy"
    applies_to = {"threat_actor": None}
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


class MetasploitSource(Source):
    source_type = "metasploit"
    display_name = "Metasploit modules"
    applies_to = {"cve": None}
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


class MITRECWESource(Source):
    source_type = "mitre_cwe"
    display_name = "MITRE CWE"
    applies_to = {"cwe": None}
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
    applies_to = {"threat_actor": None}
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
    applies_to = {"threat_actor": None, "malware": None}
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
    applies_to = {"observable": ("domain",)}
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
        Column("rank", "observable.popularity_rank", Policy.NEWER_WINS),
        Context("rank", "Tranco rank", Display.FACT),
    )
