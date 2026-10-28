"""Catalog sources: no per-entity lookup, only scheduled jobs that download a
whole file or feed. Each has an enrichment_sources row for its gateway (rate,
budget, breaker) and its on/off switch."""

from app.enrichment.base import Source
from app.enrichment.manifest import Egress, Job, License, Quota


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
    # ransomware.live allows about one call a minute per endpoint, and a sync
    # makes two (/groups, /recentvictims) every 30 minutes: 96 a day.
    quota = Quota(2, 60, daily_budget=200, ceiling_per_period=2)
    egress = Egress.NONE
    # The free API is for non-commercial use; commercial use is ransomware.live PRO.
    license = License("ransomware.live API terms", attribution="ransomware.live", commercial_ok=False)
    jobs = (
        Job(
            "sync-ransomware-victims",
            "app.workers.intel_feed_tasks.sync_ransomware_victims",
            {"type": "interval", "seconds": 1800},
            "Collect ransomware leak-site victim postings",
        ),
    )


class CybergeistSource(Source):
    source_type = "cybergeist"
    display_name = "Cybergeist"
    applies_to = {"threat_actor": None, "malware": None}
    # Two files a day.
    quota = Quota(10, 3600, daily_budget=50)
    egress = Egress.NONE
    # The public feed publishes no license.
    license = License("Cybergeist public feed (no published license)", attribution="Cybergeist", commercial_ok=False)
    jobs = (
        Job(
            "sync-cybergeist-feeds",
            "app.workers.intel_feed_tasks.sync_cybergeist_feeds",
            {"type": "crontab", "minute": "30", "hour": "2"},
            "Sync threat actor and malware feeds from Cybergeist",
        ),
    )
