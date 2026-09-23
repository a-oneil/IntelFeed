"""Pre-configured GitHub repository templates for detection engineering feeds.

Provides ``DETECTION_REPO_TEMPLATES`` — a list of well-known detection rule
repositories with sensible defaults for path filters, content types, and
polling intervals.  Used by the bulk-setup API endpoint to let users subscribe
to all major detection repos in one click.
"""

from __future__ import annotations

DETECTION_REPO_TEMPLATES: list[dict] = [
    {
        "owner": "SigmaHQ",
        "repo": "sigma",
        "branch": "master",
        "paths": ["rules/**/*.yml"],
        "label": "SigmaHQ Detection Rules",
        "description": "Community Sigma rules for SIEM detection",
        "content_types": ["sigma_rule"],
    },
    {
        "owner": "elastic",
        "repo": "detection-rules",
        "paths": ["rules/**/*.toml"],
        "label": "Elastic Detection Rules",
        "description": "Elastic Security detection rules (EQL/KQL/ES|QL)",
        "content_types": ["elastic_rule"],
    },
    {
        "owner": "splunk",
        "repo": "security_content",
        "branch": "develop",
        "paths": ["detections/**/*.yml", "stories/**/*.yml"],
        "label": "Splunk Security Content",
        "description": "Splunk security detections and analytic stories",
        "content_types": ["splunk_detection"],
    },
    {
        "owner": "LOLBAS-Project",
        "repo": "LOLBAS",
        "branch": "master",
        "paths": ["yml/**/*.yml"],
        "label": "LOLBAS Project",
        "description": "Living Off The Land Binaries, Scripts and Libraries",
        "content_types": ["lolbas_entry"],
    },
    {
        "owner": "infosecB",
        "repo": "LOOBins",
        "paths": ["LOOBins/**/*.yml"],
        "label": "LOOBins (macOS)",
        "description": "Living Off the Orchard — macOS binaries for attack",
        "content_types": ["loobin_entry"],
    },
    {
        "owner": "magicsword-io",
        "repo": "LOLDrivers",
        "branch": "main",
        "paths": ["yaml/**/*.yaml"],
        "label": "LOLDrivers",
        "description": "Living Off The Land Drivers — vulnerable/malicious drivers",
        "content_types": ["loldriver_entry"],
    },
    {
        "owner": "redcanaryco",
        "repo": "atomic-red-team",
        "branch": "master",
        "paths": ["atomics/**/T*.yaml"],
        "label": "Atomic Red Team",
        "description": "Small, portable detection tests mapped to MITRE ATT&CK",
        "content_types": ["atomic_test"],
    },
    {
        "owner": "Neo23x0",
        "repo": "signature-base",
        "branch": "master",
        "paths": ["yara/**/*.yar"],
        "label": "Neo23x0 YARA Signatures",
        "description": "Florian Roth's YARA signature collection",
        "content_types": ["yara_rule"],
    },
    {
        "owner": "Azure",
        "repo": "Azure-Sentinel",
        "branch": "master",
        "paths": ["Detections/**/*.yaml"],
        "label": "Microsoft Sentinel Detections",
        "description": "Microsoft Sentinel community detection rules (KQL)",
        "content_types": ["sentinel_rule"],
    },
    {
        "owner": "projectdiscovery",
        "repo": "nuclei-templates",
        "paths": ["**/*.yaml"],
        "label": "Nuclei Templates",
        "description": "ProjectDiscovery Nuclei vulnerability scan templates",
        "content_types": ["nuclei_template"],
    },
    {
        "owner": "chronicle",
        "repo": "GCTI",
        "paths": ["YARA/**/*.yar", "YARA/**/*.yara"],
        "label": "Google Cloud Threat Intel YARA",
        "description": "Google GCTI YARA rules for malware detection",
        "content_types": ["yara_rule"],
    },
    {
        "owner": "panther-labs",
        "repo": "panther-analysis",
        "branch": "develop",
        "paths": ["rules/**/*.py"],
        "label": "Panther Detection Rules",
        "description": "Panther detection-as-code rules (Python)",
        "content_types": ["panther_rule"],
    },
    {
        "owner": "mdecrevoisier",
        "repo": "SIGMA-detection-rules",
        "paths": ["**/*.yml"],
        "label": "mdecrevoisier Sigma Rules",
        "description": "350+ custom ATT&CK-mapped Sigma rules (Windows, AD, network)",
        "content_types": ["sigma_rule"],
    },
    {
        "owner": "Yara-Rules",
        "repo": "rules",
        "branch": "master",
        "paths": ["**/*.yar", "**/*.yara"],
        "label": "Community YARA Rules",
        "description": "Community-maintained YARA rule repository",
        "content_types": ["yara_rule"],
    },
    {
        "owner": "WithSecureLabs",
        "repo": "iocs",
        "branch": "master",
        "paths": ["**/*.yar", "**/*.yml"],
        "label": "WithSecure IOCs & Rules",
        "description": "WithSecure threat intelligence IOC and rule drops",
        "content_types": ["yara_rule", "yaml_file"],
    },
    {
        "owner": "montysecurity",
        "repo": "C2-Tracker",
        "paths": ["**/*.txt", "**/*.csv"],
        "label": "C2-Tracker",
        "description": "Live C2 server tracking (Cobalt Strike, Sliver, Havoc, Brute Ratel)",
        "content_types": ["ioc_list"],
    },
    {
        "owner": "drb-ra",
        "repo": "C2IntelFeeds",
        "branch": "master",
        "paths": ["**/*.txt", "**/*.csv"],
        "label": "C2IntelFeeds",
        "description": "Auto-generated C2 IPs and domains from Censys scans",
        "content_types": ["ioc_list"],
    },
    {
        "owner": "MBCProject",
        "repo": "mbc-markdown",
        "paths": ["**/*.md"],
        "label": "Malware Behavior Catalog",
        "description": "Malware-specific behavioral objectives mapped to ATT&CK",
        "content_types": ["markdown_file"],
    },
]


def get_template_feed_configs(
    *,
    backfill_days: int = 90,
    watch_mode: str = "commits",
    include_content: bool = True,
    interval_minutes: int = 1440,
) -> list[dict]:
    """Return a list of feed creation configs ready for the feeds API.

    Each dict contains the fields needed by the ``FeedCreateRequest`` schema
    for extended adapter creation.
    """
    configs = []
    for tmpl in DETECTION_REPO_TEMPLATES:
        url = f"https://github.com/{tmpl['owner']}/{tmpl['repo']}"
        configs.append(
            {
                "url": url,
                "feed_type": "github_repo",
                "custom_title": tmpl["label"],
                "fetch_interval_minutes": interval_minutes,
                "intel_extraction_mode": "full",
                "adapter_config": {
                    "owner": tmpl["owner"],
                    "repo": tmpl["repo"],
                    "branch": tmpl.get("branch", "main"),
                    "paths": tmpl["paths"],
                    "include_content": include_content,
                    "watch_mode": watch_mode,
                    "backfill_days": backfill_days,
                },
            }
        )
    return configs
