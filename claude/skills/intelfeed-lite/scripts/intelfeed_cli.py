#!/usr/bin/env python3
"""CLI for IntelFeed API (lite, read-only) — used by Claude skills to query IntelFeed.

Executes one or more read-only tool calls against the running IntelFeed API and
prints JSON results to stdout. Zero external dependencies — stdlib only.

Environment variables:
    INTELFEED_API_URL       Base URL of your IntelFeed instance (required); https://, or http://localhost
    INTELFEED_ALLOW_INSECURE_HTTP  1 to allow plain http:// to another host (a trusted LAN or compose network)
    INTELFEED_USERNAME      Username for authentication
    INTELFEED_PASSWORD      Password for authentication
    INTELFEED_NO_TOKEN_CACHE  1 to log in on every run instead of reusing ~/.cache/intelfeed/token-*.json
    INTELFEED_DEBUG         1 to print login/cache steps to stderr

Usage:
    # Single tool call
    python intelfeed_cli.py search_entries '{"query": "ransomware", "limit": 5}'

    # Tool call with no arguments
    python intelfeed_cli.py get_dashboard_stats

    # Multiple tool calls in one invocation
    python intelfeed_cli.py search_entries '{"query": "APT29"}' get_feeds '{"limit": 10}'

    # List available tools
    python intelfeed_cli.py --list-tools

    # Show help for a specific tool
    python intelfeed_cli.py --help-tool search_entries
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL = os.environ.get("INTELFEED_API_URL", "").strip().rstrip("/")
USERNAME = os.environ.get("INTELFEED_USERNAME", "")
PASSWORD = os.environ.get("INTELFEED_PASSWORD", "")
# Tokens are kept in ~/.cache/intelfeed/ between runs unless this is set.
TOKEN_CACHE_ENABLED = os.environ.get("INTELFEED_NO_TOKEN_CACHE", "").strip().lower() not in ("1", "true", "yes", "on")
DEBUG = os.environ.get("INTELFEED_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
# On a 429 from login/refresh, a Retry-After up to this many seconds is waited out once.
MAX_RETRY_AFTER_SLEEP = 60


def _debug(message: str) -> None:
    if DEBUG:
        print(f"[intelfeed-cli] {message}", file=sys.stderr)


def insecure_url_problem(url: str) -> str | None:
    """Why the CLI must not send the password to ``url``, or None.

    The login posts the password, so the API must be https://, or plain http://
    to this machine. INTELFEED_ALLOW_INSECURE_HTTP=1 opts in for a trusted
    network (a LAN dev box, the compose network). Same rule as intelfeed-mcp.
    """
    from urllib.parse import urlsplit

    if not url:
        return "INTELFEED_API_URL is not set. Point it at your instance, e.g. https://intelfeed.example.com."
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return None
    if parts.scheme == "http" and parts.hostname:
        allow = os.environ.get("INTELFEED_ALLOW_INSECURE_HTTP", "").strip().lower() in ("1", "true", "yes", "on")
        if parts.hostname in ("localhost", "127.0.0.1", "::1") or allow:
            return None
        return (
            f"INTELFEED_API_URL {url} is plain http:// to another host, which would send the password "
            "unencrypted. Use https://, or set INTELFEED_ALLOW_INSECURE_HTTP=1 for a trusted network."
        )
    return f"INTELFEED_API_URL {url!r} must start with https:// (or http://localhost)."

# ---------------------------------------------------------------------------
# Tool definitions (read-only: search, get, list, discover, pivot, check)
# ---------------------------------------------------------------------------

TOOLS: dict[str, dict] = {
    "check_detection_gaps": {
        "description": (
            "ATT&CK coverage analysis: observed TTPs compared with non-draft detection rules, with a "
            "summary per tactic and the list of uncovered techniques. Covers TTPs only, not CVEs."
        ),
        "params": {},
    },
    "check_requirement_match": {
        "description": (
            "Check an entry against all active intelligence requirements with the matching code the "
            "pipeline uses: linked-entity matches first, then keyword matches in the title and body, "
            "filtered by each requirement's min_relevance and feed filter. Read-only: stores nothing. "
            "Also returns the matches the pipeline already stored for this entry."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "check_telemetry_feasibility": {
        "description": (
            "Check whether detection rules can run on the configured telemetry sources. Lists the log "
            "sources a rule needs and which of them are available."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "detect_glossary_terms": {
        "description": (
            "Detect which glossary terms appear in an entry's text (word-boundary matching over each "
            "term's name and search-term aliases). Returns matched terms with per-term match counts, "
            "highest first. Takes an entry UUID, not raw text, because the API only accepts an entry."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "discover_telegram_channels": {
        "description": (
            "List every Telegram channel the IntelFeed bootstrap account has joined. is_subscribed "
            "says whether IntelFeed already ingests the channel. Use this to find channels joined in "
            "the Telegram client app that are not yet set up as IntelFeed feeds."
        ),
        "params": {
            "session_name": {
                "type": 'str',
                "default": None,
            },
            "only_unsubscribed": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "export_observables": {
        "description": (
            "Export a filtered set of observables as lines (EDL), CSV rows or JSON. Takes the same "
            "filters as search_observables, plus a minimum report count and a switch to include "
            "dual-use infrastructure. Values are returned refanged (usable form). Denied rows are "
            "always excluded, and infra-tagged rows are excluded by default."
        ),
        "params": {
            "format": {
                "type": 'str',
                "default": 'edl',
                "enum": ['edl', 'csv', 'json'],
            },
            "kind": {
                "type": 'str',
                "default": None,
            },
            "role": {
                "type": 'str',
                "default": None,
            },
            "status": {
                "type": 'str',
                "default": None,
            },
            "min_confidence": {
                "type": 'float',
                "default": None,
            },
            "min_reports": {
                "type": 'int',
                "default": None,
            },
            "include_infra_tagged": {
                "type": 'bool',
                "default": False,
            },
            "query": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_analytics": {
        "description": (
            "Get platform analytics: trending entities, intelligence velocity, detection coverage "
            "gaps, and overview stats."
        ),
        "params": {
            "metric": {
                "type": 'str',
                "required": True,
                "enum": ['overview', 'trending', 'detection_coverage', 'velocity'],
            },
            "entity_type": {
                "type": 'str',
                "default": None,
            },
            "days": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_attack_layer": {
        "description": (
            "Get MITRE ATT&CK Navigator layer JSON for a specific entry's TTPs. Without entry_id, the "
            "layer covers all observed techniques: those linked to at least one entry, excluding "
            "deprecated catalog techniques."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "title": {
                "type": 'str',
                "default": 'IntelFeed ATT&CK Coverage',
            },
        },
    },
    "get_automation_logs": {
        "description": 'Get recent automation execution logs.',
        "params": {
            "rule_id": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_automation_rules": {
        "description": 'List automation rules with optional label filter.',
        "params": {
            "label": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_automation_templates": {
        "description": 'List pre-built automation rule templates with categories.',
        "params": {},
    },
    "get_campaign": {
        "description": 'Get campaign details with timeline, linked entries, linked entities, and detection gaps.',
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_campaign_attack_layer": {
        "description": 'Get MITRE ATT&CK Navigator layer JSON for all TTPs linked to a campaign.',
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_campaign_detection_gaps": {
        "description": (
            "Telemetry-aware detection coverage for a campaign's TTPs: covered, library_only (rules "
            "blocked by missing telemetry), and gaps (no rule)."
        ),
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_campaign_timeline": {
        "description": 'Get chronological entries in a campaign, sorted by publication date.',
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_campaigns": {
        "description": 'List campaigns with optional status filter.',
        "params": {
            "status": {
                "type": 'str',
                "default": None,
                "enum": ['active', 'monitoring', 'closed', 'historical'],
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_correlation_events": {
        "description": (
            "Get recent correlation events: coverage gaps, trending entities, campaign and "
            "requirement matches, new TTPs/malware for known actors or malware, actor-malware "
            "co-occurrence, feed staleness/errors, exploit and CVE score changes, and KEV additions."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 30,
            },
            "unread_only": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "get_coverage_workspace": {
        "description": (
            "Detection coverage workspace for one threat (actor, malware, CVE or ATT&CK technique) "
            "over a window: its recent articles and the behaviours extracted from them, each with the "
            "quote it came from, the telemetry channels it needs and whether enabled telemetry can "
            "see it. A behaviour flagged below_line has no matching telemetry: a sourcing gap, not a "
            "detection gap."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": ['threat_actor', 'malware', 'cve', 'ttp'],
            },
            "entity_key": {
                "type": 'str',
                "required": True,
            },
            "window": {
                "type": 'str',
                "default": '14d',
                "enum": ['7d', '14d', '30d', '90d', 'all'],
            },
        },
    },
    "get_cve": {
        "description": (
            "Get CVE details including CVSS/EPSS scores, severity, CISA KEV status, GitHub PoC and "
            "Metasploit availability, structured NVD affected vendor/product links, NVD weakness "
            "(CWE) assignments, and linked article count."
        ),
        "params": {
            "cve_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_cwe": {
        "description": (
            "Get a MITRE CWE weakness by ID, including its abstraction level "
            "(Pillar/Class/Base/Variant), parent and lineage, MITRE mapping guidance, catalog "
            "mitigations and detection methods, how many CVEs carry it directly and across its whole "
            "subtree, how many of those are in CISA KEV, and linked article count."
        ),
        "params": {
            "cwe_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_daily_summary": {
        "description": (
            "Return the cached AI daily summary (briefing) for a day, or null if none has been "
            "generated. date is YYYY-MM-DD, defaulting to today (UTC). Read-only: this never "
            "generates a summary. Summaries are generated by the daily_summary AI task or an "
            "automation."
        ),
        "params": {
            "date": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "get_dashboard_stats": {
        "description": (
            "Get system-wide statistics: total entries, feeds, detection rules, counts for every "
            "entity type (ttp = observed techniques with linked articles; full catalog size in "
            "ttp_catalog_size), and recent activity (entries in the last 24h/7d)."
        ),
        "params": {},
    },
    "get_detection_rule": {
        "description": (
            "Get one detection rule with its full content, provenance (source repo, author, license, "
            "references), draft or published status, whether the enabled telemetry sources can "
            "support it, and a syntax validation summary."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_detection_rule_versions": {
        "description": (
            "List a detection rule's saved versions, newest first. A version is saved each time "
            "rule_content changes and before each rollback."
        ),
        "params": {
            "rule_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_detection_rules": {
        "description": (
            "List detection rules. Optionally filter by rule type (aql, crowdstrike_ql, elastic_ql, "
            "kql, nuclei, panther, sigma, snort_suricata, splunk_spl, sql, sumo, yara, yaral)."
        ),
        "params": {
            "rule_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'aql',
                    'crowdstrike_ql',
                    'elastic_ql',
                    'kql',
                    'nuclei',
                    'panther',
                    'sigma',
                    'snort_suricata',
                    'splunk_spl',
                    'sql',
                    'sumo',
                    'yara',
                    'yaral',
                ],
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_documentation_page": {
        "description": (
            "Read one IntelFeed documentation page in full, as markdown. The slug is the path under "
            "docs/ without the .md suffix, e.g. 'architecture', 'user-guide' or "
            "'diagrams/entry-pipeline'. Cite the page you used as a /documentation/<slug> link."
        ),
        "params": {
            "slug": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_enrichment_data": {
        "description": (
            "Get enrichment results stored on an entity: CVE (EPSS, KEV, GitHub PoCs, Metasploit, NVD "
            "data), malware (Malpedia, Wikipedia), threat actor (Wikipedia), or TTP (Wikipedia)."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": ['cve', 'malware', 'threat_actor', 'ttp'],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entity_graph": {
        "description": (
            "Build a relationship graph centered on an entity. Edges are typed relationship records "
            "(verb, direction, confidence, provenance) at confirmed or reported confidence. Entities "
            "that only appear in the same articles are not connected. Co-occurrence data only adds "
            "proximity and evidence articles to edges."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'cwe',
                    'malware',
                    'mitigation',
                    'observable',
                    'product',
                    'sector',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "depth": {
                "type": 'int',
                "default": 1,
            },
            "window_days": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_entity_infrastructure": {
        "description": (
            "Pivot from a threat actor, malware family, campaign or tool to its observables, in two "
            "tiers. 'claimed': attribution edges with evidence (uses, communicates_with, controls), "
            "each with a trust tier. 'reported_alongside': observables in articles that name the "
            "entity, excluding indicator-list files and newsletters. Answers 'what infrastructure "
            "does X use?'."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": ['threat_actor', 'malware', 'campaign', 'tool'],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_entity_link_stats": {
        "description": (
            "Autolinking counts: entry\u2192entity links by entity type and by source, the number of held "
            "matches (pending autolinks) waiting for their article's AI analysis, and the number of "
            "entity\u2194entity relationships that are not rejected."
        ),
        "params": {},
    },
    "get_entity_timeline": {
        "description": 'Get a chronological timeline of the articles an entity appeared in.',
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'cwe',
                    'malware',
                    'mitigation',
                    'observable',
                    'product',
                    'sector',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entity_whats_new": {
        "description": (
            "Latest developments for one entity: recent novelty and severity signals (first mention, "
            "new technique, new victim sector, exploitation news, ...) on articles linked to it. "
            "scoped=true keeps only signals whose subject is this entity, as the profile page does."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "days": {
                "type": 'int',
                "default": 14,
            },
            "scoped": {
                "type": 'bool',
                "default": True,
            },
        },
    },
    "get_entry": {
        "description": (
            "Fetch a single RSS entry by ID with its content and all extracted intelligence: TTPs, "
            "CVEs, CWEs, threat actors, malware, tools, vendors, products, countries, and "
            "mitigations. The body comes back one window at a time, but the entities cover the whole "
            "article \u2014 when `truncated` is true, call again with `offset` set to `next_offset` to "
            "read the rest."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
            "max_chars": {
                "type": 'int',
                "default": 8000,
            },
        },
    },
    "get_entry_graph": {
        "description": 'Get the relationship graph for all entities linked to one entry.',
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry_insights": {
        "description": (
            "Get follow-up findings for one entry's TTPs, CVEs and threat actors: detection gaps (no "
            "active rule), campaign matches, intelligence requirement matches, and critical CVEs. Up "
            "to 10, sorted by severity."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry_story": {
        "description": (
            "List earlier and follow-up articles linked to an entry by shared entities. Within 30 "
            "days before or after the entry, an entry is included if it shares at least one CVE, "
            "threat actor or malware, or any two entities of any type. Results are in date order, not "
            "ranked by relevance. For relevance ranking use get_similar_entries."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_extraction_stats": {
        "description": (
            "Counts for AI-created entities (created_via='ai_extraction': threat actors, malware, "
            "tools, CVEs, TTPs): totals by type, the number that need review, are orphaned, are "
            "likely duplicates or were auto-confirmed, and how many were created in the requested "
            "window and in the window before it."
        ),
        "params": {
            "window": {
                "type": 'str',
                "default": '7d',
                "enum": ['1h', '24h', '30d', '7d', 'all'],
            },
        },
    },
    "get_feed_entries": {
        "description": 'List recent entries from a specific feed.',
        "params": {
            "feed_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "get_feed_value": {
        "description": (
            "Get feed value scores: a composite 0-100 score per feed for how much intelligence its "
            "entries contribute (entity yield, new entities, correlation events, detection rules, "
            "requirement matches)."
        ),
        "params": {
            "days": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "get_feeds": {
        "description": (
            "List configured feeds of any registered adapter type (atom, bluesky, github_advisories, "
            "github_releases, github_repo, mastodon, nvd, podcast, reddit, rss, telegram, "
            "web_scraper, youtube) with health status."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "get_hygiene_feed": {
        "description": (
            "Entity cleanup log in time order: the entity-link log and the entity-maintenance log "
            "merged into one shape (action, mode, applied, subject, reason, affected-entity links, "
            "origin). Filter by action code (comma-separated for several), log source, mode, origin "
            "(adjudicator = filed by the adjudicate stage, merge_review = the duplicate review, scan "
            "= the on-demand scans), pending only, or a since timestamp. Read-only. Proposals are "
            "applied or dismissed in the Proposals queue."
        ),
        "params": {
            "action": {
                "type": 'str',
                "default": None,
            },
            "source": {
                "type": 'str',
                "default": None,
                "enum": ['link_validator', 'entity_maintenance'],
            },
            "mode": {
                "type": 'str',
                "default": None,
                "enum": ['shadow', 'apply'],
            },
            "origin": {
                "type": 'str',
                "default": None,
                "enum": ['adjudicator', 'merge_review', 'scan'],
            },
            "pending": {
                "type": 'bool',
                "default": False,
            },
            "since": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "get_hygiene_stats": {
        "description": (
            "Entity cleanup counts from both proposal logs: the adjudicate stage's mode and how many "
            "of its verdicts are not applied yet, pending reclassify suggestions and name, alias, "
            "vendor and id proposals, the orphan entity count, last run times, and how many actions "
            "were applied in the last 24h and 7d."
        ),
        "params": {},
    },
    "get_ingest_batch": {
        "description": (
            "Status of one ingest batch: per-item status (queued / parsing / created / expanded / "
            "duplicate / no_text / unsupported / too_large / failed), the entry id each item "
            "produced, and a summary. Poll until summary.status is 'complete'. Created entries then "
            "go through the pipeline and the one-pass AI analysis, like any entry fetched from a "
            "feed."
        ),
        "params": {
            "batch_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_intel_profile": {
        "description": (
            "One intel profile with its countries (resolved names), sectors (labels) and other scope "
            "fields."
        ),
        "params": {
            "profile_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_intel_report": {
        "description": 'Get a single intel report including its full content (all sections, metadata, references).',
        "params": {
            "report_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_malware": {
        "description": (
            "Get malware family profile with aliases, type, targeted sectors, associated actors, and "
            "the count of linked articles (article_count)."
        ),
        "params": {
            "malware_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_observable": {
        "description": (
            "Look up an observable (a row in the observables list) by UUID or by its value (IP, "
            "domain, URL, hash, cmdline, registry key, ...). Returns kind, role, current and base "
            "confidence with decay state, sighting count, how it was added (AI analysis, the "
            "adjudicator, a curated IOC list feed, a publisher's IOC table, a TTP observable, or an "
            "analyst) with the evidence sentence, first and last seen, and the most recent articles "
            "it was seen in. Defanged input (evil[.]com, hxxps://) is normalized."
        ),
        "params": {
            "observable": {
                "type": 'str',
                "required": True,
            },
            "kind": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "get_priority_queue": {
        "description": (
            "The analyst's reading queue, as the Priority Queue page shows it: unread entries that "
            "meet the radar threshold, ranked by signal score. Articles in the same story thread are "
            "grouped into one row, so a story covered by eleven outlets is one item, not eleven. Use "
            "this for 'what should I read next' or 'what is important right now'. Prefer it over "
            "get_triage_queue, which uses the older heuristic and does not group stories."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": None,
            },
            "unread_only": {
                "type": 'bool',
                "default": None,
            },
            "with_threads": {
                "type": 'bool',
                "default": None,
            },
            "cursor": {
                "type": 'str',
                "default": None,
            },
        },
    },
    "get_profile_threat_surface": {
        "description": (
            "The threats to one intel profile: actors and malware active against its regions and "
            "verticals. Each has the evidence for the match (which region or sector, how many "
            "articles)."
        ),
        "params": {
            "profile_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 25,
            },
        },
    },
    "get_ransomware_disclosures": {
        "description": (
            "Ransomware leak-site victim disclosures (Leak Watch), newest first. Filters: group name, "
            "canonical sector slug, country (ISO code or name), posting age, substring search, and "
            "the user's watched victims and groups. sort is 'recent', 'group' or 'sector' (ties "
            "sorted newest first). Returns a paginated list. Empty when the ransomware tracker has "
            "not synced yet."
        ),
        "params": {
            "group": {
                "type": 'list[str]',
                "default": None,
            },
            "sector": {
                "type": 'list[str]',
                "default": None,
            },
            "country": {
                "type": 'list[str]',
                "default": None,
            },
            "watched_only": {
                "type": 'bool',
                "default": None,
            },
            "since": {
                "type": 'int',
                "default": None,
            },
            "q": {
                "type": 'str',
                "default": None,
            },
            "sort": {
                "type": 'str',
                "default": None,
                "enum": ['recent', 'group', 'sector'],
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
            "offset": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_ransomware_group_victims": {
        "description": (
            "Paginated list of victim organizations disclosed by a ransomware group (a ThreatActor), "
            "newest activity first. Returns an empty page if the actor has no tracked disclosures."
        ),
        "params": {
            "actor_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
            "offset": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_ransomware_stats": {
        "description": (
            "Ransomware Landscape totals for the last N days: victim totals with week-over-week "
            "change, a weekly time series, top groups (with week-over-week trend), top sectors, top "
            "countries, and new disclosures that involve the user's watched groups, organizations and "
            "sectors. All zero when the ransomware tracker has not synced yet."
        ),
        "params": {
            "days": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_ransomware_victim": {
        "description": (
            "Fetch one ransomware victim organization by UUID: name, domain, aliases, sector, "
            "country, first and last seen, whether the user watches it, the groups that listed it, "
            "and every leak-site disclosure."
        ),
        "params": {
            "victim_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_report_share_link": {
        "description": (
            "Return this user's active public share link for an intel report ({token, url, "
            "created_at, expires_at}), or null if they have not shared it. Other analysts' links are "
            "not returned."
        ),
        "params": {
            "report_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_requirement_coverage": {
        "description": (
            "Get an intelligence requirements coverage summary: counts by status, priority and "
            "category, plus stale (active requirements with no match in 30 days)."
        ),
        "params": {},
    },
    "get_requirements": {
        "description": 'Get intelligence requirements and their coverage status.',
        "params": {
            "status": {
                "type": 'str',
                "default": None,
                "enum": ['active', 'fulfilled', 'expired', 'draft'],
            },
        },
    },
    "get_review_rows": {
        "description": (
            "The pending proposals behind one Review group (or every pending row matching the "
            "filters), newest first. Each row has its id ('<source>:<log_id>', what decide_proposals "
            "takes), action, subject, reason, payload, and `context`: the article text around the "
            "match, so the article does not need to be fetched. Admin only."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "default": None,
            },
            "entity_id": {
                "type": 'str',
                "default": None,
            },
            "action": {
                "type": 'str',
                "default": None,
            },
            "origin": {
                "type": 'str',
                "default": None,
                "enum": ['adjudicator', 'merge_review', 'scan'],
            },
            "domain": {
                "type": 'str',
                "default": None,
                "enum": ['links', 'entities', 'relationships'],
            },
            "limit": {
                "type": 'int',
                "default": 200,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "get_search_facets": {
        "description": (
            "Get available search facets: feed types (feed count per type), categories (feed count "
            "per category), and top tags (by entry usage). Use it to see what the system holds before "
            "searching."
        ),
        "params": {},
    },
    "get_sector": {
        "description": (
            "Get a sector's victimology profile: description and aliases, who targets it (found in "
            "articles, and explicit targets-sector claims), campaigns scoped to it, leak-site victim "
            "totals and top ransomware groups, victims by country, the intel profiles that include "
            "it, and recent articles."
        ),
        "params": {
            "sector": {
                "type": 'str',
                "required": True,
            },
            "window_days": {
                "type": 'int',
                "default": 90,
            },
        },
    },
    "get_share_link": {
        "description": (
            "Return this user's active public share link for an entry ({token, url, created_at, "
            "expires_at}), or null if they have not shared it. Other analysts' share links for the "
            "same entry are not returned."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_similar_entries": {
        "description": (
            "Find entries similar to the given entry. When the entry has an embedding, uses the "
            "embedding index, which finds articles about the same story written in different words. "
            "Otherwise falls back to keyword search over the search index. Excludes the entry itself "
            "and its exact duplicates (same content hash)."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_source_reliability": {
        "description": (
            "Get feeds ranked by intelligence contribution: entity extractions across every entity "
            "junction type, plus detection rules generated from each feed's entries."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "get_stack_exposure": {
        "description": (
            "My Stack exposure board: every CVE that affects the vendors and products in the user's "
            "stack (watchlist mode='stack'). CVEs are ranked by exposure lift (KEV, EPSS and "
            "weaponization multipliers). Each has a detection state (defended, blind or no_rule) "
            "based on the configured telemetry sources. Also returns CVE counts per asset and counts "
            "for each urgency and detection state pair. Empty if the user has no vendors or products "
            "in their stack."
        ),
        "params": {},
    },
    "get_story_thread": {
        "description": (
            "Read one story thread. Returns its timeline (the spine field: one update per wave of "
            "coverage, saying what was first reported and what each later wave added), every member "
            "article with its role (origin, beat for an article that adds an update, or echo for a "
            "re-report grouped under another), the techniques, CVEs, products and detection rules "
            "found in the story, and the most similar threads. Open it in the UI at "
            "/priority-queue?thread=<slug>."
        ),
        "params": {
            "slug": {
                "type": 'str',
                "required": True,
            },
            "include_members": {
                "type": 'bool',
                "default": None,
            },
        },
    },
    "get_story_threads": {
        "description": (
            "List story threads. A story thread groups the articles that cover one developing story, "
            "with near-duplicate re-reports (echoes) grouped under it. Each row has its outlet count, "
            "article and echo counts, key entities, unread count, and the priority score of its "
            "highest-scoring unread article. Use this instead of searching for the same story many "
            "times."
        ),
        "params": {
            "status": {
                "type": 'str',
                "default": None,
                "enum": ['open', 'dormant', 'closed', 'any'],
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "get_telemetry_source_notes": {
        "description": (
            "Notes and saved documentation links about one telemetry source (e.g. 'AWS GuardDuty'), "
            "newest first: what analysts learned about the source, its quirks, and pages about it. "
            "Works for any catalog or inventory source, enabled or not."
        ),
        "params": {
            "source_name": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "get_telemetry_sources": {
        "description": (
            "List configured telemetry/log sources and their coverage. Useful for assessing detection "
            "feasibility."
        ),
        "params": {},
    },
    "get_temporal_clusters": {
        "description": (
            "Find entries that share entities within a time window. Useful for spotting emerging "
            "campaigns."
        ),
        "params": {
            "days": {
                "type": 'int',
                "default": 14,
            },
            "window_hours": {
                "type": 'int',
                "default": 72,
            },
            "min_shared": {
                "type": 'int',
                "default": 3,
            },
            "limit": {
                "type": 'int',
                "default": 10,
            },
        },
    },
    "get_threat_actor": {
        "description": (
            "Get a threat actor profile including aliases, actor type, motivation, origin country, "
            "targeted sectors, associated TTPs, and the count of linked articles (article_count)."
        ),
        "params": {
            "actor_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_threat_board": {
        "description": (
            "The Threats board: actors, malware and exploited CVEs over a recency window, ranked by "
            "how many distinct stories mentioned them (not by raw article or outlet counts). Each row "
            "has its lead headline, the cached AI brief when present, source hosts, story and echo "
            "counts, the analyst's handled state, and the count of existing library rules "
            "(prior_rules). CVE rows also rank by an exposure multiplier (KEV, EPSS, weaponized) and "
            "carry their detection status (posture). Rows with is_story are story threads not linked "
            "to any entity. Use it for 'what is happening right now' and to choose what to research "
            "next."
        ),
        "params": {
            "window": {
                "type": 'str',
                "default": '14d',
                "enum": ['7d', '14d', '30d'],
            },
            "facet": {
                "type": 'str',
                "default": 'threats',
                "enum": ['threats', 'vulns', 'all'],
            },
            "limit": {
                "type": 'int',
                "default": 25,
            },
            "min_attention": {
                "type": 'int',
                "default": 3,
            },
            "include_handled": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "get_trending_entities": {
        "description": 'Get top entities by mention count over a time window.',
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": ['threat_actor', 'malware', 'cve', 'ttp'],
            },
            "days": {
                "type": 'int',
                "default": 30,
            },
            "limit": {
                "type": 'int',
                "default": 10,
            },
        },
    },
    "get_triage_queue": {
        "description": (
            "Get the priority-scored entry queue for analyst review, as GET /api/entries/triage "
            "returns it. Uses the signal-engine ranking when signal_engine_surface is enabled, "
            "otherwise the legacy composite heuristic."
        ),
        "params": {
            "days": {
                "type": 'int',
                "default": 7,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "get_ttp": {
        "description": (
            "Get a MITRE ATT&CK technique (TTP) by ID, including tactic, platforms, data sources, and "
            "linked articles."
        ),
        "params": {
            "ttp_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "list_categories": {
        "description": (
            "List feed categories as a tree (top-level categories with nested children), each with "
            "its direct feed count."
        ),
        "params": {},
    },
    "list_documentation_pages": {
        "description": (
            "List every IntelFeed documentation page shipped with this deployment (slug, title, "
            "section, one-line summary). Start here when answering a question about how IntelFeed "
            "works, then fetch the relevant page with get_documentation_page."
        ),
        "params": {},
    },
    "list_entity_links": {
        "description": (
            "List entry\u2192entity autolinks (junction rows) from all seven junction tables, newest "
            "first. Filters: entity_type, entity_id, entry_id, source (auto_link, ai, ai_reconcile, "
            "auto_extracted, manual), confidence (high, medium, low), a substring search on entity "
            "name or entry title, and a window in days. TTP and CVE links record no source, so they "
            "are excluded when source is set. CVE links have no confidence, so they are excluded when "
            "confidence is set."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "default": None,
                "enum": ['cve', 'cwe', 'malware', 'product', 'threat_actor', 'tool', 'ttp', 'vendor'],
            },
            "entity_id": {
                "type": 'str',
                "default": None,
            },
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "source": {
                "type": 'str',
                "default": None,
            },
            "confidence": {
                "type": 'str',
                "default": None,
            },
            "search": {
                "type": 'str',
                "default": None,
            },
            "days": {
                "type": 'int',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "list_entity_notes": {
        "description": (
            "List the analytical notes attached to one intelligence entity, newest first, with author "
            "usernames. Supported entity types match the entity_notes constraint (ransomware victims "
            "are not supported)."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'campaign',
                    'country',
                    'cve',
                    'cwe',
                    'malware',
                    'mitigation',
                    'observable',
                    'product',
                    'sector',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "list_entity_relationships": {
        "description": (
            "All entity\u2194entity relationships where the given entity is the source or target, newest "
            "first, with the names of both entities. Each row has a verb (relationship_type), "
            "confidence (possible, probable or confirmed), source and evidence_entry_ids. "
            "Relationships an analyst rejected, and those below the configured minimum display "
            "confidence, are hidden unless include_rejected is set."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'campaign',
                    'country',
                    'cve',
                    'malware',
                    'observable',
                    'product',
                    'sector',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "relationship_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'attributed_to',
                    'communicates_with',
                    'controls',
                    'delivers',
                    'drops',
                    'exploits',
                    'exposes',
                    'operates_in',
                    'overlaps_with',
                    'related_to',
                    'subgroup_of',
                    'successor_of',
                    'targets',
                    'uses',
                    'variant_of',
                ],
            },
            "include_rejected": {
                "type": 'bool',
                "default": False,
            },
        },
    },
    "list_extraction_entities": {
        "description": (
            "List AI-created entities (created_via='ai_extraction') with a computed status: linked "
            "(in use), review (needs analyst approval), orphan (every article link removed, but its "
            "source article still exists), or dupe (a near-duplicate entity exists; duplicate_of "
            "names it). Filter by type, status, creation window, text search and source entry. Sorted "
            "and paginated. Each row includes created_confidence, needs_review, created_from_entry_id "
            "and the source entry title."
        ),
        "params": {
            "types": {
                "type": 'str',
                "default": None,
            },
            "status": {
                "type": 'str',
                "default": 'all',
                "enum": ['all', 'linked', 'review', 'orphan', 'dupe'],
            },
            "window": {
                "type": 'str',
                "default": '7d',
                "enum": ['1h', '24h', '30d', '7d', 'all'],
            },
            "q": {
                "type": 'str',
                "default": None,
            },
            "source_entry_id": {
                "type": 'str',
                "default": None,
            },
            "sort_by": {
                "type": 'str',
                "default": 'created',
                "enum": ['created', 'entries', 'confidence', 'name'],
            },
            "sort_order": {
                "type": 'str',
                "default": 'desc',
                "enum": ['asc', 'desc'],
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "list_glossary_terms": {
        "description": (
            "List security glossary terms alphabetically with optional filters: exact category (e.g. "
            "a NIST CSF function like 'detect'), case-insensitive name substring search, and built-in "
            "vs user-created (is_system). Each term has a maturity, descriptions, technologies, and "
            "search-term aliases."
        ),
        "params": {
            "category": {
                "type": 'str',
                "default": None,
            },
            "search": {
                "type": 'str',
                "default": None,
            },
            "is_system": {
                "type": 'bool',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "list_intel_profiles": {
        "description": (
            "List the instance's intel profiles (named scopes such as a customer or portfolio: the "
            "regions, verticals and technology they care about), alphabetical. Use a profile id with "
            "get_profile_threat_surface to see which actors and malware target it."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 50,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "list_intel_reports": {
        "description": (
            "List intel reports, most recently updated first, optionally filtered by status (draft, "
            "published, archived) or template_type slug. Rows include section names but not section "
            "content. Use get_intel_report for the full report."
        ),
        "params": {
            "status": {
                "type": 'str',
                "default": None,
                "enum": ['draft', 'published', 'archived'],
            },
            "template_type": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 25,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "list_notes": {
        "description": (
            "List analyst notes (entry-attached and standalone), pinned first then most recently "
            "updated. Optionally filter to one entry or search title/content by substring. Each note "
            "includes its author and, when attached to an entry, the entry and feed titles."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "default": None,
            },
            "search": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "list_review_groups": {
        "description": (
            "The Engine \u203a Review queue: every pending cleanup proposal from both logs, grouped into "
            "one row per entity, newest first unless `sort` says otherwise. Each group gives the "
            "entity, its proposal count, counts per kind (e.g. shadow_remove, "
            "adjudication_reclassify), proposed target types, merge targets, origin, the highest "
            "verdict confidence, the newest row's subject and reason, matched forms and a sample "
            "entry; `facets` counts proposals per domain and per origin. Read a group's rows with "
            "get_review_rows. Decide them with decide_proposals. `total` and `proposals` are the "
            "queue size. Admin only."
        ),
        "params": {
            "q": {
                "type": 'str',
                "default": None,
            },
            "entity_type": {
                "type": 'str',
                "default": None,
            },
            "action": {
                "type": 'str',
                "default": None,
            },
            "domain": {
                "type": 'str',
                "default": None,
                "enum": ['links', 'entities', 'relationships'],
            },
            "origin": {
                "type": 'str',
                "default": None,
                "enum": ['adjudicator', 'merge_review', 'scan'],
            },
            "sort": {
                "type": 'str',
                "default": 'newest',
                "enum": ['newest', 'count', 'oldest', 'confidence'],
            },
            "limit": {
                "type": 'int',
                "default": 50,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
        },
    },
    "list_saved_searches": {
        "description": (
            "List this user's saved searches with unread/total entry counts. Counts come from a "
            "10-minute cache and are computed inline (via search-index queries) on a cache miss."
        ),
        "params": {},
    },
    "list_sectors": {
        "description": (
            "List the victim sectors (a fixed, seeded list of 21 industries) with counts per sector: "
            "linked articles, actors and malware with a claim that they target it, and leak-site "
            "victims in the last 90 days. Pass a slug from this list to get_sector, "
            "who_targets_sector, sector_victims or pivot_entity."
        ),
        "params": {
            "search": {
                "type": 'str',
                "default": None,
            },
            "sort_by": {
                "type": 'str',
                "default": 'article_count',
                "enum": ['name', 'article_count', 'last_seen_at', 'targeting_actor_count', 'victim_count'],
            },
            "limit": {
                "type": 'int',
                "default": 25,
            },
        },
    },
    "list_tags": {
        "description": (
            "List every tag with its entry count, by name. The tag list is shared; the counts are the "
            "caller's view (their own assignments of a personal tag, everyone's of a global one)."
        ),
        "params": {},
    },
    "list_telegram_feeds": {
        "description": (
            "List Telegram channel feeds with their adapter config: channel, last_seen_id, "
            "attribution, session, and error state."
        ),
        "params": {
            "limit": {
                "type": 'int',
                "default": 50,
            },
        },
    },
    "list_watches": {
        "description": (
            "List the current user's entity watchlist rows with resolved display names. Each row has "
            "mode 'watch' (priority boost), 'mute' (hidden), or 'stack' (the user runs this vendor or "
            "product; used for My Stack exposure scoring)."
        ),
        "params": {
            "mode": {
                "type": 'str',
                "default": None,
                "enum": ['watch', 'mute', 'stack'],
            },
        },
    },
    "list_webhook_presets": {
        "description": (
            "List saved webhook presets (reusable URL, payload and header sets for automation "
            "actions), ordered by name. Webhook URLs and header values are redacted. View them in the "
            "web UI if needed."
        ),
        "params": {
            "preset_type": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": 100,
            },
        },
    },
    "pivot_entity": {
        "description": (
            "Find the entities related to a given entity because they appear in the same entries (one "
            "hop). Each related entity has a strength tier (weak, moderate or strong). Lists are "
            "ranked and paginated, and can be filtered by tier and by time window. related_counts "
            "gives the totals before pagination."
        ),
        "params": {
            "entity_type": {
                "type": 'str',
                "required": True,
                "enum": [
                    'country',
                    'cve',
                    'cwe',
                    'malware',
                    'mitigation',
                    'observable',
                    'product',
                    'sector',
                    'threat_actor',
                    'tool',
                    'ttp',
                    'vendor',
                ],
            },
            "entity_id": {
                "type": 'str',
                "required": True,
            },
            "limit_per_type": {
                "type": 'int',
                "default": 50,
            },
            "window_days": {
                "type": 'int',
                "default": None,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
            "sort": {
                "type": 'str',
                "default": 'strength',
                "enum": ['strength', 'recent', 'articles'],
            },
            "min_tier": {
                "type": 'str',
                "default": None,
                "enum": ['weak', 'moderate', 'strong'],
            },
        },
    },
    "search_documentation": {
        "description": (
            "Full-text search across all IntelFeed documentation, returning the pages that mention a "
            "term along with excerpts around each hit. Use this to find which page covers a topic, "
            "then read it with get_documentation_page."
        ),
        "params": {
            "query": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 8,
            },
        },
    },
    "search_entities": {
        "description": (
            "Search all 13 intelligence entity types and the analyst notes stored on the instance. "
            "The types are TTPs, CVEs, CWEs (weaknesses), threat actors, malware, detection rules, "
            "tools, vendors, products, countries, mitigations, campaigns and intel reports. Returns "
            "matching entities with type and key details. Note results use type 'note' and carry "
            "note_source: 'note' for a note on an article or a standalone note, 'entity_note' for a "
            "note attached to an entity. Their description snippet is centred on the match, not the "
            "note's opening line."
        ),
        "params": {
            "query": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 30,
            },
        },
    },
    "search_entries": {
        "description": (
            "Full-text search across RSS entries. Returns titles, summaries, dates, and feed names. "
            "Supports the full query language: AND/OR/NOT, quoted phrases, entry fields (feed:, tag:, "
            "type:, date:, is:, media:, lang:, title:, author:), entity filters (threat_actor:APT29, "
            "malware:, cve:, ttp:, tool:, vendor:, product:, country:, campaign:, rule:), and sort:. "
            "Every filter is applied, not only the text terms. Supports pagination via offset for "
            "pulling large result sets."
        ),
        "params": {
            "query": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
            "offset": {
                "type": 'int',
                "default": 0,
            },
            "sort": {
                "type": 'str',
                "default": 'relevance',
                "enum": [
                    'longest',
                    'newest',
                    'oldest',
                    'radar',
                    'relevance',
                    'shortest',
                    'title_asc',
                    'title_desc',
                ],
            },
        },
    },
    "search_observables": {
        "description": (
            "Search the observables list (IOCs confirmed by AI analysis, the adjudicator, curated IOC "
            "list feeds, publisher IOC tables, TTP host artifacts, or analyst promotion). Filter by "
            "substring, kind, role, lifecycle status, or how the row was added (captured_by). Sorted "
            "by last sighting."
        ),
        "params": {
            "query": {
                "type": 'str',
                "default": None,
            },
            "kind": {
                "type": 'str',
                "default": None,
            },
            "role": {
                "type": 'str',
                "default": None,
            },
            "status": {
                "type": 'str',
                "default": None,
            },
            "captured_by": {
                "type": 'str',
                "default": None,
            },
            "infra_tag": {
                "type": 'str',
                "default": None,
            },
            "needs_review": {
                "type": 'bool',
                "default": None,
            },
            "min_confidence": {
                "type": 'float',
                "default": None,
            },
            "min_reports": {
                "type": 'int',
                "default": None,
            },
            "linked_entity_type": {
                "type": 'str',
                "default": None,
            },
            "linked_entity_id": {
                "type": 'str',
                "default": None,
            },
            "limit": {
                "type": 'int',
                "default": None,
            },
        },
    },
    "search_unified": {
        "description": (
            "Unified search across both entries and entities simultaneously, with the full query "
            "language (boolean operators, entry fields like feed:/tag:/date:, entity filters like "
            "threat_actor:APT29, sort:). Entity filters constrain entry results via linked entries. "
            "Returns combined results grouped by type."
        ),
        "params": {
            "query": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "sector_victims": {
        "description": (
            "Leak-site ransomware victims in a sector: totals (all time and in the window), monthly "
            "counts for 12 months, the ransomware groups posting the most victims in that sector, "
            "victims by country and the most recent disclosures."
        ),
        "params": {
            "sector": {
                "type": 'str',
                "required": True,
            },
            "window_days": {
                "type": 'int',
                "default": 90,
            },
            "limit": {
                "type": 'int',
                "default": 20,
            },
        },
    },
    "suggest_campaign_entries": {
        "description": "Suggest entries that share entities with a campaign but aren't yet linked to it.",
        "params": {
            "campaign_id": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 10,
            },
        },
    },
    "who_targets_sector": {
        "description": (
            "Rank the threat actors and malware families that target a sector. 'reported' rows are "
            "ranked by how many articles describe both the actor or family and an attack on the "
            "sector. 'asserted' rows have an explicit targets-sector claim, with its source (rollup, "
            "enrichment, seed, analyst) and evidence count."
        ),
        "params": {
            "sector": {
                "type": 'str',
                "required": True,
            },
            "limit": {
                "type": 'int',
                "default": 15,
            },
        },
    },
}


# ---------------------------------------------------------------------------
# API Client (stdlib only — no external dependencies)
# ---------------------------------------------------------------------------


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """urllib re-sends every header, Authorization included, to wherever a redirect points,
    even another host over plain http. The API never redirects, so a redirect comes back as
    its 3xx status (an "API returned 30x" error) instead of being followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_RefuseRedirects)


class IntelFeedClient:
    """Synchronous HTTP client for IntelFeed API using urllib.

    Tokens are kept in a small file between runs, so a shell loop of single
    calls logs in once instead of once per process. The server allows ten
    login/refresh requests per five minutes per client address.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.access_token: str | None = None
        self.refresh_token: str | None = None

    def _send(
        self, path: str, body: dict, headers: dict[str, str] | None = None
    ) -> tuple[int, dict | str, dict[str, str]]:
        """Send a POST request and return (status_code, parsed_json_or_text, response_headers)."""
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "IntelFeed-CLI-Lite/1.0",
                **(headers or {}),
            },
            method="POST",
        )
        try:
            with _OPENER.open(req, timeout=120) as resp:
                raw = resp.read().decode("utf-8")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                try:
                    return resp.status, json.loads(raw), resp_headers
                except json.JSONDecodeError:
                    return resp.status, raw, resp_headers
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            resp_headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
            try:
                return e.code, json.loads(raw), resp_headers
            except json.JSONDecodeError:
                return e.code, raw, resp_headers

    def _post(
        self, path: str, body: dict, headers: dict[str, str] | None = None
    ) -> tuple[int, dict | str]:
        """Send a POST request and return (status_code, parsed_json_or_text)."""
        status, data, _ = self._send(path, body, headers)
        return status, data

    def _auth_post(self, path: str, body: dict) -> tuple[int, dict | str]:
        """POST to a login/refresh route. On a 429, wait out a short Retry-After and
        try once more; on a long one, exit and say how long to wait."""
        _debug(f"POST {path}")
        status, data, headers = self._send(path, body)
        if status != 429:
            return status, data
        try:
            wait = int(float(headers.get("retry-after", "")))
        except ValueError:
            wait = None
        if wait is not None and 0 <= wait <= MAX_RETRY_AFTER_SLEEP:
            _debug(f"429 from {path}, waiting {wait}s and retrying once")
            time.sleep(wait)
            status, data, headers = self._send(path, body)
            if status != 429:
                return status, data
            try:
                wait = int(float(headers.get("retry-after", "")))
            except ValueError:
                wait = None
        when = f"in {wait} seconds" if wait is not None else "in a few minutes"
        print(
            f"Error: Login is rate limited (429). Try again {when}. The server allows 10 "
            "logins per 5 minutes per address. Passing several tool calls to one invocation "
            "costs one login.",
            file=sys.stderr,
        )
        sys.exit(1)

    # -- token cache ---------------------------------------------------------

    def _cache_path(self) -> str | None:
        """Where this instance + user's tokens are kept, or None when the cache is off."""
        if not TOKEN_CACHE_ENABLED:
            return None
        key = hashlib.sha256(f"{self.base_url}\n{USERNAME}".encode()).hexdigest()[:16]
        return os.path.join(os.path.expanduser("~"), ".cache", "intelfeed", f"token-{key}.json")

    def _load_cache(self) -> bool:
        """Take the token pair from the cache file. Any problem means 'no cache'."""
        path = self._cache_path()
        if not path:
            return False
        try:
            with open(path, encoding="utf-8") as f:
                cached = json.load(f)
            access, refresh = cached["access_token"], cached["refresh_token"]
            if cached.get("api_url") != self.base_url or cached.get("username") != USERNAME:
                return False
            if not (isinstance(access, str) and access and isinstance(refresh, str) and refresh):
                return False
        except (OSError, ValueError, KeyError, TypeError):
            return False
        self.access_token, self.refresh_token = access, refresh
        return True

    def _save_cache(self) -> None:
        """Write the token pair atomically, readable by this user only. Never fatal."""
        path = self._cache_path()
        if not path:
            return
        tmp = None
        try:
            directory = os.path.dirname(path)
            os.makedirs(directory, mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".token-", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "api_url": self.base_url,
                        "username": USERNAME,
                        "access_token": self.access_token,
                        "refresh_token": self.refresh_token,
                    },
                    f,
                )
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            tmp = None
        except OSError as e:
            _debug(f"could not write token cache: {e}")
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    # -- authentication ------------------------------------------------------

    def authenticate(self) -> None:
        """Get a usable token: the cached pair, else a login."""
        if self._load_cache():
            _debug("using cached token (no login)")
            return
        self.login()

    def login(self) -> None:
        if not USERNAME or not PASSWORD:
            print(
                "Error: INTELFEED_USERNAME and INTELFEED_PASSWORD must be set.",
                file=sys.stderr,
            )
            sys.exit(1)
        status, data = self._auth_post(
            "/api/auth/login",
            {"username": USERNAME, "password": PASSWORD},
        )
        if status != 200:
            print(f"Error: Login failed ({status}): {data}", file=sys.stderr)
            sys.exit(1)
        self.access_token = data["access_token"]
        self.refresh_token = data["refresh_token"]
        self._save_cache()

    def _refresh(self) -> None:
        if not self.refresh_token:
            self.login()
            return
        status, data = self._auth_post(
            "/api/auth/refresh",
            {"refresh_token": self.refresh_token},
        )
        if status == 200:
            # The server rotates refresh tokens: the one just sent is now dead,
            # so the new pair must be saved.
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self._save_cache()
        else:
            self.login()

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    def execute_tool(self, tool_name: str, args: dict) -> str:
        status, data = self._post(
            "/api/tools/execute",
            {"tool_name": tool_name, "args": args},
            headers=self._auth_headers(),
        )
        if status == 401:
            self._refresh()
            status, data = self._post(
                "/api/tools/execute",
                {"tool_name": tool_name, "args": args},
                headers=self._auth_headers(),
            )
        if status != 200:
            return json.dumps({"error": f"API returned {status}", "detail": str(data)})
        return data["result"]


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def print_tool_list() -> None:
    """Print all available tools grouped by category."""
    print("Available IntelFeed tools (lite — read-only):\n")
    for name, info in TOOLS.items():
        required = [k for k, v in info["params"].items() if v.get("required")]
        optional = [k for k, v in info["params"].items() if not v.get("required")]
        req_str = ", ".join(required) if required else ""
        opt_str = ", ".join(f"[{k}]" for k in optional) if optional else ""
        params_str = "  ".join(filter(None, [req_str, opt_str]))
        print(f"  {name}")
        print(f"    {info['description']}")
        if params_str:
            print(f"    Params: {params_str}")
        print()


def print_tool_help(tool_name: str) -> None:
    """Print detailed help for a single tool."""
    if tool_name not in TOOLS:
        print(f"Error: Unknown tool '{tool_name}'", file=sys.stderr)
        print("Run with --list-tools to see available tools.", file=sys.stderr)
        sys.exit(1)

    info = TOOLS[tool_name]
    print(f"{tool_name}")
    print(f"  {info['description']}\n")
    if info["params"]:
        print("  Parameters:")
        for pname, pinfo in info["params"].items():
            req = (
                "required"
                if pinfo.get("required")
                else f"default: {pinfo.get('default')}"
            )
            enum_str = f", values: {pinfo['enum']}" if pinfo.get("enum") else ""
            print(f"    {pname} ({pinfo['type']}) — {req}{enum_str}")
    else:
        print("  No parameters.")
    print("\n  Example:")
    example_args = {}
    for pname, pinfo in info["params"].items():
        if pinfo.get("required"):
            if pinfo["type"] == "str":
                example_args[pname] = f"<{pname}>"
            elif pinfo["type"] == "int":
                example_args[pname] = 10
            elif pinfo["type"].startswith("list"):
                example_args[pname] = [f"<{pname}_1>"]
            elif pinfo["type"] == "dict":
                example_args[pname] = {}
            elif pinfo["type"] == "bool":
                example_args[pname] = True
    print(f"    python intelfeed_cli.py {tool_name} '{json.dumps(example_args)}'")


def parse_tool_calls(args: list[str]) -> list[tuple[str, dict]]:
    """Parse CLI args into (tool_name, args_dict) pairs.

    Supports:
      tool_name '{"key": "val"}'       — tool with JSON args
      tool_name                         — tool with no args (next arg is another tool name)
    """
    calls: list[tuple[str, dict]] = []
    i = 0
    while i < len(args):
        tool_name = args[i]
        if tool_name not in TOOLS:
            print(f"Error: Unknown tool '{tool_name}'", file=sys.stderr)
            print("Run with --list-tools to see available tools.", file=sys.stderr)
            sys.exit(1)

        i += 1
        tool_args: dict = {}

        # Check if next arg is a JSON string (starts with '{')
        if i < len(args) and args[i].startswith("{"):
            try:
                tool_args = json.loads(args[i])
            except json.JSONDecodeError as e:
                print(
                    f"Error: Invalid JSON for tool '{tool_name}': {e}", file=sys.stderr
                )
                sys.exit(1)
            i += 1

        calls.append((tool_name, tool_args))

    return calls


def _is_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if args[0] == "--list-tools":
        print_tool_list()
        sys.exit(0)

    if args[0] == "--help-tool":
        if len(args) < 2:
            print("Usage: --help-tool <tool_name>", file=sys.stderr)
            sys.exit(1)
        print_tool_help(args[1])
        sys.exit(0)

    # Parse tool calls from remaining args
    calls = parse_tool_calls(args)

    if not calls:
        print("Error: No tool calls specified.", file=sys.stderr)
        sys.exit(1)

    # Execute
    problem = insecure_url_problem(API_URL)
    if problem:
        print(json.dumps({"error": problem}))
        sys.exit(1)
    client = IntelFeedClient(API_URL)
    client.authenticate()

    results = []
    for tool_name, tool_args in calls:
        # Strip None values
        cleaned_args = {k: v for k, v in tool_args.items() if v is not None}
        result = client.execute_tool(tool_name, cleaned_args)
        results.append(
            {
                "tool": tool_name,
                "result": json.loads(result) if _is_json(result) else result,
            }
        )

    # Output: single result unwrapped, multiple wrapped in array
    if len(results) == 1:
        output = results[0]
    else:
        output = results

    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()
