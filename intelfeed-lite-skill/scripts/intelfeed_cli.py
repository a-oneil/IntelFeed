#!/usr/bin/env python3
"""CLI for IntelFeed API (lite, read-only) — used by Claude skills to query IntelFeed.

Executes one or more read-only tool calls against the running IntelFeed API and
prints JSON results to stdout. Zero external dependencies — stdlib only.

Environment variables:
    INTELFEED_API_URL       Base URL of your IntelFeed instance (required); https://, or http://localhost
    INTELFEED_ALLOW_INSECURE_HTTP  1 to allow plain http:// to another host (a trusted LAN or compose network)
    INTELFEED_USERNAME      Username for authentication
    INTELFEED_PASSWORD      Password for authentication

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

import json
import os
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL = os.environ.get("INTELFEED_API_URL", "").strip().rstrip("/")
USERNAME = os.environ.get("INTELFEED_USERNAME", "")
PASSWORD = os.environ.get("INTELFEED_PASSWORD", "")


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
            "ATT&CK coverage analysis: observed TTPs vs non-draft detection rules, with per-tactic "
            "summary and the list of uncovered techniques. TTP-only \u2014 CVEs are not part of this "
            "analysis."
        ),
        "params": {},
    },
    "check_requirement_match": {
        "description": (
            "Check an entry against all active intelligence requirements using the real matching "
            "engine (linked-entity hits, then title/body keyword hits, gated by each requirement's "
            "min_relevance and feed filter). Read-only: persists nothing; also returns matches the "
            "automated pipeline already persisted for this entry."
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
            "Check if detection rules are feasible given configured telemetry sources. Identifies "
            "what log sources are needed vs available."
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
            "highest first. Note: takes an entry UUID, not raw text \u2014 that is what the API supports."
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
            "List every Telegram channel the IntelFeed bootstrap account is joined to, with "
            "is_subscribed = whether IntelFeed already ingests it. Use this to see which channels "
            "you've joined in your Telegram client app but haven't yet wired up as IntelFeed feeds."
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
            "Export a filtered slice of the ledger as lines (EDL), CSV rows, or JSON \u2014 the same "
            "filters as search_observables plus a minimum report count and an 'exclude dual-use "
            "infrastructure' switch. Values are returned refanged (operational form). Denied rows "
            "and, by default, infra-tagged rows are excluded."
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
            "Get MITRE ATT&CK Navigator layer JSON for a specific entry's TTPs, or (without entry_id) "
            "for all observed techniques \u2014 those linked to at least one entry, excluding deprecated "
            "catalog techniques."
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
            "Get recent correlation events \u2014 coverage gaps, trending entities, campaign and "
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
            "Get a MITRE CWE weakness by ID, including its position on the abstraction ladder "
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
            "generates a summary \u2014 generation runs via the daily_summary AI task/automation."
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
            "Get a single detection rule with full rule content, provenance (source "
            "repo/author/license/references), draft/published status, telemetry feasibility against "
            "the enabled Telemetry Sources inventory, and a syntax-validation summary."
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
            "List a detection rule's saved versions, newest first. Versions are snapshots taken "
            "whenever rule_content changed or a rollback occurred."
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
            "List detection rules. Optionally filter by rule type (crowdstrike_ql, elastic_ql, kql, "
            "nuclei, panther, sigma, snort_suricata, splunk_spl, yara)."
        ),
        "params": {
            "rule_type": {
                "type": 'str',
                "default": None,
                "enum": [
                    'crowdstrike_ql',
                    'elastic_ql',
                    'kql',
                    'nuclei',
                    'panther',
                    'sigma',
                    'snort_suricata',
                    'splunk_spl',
                    'yara',
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
            "Build a relationship graph centered on an entity. Claims-only: edges are typed "
            "relationship records (verb, direction, confidence, provenance) at confirmed/reported "
            "confidence \u2014 pure co-occurrence pairs are excluded; co-occurrence data only enriches "
            "edges with proximity and evidence articles."
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
            "tiers: 'claimed' (attribution edges with evidence \u2014 uses / communicates_with / controls, "
            "with trust tier) and 'reported_alongside' (observables a reporting article that names "
            "the entity also carried; indicator-list files and newsletters excluded). Answers 'what "
            "infrastructure does X use?'."
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
            "Autolinking health signals: total entry\u2192entity links by entity type and provenance "
            "source, how many held matches (pending autolinks) are waiting for their article's "
            "analysis, plus the count of non-rejected entity\u2194entity relationships."
        ),
        "params": {},
    },
    "get_entity_timeline": {
        "description": 'Get chronological timeline of when an entity appeared in articles.',
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
            "new technique, new victim sector, exploitation news...) on articles linked to it. "
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
            "Fetch a single RSS entry by ID with full content and all extracted intelligence: TTPs, "
            "CVEs, CWEs, threat actors, malware, tools, vendors, products, countries, and "
            "mitigations."
        ),
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry_graph": {
        "description": 'Get relationship graph for all entities linked to a single entry.',
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry_insights": {
        "description": "Get actionable intelligence insights for a specific entry's entities.",
        "params": {
            "entry_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_entry_story": {
        "description": (
            "Chain follow-up/precursor articles to an entry via shared entities: within a \u00b130 day "
            "window, entries sharing at least one strong entity (CVE, threat actor, malware) or two "
            "entities of any type join the story. Ordered chronologically (a timeline, not a "
            "relevance ranking \u2014 use get_similar_entries for that)."
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
            "Aggregate stats over AI-created entities (created_via='ai_extraction' across threat "
            "actors, malware, tools, CVEs, TTPs): totals by type, needs-review / orphaned / "
            "likely-duplicate / auto-confirmed counts, and how many were created in the requested "
            "window vs the preceding one."
        ),
        "params": {
            "window": {
                "type": 'str',
                "default": '7d',
                "enum": ['24h', '30d', '7d', 'all'],
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
        "description": 'Get feed value scores — composite 0-100 intelligence contribution metric per feed.',
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
            "Chronological hygiene feed: a merge of the entity-link log and the entity-maintenance "
            "log, normalized (action, mode, applied, subject, reason, affected-entity links, origin). "
            "Filter by action code (comma-separate for several), log source, mode, origin "
            "(adjudicator = filed by the adjudicate stage, merge_review = the duplicate review, scan "
            "= the on-demand scans and analysts), pending-only, or a since timestamp. Read-only \u2014 "
            "applying or dismissing proposals happens in the Proposals queue."
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
            "Combined entity-hygiene counters across both proposal logs: the adjudicate stage's mode "
            "and how many verdicts it has filed that nobody has applied yet, pending reclassify "
            "advisories and name/alias/vendor/id proposals, orphan entity count, last run times, and "
            "how many actions were applied in the last 24h / 7d."
        ),
        "params": {},
    },
    "get_ingest_batch": {
        "description": (
            "Status of one ingest batch: per-item status (queued / parsing / created / expanded / "
            "duplicate / no_text / unsupported / too_large / failed), the entry id each item "
            "produced, and a summary. Poll until summary.status is 'complete'. Created entries still "
            "go on to the pipeline and the one-pass AI analysis afterwards, like any polled entry."
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
            "Look up an observable (IOC ledger row) by UUID or by its value (IP, domain, URL, hash, "
            "cmdline, registry key, ...). Returns kind, role, current/base confidence with decay "
            "state, sighting count, capture provenance (which judgment door created it) with the "
            "evidence sentence, first/last seen, and the most recent sighting articles. Defanged "
            "input (evil[.]com, hxxps://) is normalized."
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
            "The analyst's reading queue, exactly as the Priority Queue page shows it: unread entries "
            "that clear the radar threshold, ranked by signal score, with story threads folded in as "
            "single rows so a story eleven outlets covered is one item and not eleven. Ask this for "
            "'what should I read next' / 'what's important right now'. Prefer it over "
            "get_triage_queue, which is the older heuristic and does not fold stories."
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
            "The threat surface for one intel profile: actors and malware active against its regions "
            "x verticals, each with why-matched evidence (which region/sector, how many articles)."
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
            "Reverse-chronological feed of ransomware leak-site victim disclosures (Leak Watch), with "
            "filters for group name, canonical sector slug, country (ISO code or name), posting "
            "recency, substring search, and the user's watched victims/groups. sort is 'recent', "
            "'group', or 'sector' (newest-first tiebreak). Returns a paginated list; empty when the "
            "ransomware tracker has not synced yet."
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
            "Ransomware Landscape aggregates over a trailing window: victim totals with "
            "week-over-week change, weekly timeseries, top groups (with WoW trend), top sectors, top "
            "countries, and the user's watchlist exposure (watched groups/orgs/sectors vs new "
            "disclosures). All-zero when the ransomware tracker has not synced yet."
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
            "Fetch one ransomware victim organization by UUID: name/domain/aliases, sector, country, "
            "first/last seen, whether the user watches it, the groups that listed it, and every "
            "leak-site disclosure."
        ),
        "params": {
            "victim_id": {
                "type": 'str',
                "required": True,
            },
        },
    },
    "get_requirement_coverage": {
        "description": (
            "Get intelligence requirements coverage summary \u2014 counts by status, priority, category, "
            "and staleness."
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
            "match, so the article needn't be fetched. Admin only."
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
            "per category), and top tags (by entry usage). Useful for understanding what's in the "
            "system before searching."
        ),
        "params": {},
    },
    "get_sector": {
        "description": (
            "Get a sector's victimology profile: description and aliases, who targets it (reported "
            "from articles vs asserted claims), campaigns scoped to it, leak-site victim totals and "
            "top ransomware groups, the country cross-tab, the intel profiles that include it, and "
            "recent articles."
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
            "Find entries similar to the given entry. Answers from the embedding index when the entry "
            "has been embedded \u2014 nearest neighbours find the article telling the same story in "
            "different words \u2014 and falls back to keyword search over the search index otherwise. "
            "Excludes the entry itself and its exact duplicates (same content hash)."
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
            "My Stack exposure board: every CVE affecting the vendors/products the user has declared "
            "as their stack (watchlist mode='stack'), ranked by exposure lift (KEV/EPSS/weaponization "
            "multipliers), each with a detection posture (defended / blind / no_rule) from the org's "
            "telemetry inventory, plus per-asset CVE tallies and the urgency x posture matrix counts. "
            "Empty if the user has no stack entities declared."
        ),
        "params": {},
    },
    "get_story_thread": {
        "description": (
            "Read one story thread: its spine (one beat per wave of coverage \u2014 what broke, what each "
            "wave added), every member article with its role (origin, beat, or folded echo), what the "
            "story has yielded in techniques/CVEs/products/detection rules, and the threads it most "
            "resembles. Open it in the UI at /priority-queue?thread=<slug>."
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
            "List story threads \u2014 unfolding stories assembled from the articles that cover them, with "
            "the re-reports folded underneath. Each row carries its outlets, article and echo counts, "
            "key entities, how much is unread, and the priority score of its best unread beat. Use "
            "this instead of searching for a story twenty-three times."
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
    "get_telemetry_sources": {
        "description": (
            "List configured telemetry/log sources and their coverage. Useful for assessing detection "
            "feasibility."
        ),
        "params": {},
    },
    "get_temporal_clusters": {
        "description": 'Find entries sharing entities within time windows — useful for detecting emerging campaigns.',
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
            "The Threats board: actors/malware and exploited CVEs ranked over a recency window by how "
            "many distinct stories carried them (not raw article or outlet counts). Each row leads "
            "with its lead headline, the cached AI brief when present, source hosts, story/echo "
            "counts, the analyst's handled state, prior-rule inventory and, for CVEs, exposure lift "
            "(KEV/EPSS/weaponized) and detection posture. Rows with is_story are story threads that "
            "resolved to no entity. Use it for 'what is happening right now' and to choose what to "
            "research next."
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
            "Get priority-scored entry queue for analyst review. Uses the signal-engine ranking when "
            "signal_engine_surface is enabled, otherwise the legacy composite heuristic \u2014 mirroring "
            "GET /api/entries/triage."
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
            "List entry\u2192entity autolinks (junction rows) unioned across all seven junction tables, "
            "newest first. Filter by entity_type, entity_id, entry_id, source provenance (auto_link, "
            "ai, ai_reconcile, auto_extracted, manual \u2014 TTP/CVE junctions record no source and are "
            "excluded when set), confidence (high, medium, low \u2014 the CVE junction has none and is "
            "excluded when set), a substring search on entity name / entry title, or a recency window "
            "in days."
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
            "All entity\u2194entity relationships where the given entity is source or target, newest "
            "first, with endpoint display names resolved. Each row carries verb (relationship_type), "
            "confidence (possible/probable/confirmed), provenance source and evidence_entry_ids. "
            "Analyst-rejected edges and edges below the configured min-confidence display setting are "
            "hidden unless include_rejected is set."
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
            "List AI-created entities (created_via='ai_extraction') with a computed lifecycle status: "
            "linked (in use), review (needs analyst sign-off), orphan (zero articles), or dupe "
            "(near-duplicate sibling exists, with duplicate_of naming it). Filterable by type, "
            "status, creation window, text search and source entry; sorted and paginated. Includes "
            "provenance: created_confidence, needs_review, created_from_entry_id and the source entry "
            "title."
        ),
        "params": {
            "types": {
                "type": 'str',
                "default": None,
            },
            "status": {
                "type": 'str',
                "default": 'all',
                "enum": ['all', 'linked', 'review', 'orphan', 'dupe', 'stale'],
            },
            "window": {
                "type": 'str',
                "default": '7d',
                "enum": ['24h', '30d', '7d', 'all'],
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
            "vs user-created (is_system). Each term carries maturity, descriptions, technologies, and "
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
            "List intel reports, newest-updated first, optionally filtered by status (draft, "
            "published, archived) or template_type slug. Rows are lightweight \u2014 section names only, "
            "no section content (use get_intel_report for the full report)."
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
            "The Engine \u203a Review queue: every pending hygiene proposal (both logs) folded one row per "
            "entity, most proposals first. Each group gives the entity, its proposal count, per-kind "
            "counts (e.g. shadow_remove, adjudication_reclassify), proposed target types, merge "
            "targets, origin, the newest row's subject and reason, matched forms and a sample entry. "
            "Read a group's rows with get_review_rows; decide them with decide_proposals. "
            "`total`/`proposals` are the queue size. Admin only."
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
            "List the victim-sector vocabulary (21 closed, seeded industries) with per-sector counts: "
            "linked articles, actors and malware asserted to target it, and leak-site victims in the "
            "last 90 days. Use the slug from here with get_sector / who_targets_sector / "
            "sector_victims / pivot_entity."
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
            "List Telegram channel feeds with their adapter config \u2014 channel, last_seen_id, "
            "attribution, session, error state."
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
            "mode 'watch' (priority boost), 'mute' (suppressed), or 'stack' ('I run this' \u2014 "
            "vendors/products feeding My Stack exposure scoring)."
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
            "List saved webhook presets (reusable URL + payload + header combinations for automation "
            "actions), ordered by name. Webhook URLs and header values are redacted \u2014 inspect them in "
            "the web UI if needed."
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
            "Find all entities related to a given entity via co-occurrence in entries. One-hop pivot. "
            "Related lists carry strength tiers (weak/moderate/strong) and are ranked, "
            "tier-filterable, window-filterable and paginated; related_counts reports pre-slice "
            "totals."
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
            "Search across all 13 intelligence entity types \u2014 TTPs, CVEs, CWEs (weaknesses), threat "
            "actors, malware, detection rules, tools, vendors, products, countries, mitigations, "
            "campaigns, intel reports \u2014 plus the analyst notes stored on the instance. Returns "
            "matching entities with type and key details. Note results use type 'note' and carry "
            "note_source ('note' for a note on an article or a standalone one, 'entity_note' for one "
            "attached to an entity), with a description snippet centred on the match rather than the "
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
            "malware:, cve:, ttp:, tool:, vendor:, product:, country:, campaign:, rule:), and sort: \u2014 "
            "all filters are executed, not just the text terms. Supports pagination via offset for "
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
            "Search the observables ledger (IOCs captured with judgment: AI-confirmed indicators, "
            "curated feed entries, TTP host artifacts, analyst promotions). Filter by substring, "
            "kind, role, lifecycle status, or capture door. Sorted by last sighting."
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
            "Leak-site ransomware victims in a sector: totals (all time and in the window), a "
            "12-month monthly series, the top ransomware groups posting victims in that sector, the "
            "victim-country breakdown and the most recent disclosures."
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
            "Rank the threat actors and malware families targeting a sector. 'reported' rows are "
            "ranked by how many articles describe both the actor/family and the sector being hit; "
            "'asserted' rows carry an explicit targets-sector claim with its source (rollup, "
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
    """Synchronous HTTP client for IntelFeed API using urllib."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.access_token: str | None = None
        self.refresh_token: str | None = None

    def _post(
        self, path: str, body: dict, headers: dict[str, str] | None = None
    ) -> tuple[int, dict | str]:
        """Send a POST request and return (status_code, parsed_json_or_text)."""
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
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            try:
                return e.code, json.loads(raw)
            except json.JSONDecodeError:
                return e.code, raw

    def login(self) -> None:
        if not USERNAME or not PASSWORD:
            print(
                "Error: INTELFEED_USERNAME and INTELFEED_PASSWORD must be set.",
                file=sys.stderr,
            )
            sys.exit(1)
        status, data = self._post(
            "/api/auth/login",
            {"username": USERNAME, "password": PASSWORD},
        )
        if status != 200:
            print(f"Error: Login failed ({status}): {data}", file=sys.stderr)
            sys.exit(1)
        self.access_token = data["access_token"]
        self.refresh_token = data["refresh_token"]

    def _refresh(self) -> None:
        if not self.refresh_token:
            self.login()
            return
        status, data = self._post(
            "/api/auth/refresh",
            {"refresh_token": self.refresh_token},
        )
        if status == 200:
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
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
    client.login()

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
