"""Pre-built automation rule templates for common security workflows."""

AUTOMATION_TEMPLATES: list[dict] = [
    {
        "id": "watched-entity-alert",
        "name": "Alert on Watched Entities",
        "description": "Notify when an entry mentions any entity on your watchlist (signal engine)",
        "category": "signals",
        "tags": ["watchlist", "alerting", "signals"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {"type": "entity_watchlisted", "config": {}},
        "actions": [
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Watched entity mentioned: {title}\n{app_url}",
                },
            }
        ],
    },
    {
        "id": "radar-signal-alert",
        "name": "High-Priority Radar Alert",
        "description": (
            "Notify on entries carrying rare high-value signals (KEV adds, novel entities, under-reported severity)"
        ),
        "category": "signals",
        "tags": ["signals", "kev", "alerting"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {
                    "type": "has_signal",
                    "config": {"types": ["kev_added", "novel_entity", "under_reported", "weaponized_poc"]},
                },
            ],
        },
        "actions": [
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Radar: {title}\n{app_url}",
                },
            }
        ],
    },
    # --- Observables ---
    {
        "id": "new-c2-infrastructure-alert",
        "name": "Notify on New C2 Infrastructure",
        "description": (
            "Notify when a reporting source (research write-up, publisher IOC file, analyst promote) captures "
            "command-and-control infrastructure — never a blocklist mirror, never dual-use VPN/proxy exits"
        ),
        "category": "intelligence",
        "tags": ["observables", "c2", "alerting"],
        "trigger_type": "on_observable_captured",
        "trigger_config": {"roles": ["c2"], "exclude_infra_tagged": True},
        "conditions": {},
        "actions": [
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "New C2 ({observables_count}): {title}\n{observables}\n{app_url}",
                },
            }
        ],
    },
    {
        "id": "actor-infrastructure-to-campaign",
        "name": "Add an Actor's New Infrastructure to Its Campaign",
        "description": (
            "When an article naming a tracked actor captures observables, link the article to the actor's "
            "campaign and attach the captured infrastructure as campaign entities. Set campaign_id and the "
            "name of the group you track before enabling."
        ),
        "category": "intelligence",
        "tags": ["observables", "campaign", "attribution"],
        "trigger_type": "on_observable_captured",
        "trigger_config": {"exclude_infra_tagged": True},
        "conditions": {"type": "content_contains", "config": {"pattern": "ACTOR NAME"}},
        "actions": [
            {
                "type": "add_to_campaign",
                "config": {
                    "campaign_id": "",
                    "notes": "Auto-linked on observable capture",
                    "link_observables": True,
                    "observable_roles": "c2, delivery, payload, phishing, exfil",
                },
            }
        ],
    },
    # --- Intelligence Extraction ---
    {
        "id": "full-intel-extraction",
        "name": "Full Intel Extraction Pipeline",
        "description": (
            "Extract all intelligence entities (TTPs, CVEs, threat actors, malware) from every new entry. The "
            "foundational automation for threat intelligence."
        ),
        "category": "intelligence",
        "tags": ["ttp", "cve", "threat-actor", "malware"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {},
        "actions": [
            {"type": "extract_ttps", "config": {}},
            {"type": "extract_cves", "config": {}},
            {"type": "extract_threat_actors", "config": {}},
            {"type": "extract_malware", "config": {}},
        ],
    },
    {
        "id": "cve-monitor",
        "name": "CVE Monitoring & Tagging",
        "description": "When a new entry mentions a CVE, extract CVE details and tag the entry for triage.",
        "category": "intelligence",
        "tags": ["cve", "tagging"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {"pattern": r"CVE-\d{4}-\d{4,}", "is_regex": True},
        "conditions": {},
        "actions": [
            {"type": "extract_cves", "config": {}},
            {"type": "add_tags", "config": {"tags": ["has-cve", "needs-triage"]}},
        ],
    },
    # --- Detection Engineering ---
    {
        "id": "detection-from-cve",
        "name": "Detection Rules from CVE Entries",
        "description": "Generate detection rules when a CVE is detected, then tag the entry as detection-ready.",
        "category": "detection",
        "tags": ["detection", "cve"],
        "trigger_type": "on_cve_detected",
        "trigger_config": {},
        "conditions": {},
        "actions": [
            {"type": "generate_detection_rules", "config": {}},
            {"type": "add_tags", "config": {"tags": ["detection-generated"]}},
        ],
    },
    # --- Alerting & Notifications ---
    {
        "id": "cve-vendor-alert",
        "name": "Alert on CVEs Mentioning My Stack",
        "description": (
            "Get notified when a new entry mentions CVEs related to your vendor/product stack. Customize the keyword "
            "pattern to match your environment."
        ),
        "category": "alerting",
        "tags": ["cve", "notification", "vendor"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": r"(Microsoft|Windows|Linux|Apache|Cisco|Fortinet|Palo Alto|VMware|Chrome|Firefox)",
            "is_regex": True,
        },
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "content_contains", "config": {"pattern": r"CVE-\d{4}", "is_regex": True}},
            ],
        },
        "actions": [
            {"type": "extract_cves", "config": {}},
            {"type": "mark_priority", "config": {"priority": "high"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "in_app",
                    "message": "CVE alert for your vendor stack: {title}",
                },
            },
        ],
    },
    {
        "id": "watched-actor-alert",
        "name": "Alert on Watched Threat Actors",
        "description": (
            "Auto-tag and notify when entries mention specific threat actors you're tracking. Edit the keyword pattern "
            "with your watched actor names."
        ),
        "category": "alerting",
        "tags": ["threat-actor", "notification", "monitoring"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": r"(APT28|APT29|Lazarus|Sandworm|Volt Typhoon|Scattered Spider|LockBit|BlackCat|ALPHV)",
            "is_regex": True,
        },
        "conditions": {},
        "actions": [
            {"type": "extract_threat_actors", "config": {}},
            {"type": "add_tags", "config": {"tags": ["watched-actor"]}},
            {"type": "mark_priority", "config": {"priority": "high"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "in_app",
                    "message": "Watched actor mention: {title}",
                },
            },
        ],
    },
    {
        "id": "high-severity-alert",
        "name": "High Severity Entry Alert",
        "description": (
            "Notify immediately when entries arrive with high severity (e.g., critical advisories, zero-days)."
        ),
        "category": "alerting",
        "tags": ["severity", "notification"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "severity_above", "config": {"threshold": 7}},
            ],
        },
        "actions": [
            {"type": "mark_priority", "config": {"priority": "high"}},
            {"type": "star_entry", "config": {}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "in_app",
                    "message": "High severity: {title}",
                },
            },
        ],
    },
    # --- Triage & Organization ---
    {
        "id": "ransomware-triage",
        "name": "Ransomware Content Triage",
        "description": (
            "Automatically tag, prioritize, and extract intelligence from entries mentioning ransomware keywords."
        ),
        "category": "triage",
        "tags": ["ransomware", "tagging", "triage"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": r"(ransomware|ransom|encrypt|decryptor|leak site|double extortion)",
            "is_regex": True,
        },
        "conditions": {},
        "actions": [
            {"type": "add_tags", "config": {"tags": ["ransomware", "needs-review"]}},
            {"type": "extract_threat_actors", "config": {}},
            {"type": "extract_malware", "config": {}},
            {"type": "mark_priority", "config": {"priority": "high"}},
        ],
    },
    {
        "id": "auto-tag-feed-type",
        "name": "Auto-Tag by Feed Type",
        "description": (
            "Automatically tag entries based on their source feed type (e.g., tag YouTube entries as 'video', Reddit "
            "as 'discussion')."
        ),
        "category": "triage",
        "tags": ["tagging", "organization"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "feed_type_matches", "config": {"feed_types": ["youtube"]}},
            ],
        },
        "actions": [
            {"type": "add_tags", "config": {"tags": ["video-content"]}},
        ],
    },
    # --- AI-Powered ---
    {
        "id": "ai-summarize-new",
        "name": "AI Summarize New Entries",
        "description": "Use AI to summarize every new entry. Great for long-form reports and advisories.",
        "category": "ai",
        "tags": ["ai", "summarization"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {},
        "actions": [
            {"type": "run_ai_task", "config": {"task": "summarize"}},
        ],
    },
    {
        "id": "ai-summarize-notify",
        "name": "AI Summarize & Notify",
        "description": (
            "Summarize entries with AI, then send a notification with the summary included. Useful for daily digests."
        ),
        "category": "ai",
        "tags": ["ai", "summarization", "notification"],
        "trigger_type": "on_schedule",
        "trigger_config": {"cron": "0 9 * * *"},
        "conditions": {},
        "actions": [
            {"type": "run_ai_task", "config": {"task": "summarize"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "in_app",
                    "message": "Daily AI digest: {ai_summary}",
                },
            },
        ],
    },
    # --- Correlation & Reporting ---
    {
        "id": "correlation-intel-report",
        "name": "Intel Report on Correlation Events",
        "description": (
            "When entities correlate (e.g., same actor appears across feeds), generate an intelligence report "
            "automatically."
        ),
        "category": "reporting",
        "tags": ["correlation", "reporting"],
        "trigger_type": "on_correlation_event",
        "trigger_config": {},
        "conditions": {},
        "actions": [
            {"type": "create_intel_report", "config": {}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "in_app",
                    "message": "Correlation detected — intel report generated: {title}",
                },
            },
        ],
    },
    {
        "id": "full-pipeline-with-report",
        "name": "Full Pipeline: Extract, Detect, Report",
        "description": (
            "Complete intelligence pipeline — extract all entities, generate detection rules, create an intel report, "
            "and notify."
        ),
        "category": "reporting",
        "tags": ["pipeline", "detection", "reporting"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {
                    "type": "content_contains",
                    "config": {"pattern": r"(CVE|APT|malware|ransomware|exploit|vulnerability)", "is_regex": True},
                },
            ],
        },
        "actions": [
            {"type": "extract_ttps", "config": {}},
            {"type": "extract_cves", "config": {}},
            {"type": "extract_threat_actors", "config": {}},
            {"type": "extract_malware", "config": {}},
            {"type": "generate_detection_rules", "config": {}},
            {"type": "create_intel_report", "config": {}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "in_app",
                    "message": "Full intel pipeline completed: {title}",
                },
            },
        ],
    },
    # --- Webhook & Export ---
    {
        "id": "webhook-on-cve",
        "name": "Webhook on Critical CVE",
        "description": (
            "Fire a webhook when a critical CVE is detected. Integrate with SIEM, ticketing, or SOAR platforms."
        ),
        "category": "integration",
        "tags": ["webhook", "cve", "integration"],
        "trigger_type": "on_cve_detected",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "severity_above", "config": {"threshold": 8}},
            ],
        },
        "actions": [
            {
                "type": "run_webhook",
                "config": {
                    "url": "https://your-siem.example.com/api/alert",
                    "method": "POST",
                },
            },
        ],
    },
    # --- Noise Reduction ---
    {
        "id": "mute-low-value-sources",
        "name": "Mute Low-Value Sources",
        "description": (
            "Auto-read and tag entries from noisy or low-signal feeds so they stay out of your "
            "unread view without unsubscribing. Edit feed_ids to target your marketing/vendor-blog "
            "feeds — the placeholder ID matches nothing until you set it."
        ),
        "category": "noise",
        "tags": ["noise-reduction", "triage", "mute"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "feed_matches", "config": {"feed_ids": ["00000000-0000-0000-0000-000000000000"]}},
            ],
        },
        "actions": [
            {"type": "add_tags", "config": {"tags": ["muted"]}},
            {"type": "mark_read", "config": {}},
        ],
    },
    {
        "id": "suppress-press-release-noise",
        "name": "Suppress Press-Release Noise",
        "description": (
            "Hide marketing fluff — press releases, webinar invites, and product announcements — "
            "from your feed. Tune the keyword pattern to your sources."
        ),
        "category": "noise",
        "tags": ["noise-reduction", "hide", "marketing"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {
                    "type": "content_contains",
                    "config": {
                        "pattern": (
                            r"(press release|is pleased to announce|register (for|now)"
                            r"|webinar|are excited to|now available|product launch)"
                        ),
                        "is_regex": True,
                    },
                },
            ],
        },
        "actions": [
            {"type": "hide_entry", "config": {}},
        ],
    },
    # --- Signal Engine (additions) ---
    {
        "id": "kev-in-the-wild-fastlane",
        "name": "KEV / In-the-Wild Fast-Lane",
        "description": (
            "The moment the signal engine flags an entry with a KEV-added or weaponized-PoC signal, "
            "escalate it: mark high priority, star it, and fire a notification. Wire the webhook to "
            "your alert channel."
        ),
        "category": "signals",
        "tags": ["signals", "kev", "exploitation", "priority"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "has_signal", "config": {"types": ["kev_added", "weaponized_poc"]}},
            ],
        },
        "actions": [
            {"type": "mark_priority", "config": {"priority": "high"}},
            {"type": "star_entry", "config": {}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Active exploitation / KEV: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "high-score-escalation",
        "name": "High-Score Auto-Escalation",
        "description": (
            "When the signal engine scores an entry above your priority threshold, escalate it — "
            "mark high priority, drop an analyst note, and notify. Tune `min`: priority_score runs 0–10, "
            "ranked against the last 30 days, so 9 is about the top 5% and 10 the top 1%."
        ),
        "category": "signals",
        "tags": ["signals", "priority-score", "escalation"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "priority_score_above", "config": {"min": 9.0}},
            ],
        },
        "actions": [
            {"type": "mark_priority", "config": {"priority": "high"}},
            {
                "type": "create_note",
                "config": {
                    "title": "Auto-escalated: {title}",
                    "content": "The signal engine flagged this entry as high priority.\n\n{summary}",
                },
            },
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "High-score entry: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "epss-spike-watch",
        "name": "EPSS Spike Watch",
        "description": (
            "Catch CVEs whose exploit-probability (EPSS) just jumped — an early warning that a "
            "vulnerability is heating up. Tags the entry and notifies."
        ),
        "category": "signals",
        "tags": ["signals", "epss", "cve", "early-warning"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "has_signal", "config": {"types": ["epss_jump"]}},
            ],
        },
        "actions": [
            {"type": "add_tags", "config": {"tags": ["epss-spike"]}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "EPSS spike: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "novel-entity-emergence",
        "name": "Novel Entity Emergence",
        "description": (
            "Flag entries that introduce a brand-new threat actor or malware family the platform "
            "hasn't seen before — useful for tracking emerging threats. Tags and notifies."
        ),
        "category": "signals",
        "tags": ["signals", "novel-entity", "emerging-threats"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "has_signal", "config": {"types": ["novel_entity"]}},
            ],
        },
        "actions": [
            {"type": "add_tags", "config": {"tags": ["new-entity"]}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Novel entity: {title}\n{app_url}",
                },
            },
        ],
    },
    # --- Detection Engineering (addition) ---
    {
        "id": "ransomware-detection-pipeline",
        "name": "Ransomware Detection Pipeline",
        "description": (
            "End-to-end response to ransomware coverage: extract TTPs and malware, auto-generate "
            "detection rules, and compile an intel report — all from one keyword match."
        ),
        "category": "detection",
        "tags": ["ransomware", "detection", "pipeline", "ttp"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": r"(ransomware|ransom|leak site|double extortion|data encryption|encryptor)",
            "is_regex": True,
        },
        "conditions": {},
        "actions": [
            {"type": "extract_ttps", "config": {}},
            {"type": "extract_malware", "config": {}},
            {"type": "generate_detection_rules", "config": {}},
            {"type": "create_intel_report", "config": {}},
        ],
    },
    # --- Triage (addition) ---
    {
        "id": "auto-bookmark-my-stack",
        "name": "Auto-Bookmark My-Stack Advisories",
        "description": (
            "Bookmark and tag any entry mentioning the vendors/products in your environment, so "
            "advisories affecting your stack are one click away. Edit the pattern to match your tech."
        ),
        "category": "triage",
        "tags": ["bookmark", "vendor", "curation"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {
                    "type": "content_contains",
                    "config": {
                        "pattern": (
                            r"(Microsoft|Windows|Active Directory|VMware|Cisco|Fortinet"
                            r"|Palo Alto|Citrix|Ivanti|Okta|Cloudflare|Kubernetes)"
                        ),
                        "is_regex": True,
                    },
                },
            ],
        },
        "actions": [
            {"type": "bookmark_entry", "config": {}},
            {"type": "add_tags", "config": {"tags": ["my-stack"]}},
        ],
    },
    # --- Correlation & Reporting (additions) ---
    {
        "id": "watched-actor-campaign-rollup",
        "name": "Watched-Actor → Campaign Rollup",
        "description": (
            "When a correlation event involves a watchlisted entity, link the entry into a campaign "
            "and notify — building a running dossier automatically. Set campaign_id on the action to "
            "your target campaign first."
        ),
        "category": "reporting",
        "tags": ["correlation", "campaign", "threat-actor", "watchlist"],
        "trigger_type": "on_correlation_event",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "entity_watchlisted", "config": {}},
            ],
        },
        "actions": [
            {"type": "add_to_campaign", "config": {"campaign_id": "", "notes": "Auto-linked via correlation rollup"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Watched entity correlated: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "weekly-threat-landscape",
        "name": "Weekly Threat Landscape Report",
        "description": (
            "Every Monday morning, run an AI summary across the last 7 days of entries and push a "
            "single landscape digest to your channel. Point the AI task at your briefing/summary "
            "prompt and set the webhook."
        ),
        "category": "reporting",
        "tags": ["reporting", "ai", "weekly", "digest"],
        "trigger_type": "on_schedule",
        "trigger_config": {
            "cron": "0 8 * * 1",
            "execution_mode": "batch",
            "entry_filter": {"since": "-168h"},
            "max_entries": 200,
        },
        "conditions": {},
        "actions": [
            {"type": "run_ai_task", "config": {"task_id": "summarize"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Weekly threat landscape:\n\n{ai_summary}",
                },
            },
        ],
    },
    # --- Analyst Workflow ---
    {
        "id": "on-demand-deep-enrichment",
        "name": "On-Demand Deep Enrichment",
        "description": (
            "Select entries in your triage queue and run this by hand to fully work them: extract "
            "every intelligence entity, generate detection rules, and compile an intel report. The "
            "manual trigger means it only fires when you run it."
        ),
        "category": "workflow",
        "tags": ["manual", "enrichment", "pipeline", "triage"],
        "trigger_type": "on_manual",
        "trigger_config": {},
        "conditions": {},
        "actions": [
            {"type": "extract_ttps", "config": {}},
            {"type": "extract_cves", "config": {}},
            {"type": "extract_threat_actors", "config": {}},
            {"type": "extract_malware", "config": {}},
            {"type": "generate_detection_rules", "config": {}},
            {"type": "create_intel_report", "config": {}},
        ],
    },
    {
        "id": "severity-routed-triage",
        "name": "Severity-Routed Triage",
        "description": (
            "Route each new entry down one of two paths: CVE/critical/zero-day items get "
            "prioritized, enriched, and alerted; everything else is quietly tagged for later. "
            "A worked example of conditional (branch) automation — edit either path to taste."
        ),
        "category": "workflow",
        "tags": ["branch", "routing", "triage"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {},
        "actions": [
            {
                "type": "branch",
                "config": {
                    "condition": {
                        "type": "content_contains",
                        "config": {
                            "pattern": r"(CVE-\d{4}|critical|zero.?day|actively exploited|in the wild)",
                            "is_regex": True,
                        },
                    },
                    "then_actions": [
                        {"type": "mark_priority", "config": {"priority": "high"}},
                        {"type": "extract_cves", "config": {}},
                        {
                            "type": "send_notification",
                            "config": {
                                "platform": "custom",
                                "webhook_url": "",
                                "message_template": "High-severity item routed: {title}\n{app_url}",
                            },
                        },
                    ],
                    "else_actions": [
                        {"type": "add_tags", "config": {"tags": ["fyi"]}},
                    ],
                },
            },
        ],
    },
    {
        "id": "investigate-tag-pipeline",
        "name": "Investigate-Tag Pipeline",
        "description": (
            "Tag entries with 'investigate' as you read, then run this rule over your selection to "
            "batch-work them: extract all entities, build a report, then flip the tag to 'reviewed'. "
            "Reacts to your own tagging via the manual trigger."
        ),
        "category": "workflow",
        "tags": ["manual", "tags", "investigation", "pipeline"],
        "trigger_type": "on_manual",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "tag_matches", "config": {"tags": ["investigate"]}},
            ],
        },
        "actions": [
            {"type": "extract_ttps", "config": {}},
            {"type": "extract_cves", "config": {}},
            {"type": "extract_threat_actors", "config": {}},
            {"type": "extract_malware", "config": {}},
            {"type": "create_intel_report", "config": {}},
            {"type": "remove_tags", "config": {"tags": ["investigate"]}},
            {"type": "add_tags", "config": {"tags": ["reviewed"]}},
        ],
    },
    {
        "id": "trusted-researcher-fasttrack",
        "name": "Trusted Researcher Fast-Track",
        "description": (
            "Star and prioritize entries authored by researchers or vendors you trust, so their work "
            "never gets buried. Edit the authors list to match your go-to sources (substring match)."
        ),
        "category": "triage",
        "tags": ["author", "curation", "priority"],
        "trigger_type": "on_new_entry",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {
                    "type": "author_matches",
                    "config": {"authors": ["Mandiant", "Talos", "Volexity", "Citizen Lab", "GreyNoise"]},
                },
            ],
        },
        "actions": [
            {"type": "star_entry", "config": {}},
            {"type": "mark_priority", "config": {"priority": "high"}},
        ],
    },
    {
        "id": "breaking-story-detector",
        "name": "Breaking Story Detector",
        "description": (
            "Fire when independent sources converge on the same story — a strong signal that "
            "something major is breaking. Prioritizes and notifies."
        ),
        "category": "signals",
        "tags": ["signals", "source-convergence", "breaking-news"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "has_signal", "config": {"types": ["source_convergence"]}},
            ],
        },
        "actions": [
            {"type": "mark_priority", "config": {"priority": "high"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Breaking — sources converging: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "dormant-actor-resurgence",
        "name": "Dormant Actor Resurgence",
        "description": (
            "Alert when a threat actor or malware family that had gone quiet resurfaces in coverage — "
            "often the earliest hint of a renewed campaign. Tags and notifies."
        ),
        "category": "signals",
        "tags": ["signals", "resurgence", "threat-actor"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "has_signal", "config": {"types": ["entity_resurgence"]}},
            ],
        },
        "actions": [
            {"type": "add_tags", "config": {"tags": ["resurgence"]}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Dormant entity resurfaced: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "critical-cvss-war-room",
        "name": "Critical CVSS War Room",
        "description": (
            "Escalate entries carrying a critical-CVSS or high-EPSS signal — the vulnerabilities most "
            "worth dropping everything for. Prioritizes, stars, and notifies."
        ),
        "category": "signals",
        "tags": ["signals", "cvss", "epss", "critical"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "has_signal", "config": {"types": ["critical_cvss", "epss_high"]}},
            ],
        },
        "actions": [
            {"type": "mark_priority", "config": {"priority": "high"}},
            {"type": "star_entry", "config": {}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Critical vuln war room: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "pir-match-alert",
        "name": "PIR Match Alert",
        "description": (
            "When an entry matches one of your Priority Intelligence Requirements, notify and link it "
            "into a campaign so nothing that answers a standing question slips by. Set campaign_id first."
        ),
        "category": "reporting",
        "tags": ["signals", "pir", "requirements", "campaign"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "has_signal", "config": {"types": ["pir_match"]}},
            ],
        },
        "actions": [
            {"type": "add_to_campaign", "config": {"campaign_id": "", "notes": "Auto-linked via PIR match"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "PIR match: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "detection-content-harvester",
        "name": "Detection Content Harvester",
        "description": (
            "Bookmark and tag entries that already contain detection logic (Sigma, YARA, queries) so "
            "detection engineers can mine them fast. Fires on the detection-content signal."
        ),
        "category": "detection",
        "tags": ["signals", "detection", "harvest", "bookmark"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "has_signal", "config": {"types": ["detection_content"]}},
            ],
        },
        "actions": [
            {"type": "add_tags", "config": {"tags": ["has-detection"]}},
            {"type": "bookmark_entry", "config": {}},
        ],
    },
    {
        "id": "slack-discord-priority-alerts",
        "name": "Slack / Discord Priority Alerts",
        "description": (
            "Push high-priority entries straight to a Slack or Discord channel with native formatting. "
            "Set platform to 'slack' or 'discord', paste your webhook URL, and tune the score threshold."
        ),
        "category": "integration",
        "tags": ["slack", "discord", "notification", "priority"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {
            "operator": "AND",
            "conditions": [
                {"type": "priority_score_above", "config": {"min": 9.0}},
            ],
        },
        "actions": [
            {
                "type": "send_notification",
                "config": {
                    "platform": "slack",
                    "webhook_url": "",
                    "channel": "#threat-intel",
                    "username": "IntelFeed",
                    "message_template": "Priority entry: {title}\n{url}",
                },
            },
        ],
    },
    # --- Threat-type coverage alerts (keyword-driven) ---
    {
        "id": "supply-chain-compromise-watch",
        "name": "Supply-Chain Compromise Watch",
        "description": (
            "Catch software supply-chain attacks — malicious packages, typosquats, and dependency "
            "confusion across npm / PyPI / RubyGems / NuGet, plus third-party and build-pipeline "
            "compromises. Extracts entities, prioritizes, and notifies. Tune the pattern to your "
            "ecosystems and set the webhook."
        ),
        "category": "alerting",
        "tags": ["supply-chain", "packages", "typosquat", "notification"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": (
                r"(supply.?chain|malicious package|typosquat|dependency confusion"
                r"|npm|PyPI|RubyGems|NuGet|crates\.io|compromised (package|dependency|library|update)"
                r"|poisoned|backdoored (package|dependency)|third.?party breach)"
            ),
            "is_regex": True,
        },
        "conditions": {},
        "actions": [
            {"type": "add_tags", "config": {"tags": ["supply-chain", "needs-review"]}},
            {"type": "extract_malware", "config": {}},
            {"type": "extract_threat_actors", "config": {}},
            {"type": "mark_priority", "config": {"priority": "high"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Supply-chain compromise: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "data-breach-leak-monitor",
        "name": "Data Breach & Leak Monitor",
        "description": (
            "Flag breach and data-exposure coverage — leaked databases, exposed buckets, credential "
            "dumps, and mass PII disclosures. Tags for triage and notifies. Pair with a watchlist of "
            "your org / partners to catch mentions that matter to you."
        ),
        "category": "alerting",
        "tags": ["breach", "data-leak", "exposure", "notification"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": (
                r"(data breach|breach affecting|records (were )?(exposed|stolen|leaked)"
                r"|leaked database|exposed (database|bucket|S3|Elasticsearch)"
                r"|credential(s)? (dump|leak|stuffing)|PII exposed|customer data (stolen|exposed)"
                r"|information disclosure of)"
            ),
            "is_regex": True,
        },
        "conditions": {},
        "actions": [
            {"type": "add_tags", "config": {"tags": ["breach", "needs-review"]}},
            {"type": "extract_threat_actors", "config": {}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Data breach / leak: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "phishing-aitm-campaign-alert",
        "name": "Phishing / AiTM Campaign Alert",
        "description": (
            "Surface phishing, adversary-in-the-middle, and BEC coverage — credential-harvesting kits, "
            "MFA-bypass / session-hijack tradecraft, and phishing-as-a-service toolkits. Extracts the "
            "actors behind them and notifies."
        ),
        "category": "alerting",
        "tags": ["phishing", "aitm", "bec", "credential-theft", "notification"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": (
                r"(phishing|spear.?phish|credential harvest|adversary.?in.?the.?middle|AiTM"
                r"|business email compromise|\bBEC\b|MFA (bypass|fatigue)|session (hijack|token) theft"
                r"|phishing.?as.?a.?service|PhaaS|reverse proxy phish)"
            ),
            "is_regex": True,
        },
        "conditions": {},
        "actions": [
            {"type": "add_tags", "config": {"tags": ["phishing"]}},
            {"type": "extract_threat_actors", "config": {}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Phishing / AiTM campaign: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "sector-targeted-threat-alert",
        "name": "Sector-Targeted Threat Alert",
        "description": (
            "Get alerted when coverage targets your industry. The default pattern watches "
            "healthcare, finance, energy, manufacturing, and government — replace it with the "
            "sector keywords that describe your organization. Tags, prioritizes, and notifies."
        ),
        "category": "alerting",
        "tags": ["sector", "targeting", "vertical", "notification"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": (
                r"(healthcare|hospital|health system|financial (services|sector)|bank(ing|s)?"
                r"|energy|utilit(y|ies)|power grid|manufactur(ing|er)|industrial|government|public sector"
                r"|critical infrastructure)"
            ),
            "is_regex": True,
        },
        "conditions": {},
        "actions": [
            {"type": "add_tags", "config": {"tags": ["my-sector"]}},
            {"type": "mark_priority", "config": {"priority": "high"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Sector-targeted threat: {title}\n{app_url}",
                },
            },
        ],
    },
    {
        "id": "cloud-identity-threat-watch",
        "name": "Cloud & Identity Threat Watch",
        "description": (
            "Track off-host threats — cloud and identity-provider abuse, OAuth / token theft, and "
            "container/Kubernetes attacks — that endpoint-centric feeds bury. Extracts entities and "
            "notifies. Tune the pattern to your cloud + IdP stack."
        ),
        "category": "alerting",
        "tags": ["cloud", "identity", "oauth", "kubernetes", "notification"],
        "trigger_type": "on_keyword_match",
        "trigger_config": {
            "pattern": (
                r"(Azure AD|Entra ID|Okta|Ping Identity|AWS IAM|OAuth|SAML|OpenID"
                r"|token theft|session token|refresh token|cloud (misconfig|breach|tenant)"
                r"|S3 bucket|storage account|Kubernetes|container escape|EKS|AKS|GKE"
                r"|Microsoft 365|SharePoint|federation)"
            ),
            "is_regex": True,
        },
        "conditions": {},
        "actions": [
            {"type": "add_tags", "config": {"tags": ["cloud-identity"]}},
            {"type": "extract_threat_actors", "config": {}},
            {"type": "extract_malware", "config": {}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Cloud / identity threat: {title}\n{app_url}",
                },
            },
        ],
    },
    # --- Scheduled digests ---
    {
        "id": "daily-intel-digest",
        "name": "Daily Intel Digest",
        "description": (
            "Every morning at 07:00, run an AI summary across the last 24 hours of entries and push a "
            "single digest to your channel — the whole day in one message. Point the AI task at your "
            "briefing/summary prompt and set the webhook. (Scheduled rules digest the whole time "
            "window; use the score-based alert templates for priority-only pings.)"
        ),
        "category": "reporting",
        "tags": ["digest", "daily", "ai", "schedule"],
        "trigger_type": "on_schedule",
        "trigger_config": {
            "cron": "0 7 * * *",
            "execution_mode": "batch",
            "entry_filter": {"since": "-24h"},
            "max_entries": 200,
        },
        "conditions": {},
        "actions": [
            {"type": "run_ai_task", "config": {"task_id": "summarize"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Daily intel digest — last 24h:\n\n{ai_summary}",
                },
            },
        ],
    },
    {
        "id": "category-digest",
        "name": "Category Digest (scoped)",
        "description": (
            "A focused digest of just one feed category — e.g. only your ransomware or vendor-advisory "
            "feeds — summarized daily and pushed to a channel. Set category_ids to the category you "
            "want and paste the webhook. A worked example of scoping a scheduled rule to specific feeds."
        ),
        "category": "reporting",
        "tags": ["digest", "category", "ai", "schedule", "scoped"],
        "trigger_type": "on_schedule",
        "trigger_config": {
            "cron": "0 8 * * *",
            "execution_mode": "batch",
            "entry_filter": {
                "since": "-24h",
                "category_ids": ["00000000-0000-0000-0000-000000000000"],
            },
            "max_entries": 100,
        },
        "conditions": {},
        "actions": [
            {"type": "run_ai_task", "config": {"task_id": "summarize"}},
            {
                "type": "send_notification",
                "config": {
                    "platform": "custom",
                    "webhook_url": "",
                    "message_template": "Category digest — last 24h:\n\n{ai_summary}",
                },
            },
        ],
    },
    # --- Integration: multi-channel routing ---
    {
        "id": "tiered-channel-routing",
        "name": "Tiered Channel Routing",
        "description": (
            "Split alerts across two Slack/Discord channels by priority: top-scoring entries go to a "
            "loud war-room channel, everything else lands in a quieter firehose channel. A worked "
            "example of branch-based fan-out — set both webhook URLs (or channels) and tune the "
            "score threshold."
        ),
        "category": "integration",
        "tags": ["slack", "discord", "routing", "branch", "priority"],
        "trigger_type": "on_entry_scored",
        "trigger_config": {},
        "conditions": {},
        "actions": [
            {
                "type": "branch",
                "config": {
                    "condition": {"type": "priority_score_above", "config": {"min": 9.5}},
                    "then_actions": [
                        {
                            "type": "send_notification",
                            "config": {
                                "platform": "slack",
                                "webhook_url": "",
                                "channel": "#threat-war-room",
                                "username": "IntelFeed",
                                "message_template": "🚨 High priority: {title}\n{url}",
                            },
                        },
                    ],
                    "else_actions": [
                        {
                            "type": "send_notification",
                            "config": {
                                "platform": "slack",
                                "webhook_url": "",
                                "channel": "#intel-firehose",
                                "username": "IntelFeed",
                                "message_template": "{title}\n{url}",
                            },
                        },
                    ],
                },
            },
        ],
    },
]

TEMPLATE_CATEGORIES = [
    {
        "id": "signals",
        "name": "Signal Engine",
        "description": "React to priority signals: watched entities, KEV adds, novel actors",
    },
    {
        "id": "noise",
        "name": "Noise Reduction",
        "description": "Cut clutter: mute low-value sources, hide marketing fluff",
    },
    {
        "id": "workflow",
        "name": "Analyst Workflow",
        "description": "Operator-driven: on-demand runs, conditional routing, tag pipelines",
    },
    {
        "id": "intelligence",
        "name": "Intelligence Extraction",
        "description": "Extract TTPs, CVEs, and entities from feeds",
    },
    {
        "id": "detection",
        "name": "Detection Engineering",
        "description": "Auto-generate detection rules from threat data",
    },
    {
        "id": "alerting",
        "name": "Alerting & Notifications",
        "description": "Get notified about threats relevant to your environment",
    },
    {
        "id": "triage",
        "name": "Triage & Organization",
        "description": "Auto-tag, prioritize, and organize incoming entries",
    },
    {"id": "ai", "name": "AI-Powered", "description": "Leverage AI for summarization and analysis"},
    {
        "id": "reporting",
        "name": "Correlation & Reporting",
        "description": "Generate reports from correlated intelligence",
    },
    {
        "id": "integration",
        "name": "Webhooks & Export",
        "description": "Integrate with external SIEM, SOAR, and TIP systems",
    },
]
