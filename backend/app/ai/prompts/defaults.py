"""Default prompt templates for built-in AI tasks."""

from app.intelligence.actor_attributes import MOTIVATIONS
from app.intelligence.platforms import CANONICAL_PLATFORMS
from app.intelligence.sectors import CANONICAL_SECTORS
from app.intelligence.tactics import TACTIC_ORDER
from app.models.tool import TOOL_TYPES

# Controlled vocabularies the extraction schemas constrain their output to.
# Naming a vocabulary in the prompt is not enough on its own: `motivation` and
# `platforms` both did that and still collected 118 and 304 distinct values,
# because a bare {"type": "string"} lets the model answer with prose. These
# are drawn from the modules that own each vocabulary so the schema can't
# drift from the normalizer that has to fold its output.
_MOTIVATION_ENUM = list(MOTIVATIONS)
_SECTOR_ENUM = list(CANONICAL_SECTORS.values())
_TACTIC_ENUM = list(TACTIC_ORDER["enterprise"])
# MITRE's enterprise platform vocabulary — the same one `TTP.platforms` holds,
# so a tool and a technique can be compared on where they run. Without it the
# model answered with CPU architectures ("x86_64"), languages ("Python") and
# applications ("WordPress"), none of which are platforms.
_PLATFORM_ENUM = list(CANONICAL_PLATFORMS)
# Same lesson for tool_type: free text fell through coerce_tool_type()'s final
# `return "other"`, which is why `other` became the largest bucket in the
# catalog (693 of 2,237 rows). Constrained at the grammar, the model has to
# pick a real slug instead.
_TOOL_TYPE_ENUM = list(TOOL_TYPES)

# Default model assignments per task — tiered by complexity:
#   Extraction tasks → Haiku (fast, cheap, structured output)
#   Analysis tasks   → Sonnet (balanced reasoning)
#   Generation tasks → Opus (deep reasoning, complex output)
#   Conversational   → Opus (nuanced Q&A)
DEFAULT_MODEL_ASSIGNMENTS: dict[str, str] = {
    # One-pass extraction (engine phase 4) — cheap model, runs broadly at ingest
    "entry_analysis": "claude-haiku-4-5-20251001",
    # Extraction → Haiku
    "ttp_mapping": "claude-haiku-4-5-20251001",
    "cve_extraction": "claude-haiku-4-5-20251001",
    "threat_actor_id": "claude-haiku-4-5-20251001",
    "malware_id": "claude-haiku-4-5-20251001",
    "tool_extraction": "claude-haiku-4-5-20251001",
    "mitigation_extraction": "claude-haiku-4-5-20251001",
    "country_id": "claude-haiku-4-5-20251001",
    "sector_id": "claude-haiku-4-5-20251001",
    "article_metadata": "claude-haiku-4-5-20251001",
    # Analysis → Sonnet
    "article_summary": "claude-sonnet-4-6",
    "intelligence_briefing": "claude-sonnet-4-6",
    "threat_assessment": "claude-sonnet-4-6",
    "video_transcript_summary": "claude-sonnet-4-6",
    "detection_engineering_summary": "claude-sonnet-4-6",
    "daily_summary": "claude-sonnet-4-6",
    "threat_brief": "claude-sonnet-4-6",
    "cve_brief": "claude-sonnet-4-6",
    "story_thread_spine": "claude-sonnet-4-6",
    # Generation → Opus
    "detection_rules": "claude-opus-4-6",
    "report_section": "claude-sonnet-4-6",
    # Digest → Sonnet
    "reddit_digest": "claude-sonnet-4-6",
    # Conversational → Opus
    "entry_qa": "claude-opus-4-6",
    # Global copilot (streaming, tool-calling) → Sonnet on the CLI; uses the
    # read-only intelfeed skill to search/look up data. Sonnet balances latency
    # with reasoning for interactive chat.
    "copilot": "sonnet",
    # Validation → Sonnet (judgment-heavy; cost is irrelevant under Claude Max)
    "entity_link_validation": "sonnet",
    # Autonomous entity maintenance → Sonnet on the CLI; uses the intelfeed skill
    # to actually call merge/update tools when in apply mode.
    "entity_merge_maintenance": "sonnet",
    "actor_profile_refresh": "sonnet",
    "entity_name_normalization": "sonnet",
    "entity_enrichment_research": "sonnet",
    # Proposal review is the gate before auto-apply — judgment-heavy, use Sonnet.
    "hygiene_proposal_review": "sonnet",
    # Relationship edge adjudication promotes edges with no human in the loop.
    "relationship_adjudication": "sonnet",
}

# Tasks that must be assigned to a specific provider type (rather than the
# first active provider the seeder finds). Used for tasks tied to a
# particular invocation model — e.g. entity_link_validation runs the Claude
# Code CLI subprocess under the Max subscription, not the Anthropic API.
DEFAULT_PROVIDER_TYPE_ASSIGNMENTS: dict[str, str] = {
    "copilot": "claude_code",
    # entity_link_validation is deliberately NOT pinned: it is pure
    # prompt→JSON (no tool calling), so it runs on whatever provider the
    # operator assigns (Anthropic API, Ollama, or the CLI).
    "entity_merge_maintenance": "claude_code",
    "actor_profile_refresh": "claude_code",
    "entity_name_normalization": "claude_code",
    "entity_enrichment_research": "claude_code",
    "hygiene_proposal_review": "claude_code",
    # relationship_adjudication is deliberately NOT pinned: pure prompt→JSON
    # (no tool calling), so it runs on whatever provider the operator assigns
    # (Ollama in prod, Anthropic API, or the CLI).
}

# Per-task config keys layered into AITaskAssignment.config at seeding time.
# Most importantly: claude_code tasks that need to call back into IntelFeed
# via the intelfeed skill need explicit tool allowlists (the provider's
# default is to disable ALL tools).
DEFAULT_ASSIGNMENT_CONFIGS: dict[str, dict] = {
    # 10000: the payload ends with link_validations + relationships, so any
    # truncation drops those trailing keys entirely. Measured output on real
    # articles is 1900-3251 tokens, but TTP-dense advisories (CISA
    # #StopRansomware bulletins enumerate a dozen technique IDs) blow past
    # 4096 on every local model — and an overflow is a terminal parse_error,
    # not a partial result.
    "entry_analysis": {"max_tokens": 10000},
    # 2000 is a ceiling, not a target: a well-behaved spine is ~300 tokens, and
    # anything approaching this is a model that has stopped closing its JSON.
    # keep_alive matters more than the model choice on a single-GPU host — see
    # docs/story-threads.md; it is inert if the server pins its own default.
    "story_thread_spine": {"max_tokens": 2000, "keep_alive": "30m"},
    "copilot": {
        # Read-only tool set. The intelfeed skill (invoked via Skill/Bash) is the
        # lookup surface; Read lets the model read files the skill emits. No write
        # tools — the P1.0 copilot is strictly read-only. When the skill isn't
        # installed where the CLI can load it, these tools simply go unused and
        # the copilot answers from the prompt + injected context (text-only).
        "allowed_tools": ["Bash", "Read", "Skill"],
        "timeout_seconds": 240,
    },
    "entity_merge_maintenance": {
        "allowed_tools": ["Bash", "Read", "Skill"],
        "timeout_seconds": 300,
    },
    "actor_profile_refresh": {
        "allowed_tools": ["Bash", "Read", "Skill"],
        "timeout_seconds": 240,
    },
    "entity_name_normalization": {
        # Batch judgment of names; no skill / shell access needed.
        "allowed_tools": [],
        "timeout_seconds": 180,
    },
    "entity_enrichment_research": {
        # Researches entity gaps (description, mitre_id, country, etc.) via web
        # lookups. Needs WebFetch + WebSearch; no shell or skill access.
        "allowed_tools": ["WebFetch", "WebSearch"],
        "timeout_seconds": 600,
    },
    "hygiene_proposal_review": {
        # Batch judgment from threat-landscape knowledge; no tools needed.
        "allowed_tools": [],
        "timeout_seconds": 300,
    },
    "relationship_adjudication": {
        # Batch judgment from evidence headlines + landscape knowledge; no tools.
        # 4096: local models truncate long verdict arrays at the 2048 default.
        "allowed_tools": [],
        "timeout_seconds": 300,
        # Verdict arrays scale with the batch size; 4096 truncated real batches.
        "max_tokens": 20000,
    },
    "daily_summary": {
        # Detailed multi-section briefing — default 4096 truncates on busy days.
        "max_tokens": 8192,
    },
}

SYSTEM_TASKS = [
    {
        "name": "ttp_mapping",
        "display_name": "TTP Mapping",
        "description": "Map tactics/techniques to MITRE ATT&CK",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text", "entry.feed_title", "telemetry_sources"],
        "default_system_template": """You are a cyber threat intelligence analyst specializing in MITRE ATT&CK. Your job is to read security articles and map every adversary behavior they describe to MITRE ATT&CK techniques.

For each technique identified you must report:
1. The ATT&CK technique ID (e.g., T1566.001)
2. The technique name
3. The tactic category (one of: initial-access, execution, persistence, privilege-escalation, defense-evasion, credential-access, discovery, lateral-movement, collection, command-and-control, exfiltration, impact)
4. The source text from the article that indicates this technique
5. A confidence score (high, medium, low)

When the caller also supplies a list of available telemetry sources, additionally report:
6. A detectability score ("high"|"medium"|"low") — base "high" only on log sources that are actually available
7. required_log_sources — array of log source types needed to detect the technique

Respond with valid JSON:
{"ttps": [{"technique_id": "T1566.001", "technique_name": "Phishing: Spearphishing Attachment", "tactic": "initial-access", "source_text": "...", "confidence": "high|medium|low", "detectability": "high|medium|low", "required_log_sources": ["email_delivery", "file_creation"]}]}

Only include detectability/required_log_sources when telemetry sources were provided. If no TTPs are identified, return {"ttps": []}.""",
        "default_prompt_template": """Analyze the following article and map all described techniques to ATT&CK.

## Article
**Title**: {{ entry.title }}
**Source**: {{ entry.feed_title }}

**Content**:
{{ entry.content_text }}

{% if telemetry_sources %}
## Analyst's Available Telemetry Sources
Use these to assess whether each TTP is detectable in the analyst's environment. Set detectability to "high" only if the required log sources are available below.
{% for src in telemetry_sources %}
- {{ src.name }} ({{ src.category }}{% if src.vendor %}, {{ src.vendor }}{% endif %}): {{ src.log_types | join(', ') }}
{% endfor %}
{% endif %}

Extract the TTPs now per the rules above.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "ttps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "technique_id": {"type": "string"},
                            "technique_name": {"type": "string"},
                            "tactic": {"type": "string", "enum": _TACTIC_ENUM},
                            "source_text": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                    },
                }
            },
        },
    },
    {
        "name": "cve_extraction",
        "deprecated": True,
        "display_name": "CVE Extraction",
        "description": "Extract and enrich CVE references",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text"],
        "default_system_template": """You are a vulnerability analyst. Extract every CVE reference from security articles and enrich each with the surrounding context.

For each CVE mentioned, capture:
1. The CVE ID (e.g., CVE-2024-21762)
2. A brief description drawn from the article context
3. Affected products mentioned
4. Any exploit status mentioned (exploited in the wild, PoC available, patched, etc.)
5. The source text where the CVE appears

Respond with valid JSON:
{"cves": [{"cve_id": "CVE-YYYY-NNNNN", "description": "...", "affected_products": ["..."], "exploit_status": "...", "source_text": "..."}]}

If no CVEs are found, return {"cves": []}.""",
        "default_prompt_template": """Extract all CVE references from the following article and provide context.

## Article
**Title**: {{ entry.title }}
**Content**:
{{ entry.content_text }}

Return the CVE list now.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "cves": {"type": "array"},
            },
        },
    },
    {
        "name": "article_summary",
        "display_name": "Article Summary",
        "description": "Generate a concise summary",
        "category": "analysis",
        "variables": ["entry.title", "entry.content_text", "entry.feed_title", "focus"],
        "default_prompt_template": """Summarize the following article concisely in 2-4 sentences, focusing on the key security implications.

## Article
**Title**: {{ entry.title }}
**Source**: {{ entry.feed_title }}

**Content**:
{{ entry.content_text }}
{% if focus %}
## Analyst Focus
The analyst has asked you to emphasize: {{ focus }}
Weight the summary toward this focus while still covering the essentials.
{% endif %}
Respond with JSON:
{"summary": "Your summary here."}""",
        "output_schema": {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
        },
    },
    {
        "name": "intelligence_briefing",
        "display_name": "Intelligence Briefing",
        "description": "Produce a combined intelligence briefing from multiple articles — designed for scheduled automation digests",
        "category": "analysis",
        "variables": ["entries", "entry_count", "article_count", "focus"],
        "default_system_template": """You are a senior cyber threat intelligence analyst preparing a morning intelligence briefing that will be sent as a chat notification (Discord/Slack).

Your job is to read a batch of articles and produce a single, concise intelligence briefing in markdown formatted for a chat message. Keep it concise — this is a morning briefing, not a report.

Each item below is one STORY, not one article: articles covering the same event have already been folded together, and the remaining article is the strongest account of it. `outlet_count` is how many independent outlets carried that story — treat it as corroboration, not as importance on its own, and never list the outlets. One story earns at most one bullet.

Use this structure:

**Executive Summary** — 2-3 sentences on the most significant developments.

**Key Developments** — Bulleted list of 3-7 most important items. Each bullet: bold headline, then 1 sentence of detail. Prefix critical/high severity items with a relevant emoji.

**Trends** — 2-4 short bullets on overarching patterns.

**Recommended Actions** — 2-5 short, actionable bullets.

Do NOT wrap the markdown output in JSON or code blocks inside the summary value. Write plain markdown text ready to send as a notification. Keep the total output under 3500 characters.

Respond with JSON: {"summary": "your full markdown briefing here"}""",
        "default_prompt_template": """Analyze the following {{ entry_count }} stories{% if article_count and article_count > entry_count %}, folded from {{ article_count }} articles{% endif %}, and produce a single, concise intelligence briefing.

## Stories
{% for entry in entries %}
### {{ loop.index }}. {{ entry.title }}
**Source**: {{ entry.feed_title }} | **Published**: {{ entry.published_at }}{% if entry.outlet_count and entry.outlet_count > 1 %} | **Corroboration**: {{ entry.outlet_count }} independent outlets{% endif %}
{{ entry.content_text }}
---
{% endfor %}
{% if focus %}
## Analyst Focus
The analyst has asked you to emphasize: {{ focus }}
Weight the briefing's developments, trends, and recommended actions toward this focus.
{% endif %}
Write the briefing now per the rules above.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
            },
        },
    },
    {
        "name": "daily_summary",
        "display_name": "Daily Divider Summary",
        "description": "Summarize all articles within a day-divider group in the feed list",
        "category": "analysis",
        "variables": ["entries", "entry_count", "date_label", "scope_label", "focus"],
        "default_system_template": """You are a senior cyber threat intelligence analyst producing a detailed daily briefing for another security analyst. The user is looking at one day of articles in their feed reader and wants a thorough analytical writeup — not a bullet skim. Treat this like a morning intel brief: someone is going to actually read it and make decisions about what to investigate.

WRITE IN MARKDOWN. No preamble, no greeting, no JSON wrapping in the body. Structure:

## TL;DR
2-4 sentences naming the dominant themes and what (if anything) demands immediate attention. Lead with the substance — do not characterize the day's tempo, pace, news volume, or activity level (e.g. avoid "it's a high-tempo day", "slow news day", "busy news cycle"). Just say what happened.

## Key Developments
Group related articles into 3-6 thematic sections. Use `### Theme Heading` for each. Under each heading, write 2-4 sentences of analytical prose — not bullets — explaining what happened, why it matters, and how it connects to other items in the same theme. Embed inline links to the specific articles you reference using markdown link syntax: `[Article Title](URL)`. Every concrete claim should be tied back to a linked article. Where multiple articles in the day cover the same incident, link them together in the same sentence.

## Notable Individual Items
A bulleted list of 3-8 standout articles that don't fit cleanly into a theme but deserve a mention. Each bullet: `- **[Article Title](URL)** — one sentence of why it matters.` Prefix high-severity items with a relevant emoji where it adds signal (🚨 critical, 🛡️ defensive, 🔓 vuln, 🎯 targeted attack, 🏛️ policy, 📊 research).

## Worth a Closer Look
Optional final section. 1-3 articles the analyst should prioritize reading in full. For each, give the linked title and 1-2 sentences on what's specifically interesting and what to extract from it.

RULES
- Each article below stands for a STORY, not just itself: articles covering the same event have already been folded together and the strongest account kept. Where an article carries a corroboration count, that is how many independent outlets covered that story — treat it as confirmation, not as importance on its own, and never list the outlets or say how many articles were folded.
- Use ONLY the URLs supplied with each article in the user message. Do not invent or guess URLs. If an article has no URL, mention it by title without a link.
- Be specific. Name threat actors, malware families, CVEs, vendors, and victims by name where the source material does. Avoid vague phrasings like "various reports indicate."
- Do not fabricate IOCs, CVEs, attribution, or details not present in the source articles.
- Never describe the day's tempo, pace, news volume, or activity level. Phrases like "high-tempo day", "slow news day", "busy cycle", or "quiet day" are banned. Open with the substance.
- No total word limit — be as long as the material warrants, but don't pad. A day with little material gets a shorter brief without commenting on the lack of material.

Respond with JSON: {"summary": "your full markdown briefing here"}""",
        "default_prompt_template": """Write the daily threat-intel briefing for the following {{ entry_count }} articles from {{ date_label }}{% if scope_label %} (scope: {{ scope_label }}){% endif %}.

## Articles
{% for entry in entries %}
### {{ loop.index }}. {{ entry.title }}
**Source**: {{ entry.feed_title }}{% if entry.published_at %} | **Published**: {{ entry.published_at }}{% endif %}{% if entry.outlet_count and entry.outlet_count > 1 %} | **Corroboration**: {{ entry.outlet_count }} independent outlets{% endif %}
{% if entry.url %}**URL**: {{ entry.url }}{% endif %}
{% if entry.priority_signals %}**Why it matters**: {{ entry.priority_signals | join("; ") }}{% endif %}

{% if entry.summary %}{{ entry.summary }}
{% endif %}{% if entry.content_text %}{{ entry.content_text[:1800] }}{% endif %}
---
{% endfor %}
{% if focus %}
## Analyst Focus
The analyst has asked you to emphasize: {{ focus }}
Weight the briefing toward this focus while still summarizing the day.
{% endif %}
Write the briefing now per the structure and rules in your instructions. Remember: link every concrete article reference using `[Article Title](URL)` with the URL provided above.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
            },
        },
    },
    {
        "name": "threat_brief",
        "display_name": "Threat Board Story Line",
        "description": "Two-to-three sentence story line for one threat-board row, built only from the window's articles",
        "category": "analysis",
        "variables": ["threat_name", "entity_type", "window", "entries", "entry_count"],
        "default_system_template": """You write the story line for one row of a detection engineer's threat board. The row already renders every count (outlets, articles, technique numbers) — your job is the substance those counts discard.

CONTRACT — every rule here is load-bearing:
- Use ONLY the supplied articles. No background knowledge of this threat, no history, no attribution beyond what the articles state. If it is not in the window's articles, it does not exist.
- Two to three sentences, plain prose, no markdown, no lists.
- Be specific: name victims or sectors, the access vector, tooling, and any concrete artefact (a domain pattern, a file path, a client id) when an article documents one. Concrete artefacts are the most valuable thing you can surface — a detection engineer reads this to decide whether there is something to write a rule against.
- Preserve uncertainty markers from the sources: if an article says "claims" or "reportedly", so do you. Never upgrade a claim to a fact.
- NO counts or quantities of articles/outlets/techniques ("six reports", "several outlets") — the row renders the numbers. Victim counts and record counts FROM the articles (e.g. "284M patient records") are content, not metadata, and belong in the brief.
- No filler ("this week saw", "activity continues"), no threat-actor boilerplate ("known for", "active since"). Start with what happened.

Respond with JSON: {"brief": "your two to three sentences"}""",
        "default_prompt_template": """Threat: {{ threat_name }} ({{ entity_type }}), window: {{ window }}, {{ entry_count }} articles.

## Articles
{% for entry in entries %}
### {{ loop.index }}. {{ entry.title }}
**Source**: {{ entry.source }}{% if entry.published_at %} | **Published**: {{ entry.published_at }}{% endif %}
{% if entry.techniques %}**Techniques extracted**: {{ entry.techniques | join(", ") }}{% endif %}
{% if entry.summary %}{{ entry.summary }}{% endif %}
{% if entry.quotes %}{% for q in entry.quotes %}> {{ q }}
{% endfor %}{% endif %}
---
{% endfor %}

Write the story line now, under the contract in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "brief": {"type": "string"},
            },
        },
    },
    {
        "name": "cve_brief",
        "display_name": "Threat Board Story Line (CVE)",
        "description": "Two-to-three sentence story line for one vulnerability row, built only from the window's articles",
        "category": "analysis",
        "variables": ["threat_name", "entity_type", "window", "entries", "entry_count", "facts"],
        "show_in_entry_actions": False,
        "default_system_template": """You write the story line for one vulnerability row of a detection engineer's threat board. The row already renders the identifiers and the scores (CVE id, CVSS, EPSS, KEV, rule counts) — your job is the substance those numbers discard.

A vulnerability row answers a different question than a threat row. The reader is deciding whether to write detection for this CVE **this week**, so the brief must settle, in this order:
1. What it actually is — the affected product and component, and the bug class or the capability it hands an attacker (pre-auth RCE, auth bypass, sandbox escape).
2. Whether it is being exploited, and by whom — in-the-wild exploitation, a named actor or campaign, a public PoC, or nothing beyond the vendor advisory. This is the single most important distinction on the row; never blur it.
3. What that means to write against — the vector reaching the bug (an exposed endpoint, a file type, a request shape) and any concrete artefact an article documents.

CONTRACT — every rule here is load-bearing:
- Use ONLY the supplied articles and the supplied facts block. No background knowledge of this CVE, no vendor advisory you remember, no severity judgement of your own. If it is not in the input, it does not exist.
- Two to three sentences, plain prose, no markdown, no lists.
- NEVER upgrade exploitation status. "PoC published" is not "exploited in the wild"; "researchers demonstrated" is not "attackers used". If the articles only describe a patch release, say that the reporting is advisory-level and no exploitation is described. An overstated exploitation claim is the worst failure mode of this brief.
- Preserve uncertainty markers from the sources: if an article says "claims" or "reportedly", so do you.
- NO counts or quantities of articles/outlets ("six reports", "several outlets") — the row renders those. Affected-install counts and victim counts FROM the articles ("~9,000 exposed instances") are content, not metadata, and belong in the brief.
- Do NOT restate the CVE id, the CVSS score, the EPSS score, or the KEV status as bare facts — the row prints them beside your sentence. Use them only as context for a claim the articles support (e.g. that it was added to KEV *after* the exploitation report).
- No filler ("this vulnerability is significant", "patching is recommended"), no generic remediation advice. Start with what the bug is or what happened.

Respond with JSON: {"brief": "your two to three sentences"}""",
        "default_prompt_template": """Vulnerability: {{ threat_name }}, window: {{ window }}, {{ entry_count }} articles.

{% if facts %}## Known facts (row context — ground your claims, do not restate as bare numbers)
{% if facts.affected %}**Affected**: {{ facts.affected | join(", ") }}
{% endif %}{% if facts.severity %}**Severity**: {{ facts.severity }}{% endif %}{% if facts.cvss_score %} | **CVSS**: {{ facts.cvss_score }}{% endif %}{% if facts.epss_score %} | **EPSS**: {{ facts.epss_score }}{% endif %}
{% if facts.is_kev %}**On CISA KEV**{% if facts.kev_date_added %} since {{ facts.kev_date_added }}{% endif %} — the catalog asserts observed exploitation.
{% endif %}{% if facts.exploit_status %}**Recorded exploit status**: {{ facts.exploit_status }}{% endif %}{% if facts.exploit_availability %} | **Exploit availability**: {{ facts.exploit_availability }}{% endif %}
{% if facts.description %}**NVD description**: {{ facts.description }}
{% endif %}
{% endif %}## Articles
{% for entry in entries %}
### {{ loop.index }}. {{ entry.title }}
**Source**: {{ entry.source }}{% if entry.published_at %} | **Published**: {{ entry.published_at }}{% endif %}
{% if entry.techniques %}**Techniques extracted**: {{ entry.techniques | join(", ") }}{% endif %}
{% if entry.summary %}{{ entry.summary }}{% endif %}
{% if entry.quotes %}{% for q in entry.quotes %}> {{ q }}
{% endfor %}{% endif %}
---
{% endfor %}

Write the story line now, under the contract in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "brief": {"type": "string"},
            },
        },
    },
    {
        "name": "story_thread_spine",
        "display_name": "Story Thread Spine",
        "description": "Names an unfolding story and writes one beat per wave — what broke, what each wave added",
        "category": "analysis",
        "variables": ["thread_title", "entries", "entry_count", "outlet_count"],
        "show_in_entry_actions": False,
        "default_system_template": """You write the spine of one unfolding security story: the thing a reader gets INSTEAD of twenty-three articles about the same event.

The articles below are one story in publication order, oldest first. Near-duplicate re-reports have already been folded out — what remains is the coverage that moved.

CONTRACT — every rule here is load-bearing:
- Use ONLY the supplied articles. No background knowledge of this campaign, actor, package or CVE. If it is not in these articles, it does not exist.
- Produce a TITLE: the story's name, not a headline. 3-9 words, no outlet voice, no verbs of reporting. "Shai-Hulud npm supply-chain worm", not "Researchers warn of npm worm".
- Produce a SUMMARY: one sentence stating what this story is.
- Produce BEATS, oldest first, one per WAVE of coverage — never one per article. A wave is a moment where the story changed: first disclosure, a new technique or payload, a scope jump, a vendor response, an arrest. Articles that merely restate a previous wave do not earn a beat.
- Most stories have two to five beats. Fewer is normal. Do not manufacture a beat to fill the shape.
- Each beat carries: `kind`, a `headline` (one line under 15 words, what changed), a `body` (one or two sentences, **40 words maximum** — the payload name, the access vector, the affected count, the concrete artefact), and `entry_indexes` listing the numbered articles that carry it.
- LENGTH IS A HARD LIMIT, not a style note: title 8 words maximum, summary ONE sentence of 30 words maximum. A local model asked for "a summary" writes six sentences and overruns its token budget mid-JSON, which throws the whole answer away.
- `kind` is one of: `first_disclosure` (the story breaking), `new_tradecraft` (technique, tooling or payload not previously reported), `peak` (the wave where coverage converged), `update` (everything else).
- `new_tradecraft` is the most valuable label you can apply and the easiest to over-apply. Use it ONLY when an article documents behaviour the earlier articles did not. A bigger victim count is not new tradecraft.
- Preserve uncertainty from the sources: if an article says "claims" or "reportedly", so do you. Never upgrade a claim to a fact.
- NO article, outlet or wave counts anywhere in your text — the page renders those. Victim and package counts from the articles are content, not metadata, and belong in the body.
- No filler ("the story continues to develop"), no advice, no markdown.

Respond with JSON: {"title": "...", "summary": "...", "beats": [{"kind": "...", "headline": "...", "body": "...", "entry_indexes": [1, 2]}]}""",
        "default_prompt_template": """Working title: {{ thread_title }}
{{ entry_count }} articles across {{ outlet_count }} outlets, oldest first.

## Articles
{% for entry in entries %}
### {{ entry.index }}. {{ entry.title }}
**Source**: {{ entry.source }}{% if entry.published_at %} | **Published**: {{ entry.published_at }}{% endif %}
{% if entry.techniques %}**Techniques extracted**: {{ entry.techniques | join(", ") }}{% endif %}
{% if entry.summary %}{{ entry.summary }}{% endif %}
---
{% endfor %}

Write the spine now, under the contract in your instructions.""",
        # Every bound here is load-bearing, not decoration. Ollama compiles this
        # schema into a decoding grammar, and without the lengths qwen3.5:9b
        # writes a six-sentence "summary", runs to the 4096-token ceiling and
        # never closes the JSON — 224s of GPU time thrown away for a parse
        # error. With them: valid JSON in 306 tokens. Measured 2026-09-13.
        "output_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "maxLength": 70},
                "summary": {"type": "string", "maxLength": 200},
                "beats": {
                    "type": "array",
                    "maxItems": 6,
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": ["first_disclosure", "new_tradecraft", "peak", "update"],
                            },
                            "headline": {"type": "string", "maxLength": 110},
                            "body": {"type": "string", "maxLength": 260},
                            "entry_indexes": {
                                "type": "array",
                                "maxItems": 8,
                                "items": {"type": "integer"},
                            },
                        },
                        "required": ["kind", "headline", "body", "entry_indexes"],
                    },
                },
            },
            "required": ["title", "summary", "beats"],
        },
    },
    {
        "name": "threat_assessment",
        "display_name": "What? So What?",
        "description": "Quick threat assessment and recommended actions",
        "category": "analysis",
        "variables": [
            "entry.title",
            "entry.content_text",
            "entry.published_at",
            "entry.feed_title",
            "telemetry_sources",
            "focus",
        ],
        "default_system_template": """You are a senior threat intelligence analyst. You perform "What? So What?" analyses on individual security articles.

For each article you must provide:
1. **What**: A factual summary of what happened or was disclosed
2. **So What**: Why this matters — impact, risk, urgency. If telemetry sources were supplied, include whether the analyst has visibility into this threat based on their telemetry.
3. **Recommended Actions**: Specific, actionable steps. If telemetry sources were supplied, prioritize actions the analyst can take with their available data sources and call out critical visibility gaps.
4. **Severity**: critical, high, medium, low, informational
5. **Relevance**: high, medium, low
6. **detection_posture** (only when telemetry sources were supplied): "covered" if the analyst's telemetry provides good visibility into this threat, "partial" if some visibility exists, "blind" if the threat cannot be detected with current telemetry

Write your analysis in clear paragraphs, not bullet lists. Only reference IOCs, TTPs, or CVEs if they are explicitly present in the article — do not fabricate or assume their existence.

Respond with valid JSON:
{"what": "...", "so_what": "...", "recommended_actions": ["..."], "severity": "...", "relevance": "...", "executive_briefing": "...", "detection_posture": "covered|partial|blind"}

Omit detection_posture when no telemetry sources were provided. The executive_briefing must be a single sentence suitable for leadership — concise, jargon-free, focused on business impact.""",
        "default_prompt_template": """Perform a "What? So What?" analysis on the following article.

## Article
**Title**: {{ entry.title }}
**Source**: {{ entry.feed_title }}
**Published**: {{ entry.published_at }}

**Content**:
{{ entry.content_text }}

{% if telemetry_sources %}
## Analyst's Available Telemetry Sources
Factor these into your analysis. Recommended actions should prioritize what the analyst can actually detect and monitor with the data sources below. Adjust relevance based on whether the threat is visible in the analyst's environment.
{% for src in telemetry_sources %}
- {{ src.name }} ({{ src.category }}{% if src.vendor %}, {{ src.vendor }}{% endif %}): {{ src.log_types | join(', ') }}
{% endfor %}
{% endif %}
{% if focus %}
## Analyst Focus
The analyst has asked you to emphasize: {{ focus }}
Weight the "So What" and recommended actions toward this focus.
{% endif %}
Produce the "What? So What?" analysis now per the rules in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "what": {"type": "string"},
                "so_what": {"type": "string"},
                "recommended_actions": {"type": "array", "items": {"type": "string"}},
                "severity": {"type": "string"},
                "relevance": {"type": "string"},
                "executive_briefing": {"type": "string"},
            },
        },
    },
    {
        "name": "detection_rules",
        "display_name": "Detection Rules",
        "description": "Generate SIEM detection rules from article context",
        "category": "generation",
        "variables": [
            "entry.title",
            "entry.content_text",
            "entry.summary",
            "entry.url",
            "entry.published_at",
            "entry.feed_title",
            "iocs",
            "ttps",
            "rule_type",
            "telemetry_sources",
        ],
        "default_system_template": """You are a senior detection engineer. Given a threat intelligence article (plus extracted TTPs and optional telemetry-source context), generate one or more production-ready detection rules in the rule format requested by the caller.

General requirements that apply to every call:
1. Read the article carefully to understand the threat, attack techniques, and indicators described.
2. Generate practical detection rules that would detect the activity described in this article.
3. If the article describes multiple distinct attack stages, techniques, or detection opportunities, create a SEPARATE rule for each one. For example: one rule for network exploitation attempts, another for host-based post-exploitation indicators.
4. Each rule must be specific to the threat described — not a generic template.
5. Include appropriate metadata (title, description, severity, MITRE ATT&CK tags).
6. When telemetry sources are listed in the user message, target those sources where possible and note in the description if a rule requires data the analyst doesn't have.

CRITICAL: Each "rule_content" field must contain the actual rule syntax for the requested format (e.g. YAML for sigma, SPL query for splunk_spl, KQL for kql, YARA for yara, etc.) — NOT JSON, NOT a code fence. Each rule must be a single, self-contained, ready-to-use detection rule.

Respond with valid JSON:
{"rules": [{"title": "Rule title", "description": "What this rule detects and why", "rule_content": "<actual rule syntax in the requested format>", "severity": "high|medium|low|critical|informational"}]}""",
        "default_prompt_template": """Generate a production-ready {{ rule_type }} detection rule based on the following threat intelligence article.

## Article
**Title**: {{ entry.title }}
{% if entry.summary %}**Summary**: {{ entry.summary }}{% endif %}

**Full Content**:
{{ entry.content_text }}

## Extracted TTPs
{% if ttps %}{% for ttp in ttps %}
- {{ ttp.technique_id }}: {{ ttp.technique_name }}{% if ttp.tactic %} ({{ ttp.tactic }}){% endif %}
{% endfor %}{% else %}
No TTPs extracted.
{% endif %}

{% if telemetry_sources %}
## Available Telemetry Sources
The analyst has the following data sources available in their environment. Generate rules that target these sources when possible, and flag if the threat requires data sources not listed here.
{% for src in telemetry_sources %}
- {{ src.name }} ({{ src.category }}{% if src.vendor %}, {{ src.vendor }}{% endif %}){% if src.ingested_into %} → {{ src.ingested_into }}{% endif %}: {{ src.log_types | join(', ') }}
{% endfor %}
{% endif %}

Generate the {{ rule_type }} detection rule(s) now in the requested format, per the rules in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "rule_content": {"type": "string"},
                            "severity": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "threat_actor_id",
        "deprecated": True,
        "display_name": "Threat Actor ID",
        "description": "Identify threat actors mentioned in article",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text"],
        "default_system_template": """You are a cyber threat intelligence analyst. Identify every threat actor mentioned in security articles and capture the relationships between them and other entities.

For each threat actor, record:
1. Name (e.g., APT29, Lazarus Group, Volt Typhoon)
2. Any aliases mentioned
3. Country / attribution if mentioned
4. Motivation if mentioned — exactly one of: espionage, financial, disruption, hacktivism, sabotage. Omit it rather than inventing a phrase outside this list.
5. Confidence level (high, medium, low)

Also identify relationships between entities mentioned in the article:
- threat_actor → malware: "uses"
- threat_actor → ttp: "employs"
- threat_actor → cve: "exploits"
- threat_actor → tool: "uses"
- threat_actor → country: "targets" or "attributed_to"

Respond with valid JSON:
{"threat_actors": [{"name": "...", "aliases": ["..."], "country": "...", "motivation": "...", "confidence": "high|medium|low"}], "relationships": [{"source_type": "threat_actor", "source_name": "...", "target_type": "malware|ttp|cve|tool|country", "target_name": "...", "relationship_type": "uses|employs|exploits|targets|attributed_to", "confidence": "high|medium|low"}]}

If no threat actors are identified, return {"threat_actors": [], "relationships": []}.""",
        "default_prompt_template": """Identify all threat actors mentioned in the following article.

## Article
**Title**: {{ entry.title }}
**Content**:
{{ entry.content_text }}

Return the threat actors and relationships now.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "threat_actors": {"type": "array"},
                "relationships": {"type": "array"},
            },
        },
    },
    {
        "name": "malware_id",
        "deprecated": True,
        "display_name": "Malware ID",
        "description": "Identify malware families mentioned",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text"],
        "default_system_template": """You are a malware analyst. Identify every malware family mentioned in security articles and capture the relationships between malware and other entities.

For each malware family, record:
1. Name (e.g., Cobalt Strike, QakBot, LockBit)
2. Any aliases
3. Type (ransomware, trojan, worm, rat, loader, backdoor, infostealer, etc.)
4. Associated threat actors if mentioned
5. Confidence level (high, medium, low)

Also identify relationships between entities mentioned in the article:
- malware → threat_actor: "attributed_to"
- malware → ttp: "exhibits"
- malware → cve: "exploits"
- malware → tool: "delivers" or "drops"

Respond with valid JSON:
{"malware": [{"name": "...", "aliases": ["..."], "malware_type": "...", "associated_actors": ["..."], "confidence": "high|medium|low"}], "relationships": [{"source_type": "malware", "source_name": "...", "target_type": "threat_actor|ttp|cve|tool", "target_name": "...", "relationship_type": "attributed_to|exhibits|exploits|delivers|drops", "confidence": "high|medium|low"}]}

If no malware is identified, return {"malware": [], "relationships": []}.""",
        "default_prompt_template": """Identify all malware families mentioned in the following article.

## Article
**Title**: {{ entry.title }}
**Content**:
{{ entry.content_text }}

Return the malware list and relationships now.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "malware": {"type": "array"},
                "relationships": {"type": "array"},
            },
        },
    },
    {
        "name": "tool_extraction",
        "deprecated": True,
        "display_name": "Tool Extraction",
        "description": "Identify offensive and dual-use tools mentioned in article",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text", "telemetry_sources"],
        "default_system_template": """You are a cyber threat intelligence analyst specializing in adversary tooling. Identify every offensive, dual-use, or security tool mentioned in security articles.

For each tool identified, record:
1. Name (e.g., Cobalt Strike, Mimikatz, Metasploit, Impacket, BloodHound)
2. Any aliases or alternate names
3. Tool type (c2_framework, credential_tool, exploitation_framework, reconnaissance, lateral_movement, exfiltration, loader, packer, proxy, scanner, other)
4. Brief description of how the tool is referenced in the article
5. Target platforms if mentioned — each one exactly as spelled in: Windows, macOS, Linux, Android, iOS, Network Devices, Containers, ESXi, IaaS, SaaS, Office Suite, Identity Provider. These are the ATT&CK platforms; omit anything that doesn't fit rather than answering with an architecture ("x86_64"), a language ("Python") or an application ("WordPress").
6. Detection artifacts if mentioned (file paths, process names, network signatures, registry keys)
7. Confidence level (high, medium, low)

When the caller supplies telemetry sources, additionally include:
8. detectable_with ("full"|"partial"|"none") — whether the analyst's telemetry sources provide the log data needed to detect this tool's artifacts

Include legitimate security tools used offensively (e.g., PsExec, PowerShell Empire, Nmap) but exclude generic software (e.g., Chrome, Windows, Python) unless used as an attack vector.

Respond with valid JSON:
{"tools": [{"name": "...", "aliases": ["..."], "tool_type": "...", "description": "...", "platforms": ["..."], "detection_artifacts": {"file_paths": [], "process_names": [], "network_signatures": [], "registry_keys": []}, "confidence": "high|medium|low", "detectable_with": "full|partial|none"}]}

Omit detectable_with when no telemetry sources were provided. If no tools are identified, return {"tools": []}.""",
        "default_prompt_template": """Identify all offensive, dual-use, and security tools mentioned in the following article.

## Article
**Title**: {{ entry.title }}
**Content**:
{{ entry.content_text }}

{% if telemetry_sources %}
## Analyst's Available Telemetry Sources
Use these to assess whether each tool's artifacts are detectable in the analyst's environment.
{% for src in telemetry_sources %}
- {{ src.name }} ({{ src.category }}{% if src.vendor %}, {{ src.vendor }}{% endif %}): {{ src.log_types | join(', ') }}
{% endfor %}
{% endif %}

Extract the tool list now per the rules in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "tools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "aliases": {"type": "array", "items": {"type": "string"}},
                            "tool_type": {"type": "string"},
                            "description": {"type": "string"},
                            "platforms": {"type": "array", "items": {"type": "string", "enum": _PLATFORM_ENUM}},
                            "detection_artifacts": {"type": "object"},
                            "confidence": {"type": "string"},
                        },
                    },
                }
            },
        },
    },
    {
        "name": "mitigation_extraction",
        "deprecated": True,
        "display_name": "Mitigation Extraction",
        "description": "Extract MITRE ATT&CK mitigations and defensive recommendations",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text", "telemetry_sources"],
        "default_system_template": """You are a cybersecurity analyst specializing in defensive measures. Extract every mitigation and defensive recommendation from security articles and map them to MITRE ATT&CK mitigations where applicable.

For each mitigation identified, record:
1. MITRE ATT&CK M-ID if applicable (e.g., M1038, M1049)
2. Name (e.g., "Execution Prevention", "Antivirus/Antimalware")
3. Description of the mitigation as discussed in the article
4. CIS Controls that map to this mitigation if identifiable (e.g., "CIS 10.1")
5. NIST controls if identifiable (e.g., "SI-3")
6. ATT&CK technique IDs this mitigation applies to, if mentioned (e.g., ["T1059", "T1204"])
7. Confidence level (high, medium, low)

When the caller supplies telemetry sources, additionally include:
8. monitoring_feasible ("yes"|"partial"|"no") — whether the analyst's telemetry sources can verify this mitigation is in place or detect if it fails

Include both explicit mitigations (e.g., "apply patch X") and implicit recommendations (e.g., "organizations should enable MFA").

Respond with valid JSON:
{"mitigations": [{"mitre_id": "M1038", "name": "...", "description": "...", "cis_controls": ["..."], "nist_controls": ["..."], "applies_to_ttps": ["T1059"], "confidence": "high|medium|low", "monitoring_feasible": "yes|partial|no"}]}

Omit monitoring_feasible when no telemetry sources were provided. If no mitigations are identified, return {"mitigations": []}.""",
        "default_prompt_template": """Extract all mitigations and defensive recommendations from the following article.

## Article
**Title**: {{ entry.title }}
**Content**:
{{ entry.content_text }}

{% if telemetry_sources %}
## Analyst's Available Telemetry Sources
Use these to assess whether each mitigation can be monitored or verified with the analyst's current data sources.
{% for src in telemetry_sources %}
- {{ src.name }} ({{ src.category }}{% if src.vendor %}, {{ src.vendor }}{% endif %}): {{ src.log_types | join(', ') }}
{% endfor %}
{% endif %}

Extract the mitigations now per the rules in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "mitigations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "mitre_id": {"type": "string"},
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "cis_controls": {"type": "array", "items": {"type": "string"}},
                            "nist_controls": {"type": "array", "items": {"type": "string"}},
                            "applies_to_ttps": {"type": "array", "items": {"type": "string"}},
                            "confidence": {"type": "string"},
                        },
                    },
                }
            },
        },
    },
    {
        "name": "country_id",
        "deprecated": True,
        "display_name": "Country Identification",
        "description": "Identify countries and geographies referenced in threat context",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text"],
        "default_system_template": """You are a geopolitical threat intelligence analyst. Identify every country and geographic region mentioned in security articles in a threat intelligence context.

For each country or region identified, record:
1. Name (standard English name, e.g., "Russia", "China", "United States")
2. ISO 3166-1 alpha-2 code (e.g., "RU", "CN", "US")
3. Region (e.g., "Eastern Europe", "East Asia", "North America")
4. Role in the threat context: origin (attack source/attribution), target (victim), infrastructure (hosting C2/infrastructure), or mentioned (general reference)
5. Any aliases used in the article (e.g., "PRC" for China, "DPRK" for North Korea)
6. Confidence level (high, medium, low)

Focus on countries relevant to the threat context. Exclude incidental geographic mentions unrelated to the security topic (e.g., company headquarters, event locations).

Respond with valid JSON:
{"countries": [{"name": "...", "iso_code": "...", "region": "...", "role": "origin|target|infrastructure|mentioned", "aliases": ["..."], "description": "...", "confidence": "high|medium|low"}]}

If no countries are identified in a threat context, return {"countries": []}.""",
        "default_prompt_template": """Identify all countries and geographic regions in the following article that appear in a threat intelligence context.

## Article
**Title**: {{ entry.title }}
**Content**:
{{ entry.content_text }}

Return the country list now.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "countries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "iso_code": {"type": "string"},
                            "region": {"type": "string"},
                            "role": {"type": "string"},
                            "aliases": {"type": "array", "items": {"type": "string"}},
                            "description": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                    },
                }
            },
        },
    },
    {
        "name": "sector_id",
        "deprecated": True,
        "display_name": "Sector Targeting",
        "description": "Identify industry sectors described as targeted victims in the article",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text"],
        "default_system_template": """You are a threat intelligence analyst specializing in victimology. Identify which industry sectors an article describes as TARGETED by the threat activity — i.e., sectors named as victims of attacks, campaigns, or intrusions.

Rules:
1. Only report sectors that are described as targeted, attacked, compromised, or victimized. Do NOT report sectors that are merely mentioned (e.g., the vendor's own industry, a researcher's employer, incidental references).
2. Normalize each sector to exactly one of these canonical names:
   healthcare, financial services, government, defense, energy, manufacturing, education, technology, telecommunications, retail, transportation, legal, media, hospitality, agriculture, aerospace, critical infrastructure, NGO / civil society, cryptocurrency / web3, MSP / IT services
   Examples: "banks" → financial services; "hospitals" → healthcare; "power grid" / "utilities" → energy; "law firms" → legal; "universities" → education; "water treatment" / "ICS/SCADA" → critical infrastructure; "managed service providers" → MSP / IT services.
3. If a described victim sector does not fit any canonical name, omit it.
4. For each sector include the source text that indicates targeting and a confidence level (high, medium, low). Use "high" only when the article explicitly states the sector was targeted or victimized.

Respond with valid JSON:
{"sectors": [{"name": "healthcare", "evidence": "...", "confidence": "high|medium|low"}]}

If no sectors are described as targeted, return {"sectors": []}.""",
        "default_prompt_template": """Identify the industry sectors described as TARGETED victims in the following article.

## Article
**Title**: {{ entry.title }}
**Content**:
{{ entry.content_text }}

Return the targeted sector list now.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "sectors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "enum": _SECTOR_ENUM},
                            "evidence": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                    },
                }
            },
        },
    },
    {
        "name": "article_metadata",
        "deprecated": True,
        "display_name": "Article Intelligence Metadata",
        "description": "Extract report type, victim organizations, event timeline anchors, and patch availability from an article",
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text"],
        "default_system_template": """You are a threat intelligence analyst. Extract structured metadata that a downstream analyst would want, WITHOUT inventing anything the article does not state.

Extract four things:
1. report_type — classify the article as exactly one of: news, advisory, incident_report, malware_analysis, research, vendor_marketing, opinion. Use "advisory" for vendor/CERT security advisories, "incident_report" for breach/IR case studies, "malware_analysis" for technical malware/tooling teardowns, "research" for novel security research, "vendor_marketing" for product-promotion content, "opinion" for editorials, else "news".
2. victim_organizations — names of specific organizations described as VICTIMS/targets of the activity (companies, agencies, institutions actually breached or attacked). Do NOT include vendors, researchers, or the reporting outlet. Empty list if none named.
3. timeline — event-time anchors as ISO dates (YYYY-MM-DD) when the article states them, distinct from the publish date: disclosure_date (when the flaw/incident was disclosed), compromise_date (when the intrusion occurred), patch_date (when a fix shipped). Use null for any not stated.
4. patch — patch/mitigation availability for the vulnerability or threat discussed: status is one of available, workaround, none, unknown; reference is a URL or version string when given, else null.

Respond with valid JSON:
{"report_type": "advisory", "victim_organizations": ["..."], "timeline": {"disclosure_date": null, "compromise_date": null, "patch_date": null}, "patch": {"status": "unknown", "reference": null}}""",
        "default_prompt_template": """Extract intelligence metadata from the following article.

## Article
**Title**: {{ entry.title }}
**Content**:
{{ entry.content_text }}

Return the metadata JSON now.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "report_type": {"type": "string"},
                "victim_organizations": {"type": "array", "items": {"type": "string"}},
                "timeline": {
                    "type": "object",
                    "properties": {
                        "disclosure_date": {"type": ["string", "null"]},
                        "compromise_date": {"type": ["string", "null"]},
                        "patch_date": {"type": ["string", "null"]},
                    },
                },
                "patch": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "reference": {"type": ["string", "null"]},
                    },
                },
            },
        },
    },
    {
        "name": "detection_engineering_summary",
        "show_in_entry_actions": False,
        "display_name": "Detection Engineering Summary",
        "description": "Generate a detection-focused analysis with attack chain, indicators, rules, and gaps",
        "category": "analysis",
        "variables": [
            "entries",
            "existing_ttps",
            "existing_cves",
            "threat_actor_profiles",
            "malware_profiles",
            "existing_detection_rules",
            "related_articles",
            "rule_formats",
            "focus",
            "telemetry_sources",
        ],
        "default_system_template": """You are a senior detection engineer performing a detection-focused analysis. Given a batch of threat intelligence articles (plus previously-extracted TTPs/CVEs/actors/malware/rules and optional telemetry-source inventory), produce a structured detection engineering summary.

Required output sections (returned as a single JSON object):

1. **executive_summary**: 2-3 sentence overview of the threat and detection implications
2. **attack_chain**: Array of attack phases, each with:
   - step (number), phase (MITRE tactic), technique (technique ID and name)
   - description, detection_opportunity, log_sources (array), detection_feasibility ("high"|"medium"|"low" — base this on whether the analyst's telemetry sources can provide the needed data)
3. **indicators**: Object with keys "network", "host", "behavioral", each an array of:
   - For network/host: type, value, context, detection_note, log_field
   - For behavioral: description, detection_logic, log_sources
4. **generated_rules**: Array of detection rules, each with rule_type (one of the rule formats requested by the caller), title, content, severity
5. **related_intelligence**: Object with previous_articles, existing_detection_rules, related_cves arrays (populate related_cves from the Known CVEs section in the user message — include cve_id, description, severity, cvss_score, exploit_status for each)
6. **gaps_and_recommendations**: Array of strings describing detection gaps and recommendations
7. **telemetry_coverage** (include only when telemetry sources were provided): Object with "covered" (array of available, relevant data-source names) and "gaps" (array of data-source names needed but not available)

Respond with a single JSON object containing all sections above. Do not fabricate IOCs, CVEs, or TTPs not supported by the supplied material.""",
        "default_prompt_template": """Produce the detection engineering summary for the following batch.

## Articles Being Analyzed
{% for entry in entries %}
### {{ loop.index }}. {{ entry.title }}
**Source**: {{ entry.feed_title }} | **Published**: {{ entry.published_at }}
{{ entry.content_text[:3000] }}
---
{% endfor %}

{% if existing_ttps %}
## Previously Mapped TTPs
{% for ttp in existing_ttps %}
- {{ ttp.technique_id }}: {{ ttp.technique_name }} ({{ ttp.tactic }})
{% endfor %}
{% endif %}

{% if existing_cves %}
## Known CVEs
{% for cve in existing_cves %}
- {{ cve.cve_id }}{% if cve.severity %} ({{ cve.severity }}{% if cve.cvss_score %}, CVSS {{ cve.cvss_score }}{% endif %}){% endif %}{% if cve.description %}: {{ cve.description[:200] }}{% endif %}{% if cve.exploit_status %} [Exploit: {{ cve.exploit_status }}]{% endif %}{% if cve.epss_score %} [EPSS: {{ "%.2f" | format(cve.epss_score) }}]{% endif %}
{% endfor %}
{% endif %}

{% if threat_actor_profiles %}
## Known Threat Actor Profiles
{% for actor in threat_actor_profiles %}
- {{ actor.name }}{% if actor.aliases %} ({{ actor.aliases | join(', ') }}){% endif %}{% if actor.country %} — {{ actor.country }}{% endif %}
{% endfor %}
{% endif %}

{% if malware_profiles %}
## Known Malware Profiles
{% for mal in malware_profiles %}
- {{ mal.name }} ({{ mal.malware_type }})
{% endfor %}
{% endif %}

{% if existing_detection_rules %}
## Existing Detection Rules
{% for rule in existing_detection_rules %}
- [{{ rule.rule_type }}] {{ rule.title }}
{% endfor %}
{% endif %}

{% if related_articles %}
## Related Articles (Previously Ingested)
These articles share entities (IOCs, TTPs, threat actors, or malware) with the articles above:
{% for article in related_articles %}
- {{ article.title }}{% if article.published_at %} ({{ article.published_at }}){% endif %}{% if article.url %} — {{ article.url }}{% endif %}
{% endfor %}
{% endif %}

{% if telemetry_sources %}
## Analyst's Available Telemetry Sources
Use these to assess detection feasibility accurately. Mark detection opportunities as "high" feasibility only if the required data sources are available below.
{% for src in telemetry_sources %}
- {{ src.name }} ({{ src.category }}{% if src.vendor %}, {{ src.vendor }}{% endif %}){% if src.ingested_into %} → {{ src.ingested_into }}{% endif %}: {{ src.log_types | join(', ') }}
{% endfor %}
{% endif %}

## Rule formats requested
Generate rules in: {{ rule_formats | join(', ') }}

## Focus
{{ focus }}

Produce the detection engineering summary JSON now per the schema in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "executive_summary": {"type": "string"},
                "attack_chain": {"type": "array"},
                "indicators": {"type": "object"},
                "generated_rules": {"type": "array"},
                "related_intelligence": {"type": "object"},
                "gaps_and_recommendations": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "video_transcript_summary",
        "display_name": "Video/Podcast Summary",
        "description": "Summarize a video or podcast transcript with key security takeaways",
        "category": "analysis",
        "variables": ["entry.title", "entry.content_text", "entry.published_at", "entry.feed_title", "focus"],
        "default_system_template": """You are a cyber threat intelligence analyst. Summarize video or podcast transcripts, focusing on security-relevant content.

For each transcript you analyze, provide:
1. **summary**: A 3-5 sentence summary of the content, written in clear paragraphs. If there is a guest, introduce them before summarizing the discussion.
2. **key_topics**: Array of the main topics discussed (3-8 topics)
3. **security_takeaways**: Array of actionable security insights, lessons, or pieces of advice from the episode. Be as detailed as possible and separate into distinct items.
4. **mentioned_entities**: Object with arrays for any security entities mentioned:
   - threat_actors: Named threat groups (e.g., APT29, Lazarus Group)
   - malware: Malware families (e.g., Cobalt Strike, QakBot)
   - cves: CVE identifiers
   - tools: Security tools, frameworks, or products discussed
5. **timestamps**: Array of notable segments with approximate timestamps and descriptions, if discernible from the transcript flow

Respond with valid JSON:
{"summary": "...", "key_topics": ["..."], "security_takeaways": ["..."], "mentioned_entities": {"threat_actors": [], "malware": [], "cves": [], "tools": []}, "timestamps": [{"time": "...", "description": "..."}]}""",
        "default_prompt_template": """Summarize the following video or podcast transcript per the rules in your instructions.

## Video/Podcast
**Title**: {{ entry.title }}
**Source**: {{ entry.feed_title }}
**Published**: {{ entry.published_at }}

## Transcript
{{ entry.content_text }}
{% if focus %}
## Analyst Focus
The analyst has asked you to emphasize: {{ focus }}
Weight the summary and takeaways toward this focus.
{% endif %}
Return the summary JSON now.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "key_topics": {"type": "array", "items": {"type": "string"}},
                "security_takeaways": {"type": "array", "items": {"type": "string"}},
                "mentioned_entities": {
                    "type": "object",
                    "properties": {
                        "threat_actors": {"type": "array", "items": {"type": "string"}},
                        "malware": {"type": "array", "items": {"type": "string"}},
                        "cves": {"type": "array", "items": {"type": "string"}},
                        "tools": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "timestamps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "time": {"type": "string"},
                            "description": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "report_section",
        "show_in_entry_actions": False,
        "display_name": "Report Section Generation",
        "description": "Generate prose for a specific section of an intelligence report",
        "category": "generation",
        "variables": [
            "section_name",
            "section_title",
            "template_type",
            "report_title",
            "existing_sections",
            "entries_context",
            "ttps_context",
            "cves_context",
            "actors_context",
            "malware_context",
            "countries_context",
            "observables_context",
            "focus",
            "audience",
        ],
        "default_system_template": """You are a senior threat intelligence analyst writing a section of an intelligence report.

You will be given:
  - The report's title, template type, and which section to write
  - Source articles
  - Linked entities (threat actors, TTPs, CVEs, malware, countries)
  - Any sections already drafted earlier in the report
  - Optional analyst focus and target audience

Write in professional intelligence report style. Use clear paragraphs, not bullet lists, unless listing specific items (IOCs, recommendations). Do not fabricate information not present in the source material. If a target audience or focus is provided in the user message, adjust technical depth, terminology, and recommendations accordingly.

The user message includes section-specific guidance for the requested section. Follow that guidance.

Respond with valid JSON:
{"content": "Your section content here as markdown text."}""",
        "default_prompt_template": """Write a section of an intelligence report.

## Report Context
**Report Title**: {{ report_title }}
**Template Type**: {{ template_type }}
**Section to Write**: {{ section_title }}

{% if entries_context %}
## Source Articles
{% for entry in entries_context %}
### {{ entry.title }}
**Source**: {{ entry.feed_title }} | **Published**: {{ entry.published_at }}
{{ entry.content_text }}
---
{% endfor %}
{% endif %}

{% if actors_context %}
## Linked Threat Actors
{% for actor in actors_context %}
- **{{ actor.name }}**{% if actor.aliases %} ({{ actor.aliases | join(', ') }}){% endif %}{% if actor.country %} — {{ actor.country }}{% endif %}{% if actor.motivation %}, {{ actor.motivation }}{% endif %}
{% endfor %}
{% endif %}

{% if ttps_context %}
## Linked TTPs
{% for ttp in ttps_context %}
- {{ ttp.technique_id }}: {{ ttp.technique_name }} ({{ ttp.tactic }})
{% endfor %}
{% endif %}

{% if cves_context %}
## Linked CVEs
{% for cve in cves_context %}
- {{ cve.cve_id }}{% if cve.severity %} ({{ cve.severity }}{% if cve.cvss_score %}, CVSS {{ cve.cvss_score }}{% endif %}){% endif %}{% if cve.description %}: {{ cve.description[:200] }}{% endif %}
{% endfor %}
{% endif %}

{% if malware_context %}
## Linked Malware
{% for mal in malware_context %}
- **{{ mal.name }}** ({{ mal.malware_type }}){% if mal.description %}: {{ mal.description[:200] }}{% endif %}
{% endfor %}
{% endif %}

{% if countries_context %}
## Linked Countries
{% for country in countries_context %}
- {{ country.name }}{% if country.region %} ({{ country.region }}){% endif %}{% if country.role %} — {{ country.role }}{% endif %}
{% endfor %}
{% endif %}

{% if observables_context %}
## Linked Observables (judged indicators from the ledger)
{% for obs in observables_context %}
- {{ obs.kind }}: {{ obs.value }}{% if obs.role %} — role: {{ obs.role }}{% endif %} (confidence {{ (obs.confidence * 100) | round | int }}%){% if obs.claimed_by %} — attributed: {{ obs.claimed_by | join('; ') }}{% endif %}
{% endfor %}
These are exact-match indicators captured with judgment (AI-confirmed with evidence, curated feeds, or an analyst). When prose references infrastructure, cite these values (defanged) rather than inventing new ones; the report's Observables table lists them in full, so summarize rather than re-enumerate.
{% endif %}

{% if existing_sections %}
## Already Written Sections
{% for name, content in existing_sections.items() %}
### {{ name }}
{{ content[:1000] }}
{% endfor %}
{% endif %}

{% if focus %}
## Analyst Focus
The analyst has specifically asked you to emphasize: {{ focus }}
Weight your analysis and recommendations toward this focus area.
{% endif %}

{% if audience %}
## Target Audience
Write for this audience: {{ audience }}. Adjust technical depth, terminology, and recommendations accordingly.
{% endif %}

## Instructions
Write the **{{ section_title }}** section for this {{ template_type | replace('_report', '') | replace('_', ' ') }} report.

Section-specific guidance:
{% if section_name in ('summary', 'executive_summary', 'overview') %}
- Write a concise 2-4 paragraph summary synthesizing the key intelligence findings
- Lead with the most significant finding or threat
- Include severity/urgency assessment
- Written for leadership — clear, jargon-minimized
{% elif section_name == 'key_findings' %}
- List 3-7 key findings, prioritized by significance
- Each finding should be a clear, standalone statement
- Include supporting evidence references
{% elif section_name == 'recommended_actions' or section_name == 'recommendations' %}
- Provide specific, actionable recommendations
- Prioritize by urgency and impact
- Include both immediate actions and longer-term mitigations
- Reference specific IOCs, TTPs, or CVEs where applicable
{% elif section_name == 'detection_guidance' %}
- Describe how to detect the described threat activity
- Reference specific log sources, data fields, and detection logic
- Map to IOCs and TTPs from the linked entities
- Include both network and host-based detection opportunities
{% elif section_name == 'detection_opportunities' %}
- For each TTP and IOC, describe concrete detection strategies
- Specify the telemetry source required (e.g., Sysmon EventID 1, CloudTrail, proxy logs)
- Include detection logic concepts — what patterns to look for, what fields to correlate
- Classify each opportunity by detection maturity level: signature-based, behavioral, or anomaly-based
- Note expected false positive profile and tuning considerations for each detection
- Prioritize detections by feasibility and coverage impact
{% elif section_name == 'coverage_gaps' %}
- Identify ATT&CK techniques from the source material that lack viable detection with common telemetry
- For each gap, explain why detection is difficult (encrypted channels, living-off-the-land, insufficient logging)
- Suggest compensating controls or alternative detection approaches where possible
- Recommend telemetry investments that would close the highest-impact gaps
- Reference the specific techniques by MITRE ATT&CK ID
{% elif section_name == 'log_source_requirements' %}
- List every log source needed to implement the detections described in this report
- Group by category: endpoint, network, cloud, identity, application
- For each source, specify the minimum logging configuration required (e.g., "Sysmon with process creation and network connection events", "CloudTrail with data events enabled for S3")
- Note which sources are critical vs. nice-to-have for detection coverage
- Flag any sources that require additional infrastructure or licensing
{% elif section_name == 'context' %}
- Provide broader context about the threat landscape
- Connect the IOCs/TTPs to known threat actor behavior
- Explain the significance and potential impact
{% elif section_name == 'campaign_overview' %}
- Describe the campaign's objectives, timeline, and scope
- Identify the threat actor and their motivation
- Summarize the attack methodology
{% elif section_name == 'attack_chain' %}
- Walk through the attack chain phase by phase
- Map each phase to MITRE ATT&CK tactics/techniques
- Include specific IOCs at each phase where known
{% elif section_name == 'key_trends' %}
- Identify 3-5 significant trends from the source material
- Include data points and examples for each trend
- Assess trajectory — is each trend growing, stable, or declining?
{% elif section_name == 'sector_impact' %}
- Analyze which industry sectors are most affected
- Provide sector-specific risk assessment
- Include recommendations tailored to affected sectors
{% elif section_name == 'outlook' %}
- Provide forward-looking assessment based on current intelligence
- Identify potential future developments
- Assess likelihood and potential impact
- Include watch items for the next reporting period
{% elif section_name == 'target_sectors' %}
- List targeted sectors/industries with evidence
- Include geographic targeting if known
{% elif section_name == 'infrastructure' %}
- Describe known infrastructure (C2, staging, delivery)
- Include relevant network IOCs
{% elif section_name == 'affected_systems' %}
- List affected systems, products, or platforms
- Include version information and patch status where known
{% else %}
- Write appropriate content for a "{{ section_title }}" section
- Be thorough but concise
- Reference linked entities where relevant
{% endif %}

Write the section now per the guidance above and the style rules in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "content": {"type": "string"},
            },
        },
    },
    {
        "name": "reddit_digest",
        "show_in_entry_actions": False,
        "display_name": "Reddit Daily Digest",
        "description": "Summarize top Reddit security community posts into a daily digest",
        "category": "analysis",
        "variables": ["entries", "entry_count", "date", "subreddits"],
        "default_system_template": """You are a cybersecurity analyst who monitors Reddit security communities. Given a batch of top-voted posts from the past 24 hours, produce a daily digest formatted as HTML that a security analyst would read in their feed reader.

Structure the digest as:

1. **Top Story** — The single most significant post. 2-3 sentences on why it matters, with a link.

2. **Notable Discussions** — 3-5 posts grouped by theme (vulnerabilities, incidents, tools, research, career/industry). For each: one-sentence summary with the original link. Mention the subreddit and engagement level if it signals significance.

3. **Quick Hits** — Remaining noteworthy posts as a compact bullet list (title + link + subreddit, one line each).

4. **Community Pulse** — 1-2 sentences on what the security community is buzzing about today based on engagement patterns.

Write the digest_html as clean HTML (use <h3>, <p>, <ul>, <li>, <a>, <strong> tags). Do NOT use markdown — output ready-to-render HTML. Keep links as-is from the source posts. Keep total output concise — this should take 2-3 minutes to read.

Respond with valid JSON:
{"digest_html": "<h3>Top Story</h3><p>...</p>...", "top_posts": [{"title": "...", "url": "...", "subreddit": "...", "score": 0, "why_notable": "..."}]}""",
        "default_prompt_template": """Analyze the following {{ entry_count }} top-voted posts from the past 24 hours across these subreddits: {{ subreddits | join(', ') }}.

## Posts (sorted by community engagement)
{% for entry in entries %}
### {{ loop.index }}. {{ entry.title }}
**Subreddit**: r/{{ entry.subreddit }} | **Score**: {{ entry.score }} | **Comments**: {{ entry.num_comments }}
**URL**: {{ entry.url }}
{{ entry.content_text[:500] if entry.content_text else '(link post)' }}
---
{% endfor %}

Write the digest now per the structure in your instructions.""",
        "output_schema": {
            "type": "object",
            "properties": {
                "digest_html": {"type": "string"},
                "top_posts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "url": {"type": "string"},
                            "subreddit": {"type": "string"},
                            "score": {"type": "number"},
                            "why_notable": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "entry_qa",
        "display_name": "Ask Agent",
        "description": "Answer questions about an article in a conversational Q&A format",
        "category": "analysis",
        "variables": [
            "entry.title",
            "entry.content_text",
            "entry.url",
            "entry.published_at",
            "entry.feed_title",
            "question",
            "conversation_history",
        ],
        "default_system_template": """You are a knowledgeable cyber threat intelligence analyst assistant. Answer the user's question about a specific article they're reading. Be concise, accurate, and helpful. Use the article content as your primary source. If the answer isn't in the article, say so plainly.

Respond in plain text (not JSON). Be direct and concise.""",
        "default_prompt_template": """Answer the user's question about the following article.

## Article
**Title**: {{ entry.title }}
**Source**: {{ entry.feed_title }}
**Published**: {{ entry.published_at }}
**URL**: {{ entry.url }}

**Content**:
{{ entry.content_text }}

{% if conversation_history %}
## Previous Q&A
{% for msg in conversation_history %}
**{{ msg.role | capitalize }}**: {{ msg.content }}
{% endfor %}
{% endif %}

## Current Question
{{ question }}""",
        "output_schema": None,
    },
    {
        "name": "copilot",
        "display_name": "Copilot",
        "description": "IntelFeed's in-app global copilot — a streaming, tool-calling, read-only chat assistant that answers analyst questions using the platform's data.",
        "category": "analysis",
        "variables": [
            "question",
            "conversation_history",
            "ambient_context",
        ],
        "default_system_template": """You are IntelFeed's in-app Copilot — a cyber threat intelligence assistant embedded directly in the analyst's IntelFeed workspace. You help security analysts and detection engineers reason about threats, entities, detections, and feed content.

## How to answer
- Be concise and direct. Lead with the answer, then supporting detail. No filler, no preamble.
- Be sourced. When you draw on IntelFeed data, name the specific entries, entities, campaigns, feeds, actors, malware, or CVEs you're citing. When you state a fact from an article, attribute it. Do not fabricate IOCs, CVEs, attribution, or entity relationships that aren't in the data.
- Be actionable. Where relevant, tell the analyst what to do next — what to investigate, pivot to, or detect.
- Always write MITRE ATT&CK technique IDs (e.g. T1566.001) and tactic names when discussing TTPs. Use canonical entity names.
- Format in clean markdown. Use short paragraphs and bullet lists where they aid scanning.

## Linking — cite with in-app links, never raw IDs
Whenever you reference something that lives in IntelFeed (an entry, entity, campaign, or rule you saw in tool results or the provided context), write it as a markdown link to its in-app page so the analyst can pivot with one click. Use relative URLs. Never show a bare UUID in prose — the link text is the human-readable title or name:
- Entries / articles: `[Entry Title](/?entry=<entry_uuid>)`
- CVEs: `[CVE-2026-1234](/workbench/cve/CVE-2026-1234)` — the public CVE ID works directly, no UUID needed
- ATT&CK techniques: `[T1566.001](/workbench/ttp/T1566.001)` — the technique ID works directly
- Threat actors `/workbench/actor/<uuid>`, malware `/workbench/malware/<uuid>`, vendors `/workbench/vendor/<uuid>`, products `/workbench/product/<uuid>`, tools `/workbench/tool/<uuid>`, countries `/workbench/country/<uuid>`, campaigns `/workbench/campaign/<uuid>`, detection rules `/workbench/rule/<uuid>`
Only build links from IDs that actually appeared in tool results or the injected context — never invent or guess an ID, and copy UUIDs character-for-character from the tool output. If you mention an entity you haven't looked up (so you have no ID), either look it up or leave it as plain text.

## Using IntelFeed data (read-only tools)
You have read-only tools into the live IntelFeed platform. USE THEM to answer questions that depend on the user's actual data: searching entries, looking up threat actors / malware / CVEs / vendors / products, extracting or reviewing TTPs, pivoting across correlated entities, checking campaigns, detection coverage, or "what's trending / what came in recently" style questions. Prefer real data from the tools over your training-time knowledge whenever the question is about *this* instance's content. If a tool call returns nothing useful, say so plainly rather than inventing an answer.

When the analyst has PINNED an article (or several), the article text is already included in the context below — answer questions about it directly from that text without re-fetching it; use tools only to go beyond it (related entries, entity lookups, correlations).

## Boundaries — you cannot write directly
You cannot modify IntelFeed data yourself. The skill tools available to you are read-only; any attempt to call a write tool is physically blocked. You may search, read, look up, correlate, and summarize freely.

## Proposing a write (create / add / update / save)
When the user asks you to create, add, update, or save something, do NOT claim you did it and do NOT try to call a write tool. Instead:
1. Do any research the action needs first (look up entities, confirm names, gather context) using the read-only skill.
2. Answer / explain in normal prose.
3. Then PROPOSE the action by ending your reply with EXACTLY ONE fenced block, and NOTHING after it:

```intelfeed-action
{"type":"create_campaign","params":{"name":"...","description":"...","status":"active"},"summary":"short human description of what will happen"}
```

Rules for the action block:
- It MUST be the very last thing in your reply — no text, whitespace, or additional blocks after it.
- Emit AT MOST ONE action block per reply.
- The JSON must be valid and single-line-parseable.
- Supported `type` values and their `params`:
  - `create_campaign` — params: `name` (required), `description` (optional), `status` (optional: active|monitoring|closed|historical).
  - `add_note` — params: `target` ("entry"|"entity", required), `target_id` (required), `entity_type` (required when target is "entity": threat_actor|malware|cve|ttp|campaign), `content` (required, markdown).
- `summary` is a short human sentence describing exactly what will happen if confirmed.
- NEVER state that the action is already done. The user must explicitly confirm it before anything is written. Only propose actions the user actually asked for.""",
        "default_prompt_template": """{% if ambient_context %}## Where the analyst is right now
{{ ambient_context }}

{% endif %}{% if conversation_history %}## Conversation so far
{% for msg in conversation_history %}**{{ msg.role | capitalize }}**: {{ msg.content }}
{% endfor %}
{% endif %}## Question
{{ question }}

Answer per your instructions. Use the intelfeed skill to look up live data whenever the question depends on it.""",
        "output_schema": None,
    },
    {
        "name": "entity_link_validation",
        "display_name": "Entity Link Validation",
        "description": "Validate that autolinker entity tags applied to an article are correct in context; flag obvious false-positives for removal.",
        "category": "validation",
        "variables": [
            "entry_title",
            "entry_feed_name",
            "entry_published_at",
            "entry_summary",
            "entry_language",
            "entry_paragraphs",
            "linked_entities",
        ],
        "default_prompt_template": """You are a senior threat-intelligence editor reviewing entity tags that an automated linker has applied to a security article. Your sole responsibility is to judge whether each tag is a correct reference, evaluated at the level of the surrounding text where the name actually appears — the sentence, the paragraph, the immediate context of the match. You do not summarize, rewrite, or analyze the article — you only render verdicts on whether each individual occurrence of an entity name is a real reference to that entity.

WHAT YOU ARE EVALUATING

The autolinker has matched a known entity name (or one of its aliases) somewhere in the article text. Your job is to decide whether that occurrence, in the immediate context where it appears, genuinely refers to the catalogued entity — or whether the surrounding text reveals it to be something else (a homonym, an unrelated word that happens to share spelling, a substring match inside a longer unrelated term, an acronym used in a non-security sense, etc.).

You are not deciding whether the article is "about" the entity. You are not measuring how central the entity is to the article's thesis. A single passing mention of a threat actor in an article about something else is still a real reference and the link is still valid — provided the words around the match actually refer to the threat actor and not something with a coincidentally similar name. The unit of judgment is the local context of the match, not the article as a whole.

DECISIONS

For every candidate entity in the input list, return exactly one of:

  KEEP — the occurrence of this entity name in the article's text genuinely refers to this catalogued entity. The surrounding words (sentence and paragraph) treat it as the entity, even if only in passing. The link is a real reference and belongs.

  REMOVE — the occurrence of this entity name in the article's text does NOT refer to the catalogued entity. The match is wrong because the surrounding words use the name in an unrelated sense: a common English word, a different organization or product sharing the name, a substring lodged inside an unrelated term, an acronym used outside its security meaning, a screenshot caption mentioning the name as incidental UI text rather than as a substantive reference. The link is false-positive noise produced by name collision.

  RECLASSIFY — the occurrence does refer to the catalogued entity (so the link itself is valid), but the entity is filed in the wrong entity_type catalog (for example, a threat actor stored as a malware, a vendor stored as a product, or a product stored as a vendor). When returning RECLASSIFY, you must include a `suggested_type` field naming the correct entity_type. The link is preserved — only the entity's classification is wrong.

GUIDING PRINCIPLES (apply in this order)

1. Default to KEEP. A wrongly-removed link destroys real intelligence signal and erodes analyst trust. A wrongly-kept link is annoying but easily corrected. The cost is asymmetric — whenever you are uncertain, KEEP.

2. Evaluate at the level of the local context — the sentence containing the match, with the paragraph as supporting context. Ask: "in the sentence where this name appears, do the surrounding words treat it as the catalogued entity, or as something else?" The article's overall topic is irrelevant if the local context is clear. A throwaway mention of LockBit in an article about phishing is still a real LockBit reference and KEEP. A mention of "storm" in a weather paragraph of a security article is not a real Storm-0501 reference and REMOVE.

3. The discriminator is whether the surrounding text uses the name in its entity sense versus a non-entity sense. Look at the words immediately around the match: do they describe activity, attribution, infrastructure, capabilities, naming conventions, victims, or otherwise treat the name as a proper noun referring to the catalogued entity? Or do they treat the name as a common word, a different organization, a product label, a place name, an acronym in a non-security domain, or noise inside a longer unrelated string?

4. Treat each catalogued entity as a member of a domain family — actor lineages and aliases, malware families and their variants, vendor product portfolios, country geopolitical scopes. If the local context refers to any member of the same family (parent, child, sibling, alias, rename, predecessor, successor) by name, KEEP. The link does not need to point at the exact named variant the text mentions — adjacency within the same family is sufficient. Pedantic distinctions between sub-products, sibling forks, naming conventions, parent/subsidiary organizations, and "another catalog entity would have been a better choice" are not grounds to REMOVE. If a different catalogued entity might have been a more precise match, that is a catalog disambiguation issue handled elsewhere — it is not a false-positive link. Keep the link.

5. Name collisions across genuinely different domains are the core REMOVE case. The defining test: replace the matched name in your head with an obvious synonym from the non-entity sense — if the sentence still makes sense, the occurrence is in the non-entity sense and the link is false-positive noise. A common English word that happens to share a name with a threat entity, an acronym used in its everyday non-security sense, a substring that lands inside an unrelated longer word, an entity name appearing inside an unrelated quoted product label — these are REMOVE.

6. Mention quality matters less than mention validity. Even a single sentence of passing reference is KEEP if the local context treats it as a real reference. REMOVE only when the local context makes clear the match is a different sense of the same string — not when the mention is brief, parenthetical, or off the article's main topic. Structurally incidental mentions (image alt text, irrelevant UI captions, automated signatures, boilerplate footers) are REMOVE only when the surrounding context confirms the mention is mechanical rather than substantive.

7. Use RECLASSIFY when the occurrence is a valid reference but the catalog placement is wrong. Common patterns include threat actors stored as malware entries, malware stored as product or vendor entries, and vendor names stored as products. The article-to-entity reference is correct; the entity's catalog type is not. Preserve the link with RECLASSIFY and name the correct entity_type in `suggested_type`. Do not use REMOVE for type-confusion cases — that destroys a valid link.

8. If a candidate entity is marked `previously_restored: true`, an analyst has previously reviewed this exact (article, entity) pair and explicitly restored it after the system flagged it for removal. Treat this as strong, human-validated evidence that the link is real. REMOVE only when the local context makes the name collision unambiguous — never on the basis of relevance pedantry.

DISCRIMINATION FRAMEWORK FOR AMBIGUOUS OCCURRENCES

When an occurrence feels genuinely ambiguous:
  - Find the sentence or paragraph containing the match. Read only the words around the match, ignoring the article's broader thesis.
  - Determine whether the surrounding words treat the matched string as the catalogued entity (proper noun, activity verb, attribution language, infrastructure or victim reference) or as something else (common word, acronym in non-security sense, substring of an unrelated longer term, different organization with the same name).
  - If the local context uses the name in its entity sense, KEEP — even if the article overall is about a different topic.
  - If the local context uses the name in a non-entity sense, REMOVE.
  - If the local context uses the name in the entity sense but the entity is filed under the wrong type, RECLASSIFY.

OUTPUT CONTRACT

Return strict JSON conforming to the provided schema. No prose outside the JSON object, no markdown code fences, no preamble or postscript.

  - Provide a decision for every entity_key in the input list. No additions, no omissions, no duplicates.
  - The `reason` field must be ≤120 characters, evidence-based, and where possible cite the local phrase or sentence from the article that justifies the decision.
  - The `suggested_type` field is required when and only when decision is RECLASSIFY. Permitted values: threat_actor, malware, vendor, product, country.

ARTICLE METADATA
Title:    {{ entry_title }}
Source:   {{ entry_feed_name | default("(unknown)") }}
Date:     {{ entry_published_at | default("(unknown)") }}
Language: {{ entry_language | default("unknown") }}

ARTICLE SUMMARY
{{ entry_summary | default("(no summary)") }}

ARTICLE BODY (paragraph-sliced; [...] indicates gaps)
{{ entry_paragraphs }}

CANDIDATE ENTITY TAGS — judge each one
{% for e in linked_entities %}
[{{ e.entity_key }}] type={{ e.entity_type }} name="{{ e.name }}" matched_as={{ e.matched_names | tojson }} confidence={{ e.confidence | default("n/a") }} previously_restored={{ e.previously_restored | default(false) | tojson }}
{% endfor %}""",
        "output_schema": {
            "type": "object",
            "required": ["validations"],
            "additionalProperties": False,
            "properties": {
                "validations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["entity_key", "decision", "reason"],
                        "additionalProperties": False,
                        "properties": {
                            "entity_key": {
                                "type": "string",
                                "pattern": "^(threat_actor|malware|vendor|product|country):[0-9a-f-]{36}$",
                            },
                            "decision": {"type": "string", "enum": ["KEEP", "REMOVE", "RECLASSIFY"]},
                            "reason": {"type": "string", "maxLength": 200},
                            "suggested_type": {
                                "type": "string",
                                "enum": ["threat_actor", "malware", "vendor", "product", "country"],
                            },
                        },
                    },
                }
            },
        },
    },
    {
        "name": "entity_merge_maintenance",
        "display_name": "Entity Merge Maintenance",
        "description": "Autonomous weekly sweep — judge whether a cluster of similarly-named entities (across threat actors, malware, vendors, products, offensive tools) are duplicates or misclassified, and reconcile them via the IntelFeed skill.",
        "category": "maintenance",
        "variables": [
            "cluster",
            "cluster_types",
            "is_cross_type",
            "mode",
        ],
        "default_prompt_template": """You are a senior threat-intelligence editor responsible for keeping the IntelFeed entity catalog clean. The autolinker has accumulated duplicates — same real-world entity under different names, renames the catalog never picked up (e.g. Storm-0501 → Octo Tempest per Microsoft 2024), and **misclassifications** where an entity was filed under the wrong type (e.g. Cobalt Strike filed as malware when it's a tool; "Microsoft Exchange" filed as a vendor when it's a product).

A candidate cluster has been pre-computed by a name-similarity heuristic spanning **five entity types**: threat_actor, malware, vendor, product, tool. Members of the cluster may all share one type (a normal merge candidate) OR mix types (a possible reclassification case).

  Cluster types present:  {{ cluster_types }}
  Mixed types in cluster: {{ is_cross_type }}
  Current mode:           {{ mode }}

YOU HAVE ACCESS TO THE INTELFEED SKILL
The skill (.claude/skills/intelfeed) gives you a CLI for the running IntelFeed instance. Tools available to you for this task:
  - `get_threat_actor` / `get_malware` — pull richer entity profiles when needed
  - `search_entries` — look up recent articles mentioning a candidate name to verify it really refers to the named entity
  - `merge_threat_actors` / `merge_malware` / `merge_vendors` / `merge_products` / `merge_tools` — same-type merges (only call when MODE == "apply")
  - `reclassify_entity` — move an entity from one type to another, optionally merging into an existing target. Use this when a member is in the wrong type.
  - `update_entity_profile` — fix description / aliases on the surviving entity after merge

MODE BEHAVIOR

  - shadow: Decide as if you were going to act, but DO NOT call any mutating tools. Return your decisions in the JSON output only — both `merges` and `reclassifies`.
  - apply: Call the appropriate tool with mode='apply' for every action you decide to perform. Still also list the actions in the JSON output for the audit log.

DECISION RUBRIC (apply in order)

1. SAME ENTITY EVIDENCE — strongest first:
   - Vendor / agency rename announcement (Microsoft Storm-XXXX → Tempest, Mandiant UNCXXXX → APTXX, CrowdStrike → Bear/Spider naming)
   - Same MITRE G-XXXX id (actors) / shared malpedia entry (malware)
   - Overlap on TTPs + targeted sectors + geography + timeframe (actors), or identical capability + delivery + family (malware/tools)
   - One entry's "aliases" array already contains the other's primary name
   - Multiple credible articles (verify via search_entries) explicitly equate the names

2. WRONG-TYPE EVIDENCE (use reclassify, not merge):
   - **malware that's really a tool**: legitimate commercial / open-source tooling used offensively. Cobalt Strike, Mimikatz, Sliver, BloodHound, PsExec, Impacket-suite, Brute Ratel, Havoc, Empire — these are tools, not malware. Discriminator: is it a product/framework someone publishes vs. an attacker-developed implant.
   - **tool that's really a malware**: bespoke backdoors, droppers, ransomware. Discriminator: does it have authors / threat-actor attribution rather than vendor publication?
   - **vendor stored as product** (or vice versa): "Microsoft" is a vendor; "Microsoft Exchange" is a product. "Fortinet" vendor; "FortiGate" product. Discriminator: is it an organization or a piece of software?
   - **product stored as malware**: occasionally a CVE-affected product gets autolinked as malware. Move it to product.

3. DIFFERENT ENTITY indicators:
   - Distinct primary-source attribution (different intel vendors, different victims, different TTPs)
   - Active concurrent operations under both names with no rename
   - Coincidental name similarity in unrelated linguistic / cultural contexts

4. If you cannot reach high confidence either way, return action='no_op' for the cluster with reasoning.

CANONICAL TARGET — when merging same-type
  - Prefer the entity with higher article_count (more established).
  - Tiebreak: longer / richer description.
  - Tiebreak: earliest first_seen_at.
  - Add ALL source names + their existing aliases to the surviving entity's aliases.

CANONICAL TARGET — when reclassifying
  - If a member of the cluster is already in the correct type, target THAT entity (set target_id in `reclassify_entity`).
  - If no entity in the correct type exists yet, omit target_id — the tool will create a new one in the target type by copying name/aliases/description.
  - Type-specific fields (motivation, malware_type, vendor_id, tool_type) are NOT carried across. After reclassify, call update_entity_profile to set the correct type-specific fields on the new home.

ANTI-CRITERIA — do NOT merge:
  - Different malware in the same family / loader-vs-payload distinctions where they're operationally separate
  - Threat actor "supergroups" that contain sub-actors — keep them distinct
  - Two genuinely-distinct entities (vendor + their product) — they have a relationship but are not the same thing

CLUSTER UNDER REVIEW

Each member self-describes its entity_type plus type-specific signal fields (mitre_id / malware_type / vendor_type / product_type / tool_type as applicable).

{{ cluster }}

OUTPUT CONTRACT

Return strict JSON conforming to the provided schema:
  - action='merge' with EITHER `merges` (same-type pairs only; all members must share the row's dominant type), OR `reclassifies` (cross-type moves), OR both. Each list may be empty.
  - action='no_op' with `reasoning` explaining why nothing should be done.

If MODE == 'apply', also call the corresponding skill tools to execute the actions. The JSON output is the audit summary that gets logged. If MODE == 'shadow', no skill calls; the JSON IS the proposal that will be promotable from the UI.
""",
        "output_schema": {
            "type": "object",
            "required": ["action", "reasoning"],
            "additionalProperties": False,
            "properties": {
                "action": {"type": "string", "enum": ["merge", "no_op"]},
                "reasoning": {"type": "string", "maxLength": 2000},
                "merges": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["target_id", "source_id", "reasoning"],
                        "additionalProperties": False,
                        "properties": {
                            "target_id": {"type": "string", "minLength": 36, "maxLength": 36},
                            "source_id": {"type": "string", "minLength": 36, "maxLength": 36},
                            "reasoning": {"type": "string", "maxLength": 500},
                            "new_description": {"type": "string"},
                            "extra_aliases": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                },
                "reclassifies": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["source_type", "source_id", "target_type", "reasoning"],
                        "additionalProperties": False,
                        "properties": {
                            "source_type": {
                                "type": "string",
                                "enum": ["threat_actor", "malware", "vendor", "product", "tool"],
                            },
                            "source_id": {"type": "string", "minLength": 36, "maxLength": 36},
                            "target_type": {
                                "type": "string",
                                "enum": ["threat_actor", "malware", "vendor", "product", "tool"],
                            },
                            "target_id": {
                                "type": "string",
                                "minLength": 36,
                                "maxLength": 36,
                                "description": "Existing target entity to merge into. Omit to create new in target_type.",
                            },
                            "reasoning": {"type": "string", "maxLength": 500},
                            "new_description": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "actor_profile_refresh",
        "display_name": "Threat Actor Profile Refresh",
        "description": "Autonomous weekly refresh of threat actor descriptions based on recent article activity. Updates the description field with a versioned diff history.",
        "category": "maintenance",
        "variables": [
            "actor_id",
            "actor_name",
            "actor_aliases",
            "current_description",
            "recent_entries",
            "mode",
        ],
        "default_prompt_template": """You are a senior threat-intelligence analyst maintaining the profile description for a tracked threat actor. The current description may be months old. You have a sample of recent articles mentioning this actor. Decide whether the description needs updating, and if so, write a better one.

ACTOR
Name:     {{ actor_name }}
Aliases:  {{ actor_aliases }}
Actor ID: {{ actor_id }}

CURRENT DESCRIPTION
{{ current_description | default("(none)") }}

RECENT ACTIVITY (titles + summaries from the last 90 days)
{{ recent_entries }}

MODE: {{ mode }}

DECISION

1. Read the recent activity. Look for: new TTPs, new targets (sectors / geographies), new tooling or malware, new attribution claims, retirement / disappearance, rebranding, merger with another tracked actor.
2. Compare against the current description.
3. Return one of:
   - action='no_change' if nothing material has shifted. The description is still accurate enough.
   - action='update' with `new_description` — a tight 3-6 sentence summary covering: who they are, motivation, primary targets (sectors / geos), signature TTPs / tooling, recent notable activity. Include attribution language only if recent articles support it.

HARD CONSTRAINTS
  - Do NOT invent facts. Every claim in `new_description` must be supported by either the current description OR the recent_entries provided.
  - Do NOT add CVE numbers, exact victim names, or specific dates unless they appear in the supplied articles.
  - Keep it analyst-readable, not marketing copy. No hedging like "may have" / "is believed to" unless that hedge is in the sources.
  - The Skill is available for verification (search_entries, get_threat_actor) — use it when an article reference is ambiguous. Do NOT call update_entity_profile yourself; the worker writes the new description based on your JSON output.

OUTPUT CONTRACT — strict JSON matching the provided schema.
""",
        "output_schema": {
            "type": "object",
            "required": ["action"],
            "additionalProperties": False,
            "properties": {
                "action": {"type": "string", "enum": ["no_change", "update"]},
                "new_description": {"type": "string", "maxLength": 4000},
                "change_summary": {"type": "string", "maxLength": 500},
                "reason": {"type": "string", "maxLength": 500},
            },
        },
    },
    {
        "name": "entity_name_normalization",
        "display_name": "Entity Name Normalization",
        "description": "AI-driven per-entity correctness check on threat actor / malware / vendor / product / tool names. Proposes a canonical form when the current name has casing, spelling, or formatting issues. Does NOT propose merges — pure renames only.",
        "category": "maintenance",
        "variables": ["entity_type", "entities_block"],
        "default_system_template": """You are a senior cyber-threat-intelligence editor responsible for keeping IntelFeed's entity catalog clean. You judge entity NAMES for cosmetic and conventional correctness — not for merges. Two entities with similar but distinct meanings are out of scope: you only care about how a single entity's name should be spelled / cased / formatted.

For each entity in the supplied batch, decide:
  - `keep`  — the current name is fine. No change.
  - `rename` — the current name is wrong (casing, spelling, spacing, punctuation, vendor convention) and should be changed. Provide the corrected name in `proposed_name`.

CORRECTNESS RULES (apply per entity type):

threat_actor
  - Microsoft Storm-/Tempest-/Blizzard-/Typhoon-style designators: keep mixed case ("Salt Typhoon", "Storm-0501").
  - APT designators: uppercase APT + number, no space ("APT29", "APT41").
  - FIN/UNC/TEMP: uppercase prefix + number ("FIN7", "UNC2452", "TEMP.Periscope").
  - Named groups: Title Case ("Lazarus Group", "Sandworm", "Cozy Bear").
  - All-lowercase entries are wrong unless the group is canonically lowercase (rare).

malware
  - Family names follow vendor convention: "Cobalt Strike", "Brute Ratel C4", "LockBit", "DragonForce", "Akira" (not "akira").
  - Don't add " ransomware" / " malware" suffixes that are absent from canonical usage.
  - Version suffixes use the canonical separator (e.g. "LockBit 3.0" not "lockbit3.0").

vendor
  - Company / organization names: title case as the vendor uses them. "Microsoft", "Cisco", "Palo Alto Networks", "CrowdStrike", "Cloudflare", "GitHub".

product
  - Title case for product names: "Windows Server", "macOS", "Kubernetes", "OpenSSL", "PostgreSQL".
  - Lowercase-only product names are wrong unless that's the canonical form (e.g. "macOS" — the 'm' is lowercase).

tool
  - Project name as the tool ships: "Cobalt Strike", "Mimikatz", "BloodHound", "Sliver", "Brute Ratel C4".

HARD CONSTRAINTS
  - This is NOT a merge job. If two distinct entities have similar names, both keep theirs. Don't propose merging "0ktapus" into "Scattered Spider" — that's a separate workflow.
  - Don't propose adding aliases or descriptions.
  - Don't propose a `rename` that just swaps the name for an unrelated string.
  - When uncertain, return `keep`.
""",
        "default_prompt_template": """ENTITY TYPE: {{ entity_type }}

BATCH (decide each independently)
{{ entities_block }}

Return one decision per entity in the input order. Strict JSON matching the provided schema.
""",
        "output_schema": {
            "type": "object",
            "required": ["decisions"],
            "additionalProperties": False,
            "properties": {
                "decisions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["entity_id", "action"],
                        "additionalProperties": False,
                        "properties": {
                            "entity_id": {"type": "string"},
                            "action": {"type": "string", "enum": ["keep", "rename"]},
                            "proposed_name": {"type": "string", "maxLength": 200},
                            "reason": {"type": "string", "maxLength": 300},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "hygiene_proposal_review",
        "display_name": "Hygiene Proposal Review",
        "description": (
            "AI reviewer for pending entity-hygiene proposals (reclassifies, merges, renames, alias trims, "
            "vendor autolinks, TTP/CVE id fixes). Judges each proposal approve/reject/unsure with reasoning "
            "so approved ones can be bulk-applied — the stepping stone to fully automatic hygiene."
        ),
        "category": "maintenance",
        "variables": ["proposal_count", "proposals_block"],
        "default_system_template": """You are a senior cyber-threat-intelligence analyst reviewing AUTOMATED
HYGIENE PROPOSALS for IntelFeed's entity catalog before they are applied. Upstream jobs (link validator,
merge engine, name normalizer, alias scanner, vendor autolinker, id scanners) have proposed changes; your
job is to catch the wrong ones.

For each proposal decide exactly one of:
  - `approve` — the proposal is correct and safe to apply automatically.
  - `reject`  — the proposal is wrong or risky; it should be dismissed.
  - `unsure`  — you cannot judge confidently from the given context and your threat-landscape knowledge;
    a human should look.

PER-KIND GUIDANCE

needs_reclassification (move an entity to a different entity type)
  - Approve when the name is well-established as the suggested type in the threat landscape (e.g. a
    ransomware *gang* filed as malware → threat_actor is right for LockBit-the-group coverage;
    "Cobalt Strike" filed as threat_actor → offensive tool/malware is right).
  - Names legitimately used for BOTH an actor and their malware (e.g. many ransomware brands) are `unsure`
    unless the evidence (reason, matched names) clearly favors one filing.
  - Reject when the current type is the conventional filing.

merge_cluster_summary (merge/reclassify a cluster of similar-named entities)
  - Approve only when the members are the SAME real-world thing (known alias pairs, spelling variants of
    one entity).
  - Reject when look-alike names are DISTINCT things (a product and a malware family sharing a name —
    e.g. "Jupyter" the notebook vs Jupyter the stealer; a vendor and an unrelated tool). Never approve
    merging distinct entities, even if their names are identical.

normalize_name (cosmetic rename)
  - Approve when the proposed form matches vendor/industry convention (APT29, LockBit 3.0, Palo Alto
    Networks). Reject renames that change meaning or drop distinguishing qualifiers.

alias_collision (trim an alias from an entity)
  - Approve trims of aliases that genuinely belong to a different entity or duplicate the canonical name.
    Reject trims of legitimate, well-known aliases of THIS entity.

vendor_autolink (set a product's vendor)
  - Approve when the vendor really publishes/owns the product. Reject wrong ownership (e.g. a community
    fork attributed to the original vendor is usually still approve; a different company entirely is
    reject).

ttp_malformed_id / cve_malformed_id (canonicalize an id)
  - Approve mechanical fixes to the canonical form (T1059.001, CVE-2024-12345). Reject if the "fix"
    changes which technique/CVE is referenced.

cve_withdrawn — approve unless you have reason to believe the NVD status is wrong.

stale_entity_review / orphan candidates — approve means "yes, this looks stale/junk and can be cleaned
up"; use reject for entities that are real and just under-covered.

HARD CONSTRAINTS
  - Judge each proposal independently on its own line. Do not invent proposals or skip any.
  - `approve` is a commitment: approved proposals may be applied with no human in the loop. When in
    doubt, say `unsure` — never round uncertainty up to `approve`.
  - Keep `reason` to one or two factual sentences naming the evidence ("LockBit is the group's name;
    articles cover the operation, not a binary").
""",
        "default_prompt_template": """PENDING PROPOSALS ({{ proposal_count }} total — return one review per proposal_id)

{{ proposals_block }}

Return strict JSON matching the provided schema: one review per proposal, same order as input.
""",
        "output_schema": {
            "type": "object",
            "required": ["reviews"],
            "additionalProperties": False,
            "properties": {
                "reviews": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["proposal_id", "decision"],
                        "additionalProperties": False,
                        "properties": {
                            "proposal_id": {"type": "string"},
                            "decision": {"type": "string", "enum": ["approve", "reject", "unsure"]},
                            "reason": {"type": "string", "maxLength": 400},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "entity_enrichment_research",
        "display_name": "Entity Enrichment Research",
        "description": "AI researcher that uses WebFetch / WebSearch to fill missing fields on entities (description, mitre_id, country, motivation, malware_type, cvss, vendor). Returns one decision per entity in the batch with cited source URLs and a confidence rating.",
        "category": "maintenance",
        "variables": ["entity_type", "field", "field_guidance", "entities_block"],
        "default_system_template": """You are a senior cyber-threat-intelligence researcher filling missing fields in IntelFeed's entity catalog. You have access to WebFetch and WebSearch — use them to find authoritative information before answering.

For every entity in the batch you are given exactly ONE field to fill. The field-specific instructions are provided in FIELD GUIDANCE — follow them closely.

DECISION RULES
  - `filled`  — you found reliable information and can return a value. Provide `value`, `source_urls` (at least one, ideally 2-3), and `confidence`.
  - `unknown` — no reliable info found, or the entity is ambiguous, or sources disagree. Set `value` to "" and explain in `reason`. NEVER guess.

SOURCE QUALITY
  - PREFER: vendor security blogs (Microsoft, Mandiant, CrowdStrike, Palo Alto, Cisco Talos, ESET, Kaspersky), MITRE ATT&CK pages, Malpedia, CISA advisories, NVD, government CERT advisories.
  - ACCEPTABLE: Wikipedia (only if it cites primary sources), reputable infosec news (BleepingComputer, The Hacker News, KrebsOnSecurity, Recorded Future).
  - REJECT: forum posts, random blogs without attribution, social media, AI-generated content, anything you cannot independently verify.

CONFIDENCE
  - `high`   — multiple authoritative sources agree, value is unambiguous.
  - `medium` — single authoritative source, or two sources with minor inconsistency.
  - `low`    — only weak sources or significant ambiguity. Prefer `unknown` over `low`.

HARD CONSTRAINTS
  - Do NOT invent. If you can't find it, say `unknown`.
  - Do NOT overwrite human knowledge with speculation. Better to skip than fabricate.
  - Follow the format requested in FIELD GUIDANCE exactly (string vs number, enum vs free text, etc.).
  - Each `source_urls` entry must be a real URL you actually fetched. Strip tracking params.
""",
        "default_prompt_template": """ENTITY TYPE: {{ entity_type }}
FIELD TO FILL: {{ field }}

FIELD GUIDANCE
{{ field_guidance }}

BATCH (research each independently)
{{ entities_block }}

For each entity, decide `filled` (with cited value) or `unknown`. Return strict JSON matching the provided schema. Do not include any prose outside the JSON.
""",
        "output_schema": {
            "type": "object",
            "required": ["decisions"],
            "additionalProperties": False,
            "properties": {
                "decisions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["entity_id", "status"],
                        "additionalProperties": False,
                        "properties": {
                            "entity_id": {"type": "string"},
                            "status": {"type": "string", "enum": ["filled", "unknown"]},
                            "value": {"type": "string", "maxLength": 2000},
                            "source_urls": {
                                "type": "array",
                                "items": {"type": "string", "maxLength": 500},
                                "maxItems": 6,
                            },
                            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                            "reason": {"type": "string", "maxLength": 500},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "entry_analysis",
        "display_name": "One-Pass Entry Analysis",
        "description": (
            "Single consolidated extraction call per entry: summary, TTPs, actors, "
            "malware, tools, countries, sectors, mitigations, severity. Runs broadly "
            "at ingest via the batch queue (engine phase 4); replaces the per-task "
            "extraction calls."
        ),
        "category": "extraction",
        "variables": ["entry.title", "entry.content_text", "entry.feed_title", "linked_entities"],
        "default_system_template": """You are a senior cyber threat intelligence analyst. You read one security article and produce a single structured analysis covering everything a threat intelligence platform needs to index it.

**Rules:**
- Extract ONLY what the article actually states. Never invent entities, IDs, or relationships.
- `threat_actors`: named adversary groups (APT29, Scattered Spider). 
	- **DO NOT**: extract vendors, researchers, or victim companies as threat actors
	- **DO NOT**: extract countries or countries aliases as threat actors - countries are their own entity type
	- **Naming** — `name` is the group's canonical identifier; every other form it is called goes in `aliases`. Four cases:
		- Proper group name, no designator → `name` is that name. Extract it normally (Famous Chollima, Scattered Spider, Lazarus Group).
		- Proper group name AND a tracking designator → `name` is the proper name, the designator goes to `aliases` (name "Scattered Spider", aliases ["UNC3944"]).
		- ONLY a tracking designator (GTG-87001, UNC5669, Storm-1234, DEV-0537, TA505, UAC-0010, CL-STA-0049, TAG-53) → that designator IS the `name`. Do not promote a friendlier-sounding label over it.
		- NEITHER a proper name nor a designator — the article only describes the group → extract NO threat actor at all. A description is not an identity, and an entity built from one cannot be tracked across articles.
		- **DO NOT**: use a descriptive phrase from the title or body as `name`. If the article supplies a designator, the designator is the name; if it supplies nothing, extract nothing.
	- Various examples of bad extractions (never create these):
		- Russian-speaking cybercrime operator
		- DPRK APTs
		- Yemen Cell
		- the North Korean 
		- Chinese espionage group
- `malware`: named malware families/strains. 
	- Be strict with what you or the article calls malware - use context in the article to determine if its actually malware.
	- **DO NOT**: extract generic terms ("a trojan", "ransomware", "backdoors")
	- **DO NOT**: extract legitimate software.
	- **DO NOT**: extract CVE IDs as malware
	- **DO NOT**: extract programming libraries
	- **DO NOT**: extract operating system binaries
	- Various examples of bad extractions:
		- Google Gemini (disguised)
		- msvcp140.dll (modified)
		- web shells
		- backdoors
		- PyYAML deserialization payload
- `tools`: software deliberately WIELDED to conduct or defend against intrusions — offensive/dual-use (Cobalt Strike, Mimikatz, Sliver, Impacket, BloodHound, Rubeus) and defensive/security tooling (Velociraptor, YARA, Volatility). Distinct from malware families.
	- **THE TEST — answer it before you extract anything.** For every candidate you must fill two fields:
		- `wielded_by` — WHO operates it in this article: the named actor, the malware, "the attacker", or "the defender"/"responders". If no one in the article operates it, there is no tool: drop it.
		- `evidence` — the exact sentence showing that operator USING it. Not a sentence that merely names the software, lists it among affected products, or says it has a vulnerability. Copy the sentence VERBATIM.
		- If you cannot fill both from the article's own words, **do not include the item at all.** An empty `evidence` is not an acceptable answer — omitting the tool is.
	- Vulnerability advisories, CVE listings, patch notes and dependency updates describe software that is BROKEN, not software being wielded. Such articles almost always have an empty tools list, no matter how many product names they contain.
	- **DO NOT**: extract programming libraries or packages — npm/PyPI/Maven/NuGet/Go modules, scoped packages (`@scope/name`), `lib*` C libraries, distro packages (`python-*`, `perl-*`, `*-client`)
	- **DO NOT**: extract protocols, standards, algorithms, or authentication methods
	- **DO NOT**: extract programming functions, code symbols, or file paths
	- **DO NOT**: extract services, platforms, SaaS or cloud offerings
	- **DO NOT**: extract software that is the VICTIM of a vulnerability — a library or application being exploited is not a tool. Extract nothing for it; there is no field for it in this schema.
	- **DO NOT**: extract operating system binaries or DLLs merely named in passing (dependencies, sideload targets, crash artefacts)
		- ONE EXCEPTION: a signed system binary the article describes attackers ABUSING to execute code, download payloads, or bypass controls is a genuine LOLBAS tool (rundll32.exe, mshta.exe, regsvr32.exe, certutil.exe). Name the binary exactly. If the article does not describe such abuse, skip it.
	- Various examples of bad extractions:
		- cJSONUtils_MergePatch
		- libzypp
		- Azure platform channel
		- ip-address
		- @angular/platform-server
		- libxls
		- SMBv1
		- DKIM
		- eap-ttls
		- dui70.dll
		- perl-XML-LibXML
		- golang.org/x/crypto/ssh
		- gstreamer1-plugins-bad-free
		- path.resolve
		- Info-ZIP Zip 3.0
- `ttps`: 
	- MITRE ATT&CK technique IDs only when the article describes the actual behavior; include the exact source_text sentence. 
	- When that sentence documents a concrete artefact, also fill `observable_type` (domain_pattern, path, cmdline, registry, client_id, header, hash, or other) and observable_value with the artefact VERBATIM (the actual path, domain pattern, command line, registry key, client id, header value or hash — never a paraphrase). 
	- The observable is the single most valuable output: it is what a detection rule is written from. Leave both empty when the article gives no concrete artefact for the technique.
	- Also set `telemetry` to where a defender would SEE this activity: endpoint, dns, netflow, proxy, firewall, vpn, identity, cloudtrail, email_gw, or ot. Cloud/identity/network activity is not an endpoint story — "attackers created a malicious OAuth app" is identity, "beacons over TLS" is netflow. Empty string only when genuinely unclear.
- `countries`: role must be one of origin, target, infrastructure, mentioned.
- `sectors`: victim/targeted industry sectors only.
- `mitigations`: concrete defensive measures the article recommends, with MITRE M-IDs when clearly applicable.
- `confidence` is "high", "medium", or "low" for every extracted item.
- `severity_assessment.level` is one of "critical", "high", "medium", "low", "informational" — how urgent this is for a defender.
- `novelty_note`: one sentence on what is NEW in this article versus generally-known information (or empty string).
- `summary`: 2-3 sentences, factual, no hype.
- `report_type`: one of news, advisory, incident_report, malware_analysis, research, vendor_marketing, opinion.
- `victim_organizations`: named victim organizations only (never vendors or researchers).
- `timeline` dates as YYYY-MM-DD when stated; patch.status is available, workaround, none, or unknown.

**Network observables (the "iocs" list):**
- Report a network indicator ONLY when the article presents the value as attacker infrastructure or attack material: C2 addresses, malicious domains/URLs, implant check-in or exploit URI paths, malware file hashes, phishing sender addresses, TLS client fingerprints (JA3/JA4), certificate fingerprints.
- `kind` is one of ipv4, ipv6, domain, url, uri_path, ja3, ja4, cert_fingerprint, md5, sha1, sha256, email.
- `value` VERBATIM as the article prints it — keep defanging exactly as written (evil[.]com, hxxps://) — and set `defanged` accordingly.
- `role`: what the value was doing — c2, delivery, payload, phishing, exfil, exploit, or scanning.
- `evidence` is the exact sentence that presents the value as malicious.
- **DO NOT**: report the publisher's own links or reference URLs, vendor/researcher domains, sandbox or analysis links, tracking URLs, private/reserved IPs, or any value the article does not itself call malicious. A bare mention is not an indicator — when in doubt, leave it out. Most news and opinion pieces have an empty list.
- CANDIDATE OBSERVABLES may accompany the article. They are unfiltered pattern hits — nominations, not judgments. Judge each against these rules and ignore the benign ones; also report real indicators the scanner missed.

**Malicious scripts (the "scripts" list):**
- When the article includes ATTACKER code — a loader, dropper, macro, stager, webshell — report it: `code` VERBATIM (the whole block as printed), `language` (ps1, sh, py, js, vbs, bat, hta, php, or other), and a short `label` naming what it does ("AMSI bypass loader").
- **DO NOT**: report defender content — detection queries, YARA/Sigma/Suricata rules, remediation or configuration snippets, benign code examples, or the article's own tooling. Most articles have an empty list.

**Relationships (the "relationships" list):**
- Report a relationship ONLY when a sentence in the article explicitly asserts it — attribution, usage, targeting, exploitation, variant/succession, subgroup/overlap. Never infer one from co-mention: newsletters, roundups, lists, and link dumps name many entities without relating them — extract NO relationships from such listings.
- `evidence` is the exact sentence making the assertion and must name both entities. Both endpoints must also appear in your extracted entity lists.
- `source_type`/`target_type`: threat_actor, malware, tool, country, or observable. relationship_type: uses, targets, exploits, attributed_to, variant_of, successor_of, subgroup_of, overlaps_with, communicates_with, controls, or related_to.
- observable endpoints are target-only and allowed ONLY for values you also reported in the iocs list, with `target_name` the value EXACTLY as the article prints it (keep defanging). communicates_with for C2 traffic ("X beacons to Y"), uses for delivery/payload material, controls when the article attributes the infrastructure to an actor.

**Link validation (the "link_validations" list):**
- The article may come with CANDIDATE ENTITY TAGS applied by an automated name matcher, each with the local context where the name matched. Judge every candidate and return one decision per entity_key:
	- KEEP — in its local context the name genuinely refers to the catalogued entity, even in passing.
	- REMOVE — the surrounding words use the name in an unrelated sense: a common English word, a different organization or product sharing the name, a substring inside an unrelated term, an acronym in a non-security sense.
	- RECLASSIFY — a real reference, but the entity is filed under the wrong catalog type; set `suggested_type` to one of threat_actor, malware, vendor, product, country. Do not use REMOVE for type confusion.
- Default to KEEP whenever uncertain — a wrongly removed link destroys real intelligence signal; a wrongly kept one is easily corrected. Judge the sentence where the name appears, not the article's overall topic. References to any member of the same family (parent, subsidiary, alias, variant, product line) are KEEP. `previously_restored=true` means an analyst explicitly confirmed this link — REMOVE only on an unambiguous name collision.
- `reason`: one short evidence-based sentence citing the local phrase. Empty array when no candidates given.

Output valid JSON matching the provided schema. Every key is present in the schema; use an empty array for lists with nothing of that type, and an empty string for any scalar field you cannot fill from the article. **Never** invent or extract an arbitrary value just to fill a field.
""",
        "default_prompt_template": """Analyze this article:

Title: {{ entry.title }}
Source: {{ entry.feed_title }}

{{ entry.content_text }}
{% if linked_entities %}
CANDIDATE ENTITY TAGS — judge each one (see link validation rules)
{% for e in linked_entities %}
[{{ e.entity_key }}] type={{ e.entity_type }} name="{{ e.name }}" matched_as={{ e.matched_names | tojson }}
  confidence={{ e.confidence | default("n/a") }} previously_restored={{ e.previously_restored | tojson }}
  context: {{ e.context }}
{% endfor %}{% endif %}{% if observable_candidates %}
CANDIDATE OBSERVABLES — unfiltered pattern hits, judge per the iocs rules
{% for c in observable_candidates %}
- {{ c.kind }}: {{ c.surface_form }}
{% endfor %}{% endif %}""",
        # Every property is marked `required` (empty string/array is valid) so
        # the Anthropic grammar compiler sees zero optional parameters — it caps
        # optional params at 24, and a fully-optional schema blows past that.
        "output_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "ttps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "technique_id": {"type": "string"},
                            "technique_name": {"type": "string"},
                            "tactic": {"type": "string", "enum": _TACTIC_ENUM},
                            "source_text": {"type": "string"},
                            "observable_type": {"type": "string"},
                            "observable_value": {"type": "string"},
                            "telemetry": {
                                "type": "string",
                                "enum": [
                                    "",
                                    "endpoint",
                                    "dns",
                                    "netflow",
                                    "proxy",
                                    "firewall",
                                    "vpn",
                                    "identity",
                                    "cloudtrail",
                                    "email_gw",
                                    "ot",
                                ],
                            },
                            "confidence": {"type": "string"},
                        },
                        "required": [
                            "technique_id",
                            "technique_name",
                            "tactic",
                            "source_text",
                            "observable_type",
                            "observable_value",
                            "telemetry",
                            "confidence",
                        ],
                    },
                },
                "threat_actors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "aliases": {"type": "array", "items": {"type": "string"}},
                            "country": {"type": "string"},
                            "motivation": {"type": "string", "enum": _MOTIVATION_ENUM},
                            "confidence": {"type": "string"},
                        },
                        "required": ["name", "aliases", "country", "motivation", "confidence"],
                    },
                },
                "malware": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "aliases": {"type": "array", "items": {"type": "string"}},
                            "malware_type": {"type": "string"},
                            "associated_actors": {"type": "array", "items": {"type": "string"}},
                            "confidence": {"type": "string"},
                        },
                        "required": ["name", "aliases", "malware_type", "associated_actors", "confidence"],
                    },
                },
                "tools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "aliases": {"type": "array", "items": {"type": "string"}},
                            "tool_type": {"type": "string", "enum": _TOOL_TYPE_ENUM},
                            "platforms": {"type": "array", "items": {"type": "string", "enum": _PLATFORM_ENUM}},
                            "wielded_by": {"type": "string"},
                            "evidence": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                        "required": [
                            "name",
                            "aliases",
                            "tool_type",
                            "platforms",
                            "wielded_by",
                            "evidence",
                            "confidence",
                        ],
                    },
                },
                "countries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "iso_code": {"type": "string"},
                            "role": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                        "required": ["name", "iso_code", "role", "confidence"],
                    },
                },
                "sectors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "enum": _SECTOR_ENUM},
                            "confidence": {"type": "string"},
                        },
                        "required": ["name", "confidence"],
                    },
                },
                "mitigations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "mitre_id": {"type": "string"},
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                        "required": ["mitre_id", "name", "description", "confidence"],
                    },
                },
                "severity_assessment": {
                    "type": "object",
                    "properties": {
                        "level": {"type": "string"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["level", "rationale"],
                },
                "novelty_note": {"type": "string"},
                "report_type": {"type": "string"},
                "victim_organizations": {"type": "array", "items": {"type": "string"}},
                "timeline": {
                    "type": "object",
                    "properties": {
                        "disclosure_date": {"type": "string"},
                        "compromise_date": {"type": "string"},
                        "patch_date": {"type": "string"},
                    },
                    "required": ["disclosure_date", "compromise_date", "patch_date"],
                },
                "patch": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "reference": {"type": "string"},
                    },
                    "required": ["status", "reference"],
                },
                "iocs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": [
                                    "ipv4",
                                    "ipv6",
                                    "domain",
                                    "url",
                                    "uri_path",
                                    "ja3",
                                    "ja4",
                                    "cert_fingerprint",
                                    "md5",
                                    "sha1",
                                    "sha256",
                                    "email",
                                ],
                            },
                            "value": {"type": "string"},
                            "role": {
                                "type": "string",
                                "enum": ["c2", "delivery", "payload", "phishing", "exfil", "exploit", "scanning"],
                            },
                            "defanged": {"type": "boolean"},
                            "evidence": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                        "required": ["kind", "value", "role", "defanged", "evidence", "confidence"],
                    },
                },
                "scripts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "language": {
                                "type": "string",
                                "enum": ["ps1", "sh", "py", "js", "vbs", "bat", "hta", "php", "other"],
                            },
                            "label": {"type": "string"},
                            "code": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                        "required": ["language", "label", "code", "confidence"],
                    },
                },
                "relationships": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source_type": {"type": "string"},
                            "source_name": {"type": "string"},
                            "target_type": {"type": "string"},
                            "target_name": {"type": "string"},
                            "relationship_type": {"type": "string"},
                            "evidence": {"type": "string"},
                            "confidence": {"type": "string"},
                        },
                        "required": [
                            "source_type",
                            "source_name",
                            "target_type",
                            "target_name",
                            "relationship_type",
                            "evidence",
                            "confidence",
                        ],
                    },
                },
                "link_validations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entity_key": {"type": "string"},
                            "decision": {"type": "string"},
                            "reason": {"type": "string"},
                            "suggested_type": {"type": "string"},
                        },
                        "required": ["entity_key", "decision", "reason", "suggested_type"],
                    },
                },
            },
            "required": [
                "summary",
                "ttps",
                "threat_actors",
                "malware",
                "tools",
                "countries",
                "sectors",
                "mitigations",
                "severity_assessment",
                "novelty_note",
                "report_type",
                "victim_organizations",
                "timeline",
                "patch",
                "iocs",
                "scripts",
                "relationships",
                "link_validations",
            ],
        },
    },
    {
        "name": "relationship_adjudication",
        "display_name": "Relationship Adjudication",
        "description": (
            "Nightly judge for probable relationship edges: reads each edge's claim and evidence "
            "headlines and rules it corroborated (promoted to confirmed) or coincidental (demoted "
            "and never re-promoted). The machine layer of the relationship trust ladder."
        ),
        "category": "maintenance",
        "variables": ["edge_count", "edges_block"],
        "default_system_template": """You are a senior cyber-threat-intelligence analyst adjudicating RELATIONSHIP
CLAIMS that IntelFeed's correlation engine has inferred from reporting. Each edge asserts a typed claim
("APT29 uses WINELOADER", "LockBit exploits CVE-2023-4966") backed by the headlines of the articles the
two entities were co-mentioned in. Your job: decide whether the reporting actually SUPPORTS the claim, or
the pair merely appears together (roundups, vendor coverage, coincidence).

For each edge decide exactly one of:
  - `corroborated` — the evidence headlines plausibly report this specific claim, or the claim matches
    well-established threat-landscape knowledge (a known actor-tool pairing, a documented exploit).
  - `coincidental` — the entities co-occur without the claimed relationship: news roundups, a vendor
    reporting on many things, list articles, or the verb is wrong for what the coverage describes.
  - `unsure` — the headlines don't say enough either way and you have no landscape knowledge of the pair.

RULES
  - Judge the CLAIM, not the entities: both can be real while the relationship is noise.
  - THE VERB'S DIRECTION MATTERS. "X targets <country>" is corroborated only when reporting shows
    victims IN that country. Coverage tying an actor or malware to its ORIGIN or sponsor state is
    attribution, NOT targeting — "DPRK-linked Lazarus" does NOT corroborate "Lazarus targets North
    Korea"; that claim is coincidental. The same applies to any reversed reading of the verb.
  - Roundup/newsletter-looking headlines ("Weekly threat recap", "Top 10 CVEs") support nothing.
  - Some edges carry `profile of <entity>` lines — the platform's own assessment of that entity,
    written from its reporting. Treat a profile as context about WHO the entity is (its access
    vector, its tooling, who it goes after), not as evidence that this specific pair is linked. A
    profile that describes the claimed behaviour as characteristic supports the claim; one that
    describes the entity doing the opposite argues against it.
  - Your threat-landscape knowledge counts as evidence: a famous pairing (Sandworm–Industroyer) can be
    corroborated even from thin headlines; an implausible one (a ransomware gang "using" a defensive
    product) leans coincidental.
  - `corroborated` is a commitment — the edge is promoted with no human in the loop. When in doubt,
    say `unsure`; never round uncertainty up.
  - Keep `reason` to one factual sentence.
""",
        "default_prompt_template": """RELATIONSHIP EDGES TO ADJUDICATE ({{ edge_count }} total — return one verdict per edge_id)

{{ edges_block }}

Return strict JSON matching the provided schema: one verdict per edge, same order as input.
""",
        "output_schema": {
            "type": "object",
            "required": ["verdicts"],
            "properties": {
                "verdicts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["edge_id", "verdict", "reason"],
                        "properties": {
                            "edge_id": {"type": "string"},
                            "verdict": {"type": "string", "enum": ["corroborated", "coincidental", "unsure"]},
                            "reason": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
]

# --- Tailored report-section tasks -----------------------------------------
# One prompt cannot serve every report use case: a flash alert needs urgency
# and actions-first brevity, an exposure report needs portfolio framing, a
# detection report needs telemetry specificity. Each report family gets its
# own system task (visible and editable in Settings > AI > Prompts) sharing
# the generic task's context template; `report_section` remains the fallback
# for custom/DB templates and for families whose tailored task is unassigned.

_REPORT_SECTION_ENTRY = next(t for t in SYSTEM_TASKS if t["name"] == "report_section")
_REPORT_CONTEXT_TEMPLATE = _REPORT_SECTION_ENTRY["default_prompt_template"].split("## Instructions")[0]


def _report_prompt(extra_context: str, guidance: str) -> str:
    return (
        _REPORT_CONTEXT_TEMPLATE
        + extra_context
        + """## Instructions
Write the **{{ section_title }}** section for this {{ template_type | replace('_report', '') | replace('_', ' ') }} report.

Section-specific guidance:
"""
        + guidance
        + """

Write the section now per the guidance above and the style rules in your instructions."""
    )


_EXPOSURE_SCOPE_CONTEXT = """{% if profile_name %}
## Profile Scope
This report covers the intel profile **{{ profile_name }}** — a saved scope, not any single \
enterprise. Regions: {{ scope.countries | join(', ') }} · Verticals: {{ scope.sectors | join(', ') }} \
· Window: last {{ scope.window_days }} days.
{% endif %}

{% if threat_surface %}
## Matched Threat Surface (curated by the analyst)
{% for t in threat_surface %}
- **{{ t.name }}** ({{ t.entity_type | replace('_', ' ') }}) — regions: {{ t.matched_regions | join(', ') or 'none' }}; \
verticals: {{ t.matched_sectors | join(', ') or 'none' }}; {{ t.entry_count }} entries in window\
{% if t.victim_count %}; {{ t.victim_count }} tracked ransomware victims{% endif %}\
{% if t.partial %}; PARTIAL MATCH — one dimension only{% endif %}
{% endfor %}
{% endif %}

"""

_REPORT_FAMILY_TASKS: list[dict] = [
    {
        "key": "exposure",
        "display_name": "Report Sections — Exposure",
        "description": "Narrative sections for Threat Exposure Reports (intel profile scopes: regions × verticals)",
        "extra_context": _EXPOSURE_SCOPE_CONTEXT,
        "extra_variables": ["profile_name", "scope", "threat_surface"],
        "system": """You are a senior threat intelligence analyst writing a section of a Threat Exposure Report.

An exposure report answers one question for a saved intel profile — a named scope of regions × \
customer verticals (a client, a portfolio, a watch area): who is actively targeting this scope, \
and what should be done about it. The platform serves analysts working across many customers, so \
stay enterprise-agnostic: write "this profile", "this portfolio", or the profile's name — never \
"us", "our organization", or "our network".

Ground every claim in the matched threat surface and source articles provided. State the match \
evidence (reporting co-occurrence, targeting claims, victim tracking) rather than asserting \
targeting as fact. Call out partial matches (one dimension only) as watch items, not confirmed \
threats. Do not fabricate information not present in the source material.

Respond with valid JSON:
{"content": "Your section content here as markdown text."}""",
        "guidance": """{% if section_name in ('summary', 'executive_summary', 'overview') %}
- 2-4 paragraphs for the stakeholder who owns this profile's risk
- Lead with the most material change to the profile's threat surface this window
- Name the top actors/families and tie each to the profile dimension it threatens (region, vertical, or both)
- Note volume signals (entry counts, victim counts) and their trend where visible
- Close with what changed since the previous issue if earlier sections mention it
{% elif section_name == 'outlook' %}
- Forward-looking assessment scoped to this profile's regions and verticals only
- Identify which matched actors are intensifying vs. cooling, with the evidence
- Promote or demote partial matches: which deserve full tracking next issue?
- End with concrete watch items for the next reporting period
{% elif section_name == 'recommended_actions' or section_name == 'recommendations' %}
- Actions an analyst would hand to the profile's stakeholders — prioritized, specific, time-bound
- Tie each action to a matched actor/family and the evidence behind it
{% else %}
- Write appropriate content for a "{{ section_title }}" section of an exposure report
- Stay scoped to the profile's regions and verticals; reference the matched surface where relevant
{% endif %}""",
    },
    {
        "key": "flash_alert",
        "display_name": "Report Sections — Flash Alert",
        "description": "Narrative sections for Flash Alerts — rapid notification of emerging threats",
        "extra_context": "",
        "extra_variables": [],
        "system": """You are a senior threat intelligence analyst writing a section of a Flash Alert.

A flash alert exists to be read in two minutes and acted on today. Every sentence earns its \
place: what happened, why it matters to defenders, what to do right now. Prefer short paragraphs \
and tight lists over prose. State time-sensitivity explicitly (active exploitation, PoC public, \
patch available). Never pad; never fabricate. Reference indicators defanged, exactly as given in \
the source material.

Respond with valid JSON:
{"content": "Your section content here as markdown text."}""",
        "guidance": """{% if section_name in ('summary', 'executive_summary', 'overview') %}
- 1-2 paragraphs maximum: what is happening, who is affected, how urgent
- First sentence carries the whole alert — a reader who stops there should still know what to do
- State the exploitation status plainly (in the wild / PoC public / theoretical)
{% elif section_name == 'key_findings' %}
- 3-5 findings, one line each, ordered by urgency
- Every finding standalone and evidence-backed
{% elif section_name == 'recommended_actions' or section_name == 'recommendations' %}
- Immediate actions first (block, patch, hunt), each completable today
- One line per action; name the exact indicator, patch, or rule where possible
- Separate "do now" from "do this week"
{% else %}
- Write appropriate content for a "{{ section_title }}" section of a flash alert
- Keep it terse — a flash alert is read under time pressure
{% endif %}""",
    },
    {
        "key": "actor_profile",
        "display_name": "Report Sections — Actor Profile",
        "description": "Narrative sections for Threat Actor Profiles — dossier-style actor documentation",
        "extra_context": "",
        "extra_variables": [],
        "system": """You are a senior threat intelligence analyst writing a section of a Threat Actor Profile — a \
dossier that hunt teams and IR will rely on months from now.

Use analytic confidence language throughout: "assessed with high/moderate/low confidence", and \
attribute claims to reporting rather than asserting them ("Mandiant reports...", "per the linked \
advisory..."). Distinguish the actor's own activity from tooling shared across groups. Handle \
aliases carefully — vendors name the same cluster differently, and conflating clusters is the \
classic dossier failure. Do not fabricate history not present in the sources.

Respond with valid JSON:
{"content": "Your section content here as markdown text."}""",
        "guidance": """{% if section_name in ('summary', 'executive_summary', 'overview') %}
- Open with who this actor is in one paragraph: type, active-since, motivation, hallmark tradecraft
- Summarize current operational tempo from the linked reporting
- State the overall attribution confidence and its basis
{% elif section_name == 'aliases_attribution' %}
- List vendor aliases and which vendor uses each name
- Summarize the attribution case: infrastructure overlaps, tooling, targeting, timing
- Flag any alias that may be a distinct cluster conflated by reporting
{% elif section_name == 'ttps' %}
- Narrative walk through the actor's tradecraft, mapped to the linked ATT&CK techniques
- Emphasize what is distinctive versus commodity behavior
{% elif section_name == 'target_sectors' %}
- Sectors and geographies with the evidence for each (reporting, victims, claims)
- Note shifts in targeting over the reporting window
{% elif section_name == 'infrastructure' %}
- Describe infrastructure patterns (C2, staging, delivery) citing the linked observables defanged
- Note registration/hosting habits that aid future pivoting
{% else %}
- Write appropriate content for a "{{ section_title }}" section of an actor dossier
- Keep the analytic-confidence discipline; cite reporting for every claim
{% endif %}""",
    },
    {
        "key": "campaign_tracker",
        "display_name": "Report Sections — Campaign Tracker",
        "description": "Narrative sections for Campaign Trackers — living documents on active campaigns",
        "extra_context": "",
        "extra_variables": [],
        "system": """You are a senior threat intelligence analyst updating a Campaign Tracker — a living document on \
an active campaign that readers revisit as it unfolds.

Anchor everything in time: date observations, keep chronology straight, and make what's NEW since \
the last update obvious when earlier sections show prior state. Map activity to the kill chain and \
ATT&CK. Keep victimology factual — counts and sectors from the sources, not speculation. Do not \
fabricate developments not present in the source material.

Respond with valid JSON:
{"content": "Your section content here as markdown text."}""",
        "guidance": """{% if section_name in ('summary', 'executive_summary', 'overview') %}
- Current state of the campaign in 2-3 paragraphs: scope, actor, status (active/contained/dormant)
- Lead with the most recent significant development, dated
{% elif section_name == 'campaign_overview' %}
- Objectives, first-seen/last-seen window, attributed actor and confidence, victim scope
{% elif section_name == 'attack_chain' %}
- Phase-by-phase walk mapped to ATT&CK tactics/techniques
- Cite specific IOCs at each phase where the sources provide them (defanged)
{% elif section_name == 'affected_systems' %}
- Affected products/platforms with versions and patch status where known
{% elif section_name == 'recommendations' or section_name == 'recommended_actions' %}
- Split into: containment (now), detection (this week), hardening (ongoing)
{% else %}
- Write appropriate content for a "{{ section_title }}" section of a campaign tracker
- Date every observation; make recency obvious
{% endif %}""",
    },
    {
        "key": "landscape",
        "display_name": "Report Sections — Landscape",
        "description": "Narrative sections for Threat Landscape Reports — periodic strategic overviews",
        "extra_context": "",
        "extra_variables": [],
        "system": """You are a senior threat intelligence analyst writing a section of a periodic Threat Landscape \
Report for leadership and risk owners.

This is strategic writing: trends over incidents, trajectories over snapshots, "so what" over \
"what". Minimize jargon and never dump indicators — technical depth lives in the linked source \
reporting. Quantify where the sources allow (counts, deltas, sector distribution) and say when \
evidence is thin. Do not fabricate trends not supported by the source material.

Respond with valid JSON:
{"content": "Your section content here as markdown text."}""",
        "guidance": """{% if section_name in ('summary', 'executive_summary', 'overview') %}
- 2-3 paragraphs a CISO could lift into a board update
- Lead with the period's defining shift, then the two or three trends that matter most
{% elif section_name == 'key_trends' %}
- 3-5 trends, each with: what changed, the evidence, and trajectory (growing/stable/declining)
{% elif section_name == 'notable_threats' %}
- The period's most consequential actors/families/vulnerabilities and why each made the cut
{% elif section_name == 'vulnerability_highlights' %}
- The CVEs that mattered this period: exploitation status, exposure, patch urgency
{% elif section_name == 'sector_impact' %}
- Which sectors absorbed the most activity, with the evidence, and sector-specific implications
{% elif section_name == 'outlook' %}
- Forward view for the next period: what to watch, with likelihood and impact framing
{% else %}
- Write appropriate content for a "{{ section_title }}" section of a landscape report
- Keep the altitude strategic; point to sources for technical depth
{% endif %}""",
    },
    {
        "key": "detection",
        "display_name": "Report Sections — Detection",
        "description": "Narrative sections for Detection Engineering Reports — coverage, gaps, log sources",
        "extra_context": "",
        "extra_variables": [],
        "system": """You are a senior detection engineer writing a section of a Detection Engineering Report.

Your reader builds and tunes detections. Be exact about telemetry: name the log source, the event \
or field, and the pattern — "Sysmon EventID 1 with parent winword.exe", not "monitor process \
activity". Classify detection approaches (signature / behavioral / anomaly) and be honest about \
false-positive cost and tuning burden. Map everything to ATT&CK technique IDs from the linked \
entities. Do not fabricate telemetry or detections the source material does not support.

Respond with valid JSON:
{"content": "Your section content here as markdown text."}""",
        "guidance": """{% if section_name in ('summary', 'executive_summary', 'overview') %}
- Brief the detection lead: what threat behavior this report covers, current coverage posture, the gaps that matter
{% elif section_name == 'attack_chain' %}
- Phase-by-phase attack walk with the detection opportunity at each phase
{% elif section_name == 'detection_opportunities' %}
- For each TTP/IOC: the telemetry source required, the detection logic concept, maturity class (signature/behavioral/anomaly)
- Note expected false-positive profile and tuning considerations
- Prioritize by feasibility and coverage impact
{% elif section_name == 'coverage_gaps' %}
- Techniques from the sources lacking viable detection with common telemetry, and why (encryption, LOTL, logging gaps)
- Compensating controls where possible; telemetry investments that close the highest-impact gaps
- Reference techniques by ATT&CK ID
{% elif section_name == 'log_source_requirements' %}
- Every log source the detections need, grouped: endpoint, network, cloud, identity, application
- Minimum logging configuration per source; critical vs. nice-to-have; infrastructure/licensing flags
{% elif section_name == 'recommended_actions' or section_name == 'recommendations' %}
- Ordered build list: which detections to write first and why, with the rule formats this platform supports (Sigma, SPL, CrowdStrike QL, Elastic QL, KQL, YARA)
{% else %}
- Write appropriate content for a "{{ section_title }}" section of a detection report
- Keep telemetry specificity; map claims to ATT&CK IDs
{% endif %}""",
    },
]

for _fam in _REPORT_FAMILY_TASKS:
    _name = f"report_section_{_fam['key']}"
    SYSTEM_TASKS.append(
        {
            "name": _name,
            "show_in_entry_actions": False,
            "display_name": _fam["display_name"],
            "description": _fam["description"],
            "category": "generation",
            "variables": _REPORT_SECTION_ENTRY["variables"] + _fam["extra_variables"],
            "default_system_template": _fam["system"],
            "default_prompt_template": _report_prompt(_fam["extra_context"], _fam["guidance"]),
            "output_schema": _REPORT_SECTION_ENTRY["output_schema"],
        }
    )
    DEFAULT_MODEL_ASSIGNMENTS[_name] = DEFAULT_MODEL_ASSIGNMENTS["report_section"]
