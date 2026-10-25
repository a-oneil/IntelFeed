"""Detection rule extraction from feed content.

Extracts YARA, Elastic TOML, SIGMA, Snort/Suricata, Splunk SPL, KQL, EQL and
ES|QL rules from article text using regex + parsers. No AI required.

Query languages (SPL, KQL, EQL, ES|QL) come from code blocks — Markdown
fences or the article HTML's ``<pre>``/``<code>`` — so a sentence that says
"where" never becomes a rule. The one exception is the older inline SPL scan
(a line starting ``index=``/``search``/``| tstats``).
"""

import html as html_module
import logging
import re
import tomllib
import uuid

import yaml
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.rule_validation import validate_rule
from app.intelligence.tactics import canonical_tactic
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.ttp import TTP, EntryTTP
from app.services.entity_indexer import index_rules

logger = logging.getLogger(__name__)


def extract_rules_from_content(
    text: str,
    source_url: str | None = None,
    *,
    html: str | None = None,
    article_title: str | None = None,
) -> list[dict]:
    """Extract detection rules from article content.

    ``text`` is the article's plain text (or a raw file). ``html`` is the
    sanitized article HTML when there is one: the plain text has its ``<pre>``
    blocks flattened into prose, so code blocks are read from the HTML.
    ``article_title`` names the query rules, which carry no title of their own
    ("<article title> — KQL query 2").

    Returns list of dicts with: rule_type, title, rule_content, severity,
    tags, mitre_tactics, log_sources.
    """
    # Text stripped from HTML keeps its entities (&gt; &lt; &amp;); a rule
    # saved that way doesn't run as written.
    text = html_module.unescape(text or "")
    if not text.strip() and not html:
        return []

    code_blocks = _code_blocks(text, html)

    rules: list[dict] = []

    # Run all extractors
    rules.extend(_extract_yara_rules(text))
    rules.extend(_extract_elastic_toml_rules(text))
    rules.extend(_extract_sigma_rules(text, [block for _, block in code_blocks]))
    rules.extend(_extract_snort_suricata_rules(text))
    rules.extend(_extract_query_rules(text, code_blocks))

    # Validate each rule and filter out invalid ones
    validated = []
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        key = (rule["rule_type"], _content_key(rule["rule_content"]))
        if key in seen:
            continue
        result = validate_rule(rule["rule_type"], rule["rule_content"])
        if result.valid:
            seen.add(key)
            validated.append(rule)
        else:
            logger.debug(
                "Extracted %s rule '%s' failed validation: %s",
                rule["rule_type"],
                rule.get("title", "unknown"),
                [e.message for e in result.errors],
            )

    _number_query_titles(validated, article_title)
    return validated


def _content_key(content: str) -> str:
    """Whitespace-blind identity of a rule body.

    The same query can reach the extractors twice — from its code block and
    from the flattened article text — with different line breaks.
    """
    return re.sub(r"\s+", "", content)


# ── Code blocks ──────────────────────────────────────────────────────────

_FENCE_RE = re.compile(r"```([\w|+-]*)[ \t]*\n(.*?)```", re.DOTALL)
_PRE_RE = re.compile(r"<pre\b[^>]*>(.*?)</pre>", re.DOTALL | re.IGNORECASE)
_CODE_RE = re.compile(r"<code\b([^>]*)>(.*?)</code>", re.DOTALL | re.IGNORECASE)
_LANG_CLASS_RE = re.compile(r'class="[^"]*?\blang(?:uage)?-([\w|+-]+)', re.IGNORECASE)
_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_LINE_END_RE = re.compile(r"</(?:p|div|li|tr)>", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


def _html_block_text(fragment: str) -> str:
    """Code block HTML -> the code as written (line breaks kept, entities decoded)."""
    fragment = _BR_RE.sub("\n", fragment)
    fragment = _LINE_END_RE.sub("\n", fragment)
    return html_module.unescape(_TAG_RE.sub("", fragment)).strip()


def _code_blocks(text: str, html: str | None) -> list[tuple[str, str]]:
    """Every code block in the article as (language hint, code).

    The hint is the fence tag (```kql) or a ``language-kql`` class, lowercased,
    or "" when the author gave none.
    """
    blocks: list[tuple[str, str]] = []
    for m in _FENCE_RE.finditer(text):
        blocks.append((m.group(1).lower(), m.group(2).strip()))
    if html:
        for m in _PRE_RE.finditer(html):
            # The class sits on <pre> or on the <code> just inside it.
            lang = _LANG_CLASS_RE.search(m.group(0)[:300])
            blocks.append((lang.group(1).lower() if lang else "", _html_block_text(m.group(1))))
        # <code> outside <pre> is inline code. It only counts when a whole
        # query sits in it; the shape checks reject a bare table name.
        for m in _CODE_RE.finditer(_PRE_RE.sub("", html)):
            lang = _LANG_CLASS_RE.search(m.group(1))
            blocks.append((lang.group(1).lower() if lang else "", _html_block_text(m.group(2))))
    return [(lang, code) for lang, code in blocks if code]


def _extract_yara_rules(text: str) -> list[dict]:
    """Extract YARA rules from text."""
    rules = []
    # Match rule declarations and extract balanced braces
    pattern = re.compile(r"\brule\s+(\w+)\s*(?::\s*[^\{]*)?\{", re.DOTALL)

    for match in pattern.finditer(text):
        rule_name = match.group(1)
        start = match.start()
        # Find balanced closing brace
        brace_count = 0
        end = None
        for i in range(match.end() - 1, len(text)):
            if text[i] == "{":
                brace_count += 1
            elif text[i] == "}":
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break

        if end is None:
            continue

        rule_content = text[start:end]

        # Must have condition section
        if "condition:" not in rule_content:
            continue

        # Extract metadata from meta: section
        title = rule_name
        description = None
        severity = None
        tags = []
        meta_match = re.search(
            r"meta\s*:(.*?)(?:strings\s*:|condition\s*:)",
            rule_content,
            re.DOTALL,
        )
        if meta_match:
            meta_text = meta_match.group(1)
            desc_m = re.search(r'description\s*=\s*"([^"]*)"', meta_text)
            if desc_m:
                description = desc_m.group(1)
                title = description[:200] if len(description) > 10 else rule_name

            severity_m = re.search(r'severity\s*=\s*"([^"]*)"', meta_text)
            if severity_m:
                severity = severity_m.group(1).lower()

        rules.append(
            {
                "rule_type": "yara",
                "title": title,
                "rule_content": rule_content.strip(),
                "severity": severity,
                "tags": tags,
                "mitre_tactics": [],
                "log_sources": None,
            }
        )

    return rules


def _extract_elastic_toml_rules(text: str) -> list[dict]:
    """Extract Elastic detection rules from TOML content."""
    rules = []

    # Look for TOML content with [rule] section
    if "[rule]" not in text and "[metadata]" not in text:
        return rules

    # Try to find TOML blocks - could be the whole content or in code blocks
    toml_blocks = []

    # Check for fenced code blocks with TOML
    code_block_pattern = re.compile(r"```(?:toml)?\s*\n(.*?)```", re.DOTALL)
    for m in code_block_pattern.finditer(text):
        block = m.group(1)
        if "[rule]" in block or "[metadata]" in block:
            toml_blocks.append(block)

    # If no code blocks found, try the whole text as TOML
    if not toml_blocks and "[rule]" in text:
        toml_blocks.append(text)

    for block in toml_blocks:
        try:
            parsed = tomllib.loads(block)
        except Exception:
            continue

        rule_section = parsed.get("rule")
        if not rule_section or not isinstance(rule_section, dict):
            continue

        query = rule_section.get("query", "")
        if not query:
            continue

        # Map Elastic rule type to our rule_type
        rule_type_str = rule_section.get("type", "query")
        type_map = {
            "eql": "elastic_ql",
            "esql": "elastic_ql",
            "query": "kql",
            "threshold": "kql",
            "new_terms": "kql",
        }
        rule_type = type_map.get(rule_type_str, "elastic_ql")

        # If language is specified, use that
        language = rule_section.get("language", "")
        if language == "kusto" or language == "kql":
            rule_type = "kql"
        elif language == "eql":
            rule_type = "elastic_ql"

        title = rule_section.get("name", "Elastic Detection Rule")
        severity = rule_section.get("severity", None)

        # Extract MITRE tactics from [[rule.threat]] mappings
        mitre_tactics = []
        tags = list(rule_section.get("tags", []))
        threats = rule_section.get("threat", [])
        if isinstance(threats, list):
            for threat in threats:
                if isinstance(threat, dict):
                    tactic = threat.get("tactic", {})
                    if isinstance(tactic, dict) and tactic.get("name"):
                        # Elastic writes the display name ("Defense Evasion");
                        # store the ATT&CK slug so it matches every other writer.
                        slug = canonical_tactic(tactic["name"])
                        if slug:
                            mitre_tactics.append(slug)
                    technique = threat.get("technique", [])
                    if isinstance(technique, list):
                        for t in technique:
                            if isinstance(t, dict) and t.get("id"):
                                tags.append(t["id"])

        rules.append(
            {
                "rule_type": rule_type,
                "title": title,
                "rule_content": query.strip(),
                "severity": severity,
                "tags": tags,
                "mitre_tactics": mitre_tactics,
                "log_sources": {
                    "index": rule_section.get("index", []),
                },
            }
        )

    return rules


def _extract_sigma_rules(text: str, code_blocks: list[str] | None = None) -> list[dict]:
    """Extract SIGMA rules from YAML content."""
    rules = []

    # Find YAML blocks that look like SIGMA rules
    # Could be in code blocks or raw YAML
    yaml_blocks = []

    # Fenced code blocks
    code_pattern = re.compile(r"```(?:ya?ml|sigma)?\s*\n(.*?)```", re.DOTALL)
    for m in code_pattern.finditer(text):
        yaml_blocks.append(m.group(1))

    # If no code blocks, check if the whole text looks like SIGMA YAML
    if not yaml_blocks:
        # Check for SIGMA markers
        if "title:" in text and "detection:" in text and "logsource:" in text:
            yaml_blocks.append(text)

    # <pre> blocks from the article HTML (fenced ones are already listed)
    for block in code_blocks or []:
        if "detection:" in block and "logsource:" in block and block not in yaml_blocks:
            yaml_blocks.append(block)

    for block in yaml_blocks:
        # Handle multi-document YAML
        try:
            docs = list(yaml.safe_load_all(block))
        except yaml.YAMLError:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            # Must have required SIGMA fields
            if not all(k in doc for k in ("title", "detection", "logsource")):
                continue

            title = doc.get("title", "SIGMA Rule")
            severity = doc.get("level", None)
            # Extract MITRE tags
            mitre_tactics = []
            tags = []
            for tag in doc.get("tags", []):
                if isinstance(tag, str):
                    tags.append(tag)
                    # attack.defense_evasion -> defense-evasion
                    if tag.startswith("attack.") and not tag.startswith("attack.t"):
                        slug = canonical_tactic(tag)
                        if slug:
                            mitre_tactics.append(slug)

            logsource = doc.get("logsource", {})

            # Re-serialize to YAML for storage
            rule_content = yaml.dump(doc, default_flow_style=False, sort_keys=False)

            rules.append(
                {
                    "rule_type": "sigma",
                    "title": title,
                    "rule_content": rule_content.strip(),
                    "severity": severity,
                    "tags": tags,
                    "mitre_tactics": mitre_tactics,
                    "log_sources": logsource if isinstance(logsource, dict) else None,
                }
            )

    return rules


def _extract_snort_suricata_rules(text: str) -> list[dict]:
    """Extract Snort/Suricata rules from text."""
    rules = []
    # Match lines that look like Snort/Suricata rules
    pattern = re.compile(
        r"^(alert|log|pass|drop|reject|sdrop)\s+"
        r"(tcp|udp|icmp|ip|http|ftp|tls|smb|dns|pkthdr)\s+"
        r".+?\(.+?\)\s*$",
        re.MULTILINE,
    )

    for match in pattern.finditer(text):
        rule_line = match.group(0).strip()

        # Extract msg for title
        msg_match = re.search(r'msg\s*:\s*"([^"]*)"', rule_line)
        title = msg_match.group(1) if msg_match else "Snort/Suricata Rule"

        rules.append(
            {
                "rule_type": "snort_suricata",
                "title": title,
                "rule_content": rule_line,
                "severity": None,
                "tags": [],
                "mitre_tactics": [],
                "log_sources": None,
            }
        )

    return rules


def _is_spl_query(text: str) -> bool:
    """Check whether a block of text looks like a Splunk SPL query."""
    lower = text.lower()
    has_pipe = "|" in text

    # Strong indicators
    if "index=" in lower and has_pipe:
        return True
    if lower.lstrip().startswith("search ") and has_pipe:
        return True
    if "| tstats" in lower:
        return True

    # Weaker but common: pipe into known SPL commands
    if has_pipe and any(
        cmd in lower
        for cmd in [
            "| stats",
            "| where",
            "| eval",
            "| table",
            "| rex",
            "| dedup",
            "| sort",
            "| eventstats",
            "| streamstats",
            "| lookup",
            "| inputlookup",
            "| timechart",
            "| chart",
        ]
    ):
        # Require at least one more SPL-specific token to avoid false positives
        if "index=" in lower or "sourcetype=" in lower or "source=" in lower or lower.lstrip().startswith("search "):
            return True

    return False


# ── Query languages in code blocks: KQL, EQL, ES|QL ──────────────────────

# Fence tags / language-* classes authors use for each query language.
_LANG_HINTS = {
    "spl": "splunk_spl",
    "splunk": "splunk_spl",
    "kql": "kql",
    "kusto": "kql",
    "eql": "eql",
    "esql": "esql",
    "es|ql": "esql",
}

# Microsoft Defender XDR advanced hunting and Sentinel / Log Analytics tables.
_KQL_TABLES = frozenset(
    """
    DeviceProcessEvents DeviceNetworkEvents DeviceFileEvents DeviceRegistryEvents
    DeviceImageLoadEvents DeviceLogonEvents DeviceEvents DeviceInfo DeviceNetworkInfo
    DeviceFileCertificateInfo DeviceTvmSoftwareInventory DeviceTvmSoftwareVulnerabilities
    EmailEvents EmailAttachmentInfo EmailUrlInfo EmailPostDeliveryEvents UrlClickEvents
    IdentityLogonEvents IdentityQueryEvents IdentityDirectoryEvents IdentityInfo
    CloudAppEvents AlertInfo AlertEvidence BehaviorAnalytics BehaviorInfo BehaviorEntities
    ExposureGraphNodes ExposureGraphEdges
    SecurityEvent SecurityAlert SecurityIncident SigninLogs AADNonInteractiveUserSignInLogs
    AADServicePrincipalSignInLogs AADManagedIdentitySignInLogs AADSignInEventsBeta
    AuditLogs OfficeActivity AzureActivity AzureDiagnostics CommonSecurityLog Syslog
    Event WindowsEvent DnsEvents W3CIISLog ThreatIntelligenceIndicator ThreatIntelIndicators
    Heartbeat AWSCloudTrail GCPAuditLogs MicrosoftGraphActivityLogs IntuneDevices
    IntuneAuditLogs StorageBlobLogs SentinelHealth Anomalies
    ASimProcessEventLogs ASimNetworkSessionLogs ASimDnsActivityLogs
    imProcessCreate imNetworkSession imDns imAuthentication imFileEvent imRegistry
    """.split()
)
_KQL_OPERATOR_RE = re.compile(
    r"\|\s*(?:where|project(?:-\w+)?|summarize|extend|join|distinct|take|top|order\s+by|sort\s+by|"
    r"parse(?:-\w+)?|mv-expand|make-series|count|invoke|lookup|evaluate|union|limit)\b"
)
# Syntax SPL never uses — tells a KQL query on an unlisted table from SPL.
_KQL_ONLY_RE = re.compile(
    r"\|\s*(?:project|summarize|extend|mv-expand|make-series)\b|\bago\(|=~|\bin~|!has\b|\bhas_(?:any|all)\b|\bhas\b|=="
)
_KQL_START_RE = re.compile(r"(?:let\s+\w+\s*=|union\b|([A-Za-z_]\w*)\s*\|)")

_EQL_CATEGORIES = (
    "any|process|file|network|registry|library|driver|dns|authentication|iam|"
    "configuration|intrusion_detection|api|package|session|host|web"
)
_EQL_RE = re.compile(
    rf"(?:(?:{_EQL_CATEGORIES})\s+where\s+\S"
    r"|sequence(?:\s+by\s+[\w.]+(?:\s*,\s*[\w.]+)*)?(?:\s+with\s+maxspan\s*=\s*\w+)?\s*\["
    r"|join(?:\s+by\s+[\w.]+(?:\s*,\s*[\w.]+)*)?\s*\[)",
    re.IGNORECASE,
)
_ESQL_RE = re.compile(
    r"from\s+[\w.*:,\- ]+?(?:\s+metadata\s+[\w, ]+?)?\s*\|\s*"
    r"(?:where|stats|eval|keep|limit|sort|dissect|grok|enrich|rename|drop|mv_expand|lookup)\b",
    re.IGNORECASE,
)

_QUERY_LABELS = {"splunk_spl": "SPL", "kql": "KQL", "eql": "EQL", "esql": "ES|QL"}


def _strip_leading_comments(block: str) -> str:
    """The query without the comment lines authors put above it."""
    lines = block.strip().splitlines()
    while lines and (not lines[0].strip() or lines[0].lstrip().startswith(("//", "/*", "#", "--"))):
        lines.pop(0)
    return "\n".join(lines).strip()


def _is_kql_query(block: str) -> bool:
    body = _strip_leading_comments(block)
    lower = body.lower()
    if "index=" in lower or "sourcetype=" in lower:
        return False
    start = _KQL_START_RE.match(body)
    if not start or not _KQL_OPERATOR_RE.search(body):
        return False
    if start.group(1) in _KQL_TABLES:
        return True
    # A table we don't list, or a query opening with let/union: it has to name
    # a listed table somewhere or use syntax only KQL has.
    return bool(set(re.findall(r"\b[A-Za-z_]\w+\b", body)) & _KQL_TABLES) or bool(_KQL_ONLY_RE.search(body))


def _is_eql_query(block: str) -> bool:
    return bool(_EQL_RE.match(_strip_leading_comments(block)))


def _is_esql_query(block: str) -> bool:
    return bool(_ESQL_RE.match(_strip_leading_comments(block)))


_QUERY_CHECKS = {
    "splunk_spl": _is_spl_query,
    "kql": _is_kql_query,
    "eql": _is_eql_query,
    "esql": _is_esql_query,
}


def _classify_query_block(lang: str, block: str) -> str | None:
    """Which query language a code block holds, or None for anything else."""
    # A tag is a hint, not proof: a ```kql fence holding prose is still prose.
    hinted = _LANG_HINTS.get(lang)
    if hinted and _QUERY_CHECKS[hinted](block):
        return hinted
    for kind in ("eql", "esql", "kql", "splunk_spl"):
        if _QUERY_CHECKS[kind](block):
            return kind
    return None


def _extract_query_rules(text: str, code_blocks: list[tuple[str, str]]) -> list[dict]:
    """SPL, KQL, EQL and ES|QL queries from code blocks, plus inline SPL."""
    rules = []
    seen: set[str] = set()

    def _add(kind: str, content: str) -> None:
        content = content.strip() if kind == "splunk_spl" else _strip_leading_comments(content)
        key = _content_key(content)
        if not content or key in seen:
            return
        seen.add(key)
        rules.append(
            {
                # EQL and ES|QL are both Elastic query languages: one stored type.
                "rule_type": "elastic_ql" if kind in ("eql", "esql") else kind,
                "title": "",  # numbered from the article title once validated
                "rule_content": content,
                "severity": None,
                "tags": [],
                "mitre_tactics": [],
                "log_sources": None,
                "_query_label": _QUERY_LABELS[kind],
            }
        )

    for lang, block in code_blocks:
        kind = _classify_query_block(lang, block)
        if kind:
            _add(kind, block)

    # Inline SPL in plain text — multi-line blocks starting with index=,
    # "search ", or "| tstats" followed by continuation lines. Covers text
    # with no code blocks to read (Markdown without fences, flattened HTML).
    inline_pattern = re.compile(
        r"(?:^|\n)((?:index\s*=|search\s+|\|\s*tstats\s)\S.*(?:\n(?:[ \t].*|\|.*))*)",
        re.MULTILINE | re.IGNORECASE,
    )
    for m in inline_pattern.finditer(text):
        candidate = m.group(1).strip()
        # Skip very short fragments (likely just a mention, not a full query)
        if len(candidate) >= 30 and _is_spl_query(candidate):
            _add("splunk_spl", candidate)

    return rules


def _number_query_titles(rules: list[dict], article_title: str | None) -> None:
    """Title query rules "<article title> — KQL query 2", numbered per language.

    Queries carry no name of their own. Numbering them in article order keeps
    titles distinct within an article and stable when it is processed again.
    """
    base = re.sub(r"\s+", " ", article_title or "").strip()[:440]
    counters: dict[str, int] = {}
    for rule in rules:
        label = rule.pop("_query_label", None)
        if not label:
            continue
        counters[label] = counters.get(label, 0) + 1
        rule["title"] = f"{base} — {label} query {counters[label]}" if base else f"{label} query {counters[label]}"


async def store_extracted_rules(
    db: AsyncSession,
    entry_id: uuid.UUID,
    user_id: uuid.UUID,
    rules: list[dict],
) -> list[DetectionRule]:
    """Store extracted rules: skip a body already stored, update a same-titled rule from the same entry."""
    stored = []

    # Fetch TTPs linked to this entry so we can associate them with extracted rules
    ttp_result = await db.execute(
        select(TTP.technique_id).join(EntryTTP, EntryTTP.ttp_id == TTP.id).where(EntryTTP.entry_id == entry_id)
    )
    entry_ttp_ids = [r[0] for r in ttp_result.all()]

    # Fetch CVEs linked to this entry
    cve_result = await db.execute(
        select(CVE.cve_id).join(EntryCVE, EntryCVE.cve_id == CVE.id).where(EntryCVE.entry_id == entry_id)
    )
    entry_cve_ids = [r[0] for r in cve_result.all()]

    for rule_data in rules:
        content = rule_data["rule_content"]
        title = rule_data["title"][:500]
        rule_type = rule_data["rule_type"]

        # Dedup is on the rule body, never the title: query titles repeat
        # across articles, and a title match used to let each new SPL query
        # overwrite the last one. Any auto-extracted copy counts, whoever ran
        # the extraction, so a pipeline run and a manual one don't fork it.
        existing = await db.execute(
            select(DetectionRule.id)
            .where(
                DetectionRule.rule_content == content,
                or_(
                    DetectionRule.created_by == user_id,
                    DetectionRule.tags.contains(["auto-extracted"]),
                ),
            )
            .limit(1)
        )
        if existing.scalar_one_or_none():
            continue

        # Same entry, same title, new body: the rule was edited upstream and
        # the article processed again — replace the content in place.
        existing_by_title = await db.execute(
            select(DetectionRule)
            .where(
                DetectionRule.created_by == user_id,
                DetectionRule.entry_id == entry_id,
                DetectionRule.title == title,
                DetectionRule.rule_type == rule_type,
                DetectionRule.tags.contains(["auto-extracted"]),
            )
            .limit(1)
        )
        existing_rule = existing_by_title.scalar_one_or_none()

        tags = list(set(["auto-extracted", rule_type] + (rule_data.get("tags") or [])))

        # Merge entry-level TTPs with any TTPs parsed from the rule itself
        rule_ttps = list(set(entry_ttp_ids + (rule_data.get("mitre_techniques") or [])))

        # Merge entry-level CVEs with any CVEs parsed from the rule
        rule_cves = list(set(entry_cve_ids + (rule_data.get("cve_ids") or [])))

        if existing_rule:
            # Update existing rule with new content from updated source
            existing_rule.rule_content = content
            existing_rule.severity = rule_data.get("severity")
            existing_rule.tags = tags
            existing_rule.mitre_tactics = rule_data.get("mitre_tactics") or []
            existing_rule.log_sources = rule_data.get("log_sources")
            existing_rule.source_ttps = rule_ttps
            existing_rule.source_cves = rule_cves
            stored.append(existing_rule)
        else:
            detection_rule = DetectionRule(
                entry_id=entry_id,
                created_by=user_id,
                rule_type=rule_type,
                title=title,
                rule_content=content,
                severity=rule_data.get("severity"),
                tags=tags,
                is_draft=True,
                mitre_tactics=rule_data.get("mitre_tactics") or [],
                log_sources=rule_data.get("log_sources"),
                source_ttps=rule_ttps,
                source_cves=rule_cves,
            )
            db.add(detection_rule)
            stored.append(detection_rule)

    if stored:
        await db.flush()
        await index_rules(db, stored)

    return stored
