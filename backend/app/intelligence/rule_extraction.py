"""Detection rule extraction from feed content.

Extracts YARA, Elastic TOML, SIGMA, Snort/Suricata, and Splunk SPL rules
from article text using regex + parsers. No AI required.
"""

import logging
import re
import tomllib
import uuid

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.rule_validation import validate_rule
from app.intelligence.tactics import canonical_tactic
from app.models.cve import CVE, EntryCVE
from app.models.detection_rule import DetectionRule
from app.models.ttp import TTP, EntryTTP
from app.services.entity_indexer import index_rules

logger = logging.getLogger(__name__)


def extract_rules_from_content(text: str, source_url: str | None = None) -> list[dict]:
    """Extract detection rules from article content.

    Returns list of dicts with: rule_type, title, rule_content, severity,
    tags, mitre_tactics, log_sources.
    """
    if not text or not text.strip():
        return []

    rules: list[dict] = []

    # Run all extractors
    rules.extend(_extract_yara_rules(text))
    rules.extend(_extract_elastic_toml_rules(text))
    rules.extend(_extract_sigma_rules(text))
    rules.extend(_extract_snort_suricata_rules(text))
    rules.extend(_extract_splunk_spl_rules(text))

    # Validate each rule and filter out invalid ones
    validated = []
    for rule in rules:
        result = validate_rule(rule["rule_type"], rule["rule_content"])
        if result.valid:
            validated.append(rule)
        else:
            logger.debug(
                "Extracted %s rule '%s' failed validation: %s",
                rule["rule_type"],
                rule.get("title", "unknown"),
                [e.message for e in result.errors],
            )

    return validated


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


def _extract_sigma_rules(text: str) -> list[dict]:
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


def _extract_splunk_spl_rules(text: str) -> list[dict]:
    """Extract Splunk SPL queries from code blocks and plain text."""
    rules = []
    seen: set[str] = set()

    def _add_spl(content: str) -> None:
        content = content.strip()
        if not content or content in seen:
            return
        if _is_spl_query(content):
            seen.add(content)
            rules.append(
                {
                    "rule_type": "splunk_spl",
                    "title": "Splunk SPL Query",
                    "rule_content": content,
                    "severity": None,
                    "tags": [],
                    "mitre_tactics": [],
                    "log_sources": None,
                }
            )

    # 1. Explicitly tagged code blocks (```spl or ```splunk)
    tagged_pattern = re.compile(r"```(?:spl|splunk)\s*\n(.*?)```", re.DOTALL)
    for m in tagged_pattern.finditer(text):
        _add_spl(m.group(1))

    # 2. Any fenced code block (untagged or other languages like ```text, ```bash)
    any_block_pattern = re.compile(r"```(?:\w*)\s*\n(.*?)```", re.DOTALL)
    for m in any_block_pattern.finditer(text):
        _add_spl(m.group(1))

    # 3. Inline SPL in plain text — look for multi-line blocks starting with
    #    index=, "search ", or "| tstats" followed by continuation lines
    inline_pattern = re.compile(
        r"(?:^|\n)((?:index\s*=|search\s+|\|\s*tstats\s)\S.*(?:\n(?:[ \t].*|\|.*))*)",
        re.MULTILINE | re.IGNORECASE,
    )
    for m in inline_pattern.finditer(text):
        candidate = m.group(1).strip()
        # Skip very short fragments (likely just a mention, not a full query)
        if len(candidate) >= 30:
            _add_spl(candidate)

    return rules


async def store_extracted_rules(
    db: AsyncSession,
    entry_id: uuid.UUID,
    user_id: uuid.UUID,
    rules: list[dict],
) -> list[DetectionRule]:
    """Store extracted rules, deduplicating by content or updating by title+type."""
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

        # Check for existing rule with same content (exact duplicate)
        existing = await db.execute(
            select(DetectionRule).where(
                DetectionRule.created_by == user_id,
                DetectionRule.rule_content == content,
            )
        )
        if existing.scalar_one_or_none():
            continue

        # Check for existing rule with same title+type from auto-extraction
        # (rule was updated upstream — replace content, link to new entry)
        existing_by_title = await db.execute(
            select(DetectionRule).where(
                DetectionRule.created_by == user_id,
                DetectionRule.title == title,
                DetectionRule.rule_type == rule_type,
                DetectionRule.tags.contains(["auto-extracted"]),
            )
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
            existing_rule.entry_id = entry_id
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
