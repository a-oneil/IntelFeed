"""Content type detection, metadata extraction, and structured rendering for GitHub repo files.

Handles detection rule formats (Sigma, Elastic, Splunk, YARA, etc.) and other
structured files from monitored repositories.
"""

import json
import logging
import re
from fnmatch import translate as fnmatch_translate
from html import escape
from pathlib import PurePosixPath

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Glob matching (supports ** for recursive path segments)
# ---------------------------------------------------------------------------


def _glob_match(path: str, pattern: str) -> bool:
    """Match a file path against a glob pattern with ** support."""
    parts = pattern.split("**")
    regex = ""
    for i, part in enumerate(parts):
        if i > 0:
            regex += ".*"
        regex += fnmatch_translate(part.lstrip("/")).rstrip(r"\Z$")
    regex += r"\Z"
    return bool(re.match(regex, path))


# ---------------------------------------------------------------------------
# Content type detection rules
# ---------------------------------------------------------------------------

CONTENT_TYPE_RULES: list[tuple[str, str, str]] = [
    ("SigmaHQ/sigma", "rules/**/*.yml", "sigma_rule"),
    ("SigmaHQ/sigma", "rules-emerging-threats/**/*.yml", "sigma_rule"),
    ("SigmaHQ/sigma", "rules-threat-hunting/**/*.yml", "sigma_rule"),
    ("elastic/detection-rules", "rules/**/*.toml", "elastic_rule"),
    ("splunk/security_content", "detections/**/*.yml", "splunk_detection"),
    ("splunk/security_content", "stories/**/*.yml", "splunk_story"),
    ("LOLBAS-Project/LOLBAS", "yml/**/*.yml", "lolbas_entry"),
    ("infosecB/LOOBins", "LOOBins/**/*.yml", "loobin_entry"),
    ("loldrivers-project/loldrivers", "yaml/**/*.yaml", "loldriver_entry"),
    ("redcanaryco/atomic-red-team", "atomics/**/T*.yaml", "atomic_test"),
    ("Neo23x0/signature-base", "yara/**/*.yar", "yara_rule"),
    ("chronicle/GCTI", "YARA/**/*.yar", "yara_rule"),
    ("Azure/Azure-Sentinel", "Detections/**/*.yaml", "sentinel_rule"),
    ("panther-labs/panther-analysis", "rules/**/*.py", "panther_rule"),
    ("projectdiscovery/nuclei-templates", "**/*.yaml", "nuclei_template"),
    ("mdecrevoisier/SIGMA-detection-rules", "**/*.yml", "sigma_rule"),
    ("Yara-Rules/rules", "**/*.yar", "yara_rule"),
    ("Yara-Rules/rules", "**/*.yara", "yara_rule"),
    ("WithSecureLabs/iocs", "**/*.yar", "yara_rule"),
    ("WithSecureLabs/iocs", "**/*.yml", "yaml_file"),
    ("montysecurity/C2-Tracker", "**/*.txt", "ioc_list"),
    ("montysecurity/C2-Tracker", "**/*.csv", "ioc_list"),
    ("drb-ra/C2IntelFeeds", "**/*.txt", "ioc_list"),
    ("drb-ra/C2IntelFeeds", "**/*.csv", "ioc_list"),
    ("MBCProject/mbc-markdown", "**/*.md", "markdown_file"),
]

EXTENSION_MAP: dict[str, str] = {
    ".yml": "yaml_file",
    ".yaml": "yaml_file",
    ".toml": "toml_file",
    ".json": "json_file",
    ".md": "markdown_file",
    ".yar": "yara_rule",
    ".yara": "yara_rule",
    ".py": "python_file",
    ".txt": "text_file",
    ".csv": "csv_file",
}


def detect_content_type(owner: str, repo: str, file_path: str) -> str:
    """Detect the content type of a file based on repo and path patterns."""
    repo_key = f"{owner}/{repo}"
    for rule_repo, rule_glob, content_type in CONTENT_TYPE_RULES:
        if repo_key.lower() == rule_repo.lower() and _glob_match(file_path, rule_glob):
            return content_type
    ext = PurePosixPath(file_path).suffix.lower()
    return EXTENSION_MAP.get(ext, "unknown")


# ---------------------------------------------------------------------------
# Safe parsers
# ---------------------------------------------------------------------------


def _safe_yaml_load(content: str) -> dict | None:
    """Safely parse YAML content, returning None on failure."""
    try:
        import yaml

        data = yaml.safe_load(content)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _safe_toml_load(content: str) -> dict | None:
    """Safely parse TOML content, returning None on failure."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return None
    try:
        return tomllib.loads(content)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Title derivation
# ---------------------------------------------------------------------------


def derive_title(file_path: str, content: str | None, content_type: str) -> str:
    """Extract a human-readable title from file content based on content type."""
    fallback = PurePosixPath(file_path).name

    if not content:
        return fallback

    try:
        if content_type == "sigma_rule":
            data = _safe_yaml_load(content)
            if data:
                return data.get("title", fallback)

        elif content_type == "elastic_rule":
            data = _safe_toml_load(content)
            if data:
                rule = data.get("rule", data)
                return rule.get("name", fallback)

        elif content_type in ("splunk_detection", "splunk_story"):
            data = _safe_yaml_load(content)
            if data:
                return data.get("name", fallback)

        elif content_type in ("lolbas_entry", "loobin_entry"):
            data = _safe_yaml_load(content)
            if data:
                return data.get("Name", fallback)

        elif content_type == "loldriver_entry":
            data = _safe_yaml_load(content)
            if data:
                return data.get("Name", data.get("name", fallback))

        elif content_type == "atomic_test":
            data = _safe_yaml_load(content)
            if data:
                display = data.get("display_name", "")
                tech = data.get("attack_technique", "")
                if display:
                    return display
                if tech:
                    return f"Atomic Test: {tech}"

        elif content_type == "markdown_file":
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("# "):
                    return stripped[2:].strip()

        elif content_type == "yara_rule":
            match = re.search(r"^rule\s+(\w+)", content, re.MULTILINE)
            if match:
                return match.group(1)

        elif content_type == "sentinel_rule":
            data = _safe_yaml_load(content)
            if data:
                return data.get("name", fallback)

        elif content_type == "nuclei_template":
            data = _safe_yaml_load(content)
            if data:
                info = data.get("info", {})
                if isinstance(info, dict):
                    return info.get("name", fallback)

        elif content_type == "panther_rule":
            # Try display name / rule name constants
            name_match = re.search(
                r'(?:DISPLAY_NAME|display_name|RULE_NAME|RULE_ID)\s*=\s*["\']([^"\']*)["\']',
                content,
            )
            if name_match:
                return name_match.group(1)
            # Fall back to module docstring first line
            doc_match = re.match(
                r'^(?:\s*#[^\n]*\n)*\s*(?:\'\'\'|""")(.+?)(?:\'\'\'|""")',
                content,
                re.DOTALL,
            )
            if doc_match:
                return doc_match.group(1).strip().split("\n")[0]

        elif content_type == "json_file":
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    return data.get("name", data.get("title", fallback))
            except json.JSONDecodeError:
                pass

    except Exception:
        logger.debug(f"Title derivation failed for {file_path}, using fallback")

    return fallback


# ---------------------------------------------------------------------------
# Structured metadata extraction
# ---------------------------------------------------------------------------


def _extract_attack_tags(tags: list) -> tuple[list[str], list[str]]:
    """Extract ATT&CK technique IDs and tactics from Sigma-style tags.

    Tags look like: attack.t1059.001, attack.execution, attack.defense_evasion
    Returns (technique_ids, tactics).
    """
    technique_ids = []
    tactics = []
    tactic_names = {
        "reconnaissance",
        "resource_development",
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
    }
    for tag in tags:
        if not isinstance(tag, str):
            continue
        tag_lower = tag.lower()
        if not tag_lower.startswith("attack."):
            continue
        value = tag_lower.removeprefix("attack.")
        if re.match(r"t\d{4}(\.\d{3})?$", value):
            technique_ids.append(value.upper())
        elif value in tactic_names:
            tactics.append(value.replace("_", " ").title())
    return technique_ids, tactics


def extract_metadata(content: str | None, content_type: str) -> dict:
    """Extract structured metadata from file content based on content type.

    Returns a dict of normalized metadata fields. Keys are prefixed by domain
    (e.g., rule_title, mitre_attack_ids) for consistency across types.
    """
    if not content:
        return {}

    try:
        if content_type == "sigma_rule":
            return _extract_sigma_metadata(content)
        elif content_type == "elastic_rule":
            return _extract_elastic_metadata(content)
        elif content_type in ("splunk_detection", "splunk_story"):
            return _extract_splunk_metadata(content, content_type)
        elif content_type in ("lolbas_entry", "loobin_entry"):
            return _extract_lolbas_metadata(content)
        elif content_type == "loldriver_entry":
            return _extract_loldriver_metadata(content)
        elif content_type == "atomic_test":
            return _extract_atomic_metadata(content)
        elif content_type == "yara_rule":
            return _extract_yara_metadata(content)
        elif content_type == "sentinel_rule":
            return _extract_sentinel_metadata(content)
        elif content_type == "nuclei_template":
            return _extract_nuclei_metadata(content)
        elif content_type == "panther_rule":
            return _extract_panther_metadata(content)
    except Exception:
        logger.debug(f"Metadata extraction failed for content_type={content_type}")

    return {}


def _extract_sigma_metadata(content: str) -> dict:
    data = _safe_yaml_load(content)
    if not data:
        return {}

    tags = data.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    technique_ids, tactics = _extract_attack_tags(tags)

    logsource = data.get("logsource", {})
    if not isinstance(logsource, dict):
        logsource = {}

    fps = data.get("falsepositives", [])
    if not isinstance(fps, list):
        fps = [str(fps)] if fps else []

    return {
        "rule_title": data.get("title", ""),
        "rule_description": data.get("description", ""),
        "rule_status": data.get("status", ""),
        "rule_level": data.get("level", ""),
        "rule_author": data.get("author", ""),
        "rule_date": str(data.get("date", "")),
        "rule_modified": str(data.get("modified", "")),
        "mitre_attack_ids": technique_ids,
        "mitre_tactics": tactics,
        "log_source": {
            "product": logsource.get("product", ""),
            "category": logsource.get("category", ""),
            "service": logsource.get("service", ""),
        },
        "false_positives": fps,
        "tags": [t for t in tags if isinstance(t, str)],
    }


def _extract_elastic_metadata(content: str) -> dict:
    data = _safe_toml_load(content)
    if not data:
        return {}

    rule = data.get("rule", data)
    if not isinstance(rule, dict):
        return {}

    # Extract ATT&CK from threat entries
    technique_ids = []
    tactics = []
    for threat in rule.get("threat", []):
        if not isinstance(threat, dict):
            continue
        framework = threat.get("framework", "")
        if "ATT&CK" not in framework and "MITRE" not in framework.upper():
            continue
        tactic = threat.get("tactic", {})
        if isinstance(tactic, dict) and tactic.get("name"):
            tactics.append(tactic["name"])
        for tech in threat.get("technique", []):
            if isinstance(tech, dict) and tech.get("id"):
                technique_ids.append(tech["id"])
            for sub in tech.get("subtechnique", []) if isinstance(tech, dict) else []:
                if isinstance(sub, dict) and sub.get("id"):
                    technique_ids.append(sub["id"])

    return {
        "rule_name": rule.get("name", ""),
        "rule_description": rule.get("description", ""),
        "rule_severity": rule.get("severity", ""),
        "rule_risk_score": rule.get("risk_score"),
        "rule_type": rule.get("type", ""),
        "rule_query": rule.get("query", ""),
        "rule_index": rule.get("index", []),
        "mitre_attack_ids": technique_ids,
        "mitre_tactics": tactics,
    }


def _extract_splunk_metadata(content: str, content_type: str) -> dict:
    data = _safe_yaml_load(content)
    if not data:
        return {}

    tags = data.get("tags", {})
    if not isinstance(tags, dict):
        tags = {}

    def _listy(*candidates) -> list:
        """First non-empty candidate, always as a list."""
        for value in candidates:
            if not value:
                continue
            return value if isinstance(value, list) else [value]
        return []

    # splunk/security_content restructured its detection schema: mitre_attack_id,
    # analytic_story and data_source now sit at the TOP LEVEL and `tags` is
    # empty. Reading only tags.* silently yielded no ATT&CK mapping for every
    # detection on the newer schema. Prefer top level, fall back to tags so the
    # older files (and any other repo still using them) keep working.
    mitre_ids = _listy(data.get("mitre_attack_id"), tags.get("mitre_attack_id"))
    analytic_stories = _listy(data.get("analytic_story"), tags.get("analytic_story"))
    # `data_source` names the telemetry in prose ("Windows Event Log Security
    # 4663") — a better coverage key than anything parseable out of the SPL.
    data_sources = _listy(data.get("data_source"), tags.get("data_source"))

    return {
        "detection_name": data.get("name", ""),
        "detection_description": data.get("description", ""),
        "detection_type": data.get("type", ""),
        "search_query": data.get("search", ""),
        "data_models": data.get("data_model", []),
        "data_source": [str(s) for s in data_sources],
        "mitre_attack_ids": [str(m) for m in mitre_ids],
        "analytic_stories": [str(s) for s in analytic_stories],
        "content_subtype": content_type,
    }


def _extract_lolbas_metadata(content: str) -> dict:
    data = _safe_yaml_load(content)
    if not data:
        return {}

    commands = data.get("Commands", [])
    if not isinstance(commands, list):
        commands = []

    mitre_ids = []
    abuse_functions = []
    for cmd in commands:
        if not isinstance(cmd, dict):
            continue
        mid = cmd.get("MitreID")
        if mid and str(mid) not in mitre_ids:
            mitre_ids.append(str(mid))
        cat = cmd.get("Category", "")
        if cat and cat not in abuse_functions:
            abuse_functions.append(cat)

    detection_entries = data.get("Detection", [])
    detection_guidance = []
    if isinstance(detection_entries, list):
        for det in detection_entries:
            if isinstance(det, dict):
                ioc = det.get("IOC", "")
                if ioc:
                    detection_guidance.append(str(ioc))
            elif isinstance(det, str):
                detection_guidance.append(det)

    return {
        "binary_name": data.get("Name", ""),
        "binary_description": data.get("Description", ""),
        "mitre_attack_ids": mitre_ids,
        "abuse_functions": abuse_functions,
        "detection_guidance": detection_guidance,
        "paths": [p.get("Path", "") for p in data.get("Full_Path", []) if isinstance(p, dict)],
    }


def _extract_loldriver_metadata(content: str) -> dict:
    data = _safe_yaml_load(content)
    if not data:
        return {}

    tags = data.get("Tags", [])
    if not isinstance(tags, list):
        tags = []

    return {
        "driver_name": data.get("Name", data.get("name", "")),
        "driver_description": data.get("Description", ""),
        "driver_category": data.get("Category", ""),
        "tags": [str(t) for t in tags],
        "mitre_attack_ids": [],  # LOLDrivers don't always have ATT&CK IDs
    }


def _extract_atomic_metadata(content: str) -> dict:
    data = _safe_yaml_load(content)
    if not data:
        return {}

    tests = data.get("atomic_tests", [])
    if not isinstance(tests, list):
        tests = []

    test_info = []
    supported_platforms = set()
    for test in tests:
        if not isinstance(test, dict):
            continue
        test_info.append(
            {
                "name": test.get("name", ""),
                "executor_type": test.get("executor", {}).get("name", "")
                if isinstance(test.get("executor"), dict)
                else "",
            }
        )
        platforms = test.get("supported_platforms", [])
        if isinstance(platforms, list):
            supported_platforms.update(str(p) for p in platforms)

    technique_id = data.get("attack_technique", "")

    return {
        "technique_id": str(technique_id) if technique_id else "",
        "technique_name": data.get("display_name", ""),
        "mitre_attack_ids": [str(technique_id)] if technique_id else [],
        "atomic_tests": test_info,
        "supported_platforms": sorted(supported_platforms),
    }


def _extract_yara_metadata(content: str) -> dict:
    # Parse rule name from "rule NAME {"
    rule_match = re.search(r"^rule\s+(\w+)(?:\s*:\s*(.+))?\s*\{", content, re.MULTILINE)
    rule_name = rule_match.group(1) if rule_match else ""
    rule_tags = rule_match.group(2).split() if rule_match and rule_match.group(2) else []

    # Parse meta section
    description = ""
    author = ""
    reference = ""
    date = ""
    severity = ""
    technique_ids: list[str] = []
    meta_block = re.search(r"meta\s*:(.*?)(?:strings|condition)\s*:", content, re.DOTALL)
    if meta_block:
        meta_text = meta_block.group(1)
        desc_match = re.search(r'description\s*=\s*"([^"]*)"', meta_text)
        if desc_match:
            description = desc_match.group(1)
        author_match = re.search(r'author\s*=\s*"([^"]*)"', meta_text)
        if author_match:
            author = author_match.group(1)
        ref_match = re.search(r'reference\s*=\s*"([^"]*)"', meta_text)
        if ref_match:
            reference = ref_match.group(1)
        date_match = re.search(r'(?:date|last_modified|creation_date)\s*=\s*"([^"]*)"', meta_text)
        if date_match:
            date = date_match.group(1)
        sev_match = re.search(
            r'(?:severity|threat_level|threat_level_verbose)\s*=\s*"?(\w+)"?',
            meta_text,
        )
        if sev_match:
            severity = sev_match.group(1)

        # Extract ATT&CK technique IDs from meta fields
        # Common patterns: mitre_att = "T1059", attack_technique = "T1027.001",
        # technique = "T1059", mitre_attack = "T1059.001"
        for tid_match in re.finditer(
            r'(?:mitre_att(?:ack)?|attack_technique|technique(?:_id)?)\s*=\s*"([^"]*)"',
            meta_text,
        ):
            value = tid_match.group(1).strip().upper()
            if re.match(r"T\d{4}(\.\d{3})?$", value):
                technique_ids.append(value)

        # Also check for comma-separated technique lists
        for multi_match in re.finditer(
            r'(?:mitre_att(?:ack)?_techniques?|attack_techniques?)\s*=\s*"([^"]*)"',
            meta_text,
        ):
            for tid in re.findall(r"T\d{4}(?:\.\d{3})?", multi_match.group(1)):
                if tid.upper() not in technique_ids:
                    technique_ids.append(tid.upper())

    return {
        "rule_name": rule_name,
        "rule_tags": rule_tags,
        "rule_description": description,
        "rule_author": author,
        "rule_reference": reference,
        "rule_date": date,
        "rule_severity": severity,
        "mitre_attack_ids": technique_ids,
    }


def _extract_sentinel_metadata(content: str) -> dict:
    data = _safe_yaml_load(content)
    if not data:
        return {}

    tactics = data.get("tactics", [])
    if not isinstance(tactics, list):
        tactics = []

    techniques = data.get("relevantTechniques", [])
    if not isinstance(techniques, list):
        techniques = []

    return {
        "rule_name": data.get("name", ""),
        "rule_description": data.get("description", ""),
        "rule_severity": data.get("severity", ""),
        "rule_query": data.get("query", ""),
        "mitre_attack_ids": [str(t) for t in techniques],
        "mitre_tactics": [str(t) for t in tactics],
        "required_data_connectors": [
            dc.get("connectorId", "") for dc in data.get("requiredDataConnectors", []) if isinstance(dc, dict)
        ],
    }


def _extract_panther_metadata(content: str) -> dict:
    """Extract metadata from Panther Python detection rules.

    Panther rules use Python files with specific function names and docstrings,
    plus companion .yml files for metadata. The Python file itself may contain
    structured comments or constants with metadata.
    """
    title = ""
    description = ""
    severity = ""
    technique_ids: list[str] = []
    tags: list[str] = []
    log_types: list[str] = []

    # Extract rule ID/title from module-level constants or assignments
    id_match = re.search(r'(?:RULE_ID|rule_id)\s*=\s*["\']([^"\']*)["\']', content)
    if id_match:
        title = id_match.group(1)

    # Extract display name
    name_match = re.search(r'(?:DISPLAY_NAME|display_name|RULE_NAME)\s*=\s*["\']([^"\']*)["\']', content)
    if name_match:
        title = name_match.group(1)

    # Extract severity
    sev_match = re.search(r'(?:SEVERITY|severity|DEFAULT_SEVERITY)\s*=\s*["\']([^"\']*)["\']', content)
    if sev_match:
        severity = sev_match.group(1)

    # Extract description from module docstring
    doc_match = re.match(r'^(?:\s*#[^\n]*\n)*\s*(?:\'\'\'|""")(.+?)(?:\'\'\'|""")', content, re.DOTALL)
    if doc_match:
        description = doc_match.group(1).strip().split("\n")[0]

    # Extract ATT&CK technique IDs from comments or constants
    for tid in re.findall(r"T\d{4}(?:\.\d{3})?", content):
        if tid not in technique_ids:
            technique_ids.append(tid)

    # Extract LOG_TYPES or log_type references
    log_match = re.search(r"(?:LOG_TYPES?|log_types?)\s*=\s*\[([^\]]*)\]", content)
    if log_match:
        log_types = [t.strip().strip("'\"") for t in log_match.group(1).split(",") if t.strip()]

    # Extract tags from TAGS constant
    tags_match = re.search(r"(?:TAGS|tags)\s*=\s*\[([^\]]*)\]", content)
    if tags_match:
        tags = [t.strip().strip("'\"") for t in tags_match.group(1).split(",") if t.strip()]

    # Detect key function names to confirm it's a detection rule
    has_rule = bool(re.search(r"def\s+rule\s*\(", content))
    has_title_fn = bool(re.search(r"def\s+title\s*\(", content))

    if not has_rule:
        return {}  # Not a Panther detection rule

    return {
        "rule_name": title,
        "rule_description": description,
        "rule_severity": severity,
        "mitre_attack_ids": technique_ids,
        "tags": tags,
        "log_types": log_types,
        "has_title_function": has_title_fn,
    }


def _extract_nuclei_metadata(content: str) -> dict:
    data = _safe_yaml_load(content)
    if not data:
        return {}

    info = data.get("info", {})
    if not isinstance(info, dict):
        info = {}

    tags = info.get("tags", "")
    tag_list = [t.strip() for t in tags.split(",")] if isinstance(tags, str) else []

    classification = info.get("classification", {})
    if not isinstance(classification, dict):
        classification = {}

    return {
        "template_id": data.get("id", ""),
        "template_name": info.get("name", ""),
        "template_severity": info.get("severity", ""),
        "template_description": info.get("description", ""),
        "template_author": info.get("author", ""),
        "tags": tag_list,
        "cve_ids": [classification.get("cve-id", "")] if classification.get("cve-id") else [],
        "cvss_score": classification.get("cvss-score"),
    }


# ---------------------------------------------------------------------------
# Structured HTML card rendering
# ---------------------------------------------------------------------------

_LANG_MAP: dict[str, str] = {
    ".yml": "yaml",
    ".yaml": "yaml",
    ".toml": "toml",
    ".json": "json",
    ".md": "markdown",
    ".yar": "yara",
    ".yara": "yara",
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
}

# Severity → CSS class mapping
_LEVEL_CLASSES: dict[str, str] = {
    "critical": "level-critical",
    "high": "level-high",
    "medium": "level-medium",
    "low": "level-low",
    "informational": "level-info",
}


def _escape(text: str | None) -> str:
    return escape(str(text)) if text else ""


def _render_mitre_badges(ids: list[str]) -> str:
    if not ids:
        return ""
    badges = " ".join(f'<span class="mitre-badge">{escape(tid)}</span>' for tid in ids)
    return f'<div class="mitre-tags">{badges}</div>'


def _render_tactics_badges(tactics: list[str]) -> str:
    if not tactics:
        return ""
    badges = " ".join(f'<span class="tactic-badge">{escape(t)}</span>' for t in tactics)
    return f'<div class="tactic-tags">{badges}</div>'


def render_content(
    file_path: str,
    content: str | None,
    content_type: str = "",
    metadata: dict | None = None,
) -> str:
    """Render file content as HTML for display in the feed reader.

    For known detection rule formats, renders a structured card with metadata.
    For other formats, renders syntax-highlighted code blocks.
    """
    if not content:
        return "<p><em>No content available</em></p>"

    # Try structured card rendering for known types
    if metadata and content_type:
        card = _render_structured_card(content, content_type, metadata)
        if card:
            return card

    # Fallback: syntax-highlighted code block
    return _render_code_block(file_path, content)


def _render_code_block(file_path: str, content: str) -> str:
    """Render content as a syntax-highlighted code block."""
    ext = PurePosixPath(file_path).suffix.lower()

    if ext == ".md":
        try:
            import mistune

            return mistune.html(content)
        except ImportError:
            pass
        return f'<pre><code class="language-markdown">{escape(content)}</code></pre>'

    if ext == ".json":
        try:
            parsed = json.loads(content)
            pretty = json.dumps(parsed, indent=2)
            return f'<pre><code class="language-json">{escape(pretty)}</code></pre>'
        except json.JSONDecodeError:
            pass

    lang = _LANG_MAP.get(ext, "")
    lang_attr = f' class="language-{lang}"' if lang else ""
    return f"<pre><code{lang_attr}>{escape(content)}</code></pre>"


def _render_structured_card(content: str, content_type: str, meta: dict) -> str | None:
    """Render a structured HTML card for known content types. Returns None if not applicable."""
    renderers = {
        "sigma_rule": _render_sigma_card,
        "elastic_rule": _render_elastic_card,
        "splunk_detection": _render_splunk_card,
        "splunk_story": _render_splunk_card,
        "lolbas_entry": _render_lolbas_card,
        "loobin_entry": _render_lolbas_card,
        "loldriver_entry": _render_loldriver_card,
        "atomic_test": _render_atomic_card,
        "yara_rule": _render_yara_card,
        "sentinel_rule": _render_sentinel_card,
        "nuclei_template": _render_nuclei_card,
        "panther_rule": _render_panther_card,
    }
    renderer = renderers.get(content_type)
    if not renderer:
        return None
    try:
        return renderer(content, meta)
    except Exception:
        logger.debug(f"Structured card rendering failed for {content_type}")
        return None


def _render_sigma_card(content: str, meta: dict) -> str:
    level = meta.get("rule_level", "")
    level_class = _LEVEL_CLASSES.get(level, "")
    status = meta.get("rule_status", "")
    title = _escape(meta.get("rule_title", ""))
    desc = _escape(meta.get("rule_description", ""))
    author = _escape(meta.get("rule_author", ""))
    date = _escape(meta.get("rule_date", ""))

    ls = meta.get("log_source", {})
    log_parts = [v for v in [ls.get("product"), ls.get("category"), ls.get("service")] if v]
    log_source_str = " / ".join(log_parts) if log_parts else "—"

    fps = meta.get("false_positives", [])
    fp_html = ""
    if fps:
        items = "".join(f"<li>{_escape(fp)}</li>" for fp in fps)
        fp_html = f'<div class="false-positives"><strong>False Positives:</strong><ul>{items}</ul></div>'

    return f"""<div class="rule-card sigma-rule">
<div class="rule-header">
<span class="rule-type">SIGMA</span>
{f'<span class="rule-level {level_class}">{escape(level)}</span>' if level else ""}
{f'<span class="rule-status">{escape(status)}</span>' if status else ""}
</div>
<h3>{title}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
<div class="rule-meta">
<div class="log-source"><strong>Log Source:</strong> {escape(log_source_str)}</div>
{_render_mitre_badges(meta.get("mitre_attack_ids", []))}
{_render_tactics_badges(meta.get("mitre_tactics", []))}
{f"<div class='rule-author'><strong>Author:</strong> {author}</div>" if author else ""}
{f"<div class='rule-date'><strong>Date:</strong> {date}</div>" if date else ""}
</div>
<details><summary>Detection Logic</summary>
<pre><code class="language-yaml">{escape(content)}</code></pre>
</details>
{fp_html}
</div>"""


def _render_elastic_card(content: str, meta: dict) -> str:
    severity = meta.get("rule_severity", "")
    level_class = _LEVEL_CLASSES.get(severity, "")
    risk = meta.get("rule_risk_score")
    name = _escape(meta.get("rule_name", ""))
    desc = _escape(meta.get("rule_description", ""))
    rule_type = _escape(meta.get("rule_type", ""))
    query = meta.get("rule_query", "")
    indices = meta.get("rule_index", [])

    return f"""<div class="rule-card elastic-rule">
<div class="rule-header">
<span class="rule-type">ELASTIC</span>
{f'<span class="rule-level {level_class}">{escape(severity)}</span>' if severity else ""}
{f'<span class="rule-risk-score">Risk: {risk}</span>' if risk is not None else ""}
{f'<span class="rule-subtype">{rule_type}</span>' if rule_type else ""}
</div>
<h3>{name}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
<div class="rule-meta">
{_render_mitre_badges(meta.get("mitre_attack_ids", []))}
{_render_tactics_badges(meta.get("mitre_tactics", []))}
{f"<div class='rule-index'><strong>Indices:</strong> {', '.join(escape(i) for i in indices)}</div>" if indices else ""}
</div>
{f"<details><summary>Query</summary><pre><code>{escape(query)}</code></pre></details>" if query else ""}
<details><summary>Full Rule</summary>
<pre><code class="language-toml">{escape(content)}</code></pre>
</details>
</div>"""


def _render_splunk_card(content: str, meta: dict) -> str:
    name = _escape(meta.get("detection_name", ""))
    desc = _escape(meta.get("detection_description", ""))
    det_type = _escape(meta.get("detection_type", ""))
    query = meta.get("search_query", "")
    stories = meta.get("analytic_stories", [])

    stories_str = ", ".join(escape(s) for s in stories)
    stories_html = (
        (f"<div class='analytic-stories'><strong>Analytic Stories:</strong> {stories_str}</div>") if stories else ""
    )

    query_html = (
        (
            f"<details><summary>SPL Search</summary>"
            f'<pre><code class="language-spl">{escape(query)}</code></pre>'
            f"</details>"
        )
        if query
        else ""
    )

    return f"""<div class="rule-card splunk-detection">
<div class="rule-header">
<span class="rule-type">SPLUNK</span>
{f'<span class="rule-subtype">{det_type}</span>' if det_type else ""}
</div>
<h3>{name}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
<div class="rule-meta">
{_render_mitre_badges(meta.get("mitre_attack_ids", []))}
{stories_html}
</div>
{query_html}
<details><summary>Full Detection</summary>
<pre><code class="language-yaml">{escape(content)}</code></pre>
</details>
</div>"""


def _render_lolbas_card(content: str, meta: dict) -> str:
    name = _escape(meta.get("binary_name", ""))
    desc = _escape(meta.get("binary_description", ""))
    abuse = meta.get("abuse_functions", [])
    guidance = meta.get("detection_guidance", [])
    paths = meta.get("paths", [])

    guidance_html = ""
    if guidance:
        items = "".join(f"<li>{_escape(g)}</li>" for g in guidance)
        guidance_html = f'<div class="detection-guidance"><strong>Detection IOCs:</strong><ul>{items}</ul></div>'

    abuse_str = ", ".join(escape(a) for a in abuse)
    abuse_html = (f"<div class='abuse-functions'><strong>Abuse Functions:</strong> {abuse_str}</div>") if abuse else ""

    paths_str = ", ".join(escape(p) for p in paths if p)
    paths_html = (f"<div class='binary-paths'><strong>Paths:</strong> {paths_str}</div>") if paths else ""

    return f"""<div class="rule-card lolbas-entry">
<div class="rule-header">
<span class="rule-type">LOLBAS</span>
</div>
<h3>{name}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
<div class="rule-meta">
{_render_mitre_badges(meta.get("mitre_attack_ids", []))}
{abuse_html}
{paths_html}
</div>
{guidance_html}
<details><summary>Full Entry</summary>
<pre><code class="language-yaml">{escape(content)}</code></pre>
</details>
</div>"""


def _render_loldriver_card(content: str, meta: dict) -> str:
    name = _escape(meta.get("driver_name", ""))
    desc = _escape(meta.get("driver_description", ""))
    category = _escape(meta.get("driver_category", ""))
    tags = meta.get("tags", [])

    return f"""<div class="rule-card loldriver-entry">
<div class="rule-header">
<span class="rule-type">LOLDriver</span>
{f'<span class="rule-subtype">{category}</span>' if category else ""}
</div>
<h3>{name}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
{f"<div class='driver-tags'>{' '.join(escape(t) for t in tags)}</div>" if tags else ""}
<details><summary>Full Entry</summary>
<pre><code class="language-yaml">{escape(content)}</code></pre>
</details>
</div>"""


def _render_atomic_card(content: str, meta: dict) -> str:
    technique = _escape(meta.get("technique_id", ""))
    name = _escape(meta.get("technique_name", ""))
    platforms = meta.get("supported_platforms", [])
    tests = meta.get("atomic_tests", [])

    tests_html = ""
    if tests:
        rows = ""
        for t in tests:
            rows += f"<tr><td>{_escape(t.get('name', ''))}</td><td>{_escape(t.get('executor_type', ''))}</td></tr>"
        tests_html = (
            '<table class="atomic-tests"><thead><tr><th>Test</th><th>Executor</th></tr></thead>'
            f"<tbody>{rows}</tbody></table>"
        )

    return f"""<div class="rule-card atomic-test">
<div class="rule-header">
<span class="rule-type">ATOMIC RED TEAM</span>
{f'<span class="mitre-badge">{technique}</span>' if technique else ""}
</div>
<h3>{name or technique}</h3>
{
        f"<div class='platforms'><strong>Platforms:</strong> {', '.join(escape(p) for p in platforms)}</div>"
        if platforms
        else ""
    }
{tests_html}
<details><summary>Full Test Definition</summary>
<pre><code class="language-yaml">{escape(content)}</code></pre>
</details>
</div>"""


def _render_yara_card(content: str, meta: dict) -> str:
    name = _escape(meta.get("rule_name", ""))
    desc = _escape(meta.get("rule_description", ""))
    author = _escape(meta.get("rule_author", ""))
    reference = _escape(meta.get("rule_reference", ""))
    tags = meta.get("rule_tags", [])

    return f"""<div class="rule-card yara-rule">
<div class="rule-header">
<span class="rule-type">YARA</span>
{" ".join(f'<span class="yara-tag">{escape(t)}</span>' for t in tags) if tags else ""}
</div>
<h3>{name}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
<div class="rule-meta">
{f"<div class='rule-author'><strong>Author:</strong> {author}</div>" if author else ""}
{f"<div class='rule-reference'><strong>Reference:</strong> {reference}</div>" if reference else ""}
</div>
<pre><code class="language-yara">{escape(content)}</code></pre>
</div>"""


def _render_sentinel_card(content: str, meta: dict) -> str:
    name = _escape(meta.get("rule_name", ""))
    desc = _escape(meta.get("rule_description", ""))
    severity = meta.get("rule_severity", "")
    level_class = _LEVEL_CLASSES.get(severity.lower(), "") if severity else ""
    query = meta.get("rule_query", "")
    connectors = meta.get("required_data_connectors", [])

    return f"""<div class="rule-card sentinel-rule">
<div class="rule-header">
<span class="rule-type">SENTINEL</span>
{f'<span class="rule-level {level_class}">{escape(severity)}</span>' if severity else ""}
</div>
<h3>{name}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
<div class="rule-meta">
{_render_mitre_badges(meta.get("mitre_attack_ids", []))}
{_render_tactics_badges(meta.get("mitre_tactics", []))}
{
        f"<div class='data-connectors'><strong>Data Connectors:</strong> "
        f"{', '.join(escape(c) for c in connectors if c)}</div>"
        if connectors
        else ""
    }
</div>
{
        f'<details><summary>KQL Query</summary><pre><code class="language-kql">{escape(query)}</code></pre></details>'
        if query
        else ""
    }
<details><summary>Full Rule</summary>
<pre><code class="language-yaml">{escape(content)}</code></pre>
</details>
</div>"""


def _render_nuclei_card(content: str, meta: dict) -> str:
    name = _escape(meta.get("template_name", ""))
    desc = _escape(meta.get("template_description", ""))
    severity = meta.get("template_severity", "")
    level_class = _LEVEL_CLASSES.get(severity, "")
    author = _escape(meta.get("template_author", ""))
    tags = meta.get("tags", [])
    cves = meta.get("cve_ids", [])

    return f"""<div class="rule-card nuclei-template">
<div class="rule-header">
<span class="rule-type">NUCLEI</span>
{f'<span class="rule-level {level_class}">{escape(severity)}</span>' if severity else ""}
</div>
<h3>{name}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
<div class="rule-meta">
{f"<div class='template-author'><strong>Author:</strong> {author}</div>" if author else ""}
{f"<div class='template-tags'><strong>Tags:</strong> {', '.join(escape(t) for t in tags)}</div>" if tags else ""}
{f"<div class='cve-ids'><strong>CVEs:</strong> {', '.join(escape(c) for c in cves)}</div>" if cves else ""}
</div>
<details><summary>Full Template</summary>
<pre><code class="language-yaml">{escape(content)}</code></pre>
</details>
</div>"""


def _render_panther_card(content: str, meta: dict) -> str:
    name = _escape(meta.get("rule_name", ""))
    desc = _escape(meta.get("rule_description", ""))
    severity = meta.get("rule_severity", "")
    level_class = _LEVEL_CLASSES.get(severity.lower(), "") if severity else ""
    tags = meta.get("tags", [])
    log_types = meta.get("log_types", [])

    return f"""<div class="rule-card panther-rule">
<div class="rule-header">
<span class="rule-type">PANTHER</span>
{f'<span class="rule-level {level_class}">{escape(severity)}</span>' if severity else ""}
</div>
<h3>{name}</h3>
{f"<p class='rule-description'>{desc}</p>" if desc else ""}
<div class="rule-meta">
{_render_mitre_badges(meta.get("mitre_attack_ids", []))}
{
        f"<div class='log-types'><strong>Log Types:</strong> {', '.join(escape(lt) for lt in log_types)}</div>"
        if log_types
        else ""
    }
{f"<div class='rule-tags'><strong>Tags:</strong> {', '.join(escape(t) for t in tags)}</div>" if tags else ""}
</div>
<pre><code class="language-python">{escape(content)}</code></pre>
</div>"""
