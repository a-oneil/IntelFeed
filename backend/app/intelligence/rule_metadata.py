"""Metadata extraction from detection rule content.

Wraps the extract_metadata() system from github_content_types.py to provide
auto-population of structured fields (severity, MITRE tactics, tags, etc.)
from raw rule content written in the code editor.
"""

import logging
import re

from app.adapters.github_content_types import extract_metadata
from app.intelligence.tactics import canonical_tactics

logger = logging.getLogger(__name__)

# Map DetectionRule.rule_type → github_content_types content_type
RULE_TYPE_TO_CONTENT_TYPE: dict[str, str | None] = {
    "sigma": "sigma_rule",
    "elastic_ql": "elastic_rule",
    "splunk_spl": "splunk_detection",
    "kql": "sentinel_rule",
    "yara": "yara_rule",
    "snort_suricata": None,  # No extractor
    "crowdstrike_ql": None,  # No extractor
}

# Normalize severity values from various formats to our standard scale
_SEVERITY_NORMALIZE: dict[str, str] = {
    "informational": "informational",
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def extract_rule_metadata(rule_type: str, rule_content: str) -> dict:
    """Extract structured metadata from rule content.

    Returns raw metadata dict (empty if no extractor or parse failure).
    """
    content_type = RULE_TYPE_TO_CONTENT_TYPE.get(rule_type)
    if not content_type:
        return {}

    try:
        return extract_metadata(rule_content, content_type)
    except Exception:
        logger.debug("Metadata extraction failed for rule_type=%s", rule_type)
        return {}


def map_metadata_to_fields(metadata: dict) -> dict:
    """Map extracted metadata to DetectionRule field names.

    Returns a dict of field_name -> value for fields that can be auto-populated.
    """
    mapped: dict = {}

    # Severity
    raw_severity = (
        metadata.get("rule_level")  # Sigma
        or metadata.get("rule_severity")  # Elastic, Sentinel
        or ""
    )
    if raw_severity:
        mapped["severity"] = _SEVERITY_NORMALIZE.get(raw_severity.lower(), raw_severity.lower())

    # Description
    desc = (
        metadata.get("rule_description")  # Sigma, Elastic, YARA, Sentinel
        or metadata.get("detection_description")  # Splunk
        or ""
    )
    if desc:
        mapped["description"] = desc

    # MITRE ATT&CK technique IDs → source_ttps
    attack_ids = metadata.get("mitre_attack_ids", [])
    if attack_ids:
        mapped["source_ttps"] = [tid for tid in attack_ids if tid.upper().startswith("T")]

    # MITRE tactics — fold onto the hyphenated ATT&CK slug `TTP.tactic` uses,
    # so a rule and a technique name the same tactic the same way.
    tactics = metadata.get("mitre_tactics", [])
    if tactics:
        mapped["mitre_tactics"] = canonical_tactics(tactics)

    # Tags - collect from various sources
    tags: list[str] = []
    raw_tags = metadata.get("tags", [])
    if isinstance(raw_tags, list):
        tags.extend(str(t) for t in raw_tags if t)
    rule_tags = metadata.get("rule_tags", [])  # YARA
    if isinstance(rule_tags, list):
        tags.extend(str(t) for t in rule_tags if t)
    if tags:
        mapped["tags"] = tags

    # Log sources (Sigma logsource dict, Sentinel connectors)
    log_source = metadata.get("log_source")
    if isinstance(log_source, dict) and any(log_source.values()):
        mapped["log_sources"] = log_source
    connectors = metadata.get("required_data_connectors")
    if connectors and not log_source:
        mapped["log_sources"] = {"connectors": connectors}

    # Data sources (Splunk data_models + data_source, Sentinel connectors)
    data_sources: list[str] = []
    dm = metadata.get("data_models")
    if isinstance(dm, list):
        data_sources.extend(str(d) for d in dm if d)
    # Splunk's top-level `data_source` names the telemetry directly and is
    # populated far more often than data_model.
    ds = metadata.get("data_source")
    if isinstance(ds, list):
        data_sources.extend(str(d) for d in ds if d)
    if connectors:
        data_sources.extend(str(c) for c in connectors if c)
    if data_sources:
        mapped["data_sources"] = data_sources

    # References (advisory/blog URLs the rule cites)
    references: list[str] = []
    for key in ("references", "rule_references", "rule_reference", "reference"):
        val = metadata.get(key)
        if isinstance(val, list):
            references.extend(str(v).strip() for v in val if v)
        elif isinstance(val, str) and val.strip():
            references.extend(p.strip() for p in val.split(",") if p.strip())
    references = [r for r in dict.fromkeys(references) if r.startswith("http")]
    if references:
        mapped["references"] = references

    return mapped


def apply_metadata_to_fields(
    metadata: dict,
    rule,
    explicit_fields: set[str] | None = None,
) -> None:
    """Apply extracted metadata to a DetectionRule, only filling fields NOT in explicit_fields."""
    if not metadata:
        return

    explicit = explicit_fields or set()
    mapped = map_metadata_to_fields(metadata)

    if "severity" in mapped and "severity" not in explicit:
        rule.severity = mapped["severity"]

    if "description" in mapped and "description" not in explicit:
        rule.description = mapped["description"]

    if "source_ttps" in mapped and "source_ttps" not in explicit:
        rule.source_ttps = mapped["source_ttps"]

    if "mitre_tactics" in mapped and "mitre_tactics" not in explicit:
        rule.mitre_tactics = mapped["mitre_tactics"]

    if "tags" in mapped and "tags" not in explicit:
        # Merge extracted tags with existing (no duplicates)
        existing = set(rule.tags or [])
        merged = list(existing | set(mapped["tags"]))
        rule.tags = merged

    if "log_sources" in mapped and "log_sources" not in explicit:
        rule.log_sources = mapped["log_sources"]

    if "data_sources" in mapped and "data_sources" not in explicit:
        rule.data_sources = mapped["data_sources"]
    elif "data_sources" not in explicit and not (rule.data_sources or []):
        # Nothing declared a data source outright — derive one from the log
        # source the extractor did find, so the rule is visible to the telemetry
        # coverage join instead of silently counting as unevaluatable.
        derived = derive_data_sources(rule.rule_type, mapped.get("log_sources") or rule.log_sources, rule.rule_content)
        if derived:
            rule.data_sources = derived

    if "references" in mapped and "references" not in explicit:
        rule.references = mapped["references"]


def extract_and_apply(rule, explicit_fields: set[str] | None = None) -> dict:
    """Convenience: extract metadata from rule content, store it, and apply to fields.

    Returns the extracted metadata dict.
    """
    metadata = extract_rule_metadata(rule.rule_type, rule.rule_content)
    if metadata:
        # Preserve non-extraction keys (ai_chat_history, rule_conversions, etc.)
        existing = rule.metadata_ or {}
        preserved = {k: v for k, v in existing.items() if k in ("ai_chat_history", "rule_conversions")}
        merged = {**metadata, **preserved}
        rule.metadata_ = merged
        apply_metadata_to_fields(metadata, rule, explicit_fields)
    return metadata


# --- data_sources derivation -------------------------------------------------
#
# `data_sources` is what telemetry feasibility joins against the telemetry
# inventory, but map_metadata_to_fields() only ever filled it from Splunk
# data-models and Sentinel connectors. Sigma rules — the format that most
# consistently declares its telemetry — carry a structured `logsource`
# {product, service, category} that was only stored in `log_sources` and never
# projected, so the majority of the rule library was invisible to coverage
# analysis.
#
# Names are emitted "product:service" to match the channel-level naming MITRE
# now uses in its detection strategies ("WinEventLog:Sysmon", "auditd:SYSCALL"),
# so both sides of the join speak the same dialect.

# Sigma product/service pairs that have a well-known channel name.
_SIGMA_CHANNEL_ALIASES: dict[tuple[str, str], str] = {
    ("windows", "security"): "WinEventLog:Security",
    ("windows", "system"): "WinEventLog:System",
    ("windows", "application"): "WinEventLog:Application",
    ("windows", "sysmon"): "WinEventLog:Sysmon",
    ("windows", "powershell"): "WinEventLog:PowerShell",
    ("windows", "powershell-classic"): "WinEventLog:PowerShell",
    ("windows", "taskscheduler"): "WinEventLog:TaskScheduler",
    ("windows", "windefend"): "WinEventLog:Defender",
    ("linux", "auditd"): "auditd:SYSCALL",
    ("linux", "syslog"): "linux:syslog",
    ("macos", "syslog"): "macos:unifiedlog",
}

# Splunk queries declare their telemetry inline rather than in metadata.
_SPL_SOURCE_RE = re.compile(r"\b(?:index|sourcetype|datamodel)\s*=\s*[\"']?([\w.:*-]+)", re.IGNORECASE)

# Rule formats that scan artifacts rather than log streams. A YARA signature has
# no log source to satisfy, so leaving data_sources empty is correct — flagging
# them as telemetry gaps would be a category error.
NON_TELEMETRY_RULE_TYPES = frozenset({"yara", "nuclei"})


def derive_data_sources(rule_type: str, log_sources, rule_content: str | None = None) -> list[str]:
    """Best-effort telemetry names for a rule, for the coverage join.

    Reads the structured `log_sources` the metadata extractor already stores and,
    for Splunk, the query text itself. Returns [] for artifact-scanning formats
    and for anything with nothing declared.
    """
    if rule_type in NON_TELEMETRY_RULE_TYPES:
        return []

    out: list[str] = []

    if isinstance(log_sources, dict):
        # Sigma: {product, service, category}
        product = str(log_sources.get("product") or "").strip().lower()
        service = str(log_sources.get("service") or "").strip().lower()
        category = str(log_sources.get("category") or "").strip().lower()
        if product:
            alias = _SIGMA_CHANNEL_ALIASES.get((product, service))
            if alias:
                out.append(alias)
            elif service:
                out.append(f"{product}:{service}")
            elif category:
                out.append(f"{product}:{category}")
            else:
                out.append(product)
        elif service or category:
            out.append(service or category)

        # Elastic: {indices: [...]}; Sentinel: {connectors: [...]}
        for key in ("indices", "connectors"):
            values = log_sources.get(key)
            if isinstance(values, list):
                out.extend(str(v).strip() for v in values if v)

    if rule_type == "splunk_spl" and rule_content:
        out.extend(match.lower() for match in _SPL_SOURCE_RE.findall(rule_content))

    # Preserve first-seen order; dict.fromkeys dedupes case-sensitively, which is
    # what we want since the channel aliases are deliberately capitalized.
    return [v for v in dict.fromkeys(out) if v]
