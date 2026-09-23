"""Content relevance pre-filter for selective intel extraction mode.

Lightweight keyword-based scorer that determines whether an entry
is security-relevant enough to warrant autolinker processing.
No AI, no DB calls -- pure string matching.
"""

import re

# Keyword categories (lowercase). Each category has a weight.
VULNERABILITY_KEYWORDS = frozenset(
    {
        "vulnerability",
        "cve-",
        "exploit",
        "zero-day",
        "0day",
        "zeroday",
        "remote code execution",
        "rce",
        "privilege escalation",
        "buffer overflow",
        "sql injection",
        "xss",
        "cross-site",
        "deserialization",
        "ssrf",
        "authentication bypass",
        "patch",
        "advisory",
        "security update",
        "proof of concept",
        "poc",
        "critical vulnerability",
        "cvss",
        "use-after-free",
        "heap overflow",
        "stack overflow",
        "code execution",
        "denial of service",
        "dos",
        "out-of-bounds",
    }
)

MALWARE_KEYWORDS = frozenset(
    {
        "malware",
        "ransomware",
        "trojan",
        "backdoor",
        "rootkit",
        "botnet",
        "spyware",
        "keylogger",
        "wiper",
        "loader",
        "dropper",
        "stealer",
        "infostealer",
        "cryptominer",
        "remote access trojan",
        "command and control",
        "c2 server",
        "c&c",
        "payload",
        "implant",
        "cobalt strike",
        "beacon",
        "shellcode",
    }
)

INCIDENT_KEYWORDS = frozenset(
    {
        "breach",
        "data breach",
        "incident",
        "compromise",
        "attack",
        "campaign",
        "intrusion",
        "exfiltration",
        "data leak",
        "ransomware attack",
        "supply chain",
        "phishing",
        "spear phishing",
        "social engineering",
        "watering hole",
        "drive-by",
        "credential stuffing",
        "brute force",
        "lateral movement",
        "persistence",
        "initial access",
    }
)

THREAT_ACTOR_KEYWORDS = frozenset(
    {
        "apt",
        "threat actor",
        "threat group",
        "nation-state",
        "state-sponsored",
        "financially motivated",
        "cybercrime",
        "hacktivism",
        "hacktivist",
        "espionage",
        "cyber espionage",
        "advanced persistent threat",
    }
)

DETECTION_KEYWORDS = frozenset(
    {
        "sigma",
        "yara",
        "detection",
        "ioc",
        "indicator of compromise",
        "indicators of compromise",
        "ttp",
        "mitre att&ck",
        "mitre attack",
        "technique",
        "tactic",
        "detection rule",
        "hunting",
        "threat hunting",
        "splunk",
        "elastic",
        "crowdstrike",
        "sentinel",
        "siem",
    }
)

_KEYWORD_CATEGORIES = [
    (VULNERABILITY_KEYWORDS, 0.3),
    (MALWARE_KEYWORDS, 0.3),
    (INCIDENT_KEYWORDS, 0.25),
    (THREAT_ACTOR_KEYWORDS, 0.35),
    (DETECTION_KEYWORDS, 0.2),
]

# Structured patterns — high-signal indicators
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_TTP_PATTERN = re.compile(r"\bT\d{4}(?:\.(?!000\b)\d{3})?\b")
_IOC_LIKE_PATTERN = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"  # IPv4
    r"|\b[a-fA-F0-9]{32,64}\b"  # Hashes
    r"|hxxps?://"  # Defanged URLs
)

DEFAULT_RELEVANCE_THRESHOLD = 0.15


def score_relevance(title: str, summary: str | None, content_text: str | None) -> float:
    """Score content relevance for security/threat intelligence.

    Returns 0.0 to 1.0. Higher = more relevant.
    """
    combined = " ".join(filter(None, [title, summary, content_text])).lower()
    if not combined.strip():
        return 0.0

    score = 0.0

    # Keyword category matching
    for keywords, weight in _KEYWORD_CATEGORIES:
        hits = sum(1 for kw in keywords if kw in combined)
        if hits > 0:
            # Diminishing returns: 1 hit = 60% weight, 2+ scales up
            category_score = weight * min(1.0, 0.6 + 0.2 * hits)
            score += category_score

    # Structured pattern bonuses
    if _CVE_PATTERN.search(combined):
        score += 0.4
    if _TTP_PATTERN.search(combined):
        score += 0.3
    if _IOC_LIKE_PATTERN.search(combined):
        score += 0.2

    # Title weighting: security keywords in the title are a strong signal
    title_lower = (title or "").lower()
    if title_lower:
        title_has_security = any(kw in title_lower for cat, _ in _KEYWORD_CATEGORIES for kw in cat)
        if title_has_security:
            score += 0.15

    return min(1.0, score)
