"""Content relevance pre-filter for selective intel extraction mode.

Lightweight keyword-based scorer that determines whether an entry
is security-relevant enough to warrant autolinker processing (selective
mode) and AI analysis (the junk gate). Both gates compare the score to the
one ``ai_analysis_relevance_threshold`` setting.

Keywords match at the start of a word, so "exploited" hits ``exploit`` but
"laptop" does not hit ``apt`` and "percent" does not hit ``rce``. Short
keywords (four characters or fewer) must also end the word, allowing only a
plural ``s`` or trailing digits: "APT29" and "IOCs" hit, "aptly", "pocket"
and "Siemens" do not. No AI, no DB calls in the scorer itself.
"""

import re

# Keyword categories (lowercase). Each category has a weight.
VULNERABILITY_KEYWORDS = frozenset(
    {
        "vulnerability",
        "vulnerabilities",
        "vulnerable",
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
        "prompt injection",
        "xss",
        "cross-site",
        "deserialization",
        "ssrf",
        "authentication bypass",
        "security flaw",
        "bug bounty",
        "patch",
        "advisory",
        "advisories",
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
        "ddos",
        "unpatched",
        "out-of-bounds",
    }
)

MALWARE_KEYWORDS = frozenset(
    {
        "malware",
        "malicious",
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
        "hack",
        "hacked",
        "hacker",
        "hacking",
        "data breach",
        "incident",
        "compromise",
        "attack",
        "cyberattack",
        "campaign",
        "intrusion",
        "hijack",
        "exfiltration",
        "data theft",
        "data leak",
        "ransomware attack",
        "supply chain",
        "phishing",
        "spear phishing",
        "spearphishing",
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
        "cyber threat",
        "nation-state",
        "state-sponsored",
        "financially motivated",
        "cybercrime",
        "cybercriminal",
        "hacktivism",
        "hacktivist",
        "espionage",
        "cyber espionage",
        "cyberespionage",
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

# Keywords this short are matched as whole words (plus a plural "s" or
# trailing digits); longer ones only need to start a word.
_SHORT_KEYWORD_LEN = 4


def _keyword_pattern(kw: str) -> re.Pattern[str]:
    pattern = r"(?<![a-z0-9])" + re.escape(kw)
    if len(kw) <= _SHORT_KEYWORD_LEN and kw[-1].isalnum():
        pattern += r"(?:s|\d+)?(?![a-z0-9])"
    return re.compile(pattern)


# Precompiled once per process: score_relevance runs on every ingested entry.
# Each keyword carries its plain form so the regex only runs when the
# (much cheaper) substring test has already found it somewhere.
_COMPILED_CATEGORIES: list[tuple[tuple[tuple[str, re.Pattern[str]], ...], float]] = [
    (tuple((kw, _keyword_pattern(kw)) for kw in sorted(keywords)), weight) for keywords, weight in _KEYWORD_CATEGORIES
]


def _has_keyword(text: str, kw: str, pattern: re.Pattern[str]) -> bool:
    return kw in text and pattern.search(text) is not None


async def get_relevance_threshold(db) -> float:
    """The cut-off both relevance gates use (``ai_analysis_relevance_threshold``)."""
    from app.services.system_settings import get_setting

    value = await get_setting("ai_analysis_relevance_threshold", db)
    if value is None or value == "":
        return DEFAULT_RELEVANCE_THRESHOLD
    try:
        return float(value)
    except (TypeError, ValueError):
        return DEFAULT_RELEVANCE_THRESHOLD


def score_relevance(title: str, summary: str | None, content_text: str | None) -> float:
    """Score content relevance for security/threat intelligence.

    Returns 0.0 to 1.0. Higher = more relevant.
    """
    combined = " ".join(filter(None, [title, summary, content_text])).lower()
    if not combined.strip():
        return 0.0

    score = 0.0

    # Keyword category matching
    for patterns, weight in _COMPILED_CATEGORIES:
        hits = sum(1 for kw, pat in patterns if _has_keyword(combined, kw, pat))
        if hits > 0:
            # Diminishing returns: 1 hit = 80% weight, 2+ hits = full weight
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
        title_has_security = any(
            _has_keyword(title_lower, kw, pat) for patterns, _ in _COMPILED_CATEGORIES for kw, pat in patterns
        )
        if title_has_security:
            score += 0.15

    return min(1.0, score)
