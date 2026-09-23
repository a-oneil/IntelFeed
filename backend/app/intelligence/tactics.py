"""Controlled vocabulary for ATT&CK tactics.

Tactics arrive spelled five different ways depending on who wrote the rule:
Sigma tags say ``attack.defense_evasion``, Elastic's ``[[rule.threat]]`` blocks
say ``Defense Evasion``, Sentinel says ``DefenseEvasion``, our own catalog
hydration says ``defense-evasion`` (MITRE's own ``kill_chain_phases.phase_name``),
and hand-written rules say whatever the author typed. Stored unfolded, every
spelling becomes its own value in the ``rule.tactic`` facet and a query for one
misses the rest — ``rule.tactic:defense_evasion`` does not match ``Defense
Evasion`` because the filter compares substrings, not words.

The hyphenated slug wins because it is what MITRE publishes and therefore what
``TTP.tactic`` already holds, so a rule and a technique agree on the spelling.
"""

from __future__ import annotations

import re

# Canonical kill-chain tactic ordering per ATT&CK matrix domain, taken from the
# STIX bundles' x-mitre-matrix tactic_refs. Legacy slugs are kept in position
# (v18 split defense-evasion into stealth + defense-impairment; mobile dropped
# network-effects/remote-service-effects) so both pre- and post-v18 hydrations
# order correctly — tactics with no techniques are dropped from the response.
# Any tactic in catalog data but missing here is appended (sorted) after these.
TACTIC_ORDER: dict[str, list[str]] = {
    "enterprise": [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",  # pre-v18
        "stealth",
        "defense-impairment",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ],
    "mobile": [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
        "network-effects",  # pre-v18
        "remote-service-effects",  # pre-v18
    ],
    "ics": [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "evasion",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "inhibit-response-function",
        "impair-process-control",
        "impact",
    ],
}

# Every slug any matrix uses. Membership here is what makes a value canonical.
CANONICAL_TACTICS: frozenset[str] = frozenset(slug for slugs in TACTIC_ORDER.values() for slug in slugs)

# slug.title() covers everything except lowercase conjunctions
_TACTIC_LABELS = {"command-and-control": "Command and Control"}

# Enterprise tactic IDs only. Sigma and Elastic rules cite these alongside the
# technique IDs; the mobile and ICS matrices reuse the TA#### space with
# different assignments, so guessing there would mislabel rather than fold.
_TACTIC_IDS: dict[str, str] = {
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
    "TA0042": "resource-development",
    "TA0043": "reconnaissance",
}

# Spellings that slugify cleanly but to something outside the vocabulary.
_TACTIC_ALIASES: dict[str, str] = {
    "c2": "command-and-control",
    "cnc": "command-and-control",
    "command-control": "command-and-control",
    "command-and-control-c2": "command-and-control",
    "defence-evasion": "defense-evasion",
    "privesc": "privilege-escalation",
    "priv-esc": "privilege-escalation",
    "lateral-move": "lateral-movement",
    "cred-access": "credential-access",
    "recon": "reconnaissance",
    "exfil": "exfiltration",
    "initial-compromise": "initial-access",
}

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SEPARATORS = re.compile(r"[\s_./]+")
# A technique, not a tactic. Some importers put technique IDs in this column and
# the campaign coverage join looks for them there as a fallback to source_ttps,
# so they pass through untouched — slugifying "T1059.001" into "t1059-001"
# would quietly stop that join from matching.
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def tactic_label(slug: str) -> str:
    """Display form of a canonical slug."""
    return _TACTIC_LABELS.get(slug) or slug.replace("-", " ").title()


def canonical_tactic(raw: str | None) -> str | None:
    """Fold one tactic spelling onto its canonical hyphenated slug.

    Returns None only for values that carry no tactic at all (empty, or a
    placeholder like "unknown"). A value that slugifies but isn't in the
    vocabulary comes back slugified rather than dropped: a tactic this function
    hasn't heard of is more likely a new ATT&CK release than junk, and keeping
    it lowercase still collapses the case variants that made the facet
    duplicate in the first place.
    """
    if raw is None:
        return None
    value = str(raw).strip()
    if not value:
        return None

    # Sigma tags carry the namespace: attack.defense_evasion
    if value.lower().startswith("attack."):
        value = value[len("attack.") :]

    if _TECHNIQUE_ID.match(value):
        return value.upper()

    if value.upper() in _TACTIC_IDS:
        return _TACTIC_IDS[value.upper()]

    # Split CamelCase before casefolding, or the word boundary is lost and
    # "DefenseEvasion" slugifies to "defenseevasion".
    spaced = _CAMEL_BOUNDARY.sub(" ", value)
    slug = _SEPARATORS.sub("-", spaced.strip().lower())
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    if not slug or slug in ("unknown", "n-a", "none", "other"):
        return None

    if slug in CANONICAL_TACTICS:
        return slug
    return _TACTIC_ALIASES.get(slug, slug)


def canonical_tactics(values) -> list[str]:
    """Fold a list of tactic spellings, dropping blanks and duplicates.

    Order is preserved so a rule's first-listed tactic stays first.
    """
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        slug = canonical_tactic(value)
        if slug and slug not in seen:
            seen.add(slug)
            out.append(slug)
    return out
