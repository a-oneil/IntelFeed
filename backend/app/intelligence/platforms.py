"""Controlled vocabulary for the platforms a tool or technique runs on.

`TTP.platforms` is seeded from ATT&CK and is already clean. `Tool.platforms`
is written by AI extraction and was not: 304 distinct values for what should be
a dozen, including case variants ("Windows"/"windows"), distro names, CPU
architectures ("x86_64", "ppc64le"), language runtimes ("Python", "Node.js")
and applications ("WordPress", "Snowflake"). Every one of those is a separate
row in the `tool.platform` facet.

Folding is deliberately conservative. ATT&CK's enterprise list is the target
vocabulary, but it has no entry for several things analysts genuinely mean —
"Web", "Mobile", "OT" — so a value that doesn't map is kept rather than
dropped, with only its spelling normalized. The narrow exception is
`is_not_a_platform`, which names the categories that are provably answers to a
different question.
"""

from __future__ import annotations

import re

# ATT&CK's enterprise platform list — the same vocabulary `TTP.platforms`
# holds, so a tool and a technique can be compared on where they run.
CANONICAL_PLATFORMS: tuple[str, ...] = (
    "Windows",
    "macOS",
    "Linux",
    "Android",
    "iOS",
    "Network Devices",
    "Containers",
    "ESXi",
    "IaaS",
    "SaaS",
    "Office Suite",
    "Identity Provider",
)

_BY_CASEFOLD = {p.casefold(): p for p in CANONICAL_PLATFORMS}

# Spellings observed in the tools table that name a canonical platform.
_PLATFORM_ALIASES: dict[str, str] = {
    # Linux and its distributions — a tool that runs on Ubuntu runs on Linux,
    # and the distro is not what the platform facet is asking.
    "unix": "Linux",
    "gnu/linux": "Linux",
    "ubuntu": "Linux",
    "debian": "Linux",
    "debian gnu/linux": "Linux",
    "rhel": "Linux",
    "centos": "Linux",
    "fedora": "Linux",
    "suse": "Linux",
    "alpine": "Linux",
    # macOS
    "mac": "macOS",
    "mac os": "macOS",
    "mac os x": "macOS",
    "osx": "macOS",
    "os x": "macOS",
    "darwin": "macOS",
    # Cloud. ATT&CK splits the old "Cloud" platform into IaaS/SaaS/Identity
    # Provider/Office Suite; a bare "Cloud" or a provider name is IaaS.
    "cloud": "IaaS",
    "cloud-based": "IaaS",
    "aws": "IaaS",
    "amazon web services": "IaaS",
    "azure": "IaaS",
    "gcp": "IaaS",
    "google cloud": "IaaS",
    "google cloud platform": "IaaS",
    "oracle cloud": "IaaS",
    "iaas": "IaaS",
    # Containers
    "container": "Containers",
    "docker": "Containers",
    "kubernetes": "Containers",
    "k8s": "Containers",
    "openshift": "Containers",
    # Network
    "network": "Network Devices",
    "network device": "Network Devices",
    "network appliance": "Network Devices",
    "network appliances": "Network Devices",
    "network infrastructure": "Network Devices",
    "router": "Network Devices",
    "routers": "Network Devices",
    # Virtualisation
    "vmware": "ESXi",
    "vmware esxi": "ESXi",
    "vsphere": "ESXi",
    # Office / identity
    "office 365": "Office Suite",
    "o365": "Office Suite",
    "microsoft 365": "Office Suite",
    "google workspace": "Office Suite",
    "azure ad": "Identity Provider",
    "entra id": "Identity Provider",
    "active directory": "Identity Provider",
    "okta": "Identity Provider",
    # Mobile
    "ios/ipados": "iOS",
    "ipados": "iOS",
}

# Prefixes that mean the same platform however the version is spelled out, e.g.
# "Red Hat Enterprise Linux 9.4 Update Services for SAP Solutions". These come
# from vendor advisories rather than from anyone describing a tool.
_PLATFORM_PREFIXES: tuple[tuple[str, str], ...] = (
    ("red hat enterprise linux", "Linux"),
    ("rhel", "Linux"),
    ("windows server", "Windows"),
    ("microsoft windows", "Windows"),
    ("amazon linux", "Linux"),
)

# Answers to a different question entirely. Kept narrow on purpose: a value
# that is merely absent from ATT&CK's list ("Web", "Mobile", "OT") is still
# telling you where a tool runs and survives, while a CPU architecture or a
# language runtime is not a platform under any reading.
_NOT_PLATFORM_EXACT = frozenset(
    {
        # CPU architectures
        "x86",
        "x86_64",
        "x64",
        "amd64",
        "aarch64",
        "arm",
        "arm64",
        "ppc64le",
        "s390x",
        "i386",
        # Language runtimes — how a tool is written, not where it runs
        "python",
        "java",
        "javascript",
        "node.js",
        "nodejs",
        "perl",
        "ruby",
        "go",
        "golang",
        "rust",
        "php",
        ".net",
        "c#",
        "powershell",
        # Placeholders that name nothing
        "multiple",
        "multiple versions and platforms",
        "various",
        "unknown",
        "n/a",
        "other",
        "any",
        "all",
    }
)

# Red Hat build tags (el7eap, el8eap, el9eap) and bare version strings.
_NOT_PLATFORM_PATTERN = re.compile(r"^(?:el\d+\w*|v?\d+(?:\.\d+)*)$", re.IGNORECASE)

# Noise wrapped around a value that is never part of it, backslash included: a
# few rows arrived as `\"Windows\"` with the JSON escaping from the extraction
# response intact. Brackets are deliberately absent — a value kept as written
# can legitimately contain them ("UNIX variants (UNIX, Linux, OSX)"), and
# stripping one end would leave it unbalanced.
_OUTPUT_NOISE = " \t\"'\\"
# The wider set is only used to build the lookup key, where losing a bracket
# costs nothing because the key is thrown away after the match.
_KEY_NOISE = " .,;:!?\"'()[]\\"


def is_not_a_platform(value: str) -> bool:
    """True for values that answer a different question than "where does it run".

    Used by the backfill to prune, not by the validator — dropping an
    unrecognized value on save would lose an analyst's wording, while these
    categories are wrong no matter who wrote them.
    """
    cleaned = value.strip(_KEY_NOISE).casefold()
    return bool(cleaned) and (cleaned in _NOT_PLATFORM_EXACT or bool(_NOT_PLATFORM_PATTERN.match(cleaned)))


def canonical_platform(raw: str | None) -> str | None:
    """Fold one platform spelling onto ATT&CK's vocabulary where it fits.

    A value outside the vocabulary comes back with its spelling normalized
    rather than dropped, so "Web" and "web" become one facet row without
    pretending ATT&CK has a name for them.
    """
    if raw is None:
        return None
    value = re.sub(r"\s+", " ", str(raw).strip(_OUTPUT_NOISE)).strip()
    if not value:
        return None

    key = value.strip(_KEY_NOISE).casefold()
    if key in _BY_CASEFOLD:
        return _BY_CASEFOLD[key]
    if key in _PLATFORM_ALIASES:
        return _PLATFORM_ALIASES[key]
    for prefix, canonical in _PLATFORM_PREFIXES:
        if key.startswith(prefix):
            return canonical
    if key in ("unknown", "n/a", "none"):
        return None
    # Outside the vocabulary: keep the wording, settle the spelling so the
    # facet stops listing "Web" and "web" separately.
    return value if value.isupper() else value[:1].upper() + value[1:]


def canonical_platforms(values) -> list[str]:
    """Fold a list of platform spellings, dropping blanks and duplicates."""
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        folded = canonical_platform(value)
        if folded and folded.casefold() not in seen:
            seen.add(folded.casefold())
            out.append(folded)
    return out
