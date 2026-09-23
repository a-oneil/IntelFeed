"""The canonical entity-type vocabulary, for the whole application.

One slug per entity type, spelled the same way in every layer: the API, the
autolinker, correlation, search, the AI tool schemas, the Workbench, and every
``entity_type`` column in the database. If you are writing new code that needs
to name an entity type, import the constant from here — do not type the string.

Historically three layers each invented their own spelling: the merge/dedup
stack keyed types off the model class (``malware_family``), the search index
used its own short form (``actor``), and ``offensive_tool`` survived the 2026-08
rename to ``tool``. That split silently orphaned rows — relationships written as
``malware_family`` never joined the ``malware`` ones — so the spellings were
unified in 2026-08 and the old ones are gone. ``normalize_entity_type`` remains
only to absorb stragglers from saved prompts and in-flight AI output.

This module deliberately imports nothing. Model classes, junction tables and
ORM registries live in the layers that own them; keeping this one dependency-free
is what lets ``app.models``, ``app.services``, ``app.api`` and ``app.intelligence``
all key off the same vocabulary without an import cycle.
"""

from typing import Final

# ---------------------------------------------------------------------------
# Slugs
# ---------------------------------------------------------------------------

THREAT_ACTOR: Final = "threat_actor"
MALWARE: Final = "malware"
CVE: Final = "cve"
CWE: Final = "cwe"
TTP: Final = "ttp"
COUNTRY: Final = "country"
TOOL: Final = "tool"
VENDOR: Final = "vendor"
PRODUCT: Final = "product"
MITIGATION: Final = "mitigation"
RANSOMWARE_VICTIM: Final = "ransomware_victim"
OBSERVABLE: Final = "observable"

#: Every entity type in the platform. An "entity" is a first-class noun that can
#: be linked to entries and related to other entities. Campaigns, detection rules,
#: feeds and entries are object kinds, not entity types — they are not in here.
ALL: Final = frozenset(
    {
        THREAT_ACTOR,
        MALWARE,
        CVE,
        CWE,
        TTP,
        COUNTRY,
        TOOL,
        VENDOR,
        PRODUCT,
        MITIGATION,
        RANSOMWARE_VICTIM,
        OBSERVABLE,
    }
)

# ---------------------------------------------------------------------------
# Capability subsets
# ---------------------------------------------------------------------------
# Not every type participates in every subsystem, and the differences are real
# rather than accidental — a CVE has no aliases to dedup, a vendor has no MITRE
# technique id. Each set below is the authority for one subsystem; the test in
# tests/test_entity_types.py asserts each layer's registry matches its set.

#: Types the autolinker can retro-scan entries for (name/alias or id pattern).
#: Mirrors the branches in autolinker._link_entity_to_existing_entries_inner.
#: Observables are deliberately absent: pattern *discovery* is what killed IOC
#: v1, so they never enter the dictionary or the prose scan. Their sightings
#: accrue in the observables pipeline stage instead, which only exact-matches
#: candidate values against rows the judgment doors already created.
AUTOLINKABLE: Final = frozenset({THREAT_ACTOR, MALWARE, CVE, CWE, TTP, COUNTRY, TOOL, VENDOR, PRODUCT, MITIGATION})

#: Types with a free-text name + aliases, so they can be deduped, merged,
#: reclassified across types, and indexed in entity_alias_index. Excludes the
#: id-keyed types (cve/cwe/ttp are identified by CVE-x / CWE-n / Tx, never by
#: name), country (a closed UN-seeded set that must not be merged), and
#: observable (identified by its (kind, value) pair — a hash has no aliases).
NAME_RESOLVED: Final = frozenset({THREAT_ACTOR, MALWARE, TOOL, VENDOR, PRODUCT, RANSOMWARE_VICTIM})

#: Types that can be reclassified into one another. Ransomware victims are
#: excluded: a victim is an organization, never a mis-filed actor or malware.
RECLASSIFIABLE: Final = frozenset({THREAT_ACTOR, MALWARE, TOOL, VENDOR, PRODUCT})

#: Types with entry junction tables, so they can be pivoted, graphed and
#: timelined. Mirrors intelligence.correlation.ENTITY_CONFIG.
CORRELATABLE: Final = frozenset(
    {THREAT_ACTOR, MALWARE, CVE, CWE, TTP, COUNTRY, TOOL, VENDOR, PRODUCT, MITIGATION, OBSERVABLE}
)

#: Types addressable as a field in the search bar (``threat_actor:APT29``).
#: Most search fields filter *entries* through an entry junction. Ransomware
#: victims are the exception: they arrive from leak-site sync and link to
#: VictimDisclosure rows, never to entries, so searching one returns the victim
#: itself and contributes no articles.
SEARCHABLE: Final = frozenset(
    {THREAT_ACTOR, MALWARE, CVE, CWE, TTP, COUNTRY, TOOL, VENDOR, PRODUCT, MITIGATION, RANSOMWARE_VICTIM, OBSERVABLE}
)

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

#: Singular human labels. The frontend has its own copy for i18n reasons; these
#: are for API messages, AI tool descriptions and log lines.
LABELS: Final = {
    THREAT_ACTOR: "threat actor",
    MALWARE: "malware family",
    CVE: "CVE",
    CWE: "weakness",
    TTP: "TTP",
    COUNTRY: "country",
    TOOL: "tool",
    VENDOR: "vendor",
    PRODUCT: "product",
    MITIGATION: "mitigation",
    RANSOMWARE_VICTIM: "ransomware victim",
    OBSERVABLE: "observable",
}

#: Slug → table, for raw SQL that can't go through the ORM (cluster discovery,
#: the entity_alias_index trigger). Table names keep their own history: the
#: malware table is still ``malware_families``, only the slug was unified.
TABLES: Final = {
    THREAT_ACTOR: "threat_actors",
    MALWARE: "malware_families",
    CVE: "cves",
    CWE: "cwes",
    TTP: "ttps",
    COUNTRY: "countries",
    TOOL: "tools",
    VENDOR: "vendors",
    PRODUCT: "products",
    MITIGATION: "mitigations",
    RANSOMWARE_VICTIM: "ransomware_victims",
    OBSERVABLE: "observables",
}

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

#: Spellings retired in the 2026-08 unification. No rows carry them any more
#: (the migration converted every entity_type column), but saved AI prompts and
#: in-flight tool calls can still emit them, so inbound values are folded rather
#: than rejected. Nothing should ever *write* these.
_RETIRED_SLUGS: Final = {
    "malware_family": MALWARE,
    "offensive_tool": TOOL,
    "actor": THREAT_ACTOR,
    "victim": RANSOMWARE_VICTIM,
}


def normalize_entity_type(entity_type: str) -> str:
    """Fold a retired spelling onto its canonical slug. Unknown values pass through."""
    return _RETIRED_SLUGS.get(entity_type, entity_type)


def is_entity_type(value: str) -> bool:
    """Whether ``value`` names an entity type, after normalization."""
    return normalize_entity_type(value) in ALL
