"""Controlled vocabulary for victim sector / industry targeting.

Sector targeting is intentionally NOT an entity table — it's a small, closed
vocabulary (~20 canonical sectors) with an alias map that normalizes the
free-form phrasing articles use ("banks", "hospitals", "power grid") to a
canonical slug. Slugs are stored on `entry_sectors`; display labels are used
for actor/malware `targeted_sectors` chips and triage explanations.
"""

import re

# Punctuation that is never part of a sector name but shows up wrapped around
# one. The backslash matters: a few stored values arrived as `\"Energy\"` with
# the JSON escaping intact, and a strip set without it stops at the backslash
# and never reaches the quote.
_EDGE_NOISE = " .,;:!?\"'()[]\\"


# slug -> display label
CANONICAL_SECTORS: dict[str, str] = {
    "healthcare": "Healthcare",
    "financial-services": "Financial Services",
    "government": "Government",
    "defense": "Defense",
    "energy": "Energy",
    "manufacturing": "Manufacturing",
    "education": "Education",
    "technology": "Technology",
    "telecommunications": "Telecommunications",
    "retail": "Retail",
    "transportation": "Transportation",
    "legal": "Legal",
    "media": "Media",
    "hospitality": "Hospitality",
    "agriculture": "Agriculture",
    "aerospace": "Aerospace",
    "critical-infrastructure": "Critical Infrastructure",
    "ngo": "NGO / Civil Society",
    "cryptocurrency": "Cryptocurrency / Web3",
    "msp": "MSP / IT Services",
    "professional-services": "Professional Services",
}

# lowercase alias -> slug. Exact (whole-phrase) matches only — the extraction
# prompt is instructed to emit canonical names, this map just absorbs drift.
SECTOR_ALIASES: dict[str, str] = {
    # healthcare
    "hospital": "healthcare",
    "hospitals": "healthcare",
    "medical": "healthcare",
    "health": "healthcare",
    "health care": "healthcare",
    "public health": "healthcare",
    "pharma": "healthcare",
    "pharmaceutical": "healthcare",
    "pharmaceuticals": "healthcare",
    "biotech": "healthcare",
    "life sciences": "healthcare",
    "clinics": "healthcare",
    "healthcare providers": "healthcare",
    # financial services
    "bank": "financial-services",
    "banks": "financial-services",
    "banking": "financial-services",
    "finance": "financial-services",
    "financial": "financial-services",
    "fintech": "financial-services",
    "insurance": "financial-services",
    "investment": "financial-services",
    "financial institutions": "financial-services",
    "credit unions": "financial-services",
    "securities": "financial-services",
    "capital markets": "financial-services",
    # government
    "gov": "government",
    "public sector": "government",
    "federal": "government",
    "municipal": "government",
    "state government": "government",
    "local government": "government",
    "ministries": "government",
    "public administration": "government",
    "diplomatic": "government",
    "embassies": "government",
    "foreign ministries": "government",
    "law enforcement": "government",
    # defense
    "military": "defense",
    "defence": "defense",
    "defense contractors": "defense",
    "defence contractors": "defense",
    "armed forces": "defense",
    "defense industrial base": "defense",
    # energy
    "oil and gas": "energy",
    "oil & gas": "energy",
    "oil": "energy",
    "gas": "energy",
    "utilities": "energy",
    "electric": "energy",
    "electricity": "energy",
    "power": "energy",
    "power grid": "energy",
    "nuclear": "energy",
    "petroleum": "energy",
    "renewables": "energy",
    # manufacturing
    "industrial manufacturing": "manufacturing",
    "factories": "manufacturing",
    "automotive": "manufacturing",
    "chemical": "manufacturing",
    "chemicals": "manufacturing",
    "heavy industry": "manufacturing",
    # education
    "universities": "education",
    "university": "education",
    "academia": "education",
    "academic": "education",
    "schools": "education",
    "research institutions": "education",
    "higher education": "education",
    # technology
    "tech": "technology",
    "software": "technology",
    "it": "technology",
    "information technology": "technology",
    "saas": "technology",
    "semiconductor": "technology",
    "semiconductors": "technology",
    "technology companies": "technology",
    # telecommunications
    "telecom": "telecommunications",
    "telecoms": "telecommunications",
    "telco": "telecommunications",
    "telcos": "telecommunications",
    "isp": "telecommunications",
    "isps": "telecommunications",
    "mobile operators": "telecommunications",
    "carriers": "telecommunications",
    # retail
    "e-commerce": "retail",
    "ecommerce": "retail",
    "retailers": "retail",
    "consumer goods": "retail",
    "wholesale": "retail",
    # transportation
    "logistics": "transportation",
    "shipping": "transportation",
    "aviation": "transportation",
    "airlines": "transportation",
    "airports": "transportation",
    "maritime": "transportation",
    "rail": "transportation",
    "railways": "transportation",
    "ports": "transportation",
    "transport": "transportation",
    "trucking": "transportation",
    # legal
    "law firms": "legal",
    "legal services": "legal",
    "attorneys": "legal",
    "lawyers": "legal",
    # media
    "news": "media",
    "journalism": "media",
    "journalists": "media",
    "entertainment": "media",
    "broadcasting": "media",
    "publishing": "media",
    "press": "media",
    # hospitality
    "hotels": "hospitality",
    "restaurants": "hospitality",
    "tourism": "hospitality",
    "travel": "hospitality",
    "casinos": "hospitality",
    # agriculture
    "farming": "agriculture",
    "food": "agriculture",
    "food and agriculture": "agriculture",
    "food production": "agriculture",
    "agribusiness": "agriculture",
    # aerospace
    "space": "aerospace",
    "satellite": "aerospace",
    "satellites": "aerospace",
    "satellite operators": "aerospace",
    # critical infrastructure / ICS
    "ics": "critical-infrastructure",
    "ot": "critical-infrastructure",
    "scada": "critical-infrastructure",
    "industrial control systems": "critical-infrastructure",
    "operational technology": "critical-infrastructure",
    "water": "critical-infrastructure",
    "water treatment": "critical-infrastructure",
    "wastewater": "critical-infrastructure",
    "water utilities": "critical-infrastructure",
    "dams": "critical-infrastructure",
    "pipelines": "critical-infrastructure",
    # NGO / civil society
    "ngos": "ngo",
    "non-profit": "ngo",
    "non-profits": "ngo",
    "nonprofit": "ngo",
    "nonprofits": "ngo",
    "civil society": "ngo",
    "activists": "ngo",
    "dissidents": "ngo",
    "think tanks": "ngo",
    "human rights organizations": "ngo",
    "charities": "ngo",
    # cryptocurrency / web3
    "crypto": "cryptocurrency",
    "web3": "cryptocurrency",
    "blockchain": "cryptocurrency",
    "defi": "cryptocurrency",
    "cryptocurrency exchanges": "cryptocurrency",
    "crypto exchanges": "cryptocurrency",
    "nft": "cryptocurrency",
    # MSP / IT services
    "msps": "msp",
    "managed service providers": "msp",
    "managed services": "msp",
    "it services": "msp",
    "it providers": "msp",
    "outsourcing": "msp",
    # professional services
    "professional services": "professional-services",
    "business services": "professional-services",
    "consulting": "professional-services",
    "accounting": "professional-services",
    # ransomware.live activity taxonomy (fixed vocab from /v2/victims) → canonical.
    # "Not Found" / "Other" are intentionally left unmapped (→ null).
    "retail & e-commerce": "retail",
    "government & defense": "government",
    "agriculture and food production": "agriculture",
    "food & beverage": "agriculture",
    "food and beverage": "agriculture",
    "energy & utilities": "energy",
}

# Lowercased label -> slug (so "Financial Services" round-trips)
_LABEL_TO_SLUG = {label.lower(): slug for slug, label in CANONICAL_SECTORS.items()}

# Noise suffixes commonly appended by articles/models ("healthcare sector",
# "financial services industry", "government organizations")
_STRIP_SUFFIXES = (
    " sector",
    " sectors",
    " industry",
    " industries",
    " organizations",
    " organisations",
    " companies",
    " institutions",
    " firms",
    " entities",
    " vertical",
)


def sector_label(slug: str) -> str:
    """Display label for a canonical slug (falls back to the slug itself)."""
    return CANONICAL_SECTORS.get(slug, slug)


def normalize_sector(name: str | None) -> str | None:
    """Normalize a free-form sector name to a canonical slug, or None if unknown."""
    if not name or not name.strip():
        return None
    # Underscores are a third separator alongside spaces and hyphens — AI
    # extraction wrote "critical_infrastructure" where the catalog writes
    # "critical-infrastructure" and an analyst writes "Critical Infrastructure".
    cleaned = re.sub(r"\s+", " ", name.strip().lower().replace("_", " ")).strip(_EDGE_NOISE)
    candidates = [cleaned]
    for suffix in _STRIP_SUFFIXES:
        if cleaned.endswith(suffix):
            candidates.append(cleaned[: -len(suffix)].strip())
    for cand in candidates:
        for variant in (cand, cand.rstrip("s") if len(cand) > 4 else cand):
            if variant in CANONICAL_SECTORS:
                return variant
            if variant in _LABEL_TO_SLUG:
                return _LABEL_TO_SLUG[variant]
            if variant in SECTOR_ALIASES:
                return SECTOR_ALIASES[variant]
            hyphenated = variant.replace(" ", "-").replace("/", "-")
            if hyphenated in CANONICAL_SECTORS:
                return hyphenated
    return None


def fold_sector_labels(values) -> list[str]:
    """Fold a stored `targeted_sectors` list onto canonical display labels.

    Unlike `normalize_sectors`, which returns slugs and drops what it can't
    place, this keeps an unrecognized value as written: stored sectors predate
    the controlled vocabulary and include analyst phrasing like "Political
    entities in Hong Kong" that no facet can group but nobody should delete.
    Duplicates are folded case-insensitively, so "Healthcare" and "healthcare"
    collapse to one chip while the first spelling's position is kept.

    The nightly sector rollup and the vocabulary backfill both write this
    column, so they share this function — if they folded differently the
    rollup would churn the backfill's rows straight back.
    """
    if not values:
        return []
    # A bare string is one sector, not a sequence of single-character ones:
    # iterating it would turn "Healthcare" into H, e, a, l, t, h... and the
    # sector column already carries stray single letters from a caller that
    # made exactly this mistake.
    if isinstance(values, str):
        values = [values]
    merged: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        slug = normalize_sector(value)
        canonical = sector_label(slug) if slug else value.strip(_EDGE_NOISE)
        if not canonical:
            continue
        key = canonical.casefold()
        if key not in seen:
            seen.add(key)
            merged.append(canonical)
    return merged


def normalize_sectors(names: list[str] | None) -> list[str]:
    """Normalize a list of free-form names to unique canonical slugs (order kept)."""
    slugs: list[str] = []
    for name in names or []:
        slug = normalize_sector(name)
        if slug and slug not in slugs:
            slugs.append(slug)
    return slugs


def parse_sector_setting(raw: str | None) -> list[str]:
    """Parse the comma-separated `my_sectors` setting into canonical slugs."""
    if not raw:
        return []
    return normalize_sectors([part for part in raw.split(",") if part.strip()])
