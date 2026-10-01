"""Controlled vocabulary for victim sector / industry targeting.

Sectors are a small, closed vocabulary (21 canonical slugs) with an alias map
that normalizes the free-form phrasing articles use ("banks", "hospitals",
"power grid") onto a canonical slug. Since 2026-09 the vocabulary is also a
first-class entity: the ``sectors`` table is seeded from ``CANONICAL_SECTORS``
(one row per slug, ids minted deterministically by ``sector_uuid`` so every
install shares them) and ``entry_sectors`` carries both the slug and the FK.

This module stays the single source of truth for *what* a sector is — the
seeder, the Alembic seed, the AI schema enum and the normalizer all read from
here — so growing the vocabulary is one edit plus a seed run. Nothing here
touches the database.
"""

import re
import uuid

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


def normalize_sectors(names: list[str] | None) -> list[str]:
    """Normalize a list of free-form names to unique canonical slugs (order kept)."""
    slugs: list[str] = []
    for name in names or []:
        slug = normalize_sector(name)
        if slug and slug not in slugs:
            slugs.append(slug)
    return slugs


def parse_sector_setting(raw: str | None) -> list[str]:
    """Parse a comma-separated list of sector names/aliases into canonical slugs.

    Kept for the ``my_sectors`` → watches data migration and for callers that
    accept free-form lists (the exposure builder); the setting itself is gone.
    """
    if not raw:
        return []
    return normalize_sectors([part for part in raw.split(",") if part.strip()])


# ---------------------------------------------------------------------------
# Entity rows
# ---------------------------------------------------------------------------

#: Namespace for the deterministic sector ids. A closed vocabulary gains
#: nothing from random ids and loses a lot: with uuid5 every install (dev,
#: prod, the test schema, a fresh seed) agrees on which uuid "healthcare" is,
#: so profile links survive a re-seed and fixtures never need a lookup.
SECTOR_NAMESPACE = uuid.UUID("4e6a30ee-1eeb-5751-b76b-5c4de806fec1")


def sector_uuid(slug: str) -> uuid.UUID:
    """The id of the ``sectors`` row for a canonical slug."""
    return uuid.uuid5(SECTOR_NAMESPACE, slug)


#: One-line descriptions for the profile header and the AI assessment context.
SECTOR_DESCRIPTIONS: dict[str, str] = {
    "healthcare": "Hospitals, health systems, clinics, insurers, pharmaceutical and medical-device makers.",
    "financial-services": "Banks, payment processors, insurers, asset managers and fintech.",
    "government": "National, regional and municipal government bodies, agencies and public administration.",
    "defense": "Armed forces, defense ministries and the defense industrial base.",
    "energy": "Oil and gas, electric and gas utilities, renewables and power generation.",
    "manufacturing": "Industrial, automotive, chemical and consumer-goods manufacturing.",
    "education": "Schools, universities, academic research institutions and education technology.",
    "technology": "Software, hardware, cloud, semiconductor and IT product companies.",
    "telecommunications": "Carriers, ISPs, mobile operators and network service providers.",
    "retail": "Retailers, e-commerce, consumer goods and wholesale distribution.",
    "transportation": "Airlines, airports, shipping, rail, logistics and freight.",
    "legal": "Law firms, legal services and the courts.",
    "media": "News organizations, broadcasters, publishers and entertainment.",
    "hospitality": "Hotels, restaurants, travel, tourism and gaming venues.",
    "agriculture": "Farming, food production and the agribusiness supply chain.",
    "aerospace": "Aircraft, spacecraft and satellite manufacturers and operators.",
    "critical-infrastructure": (
        "Operational technology and industrial control systems: water, power grids, pipelines "
        "and other essential services."
    ),
    "ngo": "Non-profits, charities, think tanks, activists and other civil-society organizations.",
    "cryptocurrency": "Cryptocurrency exchanges, wallets, DeFi protocols and Web3 projects.",
    "msp": (
        "Managed service providers, IT outsourcers and service desks with privileged access to customer environments."
    ),
    "professional-services": "Consulting, accounting, marketing, staffing and other business services.",
}


def sector_aliases(slug: str) -> list[str]:
    """Alias surface forms for a slug, in alias-map order, excluding the label itself.

    These populate ``sectors.aliases`` so ``sector:banks`` resolves the way
    ``country:DPRK`` does. They are never fed to the autolinker — sector names
    are common English words and a prose mention is not a targeting claim.
    """
    label = CANONICAL_SECTORS[slug].lower()
    return [alias for alias, target in SECTOR_ALIASES.items() if target == slug and alias not in (slug, label)]


def seed_rows() -> list[dict]:
    """The 21 ``sectors`` rows, as the seeder, the migration and the test schema insert them."""
    return [
        {
            "id": sector_uuid(slug),
            "slug": slug,
            "name": label,
            "aliases": sector_aliases(slug),
            "description": SECTOR_DESCRIPTIONS.get(slug),
            "article_count": 0,
        }
        for slug, label in CANONICAL_SECTORS.items()
    ]
