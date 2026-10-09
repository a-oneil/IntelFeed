"""Classify the legacy free-text ``targeted_sectors`` values for the one-time backfill.

The arrays on actors and malware were written by six paths over two years and
hold ~435 distinct strings for a 21-slug vocabulary: canonical labels, near
duplicates the normalizer misses ("Government agencies"), geography smuggled in
as industry ("Middle East", "Ukraine"), asset classes that are not sectors at
all ("Email servers", "Android users"), and single-character fragments from a
string that was iterated character by character.

``classify`` sorts one value into a decision the backfill script acts on and
reports; the override map carries the sector-shaped strings ``normalize_sector``
cannot place on its own. Nothing here touches the database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.intelligence.sectors import CANONICAL_SECTORS, normalize_sector

#: Sector-shaped strings the normalizer misses, mapped by hand after reviewing
#: the prod dump. Keys are compared case-insensitively after whitespace folding.
OVERRIDES: dict[str, str] = {
    # government
    "government agencies": "government",
    "government systems": "government",
    "government facilities": "government",
    "government personnel": "government",
    "government officials": "government",
    "government_officials": "government",
    "government financial facilities": "government",
    "ministries of foreign affairs": "government",
    "foreign affairs ministries": "government",
    "diplomatic missions": "government",
    "consulates": "government",
    "foreign diplomats": "government",
    "political entities": "government",
    "political organizations": "government",
    "political targets": "government",
    "political campaigns": "government",
    "electoral processes": "government",
    "international affairs": "government",
    "international organizations": "government",
    "city systems": "government",
    "us government": "government",
    "u.s. government": "government",
    "us treasury": "government",
    "us state department": "government",
    "us democratic party": "government",
    # education
    "educational institutions": "education",
    "us education sector": "education",
    "australian universities": "education",
    "research": "education",
    "researchers": "education",
    "research organizations": "education",
    "scientific research": "education",
    # healthcare
    "healthcare systems": "healthcare",
    "health information systems": "healthcare",
    "biomedical": "healthcare",
    "genetics": "healthcare",
    # financial services
    "banking customers": "financial-services",
    "banking systems": "financial-services",
    "banking websites": "financial-services",
    "banking applications": "financial-services",
    "online banking users": "financial-services",
    "japanese banking users": "financial-services",
    "mexican banking customers": "financial-services",
    "us banks": "financial-services",
    "european banks": "financial-services",
    "western financial systems": "financial-services",
    "turkish financial sector": "financial-services",
    "financial technology": "financial-services",
    "financial data": "financial-services",
    "financial information": "financial-services",
    "swift": "financial-services",
    # energy
    "electric utilities": "energy",
    "power plants": "energy",
    "electrical grids": "energy",
    "power infrastructure": "energy",
    # manufacturing
    "chipmakers": "manufacturing",
    "electronics manufacturers": "manufacturing",
    "global manufacturers": "manufacturing",
    "industrial": "manufacturing",
    "industrial sector": "manufacturing",
    "industrial entities": "manufacturing",
    "industrial companies": "manufacturing",
    "industrial systems": "manufacturing",
    "critical manufacturing": "manufacturing",
    "engineering": "manufacturing",
    "engineering companies": "manufacturing",
    "submarine technology": "manufacturing",
    # defense
    "military targets": "defense",
    "defense supply chain": "defense",
    "us defense sector": "defense",
    "south korean defense contractors": "defense",
    "u.s. military networks": "defense",
    "ukrainian military": "defense",
    "ukraine defense forces": "defense",
    "nato": "defense",
    # hospitality
    "gambling companies": "hospitality",
    "gambling sector": "hospitality",
    "betting companies": "hospitality",
    "gaming industry": "hospitality",
    # ngo / civil society
    "religious organizations": "ngo",
    "religious minorities (sikh community": "ngo",
    "minority activists": "ngo",
    "uyghur community": "ngo",
    "uyghur-activists": "ngo",
    "tibetan organizations": "ngo",
    "tibetan-community": "ngo",
    "chinese diaspora": "ngo",
    "think-tanks": "ngo",
    "us national security think tanks": "ngo",
    "middle_east_policy_experts": "ngo",
    "ukraine supporters": "ngo",
    # msp / it services
    "managed-service-providers": "msp",
    "msp infrastructure": "msp",
    "asian cloud service providers": "msp",
    "isp-customers": "telecommunications",
    "chilean telecommunications": "telecommunications",
    # media
    "hong kong media outlets": "media",
    "jerusalem post": "media",
    "digital marketing professionals": "professional-services",
    "advertisement agencies": "professional-services",
    # legal
    "international law firms": "legal",
    "legal adversaries": "legal",
    # transportation
    "transportation systems": "transportation",
    "ukrainian transportation": "transportation",
    "ukraine logistics support": "transportation",
    # aerospace
    "u.s. aerospace organizations": "aerospace",
    "commercial aerospace companies": "aerospace",
    "viasat ka-sat": "aerospace",
    # critical infrastructure
    "industrial-control-systems": "critical-infrastructure",
    "omron-controllers": "critical-infrastructure",
    "ukrainian infrastructure": "critical-infrastructure",
    "israeli infrastructure": "critical-infrastructure",
    "georgian infrastructure": "critical-infrastructure",
    "russian infrastructure": "critical-infrastructure",
    "large-scale infrastructure": "critical-infrastructure",
    # retail
    "e-commerce sites": "retail",
    "consumers": "retail",
    # cryptocurrency
    "cryptocurrency users": "cryptocurrency",
    "cryptocurrency holders": "cryptocurrency",
    "cryptocurrency traders": "cryptocurrency",
    "cryptocurrency enthusiasts": "cryptocurrency",
    "cryptocurrency communities": "cryptocurrency",
    "cryptocurrency exchange users": "cryptocurrency",
    "cryptocurrency operations": "cryptocurrency",
    "cryptocurrency data": "cryptocurrency",
    "cryptocurrency mining": "cryptocurrency",
    "defi communities": "cryptocurrency",
    "nft communities": "cryptocurrency",
    "darknet markets": "cryptocurrency",
}

#: Regions and multi-country areas: geography, not industry. Dropped.
REGIONS = {
    "middle east",
    "middle east region",
    "middle eastern organizations",
    "middle-eastern-entities",
    "middle east government",
    "europe",
    "european countries",
    "european organizations",
    "european companies",
    "companies in europe",
    "eastern europe",
    "asia-pacific",
    "asia pacific",
    "east asia",
    "south asia",
    "south asian organizations",
    "south-asian-entities",
    "southeast asia",
    "southeast asian countries",
    "southeast-asian-targets",
    "central asia",
    "latin america",
    "latin american countries",
    "entities in latin america",
    "asean",
    "crimea",
    "donetsk",
    "lugansk",
    "multiple countries",
    "21+ countries",
    "multi-regional targets",
    "global",
    "global targets",
    "global victims",
    "global users",
    "global organizations",
    "global enterprises",
    "global businesses",
    "global operations",
    "global infrastructure",
    "global propagation",
}

#: Values that carry no information at all.
JUNK = {
    "unknown",
    "various",
    "various organizations",
    "various industries",
    "various sectors",
    "various systems",
    "industries",
    "organizations",
    "general",
    "general users",
    "general public",
    "general victims",
    "general systems",
    "general computer users",
    "general computing systems",
    "general targets via phishing campaigns",
    "general targets via malvertising and phishing",
    "general targets via vulnerability exploitation",
    "general malware distribution",
    "multiple sectors",
    "multiple malware families",
    "opportunistic targets",
    "carefully selected organizations",
    "organizations with vulnerable systems",
    "organizations with vulnerable vpn servers",
    "high-profile organizations",
    "high-value organizations",
    "espionage targets",
    "corporate",
    "corporations",
    "corporate entities",
    "businesses",
    "enterprise",
    "enterprises",
    "private-sector",
    "private sector companies",
    "private companies",
    "private organizations",
    "commercial organizations",
    "international companies",
    "small businesses",
    "small business",
    "small and medium businesses",
    "smb",
    "individuals",
    "individual users",
    "end users",
    "web users",
    "professionals",
    "job_seekers",
    "-",
}

#: Word fragments that mark an asset or technology class rather than an industry.
_ASSET_WORDS = re.compile(
    r"\b(server|servers|system|systems|device|devices|users?|application|applications|browser|browsers|"
    r"router|routers|modem|modems|cloud|network|networks|workload|workloads|endpoint|endpoints|"
    r"credential|credentials|password|passwords|data|database|databases|email|e-mail|website|websites|"
    r"software|platform|platforms|environment|environments|infrastructure|interfaces|shares|"
    r"computers|lambda|kubernetes|docker|vpn|vpns|ssh|iis|owa|erp|cms|nas|iot|uefi|usb|dvr|solaris|ubuntu|"
    r"linux|windows|macos|mac|android|whatsapp|telegram|discord|facebook|winrar|telerik|coldfusion|"
    r"sharepoint|apache|php|red hat|cortex xdr|bitdefender|trend micro|cloudflare|antivirus_systems|"
    r"security software|security_detection|malware_delivery|software_downloaders|vulnerable_systems|"
    r"exfiltration|deployment|propaganda|information warfare|fundraising|communications|operations)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Decision:
    """What the backfill does with one stored value."""

    value: str
    kind: str  # mapped | rehomed_country | dropped_geo | dropped_asset | dropped_junk | dropped_other
    slug: str | None = None
    country: str | None = None


def _fold(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip(" .,;:!?\"'()[]\\")).lower()


def classify(value: str, country_names: set[str] | None = None) -> Decision:
    """Sort one stored string into a backfill decision.

    ``country_names`` is the lowercased set of country names and demonym aliases
    from the countries table; a value matching one is a target *country*, which
    the script can rehome onto the country junction instead of dropping.
    """
    raw = value or ""
    folded = _fold(raw)
    if len(folded) <= 1 or folded in JUNK:
        return Decision(raw, "dropped_junk")

    slug = normalize_sector(raw) or OVERRIDES.get(folded)
    if slug in CANONICAL_SECTORS:
        return Decision(raw, "mapped", slug=slug)

    if folded in REGIONS:
        return Decision(raw, "dropped_geo")
    if country_names:
        hit = _country_in(folded, country_names)
        if hit:
            return Decision(raw, "rehomed_country", country=hit)

    if _ASSET_WORDS.search(folded):
        return Decision(raw, "dropped_asset")
    return Decision(raw, "dropped_other")


_COUNTRY_SUFFIXES = (
    " organizations",
    " organisations",
    " entities",
    " companies",
    " firms",
    " government",
    " victims",
    " infrastructure",
    " targets",
    " users",
    " officials",
    " government officials",
    " government personnel",
    " government entities",
    " individuals",
    "-based victims",
    "_systems",
    "_firms",
    "-affairs",
)


def _country_in(folded: str, country_names: set[str]) -> str | None:
    """A bare country/demonym, or one followed by an organization-ish noun."""
    if folded in country_names:
        return folded
    for suffix in _COUNTRY_SUFFIXES:
        if folded.endswith(suffix):
            head = folded[: -len(suffix)].strip()
            if head in country_names:
                return head
    for prefix in ("organizations in ", "entities in ", "companies in "):
        if folded.startswith(prefix) and folded[len(prefix) :] in country_names:
            return folded[len(prefix) :]
    return None
