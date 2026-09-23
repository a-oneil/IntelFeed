"""Normalizers for threat-actor profile attributes gathered from reference feeds.

Reference sources spell the same facts differently — Malpedia and MISP Galaxy
report origin as an ISO alpha-2 code while our own seeders and the AI extraction
write full country names, and motivation arrives as anything from "Espionage" to
"Financial gain". These helpers fold both onto the values the workbench filters
and profile badges already expect, so importing a new source doesn't fragment
the vocabulary.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.sectors import normalize_sector

# Controlled motivation vocabulary — matches scripts/seed/seed_entity_attributes.py.
MOTIVATIONS = ("espionage", "financial", "disruption", "hacktivism", "sabotage")

# Substring -> canonical motivation. Ordered: the first hit wins, so put the
# more specific phrasings first.
_MOTIVATION_HINTS: tuple[tuple[str, str], ...] = (
    ("espionage", "espionage"),
    ("intelligence collection", "espionage"),
    ("surveillance", "espionage"),
    ("financial", "financial"),
    ("extortion", "financial"),
    ("ransom", "financial"),
    ("monetary", "financial"),
    ("cybercrime", "financial"),
    ("theft", "financial"),
    ("hacktivis", "hacktivism"),
    ("ideolog", "hacktivism"),
    ("protest", "hacktivism"),
    ("sabotage", "sabotage"),
    ("destruct", "sabotage"),
    ("wiper", "sabotage"),
    ("disruption", "disruption"),
    ("denial of service", "disruption"),
    ("ddos", "disruption"),
)


def coerce_motivation(raw: str | None) -> str | None:
    """Fold a free-text motivation onto the controlled vocabulary.

    Returns None for values that carry no signal ("unknown", "", prose that
    matches nothing) rather than storing noise the Motivation facet can't group.
    """
    if not raw:
        return None
    value = str(raw).strip().lower()
    if not value or value in ("unknown", "n/a", "none", "other"):
        return None
    if value in MOTIVATIONS:
        return value
    for hint, canonical in _MOTIVATION_HINTS:
        if hint in value:
            return canonical
    return None


def normalize_motivation(raw: str | None) -> str | None:
    """Write-path normalizer: fold onto the vocabulary, or clean what's left.

    `coerce_motivation` drops anything it can't place, which is right when a
    reference feed offers a value and wrong when an analyst types one — a
    motivation of "terrorism" is information, and silently discarding it on save
    would be a worse bug than the one this fixes. So an unrecognized value
    survives, lowercased: the facet still collapses `Financial Extortion` and
    `financial extortion` onto one row, and genuinely new phrasings stay
    visible for someone to fold deliberately.
    """
    if raw is None:
        return None
    value = str(raw).strip()
    if not value:
        return None
    coerced = coerce_motivation(value)
    if coerced:
        return coerced
    if value.lower() in ("unknown", "n/a", "none", "other"):
        return None
    return value.lower()[:100]


def normalize_country(raw: str | None) -> str | None:
    """Drop placeholder country names, keep real ones as written.

    Attribution is often genuinely unknown, but recording that as the string
    "Unknown" puts it in the `threat_actor.country` facet beside real countries
    — and it was stored both capitalised and not, so it appeared twice. An
    absent country already carries the meaning.
    """
    if raw is None:
        return None
    cleaned = str(raw).strip()
    if not cleaned or cleaned.casefold() in ("unknown", "n/a", "none", "unattributed"):
        return None
    return cleaned


def coerce_sectors(raw) -> list[str]:
    """Normalize a target-sector list onto canonical sector display labels.

    Accepts a string or a list of strings. Values that don't map to the
    controlled vocabulary are dropped, so a profile never shows a sector chip
    the sector facet can't filter on.
    """
    from app.intelligence.sectors import sector_label

    if not raw:
        return []
    values = [raw] if isinstance(raw, str) else list(raw)
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        slug = normalize_sector(value)
        if slug and slug not in seen:
            seen.add(slug)
            out.append(sector_label(slug))
    return out


async def resolve_country_name(db: AsyncSession, raw: str | None) -> str | None:
    """Turn an ISO alpha-2 code into the country name we store on profiles.

    Feeds report "CN"; the actor `country` column is overwhelmingly full names
    ("China"), and the workbench Country column groups on the stored string.
    Anything that isn't a bare two-letter code is passed through untouched.
    """
    from app.models.country import Country

    if not raw:
        return None
    value = str(raw).strip()
    if not value or value.lower() in ("unknown", "n/a", "none"):
        return None
    if len(value) != 2 or not value.isalpha():
        return value
    name = await db.scalar(select(Country.name).where(func.lower(Country.iso_code) == value.lower()))
    return name or value
