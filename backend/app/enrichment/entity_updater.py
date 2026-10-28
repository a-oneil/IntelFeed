"""Propagate enrichment results to entity model fields: the field map that
applies each source's declared ``Column`` outputs."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, date, datetime
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.manifest import Column, Policy
from app.enrichment.relations import apply_relations
from app.services.claim_provenance import record_claim

logger = logging.getLogger(__name__)

# Lazy model imports to avoid circular dependencies
_MODEL_MAP: dict | None = None


def _get_model_map() -> dict:
    global _MODEL_MAP
    if _MODEL_MAP is None:
        from app.models.country import Country
        from app.models.cve import CVE
        from app.models.cwe import CWE
        from app.models.malware_family import MalwareFamily
        from app.models.mitigation import Mitigation
        from app.models.observable import Observable
        from app.models.product import Product
        from app.models.threat_actor import ThreatActor
        from app.models.tool import Tool
        from app.models.ttp import TTP
        from app.models.vendor import Vendor

        _MODEL_MAP = {
            "observable": Observable,
            "threat_actor": ThreatActor,
            "malware": MalwareFamily,
            "cve": CVE,
            "ttp": TTP,
            "country": Country,
            "tool": Tool,
            "vendor": Vendor,
            "product": Product,
            "mitigation": Mitigation,
            "cwe": CWE,
        }
    return _MODEL_MAP


#: Shodan tags that name dual-use infrastructure → the ledger's infra_tag.
_SHODAN_TAG_TO_INFRA = {"vpn": "vpn", "proxy": "proxy", "tor": "tor"}


def _aliases(value, entity) -> list[str]:
    # These lists feed the autolinker vocabulary, and an unfiltered
    # dictionary-word alias is how the false-positive link epidemic started.
    from app.intelligence.autolinker import filter_aliases

    return filter_aliases([a for a in value or [] if isinstance(a, str)], getattr(entity, "name", "") or "")


def _github_url(value, entity) -> str | None:
    """The first github.com link in a reference list (dicts or plain URLs)."""
    for ref in value or []:
        url = (ref.get("url") if isinstance(ref, dict) else ref) or ""
        if "github.com/" in url:
            return url
    return None


def _infra_tag(value, entity) -> str | None:
    tags = [t.strip() for t in str(value or "").lower().split(",")]
    return next((infra for tag, infra in _SHODAN_TAG_TO_INFRA.items() if tag in tags), None)


def _benign_service(value, entity) -> str | None:
    return "benign_service" if value is True else None


def _date(value, entity) -> date | None:
    try:
        return date.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _timestamp(value, entity) -> datetime | None:
    """An ISO 8601 date or datetime (JSON carries them as text), in UTC when it names no zone."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _country_code(value, entity) -> str | None:
    code = str(value or "").strip().upper()
    return code if len(code) == 2 and code.isalpha() else None


def _asn(value, entity) -> int | None:
    """An AS number ``observables.asn`` (int4) can hold. 32-bit ASNs reach
    4,294,967,295; one past int4 stays in the source's answer only."""
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**31 - 1 else None


#: ``Column.filter`` names → transforms of (parsed value, entity) into the value written.
FILTERS = {
    "aliases": _aliases,
    "github_url": _github_url,
    "infra_tag": _infra_tag,
    "benign_service": _benign_service,
    "date": _date,
    "timestamp": _timestamp,
    "country_code": _country_code,
    "asn": _asn,
}


async def _existing_vendor(db: AsyncSession, value) -> uuid.UUID | None:
    """The vendor a source's ``{"label", "enwiki"}`` names, if IntelFeed has it:
    the one vendor whose Wikipedia article is that sitelink, else a vendor whose
    name or alias is the label. Never creates one."""
    from app.intelligence.entity_dedup import find_entity_by_name_or_alias
    from app.models.vendor import Vendor

    if not isinstance(value, dict):
        return None
    title = value.get("enwiki")
    if isinstance(title, str) and title:
        path = title.replace(" ", "_")
        urls = {f"https://en.wikipedia.org/wiki/{p}" for p in (path, quote(path, safe=";@$!*(),/~:"))}
        ids = (await db.execute(select(Vendor.id).where(Vendor.wikipedia_url.in_(urls)).limit(2))).scalars().all()
        if len(ids) == 1:
            return ids[0]
    label = value.get("label")
    vendor = await find_entity_by_name_or_alias(db, Vendor, label) if isinstance(label, str) else None
    return vendor.id if vendor else None


async def existing_country(db: AsyncSession, value):
    """The country a source names by ISO code, name or alias, if IntelFeed has
    it; None for a placeholder ("[Unknown]", "Unknown"). Never creates one."""
    from sqlalchemy import func

    from app.intelligence.actor_attributes import normalize_country
    from app.intelligence.entity_dedup import find_entity_by_name_or_alias
    from app.models.country import Country

    name = normalize_country(value) if isinstance(value, str) else None
    if not name:
        return None
    if len(name) == 2 and name.isalpha():
        return (await db.execute(select(Country).where(func.lower(Country.iso_code) == name.lower()))).scalar()
    return await find_entity_by_name_or_alias(db, Country, name)


async def _country_name(db: AsyncSession, value) -> str | None:
    country = await existing_country(db, value)
    return country.name if country else None


async def _country_id(db: AsyncSession, value) -> uuid.UUID | None:
    country = await existing_country(db, value)
    return country.id if country else None


#: ``Column.resolve`` names → database lookups of (session, value) into the
#: value written, or None when there is no match.
RESOLVERS = {
    "vendor": _existing_vendor,
    "country": _country_name,
    "country_id": _country_id,
}

_EMPTY = (None, "", [])


def _lookup(data: dict, key: str):
    for part in key.split("."):
        data = data.get(part) if isinstance(data, dict) else None
    return data


async def _value(db: AsyncSession, column: Column, data: dict, entity):
    """The value a column output would write, or None when it has none."""
    value = _lookup(data, column.key)
    if column.filter:
        value = FILTERS[column.filter](value, entity)
    elif column.policy in (Policy.FILL_BLANK, Policy.RANK):
        if isinstance(value, str):
            value = value.strip()
        elif isinstance(value, list):
            value = [v for v in value if isinstance(v, str)]
    if column.resolve and value not in _EMPTY:
        value = await RESOLVERS[column.resolve](db, value)
    return None if value in _EMPTY else value


def _get(entity, path: str):
    column, _, key = path.partition(".")
    current = getattr(entity, column)
    return (current or {}).get(key) if key else current


def _set(entity, path: str, value) -> None:
    column, _, key = path.partition(".")
    if key:
        # A new dict, so SQLAlchemy sees the JSON column change.
        value = {**(getattr(entity, column) or {}), key: value}
    setattr(entity, column, value)


def _blank(value) -> bool:
    return value in _EMPTY or (isinstance(value, str) and not value.strip())


async def apply_enrichment_results_to_entity(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    results: list[dict],
) -> bool:
    """Write enrichment results onto the entity's columns.

    Each source's manifest declares its ``Column`` outputs; this applies the
    ones for this entity type by their ``Policy``: blank columns are filled,
    ranked outputs fill from the best-ranked source that has a value, list
    columns gain the items they lack, and newer-wins outputs replace what is
    there; columns that follow a target are written with it. An output that
    resolves its value (a developer → an existing vendor's id) writes only what
    the lookup finds. Every write records a claim naming its source. A JSON
    column a source writes into (``Observable.reputation``) is stamped
    ``enriched_at`` whenever one of its sources returned a result. Each
    source's ``Relation`` outputs are applied too (``app/enrichment/relations.py``).

    Each enrichment-result entry should look like:
      {"source_type": "...", "status": "success"|"cached", "parsed_data": {...}}

    Returns True if the entity or one of its connections was changed.
    """
    from app.enrichment.registry import SOURCE_REGISTRY

    model_cls = _get_model_map().get(entity_type)
    if not model_cls:
        return False

    entity = (await db.execute(select(model_cls).where(model_cls.id == entity_id))).scalar_one_or_none()
    if not entity:
        return False

    # Index results by source. Cached results carry parsed_data too, so they're
    # equivalent to fresh successes for write-back.
    by_source: dict[str, dict] = {}
    for r in results:
        if r.get("status") not in ("success", "cached"):
            continue
        src = r.get("source_type")
        data = r.get("parsed_data") or {}
        if not src or not isinstance(data, dict):
            continue
        # First write wins — pipeline returns sources in DB order; if the same
        # source somehow appears twice, the first entry is the freshest.
        by_source.setdefault(src, data)

    # target → its (source, column) outputs; columns that follow a NEWER_WINS
    # target are kept apart, under (source, the target they follow).
    targets: dict[str, list[tuple[str, Column]]] = {}
    followers: dict[tuple[str, str], list[Column]] = {}
    stamped: set[str] = set()
    for src, data in by_source.items():
        source_cls = SOURCE_REGISTRY.get(src)
        for column in source_cls.columns() if source_cls else ():
            if column.entity_type != entity_type:
                continue
            if column.follows:
                followers.setdefault((src, column.follows), []).append(column)
            else:
                targets.setdefault(column.target, []).append((src, column))
            if "." in column.path and data:
                stamped.add(column.path.split(".", 1)[0])

    # (path, value, source) for every write, recorded once at the end — a
    # failed audit write must not cost the fill.
    claimed: list[tuple[str, object, str]] = []

    def write(src: str, column: Column, value) -> None:
        _set(entity, column.path, value)
        claimed.append((column.path, value, src))
        for follower in followers.get((src, column.target), ()):
            follower_value = _lookup(by_source[src], follower.key)
            _set(entity, follower.path, follower_value)
            claimed.append((follower.path, follower_value, src))

    for outputs in targets.values():
        outputs.sort(key=lambda o: o[1].rank or 0)
        path, policy = outputs[0][1].path, outputs[0][1].policy
        current = _get(entity, path)

        if policy in (Policy.FILL_BLANK, Policy.RANK):
            if not _blank(current):
                continue
            for src, column in outputs:
                value = await _value(db, column, by_source[src], entity)
                if value is not None:
                    write(src, column, value)
                    break

        elif policy == Policy.UNION:
            held = list(current or [])
            seen = {a.casefold() for a in held} | {(getattr(entity, "name", "") or "").casefold()}
            for src, column in outputs:
                added = [
                    a
                    for a in await _value(db, column, by_source[src], entity) or []
                    if a.casefold() not in seen and not seen.add(a.casefold())
                ]
                if added:
                    held += added
                    claimed.append((path, added, src))
            if len(held) > len(current or []):
                _set(entity, path, held)

        elif policy == Policy.NEWER_WINS:
            for src, column in outputs:
                value = await _value(db, column, by_source[src], entity)
                if (value is None and not column.clears) or value == _get(entity, path):
                    continue
                write(src, column, value)

    for column in stamped:
        _set(entity, f"{column}.enriched_at", datetime.now(UTC).isoformat())

    related = False
    for src, data in by_source.items():
        related |= await apply_relations(db, entity_type, entity_id, src, data)

    if not (claimed or stamped):
        return related
    db.add(entity)
    for path, value, src in claimed:
        await record_claim(
            db,
            entity_type=entity_type,
            entity_id=entity_id,
            field=path,
            value=value,
            source_kind="enrichment",
            source_ref=src,
        )
    return True
