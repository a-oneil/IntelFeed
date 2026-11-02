"""Propagate enrichment results to entity model fields: the field map that
applies each source's declared ``Column`` outputs."""

from __future__ import annotations

import functools
import logging
import uuid
from datetime import UTC, date, datetime
from decimal import Decimal
from math import inf
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.manifest import Column, Policy
from app.enrichment.relations import apply_relations
from app.models.entity_field_claim import EntityFieldClaim
from app.services.claim_provenance import record_claim, render_value

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
        from app.models.ransomware import RansomwareVictim
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
            "ransomware_victim": RansomwareVictim,
        }
    return _MODEL_MAP


#: Shodan tags that name dual-use infrastructure → the ledger's infra_tag.
#: The first listed wins: a VPN exit that also scans reads as a VPN.
_SHODAN_TAG_TO_INFRA = {"vpn": "vpn", "proxy": "proxy", "tor": "tor", "scanner": "scanner"}


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
    """A valid AS number: 32-bit ASNs reach 4,294,967,295 (``observables.asn``
    is bigint)."""
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**32 - 1 else None


def _motivation(value, entity) -> str | None:
    from app.intelligence.actor_attributes import coerce_motivation

    return coerce_motivation(value) if isinstance(value, str) else None


def _ids(value, entity) -> list[str]:
    """Other identifiers for the same record (OSV's GHSA-…, a distro's id),
    trimmed, without the entity's own id."""
    own = (getattr(entity, "cve_id", None) or "").casefold()
    ids = (v.strip() for v in value or [] if isinstance(v, str))
    return list(dict.fromkeys(i for i in ids if i and i.casefold() != own))


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
    "ids": _ids,
    "motivation": _motivation,
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


def _claim_ref(src: str, column: Column) -> str:
    """The ``source_ref`` a column output's claims carry: the source, or the
    part of its answer the source's ``claim_refs`` names for the output's key
    (``cvelist:cna``), so the profile can tell a CNA's score from CISA's."""
    from app.enrichment.registry import SOURCE_REGISTRY

    return getattr(SOURCE_REGISTRY.get(src), "claim_refs", {}).get(column.key, src)


@functools.cache
def _source_ranks() -> dict[str, dict[str, int]]:
    """target → {source_type: the source's best rank for it}, for RANK outputs."""
    from app.enrichment.registry import SOURCE_REGISTRY

    ranks: dict[str, dict[str, int]] = {}
    for src, cls in SOURCE_REGISTRY.items():
        for column in cls.columns():
            if column.policy == Policy.RANK and not column.follows:
                held = ranks.setdefault(column.target, {})
                held[src] = min(held.get(src, column.rank or 0), column.rank or 0)
    return ranks


def _equal(current, new) -> bool:
    """Whether a column already holds ``new``: numbers by value (the column's
    Decimal 9.8 is a source's float 9.8)."""
    numeric = (int, float, Decimal)
    if (
        isinstance(current, numeric)
        and isinstance(new, numeric)
        and not isinstance(current, bool)
        and not isinstance(new, bool)
    ):
        return float(current) == float(new)
    return current == new


def _same(text: str, value) -> bool:
    """Whether a claim's rendered value names ``value``: numbers by value
    (a claim's "10" is the column's Decimal 10.0), text case-insensitively."""
    if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        try:
            return float(text) == float(value)
        except ValueError:
            return False
    return text.casefold() == render_value(value).casefold()


#: Who holds a ranked column's value. ``None``: nobody we may replace (an
#: analyst asserted it, or nothing did). Otherwise (rank, sources): the best
#: rank among the enrichment sources that claim it and those sources; an
#: AI or reference-feed value holds at no rank, so any source replaces it.
_Holder = tuple[float, frozenset[str]] | None


async def _holders(db: AsyncSession, entity_type: str, entity_id: uuid.UUID, current: dict) -> dict[str, _Holder]:
    """The holder of each ranked path's current (non-blank) value, from the
    claims recorded for it."""
    if not current:
        return {}
    rows = (
        await db.execute(
            select(
                EntityFieldClaim.field,
                EntityFieldClaim.source_kind,
                EntityFieldClaim.source_ref,
                EntityFieldClaim.value_text,
            ).where(
                EntityFieldClaim.entity_type == entity_type,
                EntityFieldClaim.entity_id == entity_id,
                EntityFieldClaim.field.in_(list(current)),
            )
        )
    ).all()
    ranks = _source_ranks()
    holders: dict[str, _Holder] = {}
    for path, (target, value) in current.items():
        matching = [(kind, ref) for field, kind, ref, text in rows if field == path and _same(text, value)]
        if not matching or any(kind == "analyst" for kind, _ in matching):
            holders[path] = None
            continue
        # A claim's ref is its source, or "<source>:<part>" for one part of
        # a source's answer (cvelist's CNA and CISA-ADP scores).
        holding = {ref.split(":", 1)[0] for kind, ref in matching if kind == "enrichment" and ref}
        sources = {src: ranks.get(target, {}).get(src, inf) for src in holding}
        holders[path] = (min(sources.values(), default=inf), frozenset(sources))
    return holders


async def apply_enrichment_results_to_entity(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    results: list[dict],
) -> bool:
    """Write enrichment results onto the entity's columns.

    Each source's manifest declares its ``Column`` outputs; this applies the
    ones for this entity type by their ``Policy``: blank columns are filled,
    list columns gain the items they lack, newer-wins outputs replace what is
    there, and ranked outputs follow the rank of whoever holds the value now
    (see ``_rank``). Columns that follow a target are written with it. An
    output that resolves its value (a developer → an existing vendor's id)
    writes only what the lookup finds. Every value a source gives is recorded
    as a claim naming the source, the ones that lost on rank too, so the
    profile can show each source's answer. A JSON column a source writes into
    (``Observable.reputation``) is stamped ``enriched_at`` whenever one of its
    sources returned a result. Each source's ``Relation`` outputs are applied
    too (``app/enrichment/relations.py``).

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

    # (path, value, source) for every claim, recorded once at the end — a
    # failed audit write must not cost the fill.
    claimed: list[tuple[str, object, str]] = []
    changed = False

    def write(src: str, column: Column, value) -> None:
        nonlocal changed
        writes = [(column.path, value)] + [
            (f.path, _lookup(by_source[src], f.key)) for f in followers.get((src, column.target), ())
        ]
        for path, new in writes:
            if not _equal(_get(entity, path), new):
                _set(entity, path, new)
                changed = True
            claimed.append((path, new, _claim_ref(src, column)))

    def lost(src: str, column: Column, value) -> None:
        """A value that didn't win is still that source's claim."""
        ref = _claim_ref(src, column)
        claimed.append((column.path, value, ref))
        for f in followers.get((src, column.target), ()):
            claimed.append((f.path, _lookup(by_source[src], f.key), ref))

    # Who holds each ranked column that has a value now.
    ranked_now = {}
    for target, outputs in targets.items():
        path = outputs[0][1].path
        if outputs[0][1].policy == Policy.RANK and not _blank(current := _get(entity, path)):
            ranked_now[path] = (target, current)
    holders = await _holders(db, entity_type, entity_id, ranked_now)

    for target, outputs in targets.items():
        outputs.sort(key=lambda o: o[1].rank or 0)
        path, policy = outputs[0][1].path, outputs[0][1].policy
        current = _get(entity, path)

        if policy == Policy.FILL_BLANK:
            if not _blank(current):
                continue
            for src, column in outputs:
                value = await _value(db, column, by_source[src], entity)
                if value is not None:
                    write(src, column, value)
                    break

        elif policy == Policy.RANK:
            await _rank(db, entity, outputs, by_source, current, holders.get(path), write, lost)

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
                    claimed.append((path, added, _claim_ref(src, column)))
            if len(held) > len(current or []):
                _set(entity, path, held)
                changed = True

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

    if changed or stamped:
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
    return changed or bool(stamped) or related


async def _rank(db, entity, outputs, by_source, current, holder: _Holder, write, lost) -> None:
    """A ranked column. Blank: the best-ranked value fills it. Held: a source
    that outranks the holder replaces the value, and the holder itself may
    update it, or clear it when its answer no longer carries one (and no other
    source claims it). A value an analyst asserted, or that nothing claims,
    stays. Every other value given is recorded as a losing claim."""
    candidates = []
    for src, column in outputs:
        value = await _value(db, column, by_source[src], entity)
        if value is not None:
            candidates.append((src, column, value))

    winner = None
    if _blank(current):
        winner = candidates[0] if candidates else None
    elif holder is not None:
        hold_rank, hold_sources = holder
        ranks = _source_ranks().get(outputs[0][1].target, {})
        for candidate in candidates:
            src, column, _ = candidate
            own = src in hold_sources and ranks.get(src, inf) <= hold_rank
            if own or (column.rank or 0) < hold_rank:
                winner = candidate
                break
        if winner is None and len(hold_sources) == 1:
            (src,) = hold_sources
            column = next((c for s, c in outputs if s == src), None)
            # A "not found" answer withdraws only from an output that clears:
            # for those sources, not knowing the entity is itself the answer.
            answered = column is not None and (by_source[src].get("found", True) is not False or column.clears)
            if answered and not any(c[0] == src for c in candidates):
                # The holder's own answer no longer carries a value: it
                # withdraws it, and no other source claims what is there.
                write(src, column, None)

    for candidate in candidates:
        if candidate is winner:
            write(*candidate)
        else:
            lost(*candidate)
