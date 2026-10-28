"""Wikidata: structured facts for the vendors, products and countries that
already carry an English Wikipedia article.

The weekly job reads items with the action API's ``wbgetentities`` rather than
the SPARQL query service: one call turns up to ``TITLES_PER_CALL`` article
titles straight into their items (no title → QID step), the API is the cached,
stable read path Wikimedia asks bots to use, and it has none of the query
service's per-query timeouts. Item-valued claims (a country, a headquarters, a
developer) name other items, so their English labels and article titles come
from a second, batched call.

Each claim is read at its best rank: the ``preferred`` statements when there
are any, else the ``normal`` ones; ``deprecated`` statements never count. That
is what makes Microsoft's logo the current one rather than its 1980 one.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from urllib.parse import quote, unquote

import httpx
from sqlalchemy import exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.base import EnrichmentData, Source
from app.enrichment.gateway import SOURCE_REFUSALS, SourceGateway
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Quota

logger = logging.getLogger(__name__)

API_URL = "https://www.wikidata.org/w/api.php"

#: Titles per wbgetentities call. The API takes 50, but a country's item runs
#: to megabytes of claims (Germany: 2.7 MB), so smaller calls keep a batch's
#: response, and the worker's memory, bounded.
TITLES_PER_CALL = 20
#: Ids per label call (the API's limit).
IDS_PER_CALL = 50
#: Entities of each type looked up per run.
RUN_LIMIT = 200
TTL_HOURS = 720

_ENWIKI = re.compile(r"^https?://en\.(?:m\.)?wikipedia\.org/wiki/([^?#]+)")

#: Continents (P30) → the country region vocabulary the seed data uses.
CONTINENT_REGION = {
    "Q15": "Africa",
    "Q48": "Asia",
    "Q46": "Europe",
    "Q49": "North America",
    "Q18": "South America",
    "Q55643": "Oceania",
    "Q538": "Oceania",  # Insular Oceania
    "Q3960": "Oceania",  # Australian continent
    "Q51": "Antarctica",
}


class WikidataSource(Source):
    source_type = "wikidata"
    display_name = "Wikidata"
    applies_to = {"vendor": None, "product": None, "country": None}
    # Wikimedia publishes no hard read limit; its API etiquette asks for
    # requests one at a time, not in parallel, from a client that names itself
    # (https://www.mediawiki.org/wiki/API:Etiquette). A run makes about 40
    # calls, so 30 a minute is unhurried.
    quota = Quota(30, 60, daily_budget=500)
    # Sends the article titles of the entities it looks up.
    egress = Egress.LOW
    # https://www.wikidata.org/wiki/Wikidata:Licensing — structured data is CC0.
    license = License("CC0 1.0", attribution="Wikidata")
    jobs = (
        Job(
            "wikidata-sync",
            "app.workers.enrichment_tasks.run_wikidata_sync",
            {"type": "crontab", "minute": "30", "hour": "4", "day_of_week": "4"},
            "Fill vendor websites, product vendors and country regions from Wikidata",
        ),
    )
    outputs = (
        Column("website", "vendor.website"),
        Column("developer", "product.vendor_id", resolve="vendor"),
        Column("region", "country.region"),
        Column("iso_code", "country.iso_code"),
        Context("founded", "Founded", Display.FACT, entity_types=("vendor",)),
        Context("headquarters", "Headquarters", Display.FACT, entity_types=("vendor",)),
        Context("country", "Country", Display.FACT, entity_types=("vendor",)),
        Context("industry", "Industry", Display.CHIPS, entity_types=("vendor",)),
        Context("logo", "Logo", Display.LINK, entity_types=("vendor",)),
        Context("item", "Wikidata item", Display.LINK),
    )


# ── Reading claims ───────────────────────────────────────────────────


def best_values(claims: dict, prop: str) -> list:
    """The values of ``prop``'s best-ranked statements: preferred ones when
    there are any, else normal ones. Deprecated statements and statements with
    no value ("unknown", "none") are skipped."""
    statements = [s for s in claims.get(prop) or [] if s.get("mainsnak", {}).get("snaktype") == "value"]
    preferred = [s for s in statements if s.get("rank") == "preferred"]
    chosen = preferred or [s for s in statements if s.get("rank") == "normal"]
    return [s["mainsnak"].get("datavalue", {}).get("value") for s in chosen]


def _best(claims: dict, prop: str):
    values = best_values(claims, prop)
    return values[0] if values else None


def _item_id(value) -> str | None:
    return value.get("id") if isinstance(value, dict) else None


def _date(value) -> str | None:
    """A time value at its precision: 1975-04-04, 1975-04 or 1975."""
    if not isinstance(value, dict):
        return None
    match = re.match(r"^\+(\d{4})-(\d\d)-(\d\d)", value.get("time") or "")
    if not match:
        return None
    year, month, day = match.groups()
    precision = value.get("precision", 9)
    if precision >= 11:
        return f"{year}-{month}-{day}"
    return f"{year}-{month}" if precision == 10 else year


def _commons_file(value) -> dict | None:
    if not isinstance(value, str) or not value:
        return None
    return {"url": "https://commons.wikimedia.org/wiki/File:" + quote(value.replace(" ", "_")), "label": value}


def item_facts(entity_type: str, item: dict) -> tuple[dict, list[str]]:
    """What an item says about an entity of ``entity_type``, before item
    labels are known, and the item ids whose labels it needs."""
    claims = item.get("claims") or {}
    qid = item["id"]
    facts: dict = {"found": True, "qid": qid, "item": {"url": f"https://www.wikidata.org/wiki/{qid}", "label": qid}}
    if entity_type == "vendor":
        facts["website"] = _best(claims, "P856")
        facts["founded"] = _date(_best(claims, "P571"))
        facts["logo"] = _commons_file(_best(claims, "P154"))
        facts["country"] = _item_id(_best(claims, "P17"))
        facts["headquarters"] = _item_id(_best(claims, "P159"))
        facts["industry"] = [i for i in map(_item_id, best_values(claims, "P452")) if i]
        needs = [facts["country"], facts["headquarters"], *facts["industry"]]
    elif entity_type == "product":
        facts["developer"] = _item_id(_best(claims, "P178"))
        needs = [facts["developer"]]
    else:
        facts["region"] = next(
            (CONTINENT_REGION[i] for i in map(_item_id, best_values(claims, "P30")) if i in CONTINENT_REGION),
            None,
        )
        facts["iso_code"] = _best(claims, "P297")
        needs = []
    return facts, [n for n in needs if n]


def with_labels(facts: dict, labels: dict[str, dict]) -> dict:
    """``facts`` with item ids replaced by their labels; a developer becomes
    ``{"qid", "label", "enwiki"}`` for the vendor resolver. An item with no
    English label is dropped."""

    def label(qid):
        return (labels.get(qid) or {}).get("label")

    out = dict(facts)
    for key in ("country", "headquarters"):
        if key in out:
            out[key] = label(out[key])
    if "industry" in out:
        out["industry"] = [t for t in map(label, out["industry"]) if t]
    if out.get("developer"):
        known = labels.get(out["developer"]) or {}
        out["developer"] = {"qid": out["developer"], "label": known.get("label"), "enwiki": known.get("enwiki")}
    return out


def enwiki_title(url: str | None) -> str | None:
    """The article title in an English Wikipedia URL, as Wikidata's sitelinks
    spell it (spaces, first letter upper case)."""
    match = _ENWIKI.match(url or "")
    if not match:
        return None
    title = unquote(match.group(1)).replace("_", " ").strip()
    return title[:1].upper() + title[1:] if title else None


# ── Fetching ─────────────────────────────────────────────────────────


async def fetch_items(client, titles: list[str]) -> dict[str, dict]:
    """English article title → its item, for the titles Wikidata has."""
    resp = await client.get(
        API_URL,
        params={
            "action": "wbgetentities",
            "sites": "enwiki",
            "titles": "|".join(titles),
            "props": "claims|sitelinks",
            "sitefilter": "enwiki",
            "format": "json",
        },
    )
    resp.raise_for_status()
    items = {}
    for item in (resp.json().get("entities") or {}).values():
        title = ((item.get("sitelinks") or {}).get("enwiki") or {}).get("title")
        if title and "missing" not in item:
            items[title] = item
    return items


async def fetch_labels(client, ids: list[str]) -> dict[str, dict]:
    """Item id → ``{"label", "enwiki"}``, ``IDS_PER_CALL`` ids per request."""
    labels: dict[str, dict] = {}
    for start in range(0, len(ids), IDS_PER_CALL):
        resp = await client.get(
            API_URL,
            params={
                "action": "wbgetentities",
                "ids": "|".join(ids[start : start + IDS_PER_CALL]),
                "props": "labels|sitelinks",
                "languages": "en",
                "sitefilter": "enwiki",
                "format": "json",
            },
        )
        resp.raise_for_status()
        for qid, item in (resp.json().get("entities") or {}).items():
            labels[qid] = {
                "label": ((item.get("labels") or {}).get("en") or {}).get("value"),
                "enwiki": ((item.get("sitelinks") or {}).get("enwiki") or {}).get("title"),
            }
    return labels


# ── The job ──────────────────────────────────────────────────────────


def _models() -> dict:
    from app.models.country import Country
    from app.models.product import Product
    from app.models.vendor import Vendor

    return {"vendor": Vendor, "product": Product, "country": Country}


def _gap(entity_type: str, model):
    """SQL: the entity still lacks something Wikidata fills. Every vendor
    counts, since its profile shows Wikidata's facts."""
    if entity_type == "product":
        return model.vendor_id.is_(None)
    if entity_type == "country":
        return or_(model.region.is_(None), model.region == "", model.iso_code.is_(None), model.iso_code == "")
    return None


async def _candidates(db: AsyncSession, entity_type: str, model) -> list:
    """Entities with an English article, no unexpired Wikidata answer, and a gap."""
    from app.models.enrichment import EnrichmentResult

    fresh = exists().where(
        EnrichmentResult.entity_type == entity_type,
        EnrichmentResult.entity_id == model.id,
        EnrichmentResult.source_type == WikidataSource.source_type,
        EnrichmentResult.expires_at > datetime.now(UTC),
    )
    query = select(model).where(model.wikipedia_url.ilike("%://en.%wikipedia.org/wiki/%"), ~fresh)
    gap = _gap(entity_type, model)
    if gap is not None:
        query = query.where(gap)
    return list((await db.execute(query.order_by(model.name).limit(RUN_LIMIT))).scalars())


async def sync_wikidata(db: AsyncSession, gateway: SourceGateway) -> dict:
    """Look up the candidates' items in batches and apply what they say.

    A title Wikidata has no item for is stored as not found, so it isn't asked
    for again until the answer expires. Each batch commits; a refusal stops the
    run and keeps what it did."""
    from app.enrichment.pipeline import apply_catalog_result

    stats = {"looked_up": 0, "found": 0, "updated": 0, "failed": 0, "stopped": None}
    pending = []
    for entity_type, model in _models().items():
        for entity in await _candidates(db, entity_type, model):
            if title := enwiki_title(entity.wikipedia_url):
                pending.append((entity_type, entity, title))

    async with gateway.client(timeout=60.0) as client:
        for start in range(0, len(pending), TITLES_PER_CALL):
            batch = pending[start : start + TITLES_PER_CALL]
            try:
                items = await fetch_items(client, sorted({title for _, _, title in batch}))
                found = []
                needs: set[str] = set()
                for entity_type, entity, title in batch:
                    if item := items.get(title):
                        facts, ids = item_facts(entity_type, item)
                        found.append((entity_type, entity, facts))
                        needs.update(ids)
                    else:
                        found.append((entity_type, entity, None))
                labels = await fetch_labels(client, sorted(needs)) if needs else {}
            except SOURCE_REFUSALS as e:
                logger.warning("Wikidata sync stopping: %s", e)
                stats["stopped"] = e.status
                break
            except (httpx.HTTPError, ValueError) as e:
                # An error status, a dropped connection or a body that isn't
                # JSON costs this batch only; repeated ones open the breaker.
                logger.warning("Wikidata batch failed: %s", e)
                stats["failed"] += len(batch)
                continue

            for entity_type, entity, facts in found:
                stats["looked_up"] += 1
                if facts is None:
                    data = EnrichmentData(raw_response={}, parsed_data={"found": False}, ttl_hours=TTL_HOURS)
                else:
                    stats["found"] += 1
                    data = EnrichmentData(
                        raw_response={"qid": facts["qid"]},
                        parsed_data=with_labels(facts, labels),
                        ttl_hours=TTL_HOURS,
                    )
                if await apply_catalog_result(db, entity_type, entity.id, WikidataSource.source_type, data):
                    stats["updated"] += 1
            await db.commit()
    return stats
