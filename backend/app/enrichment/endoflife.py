"""endoflife.date: the support lifecycle of the products IntelFeed tracks.

The daily job reads endoflife.date's product list, matches IntelFeed products
to it exactly, fetches each matched product's releases and writes:

- ``support_status``: the product as a whole, from its releases' flags:
  ``maintained`` when a release still gets regular updates (maintained, its
  active support and its security support not over), ``security_only`` when
  maintained releases only get security fixes (active support over, or past
  end of life in extended support), ``eol`` when no release is maintained,
  ``unknown`` when endoflife.date lists no releases.
- ``next_eol``: the soonest date a maintained release stops getting security
  fixes (its end of life, or the end of extended support for one already past
  it), counting only dates after today; empty when there is none.
- a releases table and the endoflife.date link on the profile.

Matching is exact, never fuzzy: an IntelFeed product's name, or its vendor's
name followed by it, equals an endoflife.date product's name, label or alias
once case and punctuation are dropped ("Windows Server" = ``windows-server``,
"Microsoft Exchange" = "Microsoft Exchange"). A product whose forms point at
two endoflife.date products gets nothing. ``OVERRIDES`` covers known
mismatches. The product's aliases are not used: extracted aliases are too
noisy ("XDR", "AWS Lambda") to name a lifecycle.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, date, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.enrichment.base import EnrichmentData, Source
from app.enrichment.gateway import SOURCE_REFUSALS, SourceGateway
from app.enrichment.manifest import Column, Context, Display, Egress, Job, License, Policy, Quota

logger = logging.getLogger(__name__)

API_URL = "https://endoflife.date/api/v1/products"

#: IntelFeed product name (case-insensitive) → endoflife.date product, where
#: the names differ.
OVERRIDES = {
    "suse linux enterprise": "sles",
    "splunk enterprise": "splunk",
}

#: Releases shown on the profile, newest first.
TABLE_RELEASES = 20
TTL_HOURS = 48


class EndOfLifeSource(Source):
    source_type = "endoflife"
    display_name = "endoflife.date"
    applies_to = {"product": None}
    # endoflife.date publishes no rate limit (https://endoflife.date/docs/api/v1/);
    # one request a second is polite, and a run makes one per matched product.
    quota = Quota(1, 1, daily_budget=1000)
    egress = Egress.NONE
    # The data is MIT-licensed with attribution:
    # https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE
    license = License("MIT", attribution="endoflife.date")
    jobs = (
        Job(
            "endoflife-sync",
            "app.workers.enrichment_tasks.run_endoflife_sync",
            {"type": "crontab", "minute": "15", "hour": "5"},
            "Refresh product support lifecycles from endoflife.date",
        ),
    )
    outputs = (
        Column("support_status", "product.support_status", Policy.NEWER_WINS),
        Column("next_eol", "product.next_eol", Policy.NEWER_WINS, filter="date", clears=True),
        Context(
            "releases",
            "Releases",
            Display.TABLE,
            item={
                "Release": "release",
                "Released": "released",
                "Active until": "active_until",
                "Security until": "security_until",
                "Status": "status",
            },
        ),
        Context("link", "endoflife.date", Display.LINK),
    )


# ── Matching ─────────────────────────────────────────────────────────


def _form(text: str) -> str:
    """Case and punctuation dropped: "Windows Server", "windows-server" and
    "windowsserver" are one form."""
    return re.sub(r"[^0-9a-z]", "", text.casefold())


def product_index(products: list[dict]) -> dict[str, set[str]]:
    """Each name, label and alias form → the endoflife.date products with it."""
    index: dict[str, set[str]] = {}
    for product in products:
        name = product.get("name")
        if not name:
            continue
        for text in (name, product.get("label"), *(product.get("aliases") or [])):
            if isinstance(text, str) and _form(text):
                index.setdefault(_form(text), set()).add(name)
    return index


def match_product(name: str, vendor: str | None, index: dict[str, set[str]], known: set[str]) -> str | None:
    """The endoflife.date product an IntelFeed product is, or None."""
    override = OVERRIDES.get(name.casefold())
    if override:
        return override if override in known else None
    forms = [_form(name)] + ([_form(f"{vendor} {name}")] if vendor else [])
    hits = set().union(*(index.get(f, set()) for f in forms if f))
    return hits.pop() if len(hits) == 1 else None


# ── Lifecycle ────────────────────────────────────────────────────────


def release_status(release: dict) -> str:
    if not release.get("isMaintained"):
        return "eol"
    if release.get("isEoas") is True or release.get("isEol") is True:
        return "security_only"
    return "maintained"


def _security_end(release: dict) -> str | None:
    """When a maintained release stops getting security fixes."""
    end = release.get("eoesFrom") if release.get("isEol") is True else release.get("eolFrom")
    return end if isinstance(end, str) else None


def lifecycle(releases: list[dict], today: date) -> tuple[str, str | None]:
    """``(support_status, next_eol)`` for a product's releases (module docstring)."""
    if not releases:
        return "unknown", None
    statuses = {release_status(r) for r in releases}
    status = next(s for s in ("maintained", "security_only", "eol") if s in statuses)
    upcoming = sorted(
        end for r in releases if release_status(r) != "eol" and (end := _security_end(r)) and end > today.isoformat()
    )
    return status, upcoming[0] if upcoming else None


def parse_product(result: dict, today: date) -> dict:
    """The parsed_data for one endoflife.date product."""
    releases = [r for r in result.get("releases") or [] if isinstance(r, dict)]
    status, next_eol = lifecycle(releases, today)
    links = result.get("links") or {}
    return {
        "found": True,
        "product": result.get("name"),
        "support_status": status,
        "next_eol": next_eol,
        "releases": [
            {
                "release": r.get("label") or r.get("name"),
                "released": r.get("releaseDate"),
                "active_until": r.get("eoasFrom"),
                "security_until": r.get("eolFrom"),
                "status": release_status(r).replace("_", " "),
            }
            for r in releases[:TABLE_RELEASES]
        ],
        "link": {"url": links.get("html"), "label": f"endoflife.date/{result.get('name')}"},
    }


# ── The job ──────────────────────────────────────────────────────────


async def sync_endoflife(db: AsyncSession, gateway: SourceGateway) -> dict:
    """Match products, fetch each matched endoflife.date product once, apply.
    A refusal stops the run and keeps what it did; a product that fails to
    load is skipped."""
    from app.enrichment.pipeline import apply_catalog_result
    from app.models.product import Product

    stats = {"catalog": 0, "matched": 0, "updated": 0, "failed": 0, "stopped": None}
    today = datetime.now(UTC).date()
    async with gateway.client(timeout=30.0) as client:
        try:
            resp = await client.get(API_URL)
            resp.raise_for_status()
        except SOURCE_REFUSALS as e:
            logger.warning("endoflife.date sync skipped: %s", e)
            return {**stats, "stopped": e.status}
        catalog = [p for p in resp.json().get("result") or [] if isinstance(p, dict)]
        stats["catalog"] = len(catalog)
        index = product_index(catalog)
        known = {p["name"] for p in catalog if p.get("name")}

        matches: dict[str, list] = {}
        for product in (await db.execute(select(Product).options(selectinload(Product.vendor)))).scalars():
            slug = match_product(product.name, product.vendor.name if product.vendor else None, index, known)
            if slug:
                matches.setdefault(slug, []).append(product)
        stats["matched"] = sum(len(p) for p in matches.values())

        for slug, products in sorted(matches.items()):
            try:
                resp = await client.get(f"{API_URL}/{slug}")
                resp.raise_for_status()
                result = resp.json()["result"]
            except SOURCE_REFUSALS as e:
                logger.warning("endoflife.date sync stopping: %s", e)
                stats["stopped"] = e.status
                break
            except (httpx.HTTPError, ValueError, KeyError) as e:
                logger.warning("endoflife.date %s failed: %s", slug, e)
                stats["failed"] += len(products)
                continue
            data = EnrichmentData(raw_response=result, parsed_data=parse_product(result, today), ttl_hours=TTL_HOURS)
            for product in products:
                if await apply_catalog_result(db, "product", product.id, EndOfLifeSource.source_type, data):
                    stats["updated"] += 1
            await db.commit()
    return stats
