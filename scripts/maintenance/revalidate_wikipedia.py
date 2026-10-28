"""Re-validate stored Wikipedia content against the title-match guardrail.

Clears wikipedia_url/wikipedia_content/wikipedia_image_url (and a description
that was auto-filled from the bad article) on entities whose stored article
title doesn't match the entity name/aliases — so they can re-enrich correctly.
Also drops the cached wikipedia EnrichmentResult rows for cleared entities.

Idempotent. Run inside the API container:
    docker compose -f docker-compose.dev.yml exec api python scripts/maintenance/revalidate_wikipedia.py [--dry-run]
"""

import asyncio
import sys
from urllib.parse import unquote

sys.path.insert(0, "/app")

from sqlalchemy import delete, select

from app.database import async_session
from app.enrichment.gateway import USER_AGENT
from app.enrichment.wikipedia_helper import (
    extract_first_paragraph,
    get_search_queries,
    title_matches_entity,
)
from app.models.country import Country
from app.models.cve import CVE
from app.models.enrichment import EnrichmentResult
from app.models.malware_family import MalwareFamily
from app.models.mitigation import Mitigation
from app.models.product import Product
from app.models.threat_actor import ThreatActor
from app.models.tool import Tool
from app.models.ttp import TTP
from app.models.vendor import Vendor

# (entity_type, model, name attributes checked in order)
ENTITY_MODELS = [
    ("threat_actor", ThreatActor, ("name",)),
    ("malware", MalwareFamily, ("name",)),
    ("cve", CVE, ("cve_id",)),
    ("ttp", TTP, ("technique_id", "name")),
    ("country", Country, ("name",)),
    ("vendor", Vendor, ("name",)),
    ("product", Product, ("name",)),
    ("mitigation", Mitigation, ("name",)),
    ("tool", Tool, ("name",)),
]


def title_from_url(url: str) -> str | None:
    """Extract the article title from a Wikipedia URL."""
    if "/wiki/" not in url:
        return None
    return unquote(url.rsplit("/wiki/", 1)[-1]).replace("_", " ").strip() or None


def redirect_confirms(name: str, entity_type: str, stored_title: str) -> bool | None:
    """Live check: does a direct lookup of the entity name redirect to the stored title?

    Wikipedia redirects are trustworthy (e.g. "CVE-2021-44228" -> "Log4Shell"), unlike
    the old auto-suggest search that caused mismatches like "Iran" -> "ISBN".
    Returns True/False, or None if Wikipedia was unreachable (caller should keep).
    """
    try:
        import wikipediaapi

        wiki = wikipediaapi.Wikipedia(user_agent=USER_AGENT, language="en")
        for q in get_search_queries(name, entity_type):
            page = wiki.page(q)
            if page.exists() and title_matches_entity(stored_title, page.title):
                return True
        return False
    except Exception as e:
        print(f"  WARN: could not verify {name!r} against Wikipedia ({e}) — keeping")
        return None


async def main(dry_run: bool) -> None:
    total_checked = 0
    total_cleared = 0

    async with async_session() as db:
        for entity_type, model, name_attrs in ENTITY_MODELS:
            result = await db.execute(select(model).where(model.wikipedia_url.isnot(None)))
            entities = result.scalars().all()

            cleared = 0
            for entity in entities:
                total_checked += 1
                name = next((getattr(entity, a, None) for a in name_attrs if getattr(entity, a, None)), None)
                if not name:
                    continue

                title = title_from_url(entity.wikipedia_url or "")
                if not title:
                    continue

                aliases = list(getattr(entity, "aliases", None) or [])
                # Secondary name attrs (e.g. TTP name) count as aliases too
                aliases += [getattr(entity, a, None) for a in name_attrs[1:] if getattr(entity, a, None)]
                expected = get_search_queries(name, entity_type)

                if title_matches_entity(title, name, aliases, extra_titles=expected):
                    continue

                # Title doesn't match — but a direct lookup redirecting to it is legit
                # (e.g. CVE-2021-44228 -> Log4Shell). Only clear confirmed mismatches.
                if redirect_confirms(name, entity_type, title) is not False:
                    continue

                cleared += 1
                total_cleared += 1
                print(f"  MISMATCH {entity_type} {name!r}: article {title!r} ({entity.wikipedia_url})")
                if dry_run:
                    continue

                # Clear a description that was auto-filled from the bad article
                bad_first_para = extract_first_paragraph(entity.wikipedia_content or "")
                if (
                    bad_first_para
                    and hasattr(entity, "description")
                    and (entity.description or "").strip() == bad_first_para.strip()
                ):
                    entity.description = None

                entity.wikipedia_url = None
                entity.wikipedia_content = None
                entity.wikipedia_image_url = None
                db.add(entity)

                await db.execute(
                    delete(EnrichmentResult).where(
                        EnrichmentResult.entity_type == entity_type,
                        EnrichmentResult.entity_id == entity.id,
                        EnrichmentResult.source_type == "wikipedia",
                    )
                )

            print(f"{entity_type}: {len(entities)} checked, {cleared} mismatched")
            if not dry_run:
                await db.commit()

    action = "would clear" if dry_run else "cleared"
    print(f"Done. Checked {total_checked} entities, {action} {total_cleared}.")


if __name__ == "__main__":
    asyncio.run(main(dry_run="--dry-run" in sys.argv))
