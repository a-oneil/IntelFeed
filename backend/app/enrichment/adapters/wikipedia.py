"""Wikipedia enrichment adapter — auto-populates entity Wikipedia content on discovery."""

from __future__ import annotations

import logging

from app.enrichment.base import EnrichmentAdapter, EnrichmentData
from app.enrichment.gateway import GatewayError
from app.enrichment.manifest import Column, Egress, Job, License, Policy, Quota
from app.enrichment.wikipedia_helper import extract_first_paragraph, fetch_wikipedia

logger = logging.getLogger(__name__)

_TYPES = ("threat_actor", "malware", "tool", "country", "vendor", "product", "ttp", "mitigation", "cve", "cwe")


def _article_columns(entity_type: str) -> tuple[Column, ...]:
    """The article's URL, text and image move together: a new URL replaces all
    three, so the old article's image never stays behind."""
    url = f"{entity_type}.wikipedia_url"
    return (
        Column("wikipedia_url", url, Policy.NEWER_WINS),
        Column("wikipedia_content", f"{entity_type}.wikipedia_content", Policy.NEWER_WINS, follows=url),
        Column("wikipedia_image_url", f"{entity_type}.wikipedia_image_url", Policy.NEWER_WINS, follows=url),
        # Human-curated prose, so it ranks ahead of the security catalogs;
        # a CVE's own record (NVD) is the exception.
        Column("first_paragraph", f"{entity_type}.description", Policy.RANK, rank=2 if entity_type == "cve" else 1),
    )


class WikipediaAdapter(EnrichmentAdapter):
    source_type = "wikipedia"
    display_name = "Wikipedia"
    applies_to = dict.fromkeys(_TYPES)
    # MediaWiki sets no fixed limit on reads but asks clients to send them one
    # at a time and back off when told (mediawiki.org/wiki/API:Etiquette). An
    # entity costs three to five requests. 20 a minute keeps the weekly sync
    # (about 1,100 requests in its hour) and a day's lookups inside the budget.
    quota = Quota(20, 60, daily_budget=2000)
    egress = Egress.LOW
    license = License("CC BY-SA 4.0", attribution="Wikipedia")
    default_trigger_mode = "auto"
    jobs = (
        Job(
            "wikipedia-bulk-sync",
            "app.workers.enrichment_tasks.run_wikipedia_bulk_sync",
            {"type": "crontab", "minute": "0", "hour": "4", "day_of_week": "3"},
            "Enrich entities missing Wikipedia content",
        ),
    )
    outputs = tuple(column for t in _TYPES for column in _article_columns(t))

    async def enrich(self, entity_type: str, entity_value: str) -> EnrichmentData:
        """Fetch Wikipedia content for an entity."""
        try:
            result = await fetch_wikipedia(entity_value, entity_type, transport=self.http_transport())
        except GatewayError:
            raise
        except Exception as e:
            logger.warning("Wikipedia fetch failed for %s/%s: %s", entity_type, entity_value, e)
            return EnrichmentData(
                raw_response={"error": str(e)},
                parsed_data={"found": False, "error": str(e)},
                ttl_hours=1,
            )

        if not result:
            return EnrichmentData(
                raw_response={"status": "not_found"},
                parsed_data={"found": False},
                ttl_hours=168,  # 7 days before retrying
            )

        # Topical guard (F11): don't hand back wrong-subject content (calendar
        # year, disambiguation, geography, unrelated bio) — a wrong description
        # anchors later AI resolution to the wrong identity.
        from app.intelligence.entity_resolution import enrichment_content_ok

        ok, reject_reason = enrichment_content_ok(entity_value, result["content"])
        if not ok:
            logger.warning(
                "Wikipedia content for %s/%s rejected by topical guard: %s", entity_type, entity_value, reject_reason
            )
            return EnrichmentData(
                raw_response={"status": "rejected", "reason": reject_reason, "url": result.get("url")},
                parsed_data={"found": False, "rejected": reject_reason},
                ttl_hours=720,  # don't refetch the same wrong article for a month
            )

        first_para = extract_first_paragraph(result["content"])

        return EnrichmentData(
            raw_response={
                "title": result["title"],
                "url": result["url"],
                "content": result["content"],
                "image_url": result.get("image_url"),
            },
            parsed_data={
                "found": True,
                "wikipedia_url": result["url"],
                "wikipedia_content": result["content"],
                "wikipedia_image_url": result.get("image_url"),
                "title": result["title"],
                "first_paragraph": first_para,
            },
            ttl_hours=720,  # 30 days — Wikipedia content is slow-changing
        )

    async def check_health(self) -> bool:
        """Verify Wikipedia API is reachable."""
        # fetch_wikipedia answers None for anything but a gateway refusal.
        return await fetch_wikipedia("Computer security", "ttp", transport=self.http_transport()) is not None
