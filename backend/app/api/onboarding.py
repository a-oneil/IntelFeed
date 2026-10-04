"""Is this instance actually usable yet?

The onboarding wizard used to onboard people into *configuring* IntelFeed
without ever checking the configuration took. The two failure modes it could
not see are the ones that bite hardest on a fresh install:

* **Nothing seeded.** The autolinker matches entry text against a vocabulary of
  countries, techniques, weaknesses, vendors and products. With none of it
  seeded, articles ingest perfectly and link to absolutely nothing — and the
  only symptom is empty entity pages, which reads as "this product is broken"
  rather than "run the seeder".
* **Nothing polled.** You can finish a wizard having added forty feeds and
  still be looking at an empty reader, with no way to tell whether that is
  normal latency or a dead configuration.

So this endpoint answers both, cheaply, as counts the wizard can show and
re-poll. It is read-only and takes no arguments.
"""

import os
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database import get_db
from app.models.ai_provider import AIProvider
from app.models.country import Country
from app.models.cve import EntryCVE
from app.models.cwe import CWE, EntryCWE
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.product import Product
from app.models.ttp import TTP, EntryTTP
from app.models.user import User
from app.models.vendor import Vendor

router = APIRouter()

# Each seeder, the table that proves it ran, and roughly what the catalog holds
# when it has. The threshold is a floor, not the real count: it only has to be
# high enough that a half-finished or hand-inserted row doesn't read as seeded.
REFERENCE_CHECKS: tuple[tuple[str, str, type, int], ...] = (
    ("countries", "Countries & demonyms", Country, 150),
    ("attack", "MITRE ATT&CK catalog", TTP, 500),
    ("cwe", "CWE catalog", CWE, 500),
    ("vendors", "Vendors", Vendor, 50),
    ("products", "Products", Product, 200),
)

SEED_SCRIPT = "python scripts/seed/seed_all.py"


def _seed_command() -> str:
    """The whole line to paste, compose file included.

    The seeders run inside the api container, so the command depends on which
    compose file this instance runs under — which the browser has no way to
    know. The UI used to wrap the script in a hardcoded `-f
    docker-compose.prod.yml`, wrong on every dev install, so resolve it here
    off the same ENV var config.py reads.
    """
    env = os.getenv("ENV", "development").lower()
    compose = "docker-compose.prod.yml" if env == "production" else "docker-compose.dev.yml"
    return f"docker compose -f {compose} exec api {SEED_SCRIPT}"


class ReferenceCheck(BaseModel):
    key: str
    label: str
    count: int
    ok: bool


class ReferenceData(BaseModel):
    ok: bool
    checks: list[ReferenceCheck]
    missing: list[str]
    # The exact thing to run, so the wizard never has to hardcode a command that
    # can drift away from the script that actually exists.
    remedy: str
    consequence: str


class FeedsStatus(BaseModel):
    total: int
    polled_ok: int
    errored: int
    never_polled: int


class EntriesStatus(BaseModel):
    total: int
    last_24h: int


class AutolinkStatus(BaseModel):
    entity_links: int


class AIStatus(BaseModel):
    providers: int
    active: str | None


class OnboardingStatus(BaseModel):
    reference_data: ReferenceData
    feeds: FeedsStatus
    entries: EntriesStatus
    autolink: AutolinkStatus
    ai: AIStatus
    # True once the instance can demonstrate itself: seeded, polling, ingesting.
    ready: bool


async def _count(db: AsyncSession, model: type) -> int:
    return int((await db.execute(select(func.count()).select_from(model))).scalar() or 0)


@router.get("/status", response_model=OnboardingStatus)
async def onboarding_status(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OnboardingStatus:
    """Report whether this instance is seeded, polling and linking.

    Backs the wizard's readiness and verification steps: readiness blocks on
    `reference_data`, verification re-polls until `feeds.polled_ok` and
    `entries.total` move. Available to any authenticated user — the counts are
    not sensitive, and a non-admin hitting an unusable instance deserves to be
    told why rather than left guessing.
    """
    checks: list[ReferenceCheck] = []
    for key, label, model, floor in REFERENCE_CHECKS:
        count = await _count(db, model)
        checks.append(ReferenceCheck(key=key, label=label, count=count, ok=count >= floor))
    missing = [c.key for c in checks if not c.ok]

    reference = ReferenceData(
        ok=not missing,
        checks=checks,
        missing=missing,
        # Always the whole seeder rather than `--only <missing>`: it is
        # idempotent and fills gaps, the steps have ordering dependencies
        # between them, and these check keys are not all seed_all step names
        # (products come from the `vendors` step).
        remedy=_seed_command(),
        consequence=(
            "Entries will ingest, but the autolinker has no vocabulary — no actor, "
            "technique, CVE, weakness or vendor will ever link to an article."
        ),
    )

    feed_rows = (
        await db.execute(
            select(
                func.count(Feed.id),
                func.count(Feed.id).filter(Feed.last_fetched_at.isnot(None), Feed.error_count == 0),
                func.count(Feed.id).filter(Feed.error_count > 0),
                func.count(Feed.id).filter(Feed.last_fetched_at.is_(None)),
            ).where(Feed.is_active.is_(True))
        )
    ).one()
    feeds = FeedsStatus(
        total=feed_rows[0] or 0,
        polled_ok=feed_rows[1] or 0,
        errored=feed_rows[2] or 0,
        never_polled=feed_rows[3] or 0,
    )

    day_ago = datetime.now(UTC) - timedelta(hours=24)
    entry_rows = (
        await db.execute(
            select(
                func.count(Entry.id),
                func.count(Entry.id).filter(Entry.created_at >= day_ago),
            )
        )
    ).one()
    entries = EntriesStatus(total=entry_rows[0] or 0, last_24h=entry_rows[1] or 0)

    # A proxy for "the autolinker is doing something", summed over the junctions
    # the dictionary scan writes most often. Not every junction — this is a
    # yes/no signal for a wizard, not an analytics figure.
    links = 0
    for junction in (EntryTTP, EntryCVE, EntryCWE):
        links += await _count(db, junction)
    autolink = AutolinkStatus(entity_links=links)

    provider_rows = (
        await db.execute(select(AIProvider.provider_type, AIProvider.is_active).order_by(AIProvider.created_at))
    ).all()
    # Startup seeds an active CLI provider for link validation. Prefer a
    # provider the admin chose, even if it was registered after that seed.
    active_types = [p_type for p_type, is_active in provider_rows if is_active]
    active = next((p_type for p_type in active_types if p_type != "claude_code"), None)
    if active is None:
        active = next(iter(active_types), None)
    ai = AIStatus(providers=len(provider_rows), active=active)

    return OnboardingStatus(
        reference_data=reference,
        feeds=feeds,
        entries=entries,
        autolink=autolink,
        ai=ai,
        ready=reference.ok and feeds.polled_ok > 0 and entries.total > 0,
    )
