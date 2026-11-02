"""Review flags enrichment raises on an observable.

An IP that Shodan tags ``scanner``, or that GreyNoise classes as benign
mass-scanning noise, is most likely a research crawler (Shodan's own, Censys)
rather than attacker infrastructure. It stays in the ledger, flagged
``needs_review`` so an analyst decides. The flag is raised only when the
signal first appears: an analyst who cleared it isn't asked again until the
source stops and restarts saying so.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession


def shodan_says_scanner(tags) -> bool:
    return "scanner" in {t.strip() for t in str(tags or "").lower().split(",")}


def greynoise_says_benign_noise(parsed: dict) -> bool:
    return parsed.get("noise_class") == "benign" and parsed.get("noise") is True


async def flag_for_review(db: AsyncSession, entity_id: uuid.UUID, now: bool, before) -> None:
    """Set ``needs_review`` on the observable when ``now`` holds and ``before``
    (the same test against what the entity held before this answer) didn't.
    A denied row is never flagged."""
    from app.models.observable import Observable

    if not now:
        return
    obs = await db.get(Observable, entity_id)
    if obs is None or obs.is_denied or before(obs):
        return
    obs.needs_review = True
