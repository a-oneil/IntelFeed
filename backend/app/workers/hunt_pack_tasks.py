"""Draft a hunt pack on the AI worker (see app.services.hunt_pack).

Queued by POST /api/hunt-packs/...: the analyst clicked Draft or Download
hunt package and may leave the page. The draft's state lives in Redis
(drafting → cleared on success, failed with a message on error); the pack
itself lands in ai_results where the API reads it.
"""

import logging
import uuid

from celery.exceptions import SoftTimeLimitExceeded

from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.workers.hunt_pack_tasks.draft_hunt_pack",
    bind=True,
    soft_time_limit=600,
    time_limit=720,
    max_retries=0,
)
def draft_hunt_pack(self, user_id: str, entity_type: str, entity_key: str, scope: str, lang: str, append: bool = False):
    run_async(_draft(user_id, entity_type, entity_key, scope, lang, append))


async def _draft(user_id: str, entity_type: str, entity_key: str, scope: str, lang: str, append: bool) -> None:
    from app.ai.engine import derive_caller
    from app.services import hunt_pack as hp

    target_id = hp.pack_target_id(entity_type, entity_key, scope, lang)
    async with worker_session() as db:
        try:
            uid = uuid.UUID(user_id)
            pack = await hp.generate_hunt_pack(
                db, uid, entity_type, entity_key, scope, lang, caller=await derive_caller(db, uid), append=append
            )
        except SoftTimeLimitExceeded:
            await hp.set_draft_state(target_id, "failed", error="The model took more than ten minutes.")
            return
        except hp.NothingToHunt:
            await hp.set_draft_state(target_id, "failed", error="Nothing to draft hunts from yet.")
            return
        except Exception as exc:  # noqa: BLE001 — every failure must reach the UI, not just the log
            logger.exception("hunt pack draft failed for %s %s (%s)", entity_type, entity_key, scope)
            await hp.set_draft_state(target_id, "failed", error=str(exc)[:300] or exc.__class__.__name__)
            return
    if pack is None:
        reason = (
            "The model returned no hunts that aren't already in the pack."
            if append
            else "The model returned no usable hunts, or no provider is assigned."
        )
        await hp.set_draft_state(target_id, "failed", error=reason)
        return
    await hp.clear_draft_state(target_id)
