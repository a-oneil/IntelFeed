"""Per-user Radar personalisation — read-time, never written back.

``Entry.priority_raw`` is global: one number per entry, computed by the
signal engine with admin-set family multipliers and the pooled feedback nudge
(``priority_score`` is the same number on the 0–10 scale). This module adds the
*personal* half on top, in raw units, the same way My Stack exposure does (see
``app/services/exposure.py``):

  effective_score = priority_raw + exposure_lift + personal_lift

``personal_lift`` is the difference between what the engine scored and what it
would have scored using this analyst's own fitted family weights. Because the
per-signal contribution is linear (``score x idf_weight x multiplier``), that
delta is a plain weighted sum over the entry's stored ``entry_signals`` rows —
no re-scoring, one grouped subquery, and switching personalisation off simply
drops the term.

Weights are fitted nightly by ``fit_user_signal_weights``; this module only
reads them.
"""

import uuid

from sqlalchemy import Float, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.signals import (
    SIGNAL_FAMILIES,
    get_signal_rates,
    personal_signal_coefficients,
)
from app.models.entry_signal import EntrySignal
from app.models.user_signal_weight import UserSignalWeight

# User.settings key holding the per-analyst opt-out. Absent means opted in —
# personalisation only ever engages once the nightly fit has produced weights,
# so a new user sees the global Radar until they have actually voted.
USER_SETTING_KEY = "radar_personalized"


def is_personalization_opted_in(user_settings: dict | None) -> bool:
    if not user_settings:
        return True
    return bool(user_settings.get(USER_SETTING_KEY, True))


async def get_user_weights(db: AsyncSession, user_id: uuid.UUID) -> dict[str, float]:
    """Fitted family multipliers for one user. Empty dict = no divergence yet."""
    rows = (
        await db.execute(
            select(UserSignalWeight.family, UserSignalWeight.weight).where(UserSignalWeight.user_id == user_id)
        )
    ).all()
    return {family: float(weight) for family, weight in rows}


async def get_personal_coefficients(db: AsyncSession, user_id: uuid.UUID) -> dict[str, float]:
    """signal_type -> per-unit-score lift coefficient for this user (may be empty)."""
    weights = await get_user_weights(db, user_id)
    if not weights:
        return {}
    return personal_signal_coefficients(weights, await get_signal_rates())


def personal_lift_subquery(coefficients: dict[str, float]):
    """Subquery of (entry_id, lift) = SUM(signal.score x coefficient[signal_type]).

    Returns None when the user has no non-neutral families, so the caller can
    skip the join entirely rather than adding a subquery that always sums zero.
    """
    if not coefficients:
        return None
    lift_expr = cast(
        case(
            *[(EntrySignal.signal_type == sig, EntrySignal.score * coeff) for sig, coeff in coefficients.items()],
            else_=0.0,
        ),
        Float,
    )
    return (
        select(
            EntrySignal.entry_id.label("entry_id"),
            func.sum(lift_expr).label("lift"),
        )
        .where(EntrySignal.signal_type.in_(list(coefficients)))
        .group_by(EntrySignal.entry_id)
        .subquery()
    )


async def enrich_personal(
    db: AsyncSession,
    entry_ids: list[uuid.UUID],
    coefficients: dict[str, float],
    weights: dict[str, float],
) -> dict[uuid.UUID, dict]:
    """Per-entry personalisation detail for a page of entries.

    Returns ``{entry_id: {lift, families: [{family, weight, delta}]}}`` for the
    entries the user's weights actually moved. Powers the "Tuned for you" row
    in the reader's Why-it's-ranked card — the lift is never shown as a bare
    number without the families that produced it.
    """
    if not coefficients or not entry_ids:
        return {}
    rows = (
        await db.execute(
            select(EntrySignal.entry_id, EntrySignal.signal_type, EntrySignal.score).where(
                EntrySignal.entry_id.in_(entry_ids),
                EntrySignal.signal_type.in_(list(coefficients)),
            )
        )
    ).all()
    out: dict[uuid.UUID, dict] = {}
    for entry_id, signal_type, score in rows:
        delta = (score or 0.0) * coefficients[signal_type]
        if not delta:
            continue
        family = SIGNAL_FAMILIES.get(signal_type, "interest")
        bucket = out.setdefault(entry_id, {"lift": 0.0, "_by_family": {}})
        bucket["lift"] += delta
        bucket["_by_family"][family] = bucket["_by_family"].get(family, 0.0) + delta
    result: dict[uuid.UUID, dict] = {}
    for entry_id, bucket in out.items():
        by_family = bucket.pop("_by_family")
        result[entry_id] = {
            "lift": round(bucket["lift"], 4),
            "families": [
                {
                    "family": family,
                    "weight": round(weights.get(family, 1.0), 3),
                    "delta": round(delta, 4),
                }
                for family, delta in sorted(by_family.items(), key=lambda kv: abs(kv[1]), reverse=True)
            ],
        }
    return result
