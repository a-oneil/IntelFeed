"""Threats page board.

Its own router rather than another block in api/intelligence.py (4,632 lines).
The old coverage-board endpoint stays where it is and keeps its response shape
until the frontend moves over.
"""

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.intelligence.story_threads import SIMILAR_FLOOR
from app.models.user import User
from app.schemas.threat_board import ThreatBoardItem, ThreatBoardResponse, ThreatStateUpdate
from app.services.threat_board import (
    STORY,
    WINDOW_HOURS,
    ThreatRow,
    build_cve_board,
    build_story_rows,
    build_threat_board,
    fold_claimed_cves,
)
from app.services.threat_brief import get_cached_briefs

router = APIRouter()

# A thread below this cosine is the closest thing in the index rather than a
# precedent. Same bar as "more like this", applied to thread centroids —
# imported rather than restated so one tuning pass moves both.
PRECEDENT_FLOOR = SIMILAR_FLOOR


def _item(r: ThreatRow, brief: tuple[str, list[str]] | None = None) -> ThreatBoardItem:
    return ThreatBoardItem(
        entity_type=r.entity_type,
        entity_key=r.entity_key,
        label=r.label,
        facets=r.facets,
        attention=r.attention,
        new_techniques=r.new_techniques,
        on_record=r.on_record,
        prior_rules=r.prior_rules,
        prior_rules_strong=r.prior_rules_strong,
        prior_rule_repos=r.prior_rule_repos,
        last_seen=r.last_seen,
        state=r.state,
        is_generic=r.is_generic,
        score=round(r.score, 2),
        action=r.action,
        articles=r.articles,
        stories=r.stories,
        echoes_folded=r.echoes_folded,
        beats=r.beats,
        headline=r.headline,
        sources=r.sources,
        writable_observables=r.writable_observables,
        brief=brief[0] if brief else None,
        brief_sources=brief[1] if brief else [],
        product=r.product,
        in_stack=r.in_stack,
        is_kev=r.is_kev,
        cvss_score=r.cvss_score,
        epss_score=r.epss_score,
        exploit_status=r.exploit_status,
        posture=r.posture,
        profile_id=r.profile_id,
        on_surface=r.on_surface,
        thread_slug=r.thread_slug,
        thread_title=r.thread_title,
        is_story=r.is_story,
        merged_from=r.merged_from,
    )


@router.get("", response_model=ThreatBoardResponse)
async def get_threat_board(
    window: str = Query("14d", pattern="^(7d|14d|30d)$", description="Recency window"),
    facet: str = Query(
        "threats",
        pattern="^(threats|vulns|all)$",
        description=(
            "threats = actor/malware rows; vulns = exploitation-ranked CVE rows; "
            "all = both interleaved by score, with CVEs claimed by a visible threat "
            "folded onto that threat's cluster instead of getting their own line"
        ),
    ),
    limit: int = Query(25, ge=1, le=100, description="Maximum threats returned"),
    min_attention: int = Query(3, ge=1, le=50, description="Minimum distinct source domains"),
    include_handled: bool = Query(False, description="Include threats already marked handled"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """The board: threats and vulnerabilities ranked over the window.

    Counts are never blended into a coverage percentage. Each row leads with
    evidence: the window's lead headline, the nightly AI `brief` when one is
    cached (built only from the window's entries — render the headline as
    fallback when null), and the source hosts behind the attention count.
    Ranking counts *stories*, not articles or outlets: a wave carried by eleven
    outlets is one thing that happened, and `stories` / `echoes_folded` say so
    on the row. Vulnerability rows rank by that count x the exposure severity
    lift (KEV / EPSS / weaponized) and carry detection posture; their action is
    write / adopt / collect. `prior_rules` is the library inventory —
    a count to go read, not a verdict. Rows with `is_story` are backed only by
    a story thread: real coverage that resolved to no entity, so the
    entity-keyed ranking has never been able to show it.
    """
    threats: list[ThreatRow] = []
    cves: list[ThreatRow] = []
    if facet in ("threats", "all"):
        threats = await build_threat_board(
            db, window=window, limit=limit, min_attention=min_attention, include_handled=include_handled
        )
        threats += await build_story_rows(
            db,
            window=window,
            limit=limit,
            min_attention=min_attention,
            include_handled=include_handled,
            user_id=user.id,
        )
        # Story rows arrive with their own limit, so the board has to be cut
        # again once they are interleaved — or asking for 40 rows returns 41.
        threats.sort(key=lambda r: (r.is_generic, r.state != "tracked", -r.score))
        tracked_threats = sum(1 for r in threats if r.state == "tracked")
        threats = threats[: max(limit, tracked_threats)]
    if facet in ("vulns", "all"):
        cves = await build_cve_board(
            db,
            window=window,
            limit=limit,
            min_attention=min_attention,
            include_handled=include_handled,
            user_id=user.id,
        )
    if facet == "all" and cves:
        cves = await fold_claimed_cves(db, threats, cves, window=window)
        merged = threats + cves
        merged.sort(key=lambda r: (r.is_generic, r.state != "tracked", not r.on_surface, -r.score))
        tracked = sum(1 for r in merged if r.state == "tracked")
        rows = merged[: max(limit, tracked)]
    else:
        rows = threats or cves

    briefs = await get_cached_briefs(
        db, [(r.entity_type, r.entity_key) for r in rows if not r.is_generic], window=window
    )
    items = [_item(r, briefs.get((r.entity_type, r.entity_key))) for r in rows]
    return ThreatBoardResponse(window=window, items=items, total=len(items))


@router.put("/{entity_type}/{entity_key}/state", response_model=ThreatBoardItem)
async def set_threat_state(
    entity_type: str = Path(..., description="Entity type from app.entity_types"),
    entity_key: str = Path(..., description="Entity uuid, cve_id or technique_id"),
    window: str = Query("14d", pattern="^(7d|14d|30d)$", description="The window the caller's board view is using"),
    body: ThreatStateUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a threat open, handled or muted.

    Records the threat's current `new_techniques` count alongside the decision.
    A handled threat reopens on its own once that count rises, so there is no
    snooze date and nothing to expire. Pass the board view's `window` — a row
    visible only at 30d must be handleable from the 30d view.
    """
    if entity_type == "cve":
        board = await build_cve_board(
            db, window=window, limit=200, min_attention=1, include_handled=True, user_id=user.id
        )
    elif entity_type == STORY:
        board = await build_story_rows(
            db, window=window, limit=200, min_attention=1, include_handled=True, user_id=user.id
        )
    else:
        board = await build_threat_board(db, window=window, limit=200, min_attention=1, include_handled=True)
    row = next((r for r in board if r.entity_type == entity_type and r.entity_key == entity_key), None)
    if row is None and body.state == "tracked":
        # The pull path: tracking is exactly for threats the ranking hasn't
        # surfaced. Validate the entity exists and pin it with empty counts —
        # the next board read computes the real ones.
        label = None
        if entity_type == "cve":
            label = (
                await db.execute(text("SELECT cve_id FROM cves WHERE cve_id = :id"), {"id": entity_key})
            ).scalar_one_or_none()
        elif entity_type == STORY:
            label = (
                await db.execute(text("SELECT title FROM story_threads WHERE slug = :slug"), {"slug": entity_key})
            ).scalar_one_or_none()
        elif table := {"threat_actor": "threat_actors", "malware": "malware_families"}.get(entity_type):
            label = (
                await db.execute(text(f"SELECT name FROM {table} WHERE id::text = :id"), {"id": entity_key})  # noqa: S608
            ).scalar_one_or_none()
        if label is None:
            raise AppError(code="not_found", message="Entity not found", status_code=404)
        row = ThreatRow(
            entity_type=entity_type,
            entity_key=entity_key,
            label=label,
            facets=[entity_type],
            attention=0,
            new_techniques=0,
            on_record=0,
            prior_rules=0,
            prior_rules_strong=0,
            prior_rule_repos={},
            last_seen=None,
            state="tracked",
            is_generic=False,
            score=0.0,
        )
    if row is None:
        raise AppError(code="not_found", message="Threat not on the board", status_code=404)

    # A row that folded others carries their decision too. The analyst handled
    # one row because the board showed one row; leaving the absorbed entities
    # open would pop them back out as their own rows the moment the fold stops
    # applying, asking again about work that was already decided.
    decided = [(entity_type, entity_key), *((m["entity_type"], m["entity_key"]) for m in row.merged_from)]
    for et, ek in decided:
        await db.execute(
            text(
                """
                INSERT INTO threat_board_state
                    (entity_type, entity_key, state, new_count_at_decision, decided_by, note)
                VALUES (:et, :ek, :state, :n, :uid, :note)
                ON CONFLICT (entity_type, entity_key) DO UPDATE SET
                    state = EXCLUDED.state,
                    new_count_at_decision = EXCLUDED.new_count_at_decision,
                    decided_by = EXCLUDED.decided_by,
                    decided_at = now(),
                    note = EXCLUDED.note
                """
            ),
            {
                "et": et,
                "ek": ek,
                "state": body.state,
                # The merged row's count, for every entity it spoke for: they
                # share a story, so new tradecraft on it reopens all of them.
                "n": row.new_techniques,
                "uid": user.id,
                "note": body.note,
            },
        )
    await db.commit()

    briefs = await get_cached_briefs(db, [(row.entity_type, row.entity_key)], window=window)
    item = _item(row, briefs.get((row.entity_type, row.entity_key)))
    return item.model_copy(update={"state": body.state})


@router.get("/{entity_type}/{entity_key}/rules")
async def get_row_rules(
    entity_type: str = Path(..., description="threat_actor, malware or cve"),
    entity_key: str = Path(..., description="Entity uuid or CVE id — the rule_coverage key"),
    limit: int = Query(50, ge=1, le=200, description="Maximum rules returned"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Every library rule that resolves to this board row, strongest first.

    The drawer's full-width inventory: each row carries `via`, `confidence` and
    `matched_on` so a body-text hit never reads like a rule that names the
    threat. This is the list behind the caption's "N rules name it" — a count
    to go read, finally readable in place.
    """
    rows = (
        await db.execute(
            text(
                """
                SELECT r.id, r.title, r.rule_type, r.is_draft, r.license, r.severity,
                       coalesce(r.metadata->>'repo', 'local') AS repo,
                       rc.via, rc.confidence, rc.matched_on
                FROM rule_coverage rc
                JOIN detection_rules r ON r.id = rc.rule_id
                WHERE rc.entity_type = :etype AND rc.entity_key = :ekey
                ORDER BY CASE rc.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                         r.is_draft, r.title
                LIMIT :cap
                """
            ),
            {"etype": entity_type, "ekey": entity_key, "cap": limit},
        )
    ).all()
    strong = sum(1 for r in rows if r.confidence in ("high", "medium"))
    return {
        "items": [
            {
                "rule_id": str(r.id),
                "title": r.title,
                "rule_type": r.rule_type,
                "is_draft": r.is_draft,
                "license": r.license,
                "severity": r.severity,
                "repo": r.repo,
                "via": r.via,
                "confidence": r.confidence,
                "matched_on": r.matched_on,
            }
            for r in rows
        ],
        "total": len(rows),
        "strong": strong,
        "weak": len(rows) - strong,
    }


@router.get("/precedent")
async def get_precedent(
    thread: str = Query(..., description="Thread slug from a row's `thread_slug`"),
    limit: int = Query(3, ge=1, le=10, description="Maximum prior stories returned"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Stories this row's story resembles — "have we seen this shape before".

    Answered from the thread centroids, so it can find the Cisco ASA wave from
    eighteen months ago when this week's story is the same shape under another
    vendor's name. Keyword search structurally cannot.
    """
    from app.intelligence.story_threads import nearest_threads

    thread_id = (
        await db.execute(text("SELECT id FROM story_threads WHERE slug = :slug"), {"slug": thread})
    ).scalar_one_or_none()
    if thread_id is None:
        raise AppError(code="not_found", message="No story thread with that slug", status_code=404)
    near = await nearest_threads(db, thread_id, limit=limit)
    return {
        "thread": thread,
        "items": [
            {
                "slug": n["slug"],
                "title": n["title"],
                "status": n["status"],
                "entry_count": n["entry_count"],
                "similarity": round(float(n["similarity"] or 0), 3),
            }
            for n in near
            if float(n["similarity"] or 0) >= PRECEDENT_FLOOR
        ],
    }


@router.get("/windows")
async def get_windows(user: User = Depends(get_current_user)):
    """Windows the board offers, for the segmented control."""
    return {"windows": list(WINDOW_HOURS)}
