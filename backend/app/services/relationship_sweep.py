"""The edge sweep: settle relationship claims the per-article review left open.

The per-article review (app/services/entry_adjudication.py) judges a claim
one article at a time, and many claims never get a counted answer there: the
model left the edge out or was not sure, the article overflowed the edge cap,
its review failed, or one article kept the claim while another demoted it
(``disputed``). This job takes those edges one at a time, oldest first, and
asks the model about the claim with the passages from up to
``_MAX_ARTICLES`` of its evidence articles side by side.

The answer must quote the article: a keep or a correction whose quote is not
found in that article's text, or does not name both ends, is not accepted.
What a run may change is ``relationship_sweep_mode``:

* ``shadow`` (default) — the answer is recorded as an uncounted review
  (``relationship_reviews``, reviewer ``sweep``) and nothing changes; the
  eval script compares those answers with hand labels before apply is
  switched on;
* ``apply`` — at ``relationship_sweep_min_confidence`` a stated claim is
  ``kept``, a wrong verb or direction is corrected (the claim is demoted and
  the corrected edge credited), and an unstated claim is ``coincidental``
  (hidden from display surfaces). Demotes and corrections write the same
  Review history rows as the per-article review, so Restore undoes them.

An edge the sweep could not settle is not asked again for
``relationship_sweep_retry_days``; it stays in Review's Relationships lens.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence import edge_evidence
from app.models.entity_relationship import EntityRelationship, RelationshipReview

logger = logging.getLogger(__name__)

TASK_NAME = "relationship_review"
# ai_results.target_type is varchar(20).
TARGET_TYPE = "relationship"
LOCK_KEY = "intelfeed:relationship_sweep:lock"
LOCK_TTL_SECONDS = 3600

MODES = ("off", "shadow", "apply")
# What apply mode may change, each switched on once the eval shows it is
# right often enough (relationship_sweep_actions).
ACTIONS = ("keep", "correct", "hide")
# None is on by default: on 790 labeled edges (2026-11-21, qwen3.5:9b) keeps
# were right 80% of the time, hides 81%, corrections 36% — short of the 95%
# a change made without a person needs. A keep of "X targets <country>" is
# never applied: origin read as target is the most common wrong claim (60 of
# 80 co-occurrence country keeps right).
_NO_AUTO_KEEP = {("threat_actor", "targets", "country"), ("malware", "targets", "country")}
DECISIONS = ("asserted", "wrong_verb", "wrong_direction", "not_asserted", "wrong_entity", "unsure")
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
_MAX_ARTICLES = 4
_DESCRIPTION_MAX = 200


async def sweep_settings(db: AsyncSession) -> dict:
    from app.services.system_settings import get_setting

    async def _get(key, default):
        value = await get_setting(key, db)
        return default if value is None or value == "" else value

    mode = str(await _get("relationship_sweep_mode", "shadow")).lower()
    floor = str(await _get("relationship_sweep_min_confidence", "high")).lower()
    return {
        "mode": mode if mode in MODES else "shadow",
        "batch_size": max(0, int(await _get("relationship_sweep_batch_size", 30))),
        "min_age_hours": max(0, int(await _get("relationship_sweep_min_age_hours", 24))),
        "retry_days": max(1, int(await _get("relationship_sweep_retry_days", 30))),
        "min_conf": floor if floor in _CONF_RANK else "high",
        "actions": {
            a.strip().lower()
            for a in str(await _get("relationship_sweep_actions", "") or "").split(",")
            if a.strip().lower() in ACTIONS
        },
    }


# --------------------------------------------------------------------- the case


@dataclass
class End:
    entity_type: str
    entity_id: uuid.UUID
    name: str
    forms: list[str]
    description: str = ""


@dataclass
class Passage:
    index: int
    entry_id: uuid.UUID
    feed_id: uuid.UUID | None
    title: str
    feed_title: str
    text: str  # the article text the quote must come from (title and summary included)
    lines: list[str] = field(default_factory=list)
    paragraphs: list[str] = field(default_factory=list)
    # The names each end goes by in this article (catalog forms + what the
    # autolinker matched here): what a quote must name.
    source_forms: list[str] = field(default_factory=list)
    target_forms: list[str] = field(default_factory=list)
    # What ``lines`` says, kept apart for display: the analysis's (verb,
    # sentence) when it asserted the pair, the passages naming both ends, and
    # failing those the first passage naming each end alone.
    published_at: datetime | None = None
    asserted: tuple[str, str] | None = None
    both: list[str] = field(default_factory=list)
    source_only: str | None = None
    target_only: str | None = None


@dataclass
class EdgeCase:
    edge: EntityRelationship
    source: End
    target: End
    passages: list[Passage]

    @property
    def claim(self) -> str:
        verb = self.edge.relationship_type.replace("_", " ")
        return f"{self.source.name} ({self.source.entity_type}) {verb} {self.target.name} ({self.target.entity_type})"


@dataclass
class Judgment:
    decision: str
    confidence: str
    reason: str
    quote: str = ""
    passage: Passage | None = None
    suggested_verb: str | None = None
    flip: bool = False
    # Why an answer was not accepted as given (it then reads as unsure).
    rejected: str | None = None


async def _end(db: AsyncSession, entity_type: str, entity_id: uuid.UUID) -> End:
    from app.services.entry_adjudication import _display_name, _model_for

    model = _model_for(entity_type)
    obj = await db.get(model, entity_id) if model is not None else None
    name = _display_name(obj) if obj is not None else f"{entity_type}:{entity_id}"
    description = ""
    for attr in ("description", "technique_name"):
        value = getattr(obj, attr, None) if obj is not None else None
        if value:
            description = " ".join(str(value).split())[:_DESCRIPTION_MAX]
            break
    forms = await edge_evidence.edge_forms(db, entity_type, entity_id)
    return End(entity_type, entity_id, name, forms or [name], description)


async def build_case(db: AsyncSession, edge: EntityRelationship, max_articles: int = _MAX_ARTICLES) -> EdgeCase | None:
    """The claim and up to _MAX_ARTICLES passages: articles with a sentence
    naming both ends first, one per feed before a second from any feed,
    reposts last."""
    from app.models.ai_analysis import AIAnalysisRequest
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.services.entry_adjudication import _current_analysis
    from app.services.entry_analysis import analysis_content_text

    source = await _end(db, edge.source_type, edge.source_id)
    target = await _end(db, edge.target_type, edge.target_id)
    ids = list(dict.fromkeys(edge.evidence_entry_ids or []))
    if not ids:
        return None
    entries = (await db.execute(select(Entry).where(Entry.id.in_(ids)))).scalars().all()
    if not entries:
        return None
    echoes = set(
        (
            await db.execute(
                select(AIAnalysisRequest.entry_id).where(
                    AIAnalysisRequest.entry_id.in_([e.id for e in entries]), AIAnalysisRequest.status == "reused_echo"
                )
            )
        ).scalars()
    )
    feed_titles = dict(
        (await db.execute(select(Feed.id, Feed.title).where(Feed.id.in_({e.feed_id for e in entries})))).all()
    )

    candidates = []
    for entry in entries:
        title = entry.translated_title or entry.title or ""
        paras = edge_evidence.paragraphs(title, entry.summary, analysis_content_text(entry))
        text = "\n\n".join(paras)
        src_forms = [*source.forms, *await edge_evidence.edge_forms(db, edge.source_type, edge.source_id, entry.id)]
        tgt_forms = [*target.forms, *await edge_evidence.edge_forms(db, edge.target_type, edge.target_id, entry.id)]
        _result, parsed = await _current_analysis(db, entry.id)
        lines: list[str] = []
        asserted = edge_evidence.analysis_evidence(parsed, src_forms, tgt_forms)
        if asserted and edge_evidence.quote_in(text, asserted[1]):
            lines.append(f'the analysis quoted ({asserted[0].replace("_", " ")}): "{asserted[1]}"')
        else:
            asserted = None
        body = paras[1:] if title else paras
        both, only_src, only_tgt = edge_evidence.passages_naming(body, src_forms, tgt_forms)
        if title and (edge_evidence.names(title, src_forms) or edge_evidence.names(title, tgt_forms)):
            lines.insert(0, f'title: "{title}"')
        lines += [f'passage: "{p}"' for p in both]
        if not both:
            for end, found in ((source, only_src), (target, only_tgt)):
                if found:
                    lines.append(f'{end.name} is named (no passage names both): "{found[0]}"')
                elif not edge_evidence.names(title, src_forms if end is source else tgt_forms):
                    lines.append(f"{end.name} is not found in the text")
        found = {
            "asserted": asserted,
            "both": both,
            "source_only": None if both or not only_src else only_src[0],
            "target_only": None if both or not only_tgt else only_tgt[0],
        }
        candidates.append((bool(both), entry, text, lines, src_forms, tgt_forms, paras, found))

    epoch = datetime.min.replace(tzinfo=UTC)
    candidates.sort(key=lambda c: (not c[0], c[1].id in echoes, -(c[1].published_at or epoch).timestamp()))
    picked, seen_feeds = [], set()
    for c in candidates:
        if c[1].feed_id not in seen_feeds:
            picked.append(c)
            seen_feeds.add(c[1].feed_id)
    for c in candidates:
        if c not in picked:
            picked.append(c)
    passages = [
        Passage(
            index=i + 1,
            entry_id=entry.id,
            feed_id=entry.feed_id,
            title=entry.translated_title or entry.title or "",
            feed_title=feed_titles.get(entry.feed_id) or "",
            text=text,
            lines=lines,
            paragraphs=paras,
            source_forms=src_forms,
            target_forms=tgt_forms,
            published_at=entry.published_at,
            **found,
        )
        for i, (_both, entry, text, lines, src_forms, tgt_forms, paras, found) in enumerate(picked[:max_articles])
    ]
    return EdgeCase(edge=edge, source=source, target=target, passages=passages)


def render_case(case: EdgeCase) -> str:
    edge = case.edge
    origin = (
        "an automated analysis asserted it"
        if edge.source == "auto_extracted"
        else "both are named in one paragraph, and the verb was chosen from the two entity types alone"
    )
    out = [f"CLAIM: {case.claim}", f"  (how it was drawn: {origin})"]
    for end in (case.source, case.target):
        also = ", ".join(f for f in end.forms if f != end.name)[:160]
        line = f"  {end.name} — {end.entity_type}"
        if also:
            line += f"; also called {also}"
        if end.description:
            line += f"; {end.description}"
        out.append(line)
    out.append("")
    out.append(f"ARTICLES ({len(case.passages)} of the {len(edge.evidence_entry_ids or [])} it was drawn from):")
    for p in case.passages:
        out.append(f'[{p.index}] "{p.title}" — {p.feed_title}')
        out += [f"    {line}" for line in p.lines]
    return "\n".join(out)


# ------------------------------------------------------------------- the answer


def parse_answer(result: dict, case: EdgeCase) -> Judgment:
    """The model's answer, held to the rules: a quote from the article it
    names, naming both ends, for anything but a plain 'not stated'."""
    from app.intelligence.relationship_matrix import corrected_orientation

    decision = str(result.get("decision") or "unsure").strip().lower().replace(" ", "_")
    if decision not in DECISIONS:
        decision = "unsure"
    confidence = str(result.get("confidence") or "low").strip().lower()
    if confidence not in _CONF_RANK:
        confidence = "low"
    reason = " ".join(str(result.get("reason") or "").split())[:500]
    quote = " ".join(str(result.get("quote") or "").split())[:500]
    j = Judgment(decision, confidence, reason, quote)
    try:
        idx = int(result.get("article") or 0)
    except (TypeError, ValueError):
        idx = 0
    j.passage = next((p for p in case.passages if p.index == idx), None)

    if decision in ("asserted", "wrong_verb", "wrong_direction"):
        if j.passage is None:
            j.passage = next((p for p in case.passages if edge_evidence.quote_in(p.text, quote)), None)
        if j.passage is None or not edge_evidence.quote_in(j.passage.text, quote):
            j.rejected = "quote not found in the article"
        else:
            # The quote names both ends, or names one and sits in a paragraph
            # (or under a title) that names the other: "the attackers deployed
            # MythicRatatoskr" in the paragraph about UAC-0099.
            src_forms = j.passage.source_forms or case.source.forms
            tgt_forms = j.passage.target_forms or case.target.forms
            held = edge_evidence.paragraph_holding(j.passage.paragraphs, quote) or ""
            title = j.passage.paragraphs[0] if j.passage.paragraphs else ""
            near = f"{held}\n{title}"
            names_src = edge_evidence.names(quote, src_forms)
            names_tgt = edge_evidence.names(quote, tgt_forms)
            src_ok = names_src or edge_evidence.names(near, src_forms)
            tgt_ok = names_tgt or edge_evidence.names(near, tgt_forms)
            if not (names_src or names_tgt) or not (src_ok and tgt_ok):
                j.rejected = "quote does not name both ends"
    if decision in ("wrong_verb", "wrong_direction") and j.rejected is None:
        verb = str(result.get("suggested_verb") or "").strip().lower().replace(" ", "_") or case.edge.relationship_type
        flip = decision == "wrong_direction" or bool(result.get("flip"))
        fixed = corrected_orientation(
            case.edge.source_type, case.edge.relationship_type, case.edge.target_type, verb, flip
        )
        if fixed is None:
            j.rejected = "no allowed correction"
        else:
            j.suggested_verb, j.flip = fixed
    if decision in ("not_asserted", "wrong_entity") and not reason:
        j.rejected = "no reason"
    if j.rejected:
        j.decision = "unsure"
    return j


# ----------------------------------------------------------------- the effect


async def apply_judgment(
    db: AsyncSession, case: EdgeCase, j: Judgment, cfg: dict, ai_result_id: uuid.UUID | None
) -> str:
    """Record the answer and, in apply mode at the floor, act on it. Returns
    what happened: kept / corrected / demoted / recorded."""
    from app.models.entity_maintenance import EntityMaintenanceLog
    from app.services import edge_settlement as es
    from app.services.entry_adjudication import (
        ACTION_EDGE_DEMOTE,
        LOG_TYPE_RELATIONSHIP,
        _demote_edge,
        _reverb_edge,
    )

    edge = case.edge
    verdict = {
        "asserted": es.KEEP,
        "wrong_verb": es.REVERB,
        "wrong_direction": es.REVERB,
        "not_asserted": es.DEMOTE,
        "wrong_entity": es.DEMOTE,
    }.get(j.decision, es.UNSURE)
    entry_id = j.passage.entry_id if j.passage else (case.passages[0].entry_id if case.passages else None)
    action = {es.KEEP: "keep", es.REVERB: "correct", es.DEMOTE: "hide"}.get(verdict)
    claim_types = (edge.source_type, edge.relationship_type, edge.target_type)
    acts = (
        cfg["mode"] == "apply"
        and action in cfg.get("actions", set(ACTIONS))
        and not (action == "keep" and claim_types in _NO_AUTO_KEEP)
        and _CONF_RANK[j.confidence] >= _CONF_RANK[cfg["min_conf"]]
    )
    if not acts:
        await es.record_review(
            db,
            edge.id,
            reviewer=es.SWEEP,
            verdict=verdict,
            entry_id=entry_id,
            confidence=j.confidence,
            reason=j.reason if not j.rejected else f"{j.reason} [not accepted: {j.rejected}]",
            quote=j.quote,
            suggested_verb=j.suggested_verb,
            flipped=j.flip,
            ai_result_id=ai_result_id,
        )
        return "recorded"

    if verdict == es.KEEP:
        await es.record_review(
            db,
            edge.id,
            reviewer=es.SWEEP,
            verdict=es.KEEP,
            entry_id=entry_id,
            confidence=j.confidence,
            reason=j.reason,
            quote=j.quote,
            counted=True,
            ai_result_id=ai_result_id,
        )
        await es.settle_edge(db, edge)
        return "kept"

    claim = case.claim
    before = await _demote_edge(
        db,
        edge.id,
        j.reason,
        entry_id=entry_id,
        reviewer=es.SWEEP,
        confidence=j.confidence,
        ai_result_id=ai_result_id,
    )
    if before is None:
        return "recorded"
    after = {"reason": j.reason, "confidence": j.confidence, "quote": j.quote, "origin": "sweep"}
    if verdict == es.REVERB and entry_id is not None:
        fixed = await _reverb_edge(
            db,
            edge.id,
            j.suggested_verb or "",
            j.flip,
            entry_id,
            j.reason,
            reviewer=es.SWEEP,
            ai_result_id=ai_result_id,
        )
        after["reverb"] = {"verb": j.suggested_verb, "flip": j.flip, **(fixed or {})}
    db.add(
        EntityMaintenanceLog(
            entity_type=LOG_TYPE_RELATIONSHIP,
            entity_id=edge.id,
            action=ACTION_EDGE_DEMOTE,
            mode="apply",
            before={"entry_id": str(entry_id) if entry_id else None, "claim": claim, **before},
            after=after,
            reasoning=j.reason,
            ai_result_id=ai_result_id,
            applied=True,
        )
    )
    return "corrected" if verdict == es.REVERB else "demoted"


# ------------------------------------------------------------------- the run


async def select_edges(db: AsyncSession, cfg: dict, limit: int | None = None) -> list[EntityRelationship]:
    """Open machine edges old enough that the per-article review had its
    turn, not asked by the sweep within the retry window: disputed first,
    then oldest."""
    from app.services.edge_settlement import DISPUTED, SETTLEABLE_SOURCES

    now = datetime.now(UTC)
    asked = exists().where(
        RelationshipReview.relationship_id == EntityRelationship.id,
        RelationshipReview.reviewer == "sweep",
        RelationshipReview.created_at > now - timedelta(days=cfg["retry_days"]),
    )
    evidence_n = func.coalesce(func.array_length(EntityRelationship.evidence_entry_ids, 1), 0)
    rows = await db.execute(
        select(EntityRelationship)
        .where(
            EntityRelationship.source.in_(SETTLEABLE_SOURCES),
            EntityRelationship.adjudication_verdict.is_(None) | (EntityRelationship.adjudication_verdict == DISPUTED),
            EntityRelationship.created_at < now - timedelta(hours=cfg["min_age_hours"]),
            evidence_n > 0,
            ~asked,
        )
        .order_by(
            (EntityRelationship.adjudication_verdict == DISPUTED).desc().nullslast(), EntityRelationship.created_at
        )
        .limit(limit if limit is not None else cfg["batch_size"])
    )
    return list(rows.scalars())


async def judge(db: AsyncSession, case: EdgeCase, user_id: uuid.UUID) -> tuple[Judgment | None, uuid.UUID | None, str]:
    """One model call for one edge. Returns (judgment, ai_result_id, status)."""
    from app.ai.caller import Caller
    from app.ai.engine import run_task
    from app.models.ai_result import AIResult

    result = await run_task(
        db=db,
        user_id=user_id,
        task_name=TASK_NAME,
        variables={"claim_block": render_case(case)},
        target_type=TARGET_TYPE,
        target_id=case.edge.id,
        force=True,
        caller=Caller.system(user_id),
    )
    if not result:
        return None, None, "no_assignment"
    status = result.get("_extraction_status")
    if status not in (None, "success"):
        return None, None, f"ai_{status}"
    ai_result_id = (
        await db.execute(
            select(AIResult.id)
            .where(AIResult.target_type == TARGET_TYPE, AIResult.target_id == case.edge.id)
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return parse_answer(result, case), ai_result_id, "success"


async def _record_unjudged(db: AsyncSession, edge: EntityRelationship, why: str) -> None:
    """An uncounted sweep row for an edge the sweep could not judge (no
    passages, a failed call), so it is not selected again until the retry
    window has passed and the rest of the backlog gets its turn."""
    from app.services import edge_settlement as es

    await es.record_review(db, edge.id, reviewer=es.SWEEP, verdict=es.UNSURE, reason=f"not judged: {why}")


async def sweep(db: AsyncSession, limit: int | None = None) -> dict:
    """One run: select, judge, apply, commit after each edge."""
    from app.services.entry_adjudication import RESWEEP_QUEUE_CEILING, _ai_queue_depth
    from app.services.system_user import get_system_user_id

    cfg = await sweep_settings(db)
    if cfg["mode"] == "off" or cfg["batch_size"] == 0:
        return {"status": "off"}
    depth = await _ai_queue_depth()
    if depth > RESWEEP_QUEUE_CEILING:
        return {"status": "deferred", "ai_queue": depth}
    user_id = await get_system_user_id(db)
    if user_id is None:
        return {"status": "no_system_user"}
    stats: dict[str, int] = {}
    for edge in await select_edges(db, cfg, limit):
        case = await build_case(db, edge)
        if case is None or not case.passages:
            # Recorded as asked; otherwise select_edges hands back the same
            # edges every run and the sweep never reaches the rest.
            await _record_unjudged(db, edge, "no passages name both ends")
            stats["no_passages"] = stats.get("no_passages", 0) + 1
            await db.commit()
            continue
        try:
            j, ai_result_id, status = await judge(db, case, user_id)
        except Exception as e:
            from app.ai.providers.claude_code_provider import QuotaExhaustedError

            if isinstance(e, QuotaExhaustedError):
                await db.commit()
                return {"status": "provider_paused", "mode": cfg["mode"], **stats}
            raise
        if status == "no_assignment":
            await db.commit()
            return {"status": "no_assignment", **stats}
        if j is None:
            await _record_unjudged(db, edge, status)
            stats[status] = stats.get(status, 0) + 1
            await db.commit()
            continue
        outcome = await apply_judgment(db, case, j, cfg, ai_result_id)
        stats[outcome] = stats.get(outcome, 0) + 1
        stats[f"decision_{j.decision}"] = stats.get(f"decision_{j.decision}", 0) + 1
        if j.rejected:
            stats["not_accepted"] = stats.get("not_accepted", 0) + 1
        await db.commit()
    return {"status": "ok", "mode": cfg["mode"], **stats}
