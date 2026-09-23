"""Rule → entity resolution, materialised into ``rule_coverage``.

The tag columns on ``detection_rules`` answer "which entity does this rule
cover?" for a third of the library and for zero actors, because only two of the
eleven upstream repos carry the field. This module resolves the rest and writes
the answer down, so the read side is a join instead of a scan.

Three writers, strongest first:

``tag``   ``source_cves`` / ``source_ttps`` / ``source_actors`` — an explicit
          upstream mapping, trusted as-is.
``meta``  the stored ``extract_metadata()`` pass — the same mapping, from a
          format the tag columns were never populated from.
``text``  regex + the autolinker's Aho-Corasick vocabulary over title, tags and
          body. Confidence tracks *where* it hit: a name in the title is what the
          rule is about, a name in the body may be a comment.

Precedence matters because the table's primary key allows one row per
(rule, entity): a rule that both tags CVE-2026-1731 and names it in the title
keeps the ``tag`` row. Nothing here launders a body-text hit into a tag.

False positives are the whole risk (see the autolinker's own history): rule
bodies are full of English prose in ``description:`` and ``falsepositives:``
blocks. The text writer therefore admits **canonical names only** — never
aliases — and re-applies the guards the autolinker learned the hard way.
"""

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.intelligence.autolinker import (
    _ensure_vocabulary,
    is_common_english_word,
    is_fp_entity_name,
    is_junk_alias,
    scan_text,
)
from app.models.detection_rule import DetectionRule
from app.models.rule_coverage import RuleCoverage

logger = logging.getLogger(__name__)

VIA_TAG = "tag"
VIA_META = "meta"
VIA_TEXT = "text"

#: Lower wins. A row is only replaced by a writer that is strictly more trusted.
_VIA_RANK = {VIA_TAG: 0, VIA_META: 1, VIA_TEXT: 2}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
#: Only the ``attack.tNNNN`` tag form, never a bare ``TNNNN``. Rule bodies are
#: full of four-digit identifiers (ports, event ids, error codes) that a bare
#: pattern would happily read as techniques.
ATTACK_TAG_RE = re.compile(r"attack\.t(\d{4})(?:\.(\d{3}))?", re.IGNORECASE)

#: Which vocabulary types the text writer will link. Vendors and products are
#: deliberately out: every Windows rule mentions Windows, and "covered by 400
#: rules" is not an answer anyone can act on.
TEXT_ENTITY_TYPES = frozenset({entity_types.THREAT_ACTOR, entity_types.MALWARE})

#: (region name, confidence). Order is the precedence order — a title hit is
#: what the rule is *for*, a body hit might be a comment.
_REGIONS = (("title", "high"), ("tags", "medium"), ("story", "low"), ("body", "low"))

# Splunk security_content bundles analytics into "analytic stories" and emits
# them as ``story:<name>`` tags. Membership is curation, not attribution:
# "Detect New Local Admin account" sits in five stories and "Windows Access
# Token Manipulation SeDebugPrivilege" in eighteen. Left in the ordinary tags
# region those became 1,122 of 1,123 medium-confidence actor rows and re-created
# the very dilution the board exists to remove, so they are scored separately.
_STORY_TAG_PREFIX = "story:"

# Past this many stories a rule is a general-purpose analytic that Splunk
# reuses everywhere, and its story tags say nothing about any one threat.
_MAX_STORY_TAGS = 4


@dataclass(frozen=True)
class CoverageRow:
    entity_type: str
    entity_key: str
    via: str
    confidence: str
    matched_on: str | None


@dataclass(frozen=True)
class RuleFacts:
    """The columns the resolver reads.

    Deliberately not a ``DetectionRule``: that model carries ``entry`` as
    ``lazy="joined"``, so loading whole rows for the library pulls every linked
    entry's content along with it and OOMs the worker.
    """

    id: uuid.UUID
    title: str
    tags: list[str]
    rule_type: str
    rule_content: str
    source_cves: list
    source_ttps: list
    source_actors: list
    metadata_: dict | None

    @classmethod
    def from_rule(cls, rule: DetectionRule) -> "RuleFacts":
        return cls(
            id=rule.id,
            title=rule.title or "",
            tags=list(rule.tags or []),
            rule_type=rule.rule_type or "",
            rule_content=rule.rule_content or "",
            source_cves=list(rule.source_cves or []),
            source_ttps=list(rule.source_ttps or []),
            source_actors=list(rule.source_actors or []),
            metadata_=rule.metadata_,
        )


# --- normalization -----------------------------------------------------------


# Lines that cite prior work rather than describe a detection. A rule whose only
# mention of CVE-2017-5638 is a link to a blog post about it does not detect it;
# measured at 46 of 318 CVE text rows before this filter.
_CITATION_LINE_RE = re.compile(
    r"^\s*(?:#\s*)?(?:-\s*)?(?:reference|references|ref|source|link|url|see[ _]also|advisory|blog)\b",
    re.IGNORECASE,
)


def _is_citation_only(text: str, match: re.Match) -> bool:
    """True when this occurrence sits inside a URL or on a reference line.

    Scoped to the single occurrence, not the rule: a rule that both cites an
    advisory and matches the exploit still resolves on its detecting mention.
    """
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.end())
    line = text[line_start : line_end if line_end != -1 else len(text)]
    if _CITATION_LINE_RE.match(line):
        return True
    # A bare URL containing the id — the CVE is part of someone else's path.
    before = text[line_start : match.start()]
    return "http://" in before or "https://" in before


def _cve_key(value: str) -> str | None:
    match = CVE_RE.fullmatch((value or "").strip())
    return match.group().upper() if match else None


_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _technique_key(value: str) -> str | None:
    form = (value or "").strip().removeprefix("attack.").removeprefix("ATTACK.")
    return form.upper() if _TECHNIQUE_RE.match(form) else None


def _attack_tag_key(match: re.Match) -> str | None:
    technique, sub = match.group(1), match.group(2)
    # ".000" is not a valid sub-technique; fall back to the parent rather than
    # minting an id the ATT&CK catalog will never match.
    if sub and sub != "000":
        return f"T{technique}.{sub}"
    return f"T{technique}"


# --- the three writers -------------------------------------------------------


def _tag_rows(facts: RuleFacts):
    """Explicit upstream mappings on the rule's own columns."""
    for raw in facts.source_cves or []:
        key = _cve_key(str(raw))
        if key:
            yield CoverageRow(entity_types.CVE, key, VIA_TAG, "high", str(raw))

    for raw in facts.source_ttps or []:
        key = _technique_key(str(raw))
        if key:
            yield CoverageRow(entity_types.TTP, key, VIA_TAG, "high", str(raw))

    for raw in facts.source_actors or []:
        # An actor tag is a uuid, not a literal a human can be shown — the row's
        # provenance is the `tag` via, so matched_on stays empty.
        yield CoverageRow(entity_types.THREAT_ACTOR, str(raw), VIA_TAG, "high", None)


def _meta_rows(facts: RuleFacts):
    """The extract-metadata pass, for the formats the tag columns never got.

    Reads the metadata the importer already stored; only re-parses when a rule
    carries none, so a full pass doesn't re-YAML the whole library.
    """
    metadata = facts.metadata_ or {}
    if not metadata:
        from app.intelligence.rule_metadata import extract_rule_metadata

        metadata = extract_rule_metadata(facts.rule_type, facts.rule_content)
    if not metadata:
        return

    for raw in metadata.get("mitre_attack_ids") or []:
        key = _technique_key(str(raw))
        if key:
            yield CoverageRow(entity_types.TTP, key, VIA_META, "high", str(raw))

    for raw in metadata.get("cve_ids") or []:
        key = _cve_key(str(raw))
        if key:
            yield CoverageRow(entity_types.CVE, key, VIA_META, "high", str(raw))


def _canonical_surface_form(match: dict) -> str | None:
    """The canonical name, if that is what actually matched — otherwise None.

    ``scan_text`` reports every surface form it saw for an entity, alias or not.
    Aliases are where the dictionary-word false positives live, so a rule only
    earns a coverage row when the entity's own name is in the text.
    """
    canonical = (match.get("canonical_name") or "").strip()
    if not canonical:
        return None
    forms = match.get("surface_forms") or [match.get("surface_form")]
    for form in forms:
        if form and form.strip().lower() == canonical.lower():
            return form
    return None


def _text_rows(facts: RuleFacts):
    """Regex identifiers + canonical entity names, per region.

    Each region is scanned on its own rather than as one blob: the autolinker's
    ambiguous-name frequency gate counts occurrences across everything it is
    given, and a YARA rule that repeats "LockBit" in twenty string definitions
    would otherwise suppress the same name in its own title.
    """
    regions = {
        "title": facts.title or "",
        "tags": " ".join(facts.tags or []),
        "body": facts.rule_content or "",
    }

    story_tags = [t for t in (facts.tags or []) if t.lower().startswith(_STORY_TAG_PREFIX)]
    regions["tags"] = " ".join(t for t in (facts.tags or []) if t not in story_tags)
    regions["story"] = " ".join(story_tags) if len(story_tags) <= _MAX_STORY_TAGS else ""

    for region, confidence in _REGIONS:
        text = regions[region]
        if not text:
            continue

        for match in CVE_RE.finditer(text):
            if _is_citation_only(text, match):
                continue
            yield CoverageRow(entity_types.CVE, match.group().upper(), VIA_TEXT, confidence, match.group())

        for match in ATTACK_TAG_RE.finditer(text):
            key = _attack_tag_key(match)
            if key:
                yield CoverageRow(entity_types.TTP, key, VIA_TEXT, confidence, match.group())

        for match in scan_text(text):
            if match.get("entity_type") not in TEXT_ENTITY_TYPES or not match.get("entity_id"):
                continue
            # A dictionary-word surface form held for AI confirmation is exactly
            # the match a rule body will generate by accident.
            if match.get("provisional"):
                continue
            form = _canonical_surface_form(match)
            if not form:
                continue
            canonical = match["canonical_name"]
            if is_junk_alias(form) or is_fp_entity_name(canonical) or is_common_english_word(form):
                continue
            yield CoverageRow(match["entity_type"], match["entity_id"], VIA_TEXT, confidence, form)


def resolve_facts(facts: RuleFacts) -> list[CoverageRow]:
    """Every writer's output for one rule, deduplicated by strongest provenance."""
    best: dict[tuple[str, str], CoverageRow] = {}
    for row in (*_tag_rows(facts), *_meta_rows(facts), *_text_rows(facts)):
        key = (row.entity_type, row.entity_key)
        current = best.get(key)
        if current is None or _rank(row) < _rank(current):
            best[key] = row
    return list(best.values())


def _rank(row: CoverageRow) -> tuple[int, int]:
    return (_VIA_RANK.get(row.via, 9), _CONFIDENCE_RANK.get(row.confidence, 9))


# --- persistence -------------------------------------------------------------


async def _write(db: AsyncSession, resolved: dict[uuid.UUID, list[CoverageRow]]) -> int:
    """Replace the coverage of every rule in ``resolved``.

    Delete-then-insert rather than upsert-then-prune: a rule whose title stopped
    naming an actor must lose that row, and there is no cheap way to spot the
    absence without the delete.
    """
    rule_ids = list(resolved)
    if not rule_ids:
        return 0

    await db.execute(delete(RuleCoverage).where(RuleCoverage.rule_id.in_(rule_ids)))

    now = datetime.now(UTC)
    values = [
        {
            "rule_id": rule_id,
            "entity_type": row.entity_type,
            "entity_key": row.entity_key[:255],
            "via": row.via,
            "confidence": row.confidence,
            "matched_on": row.matched_on,
            "updated_at": now,
        }
        for rule_id, rows in resolved.items()
        for row in rows
    ]
    if not values:
        return 0

    # on_conflict guards against a concurrent single-rule resolve racing a batch;
    # resolve_facts() already guarantees the batch itself has no duplicates.
    stmt = pg_insert(RuleCoverage).values(values)
    await db.execute(
        stmt.on_conflict_do_update(
            index_elements=["rule_id", "entity_type", "entity_key"],
            set_={
                "via": stmt.excluded.via,
                "confidence": stmt.excluded.confidence,
                "matched_on": stmt.excluded.matched_on,
                "updated_at": stmt.excluded.updated_at,
            },
        )
    )
    return len(values)


async def resolve_rule(db: AsyncSession, rule: DetectionRule) -> int:
    """Re-resolve one rule. Cheap enough for the create/update request path.

    Does not commit — the caller's transaction owns it.
    """
    await _ensure_vocabulary(db)
    facts = RuleFacts.from_rule(rule)
    return await _write(db, {facts.id: resolve_facts(facts)})


async def resolve_all(
    db: AsyncSession,
    since: datetime | None = None,
    batch_size: int = 500,
) -> dict:
    """Rebuild coverage for the library, or for rules changed since ``since``.

    ``since`` picks up anything that moved: ``upstream_updated_at`` for mirrored
    rules, ``updated_at`` for locally authored ones. Filtering on the repo-sync
    watermark alone skips every in-app rule, because ``upstream_updated_at`` is
    NULL for all ~540 of them — an authored or edited rule would stay invisible
    to the board until the next full pass.
    """
    await _ensure_vocabulary(db)

    stats = {"rules": 0, "rows": 0}
    query = select(
        DetectionRule.id,
        DetectionRule.title,
        DetectionRule.tags,
        DetectionRule.rule_type,
        DetectionRule.rule_content,
        DetectionRule.source_cves,
        DetectionRule.source_ttps,
        DetectionRule.source_actors,
        DetectionRule.metadata_,
    ).order_by(DetectionRule.id)
    if since is not None:
        query = query.where(
            or_(
                DetectionRule.upstream_updated_at >= since,
                DetectionRule.updated_at >= since,
            )
        )

    offset = 0
    while True:
        rows = (await db.execute(query.limit(batch_size).offset(offset))).all()
        if not rows:
            break

        resolved: dict[uuid.UUID, list[CoverageRow]] = {}
        for row in rows:
            facts = RuleFacts(
                id=row.id,
                title=row.title or "",
                tags=list(row.tags or []),
                rule_type=row.rule_type or "",
                rule_content=row.rule_content or "",
                source_cves=list(row.source_cves or []),
                source_ttps=list(row.source_ttps or []),
                source_actors=list(row.source_actors or []),
                metadata_=row.metadata_,
            )
            resolved[facts.id] = resolve_facts(facts)

        stats["rows"] += await _write(db, resolved)
        stats["rules"] += len(rows)
        await db.commit()

        offset += batch_size
        if len(rows) < batch_size:
            break

    logger.info("rule_coverage resolve: %s rules -> %s rows", stats["rules"], stats["rows"])
    return stats
