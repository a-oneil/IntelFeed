"""Coverage Workspace — the four regions behind the profile's Detection tab.

The Detection tab already answers "is this technique covered?" from
``services/detection_coverage.py``. It cannot answer the question that follows —
*what would I write, and from which sentence?* — because it has no article
context, no extracted observables and nowhere to collect what gets assembled.

Four regions, each a read over data already stored:

``articles``    the entity's entries in the window, split by whether they
                actually contributed techniques. A recap that added nothing is
                not the same input as the report that carried the chain.
``behaviours``  techniques extracted for this entity in the window, each with
                its ``entry_ttps.source_text`` quote (20,039 of 21,829 rows have
                one), its ``paragraph_indices`` where present, and the ATT&CK
                channels on ``ttps.data_sources`` (856 of 1,198 techniques)
                classified against the enabled telemetry inventory.
``prior rules`` ``rule_coverage`` candidates for one behaviour, carrying ``via``
                and ``matched_on`` so a body-text hit never reads like a rule
                that names the threat.
``set``         what the user is assembling, persisted as a ``DetectionSummary``
                row so reopening the workspace is a read.

Two rules this module exists to enforce:

1. A behaviour whose channels match *nothing* in the inventory is **not** a
   detection gap. Writing a rule for it changes nothing, because the rule could
   not fire. It sorts below a labelled divider carrying the category that is
   missing, so it reads as a sourcing item.
2. No AI call. ``GET /detection-rules/{id}`` measures ~5s on this box and the
   summary generator 503s under load, so the workspace is assembled from stored
   rows only — the AI path stays behind the existing explicit generate action.
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types
from app.core.exceptions import AppError
from app.models.detection_summary import DetectionSummary
from app.services.detection_coverage import (
    TIER_CATEGORY,
    TIER_LOG_TYPE,
    TIER_SOURCE,
    TelemetryProfile,
    _expand_rule_token,  # no public accessor; see _missing_categories()
    classify_data_sources,
    get_available_telemetry,
    telemetry_tokens_from_rule,
)
from app.services.threat_board import WINDOW_HOURS

# The Detection tab asks a longer question than the board does. The board ranks
# what moved this week; a profile asks "what has this threat ever done that I
# could detect?", which only "all" answers. `None` means no lower bound.
WORKSPACE_WINDOW_HOURS: dict[str, int | None] = {**WINDOW_HOURS, "90d": 2160, "all": None}

# Recency still has to mean something under "all": every technique would read as
# new against an unbounded floor. `is_new` keeps its own 14-day horizon there.
NEW_HORIZON_HOURS = 336

# Lower bound for the unbounded window. A real datetime rather than dropping the
# predicate keeps one SQL body for every window.
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# One Detection tab, four faces. Actors and malware are the board's identities;
# a CVE gets the same workspace with exploitation context where a threat would
# have its fold; a technique gets an unranked coverage bench for itself — it is
# deliberately NOT tracked on the Threats board (technique coverage is a
# project, not an event), but the build verbs are identical.
ENTITY_SOURCES: dict[str, tuple[str, str]] = {
    entity_types.THREAT_ACTOR: ("entry_threat_actors", "threat_actor_id"),
    entity_types.MALWARE: ("entry_malware", "malware_family_id"),
    entity_types.CVE: ("entry_cves", "cve_id"),
    entity_types.TTP: ("entry_ttps", "ttp_id"),
    # A campaign's articles are chosen rather than matched, but the behaviours
    # they carry are read the same way — so it gets the same build bench as an
    # actor instead of the bare coverage list it had.
    "campaign": ("campaign_entries", "campaign_id"),
}

_ENTITY_TABLE: dict[str, str] = {
    entity_types.THREAT_ACTOR: "threat_actors",
    entity_types.MALWARE: "malware_families",
    "campaign": "campaigns",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.I)

# Strongest first. Ordering rules by this puts the ones that can actually fire
# against the current inventory at the top of the candidate list.
_TIER_RANK: dict[str | None, int] = {
    TIER_SOURCE: 0,
    TIER_LOG_TYPE: 1,
    TIER_CATEGORY: 2,
    None: 3,
}

# A `low` row resolved from body text or a story tag is real inventory but weak
# evidence — it is not a rule that names this threat, and must not sort or read
# as if it were.
_CONFIDENCE_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2}

# Quotes per behaviour. The point is to show the sentence a rule would be written
# from, not to reprint the article.
MAX_QUOTES = 3

# Operations a set item can carry. Deliberately not a lifecycle: adopt/extend/
# new/skip describe what the user is doing with a rule right now, not a state
# it sits in. A skip persists with its reason — it is coverage documentation,
# and exports render it as a known gap.
SET_OPS = ("adopt", "extend", "new", "skip")

# Marker on summary_content so the workspace can find its own rows in
# detection_summaries, which otherwise holds AI-generated article summaries.
SET_KIND = "coverage_set"


@dataclass(frozen=True)
class Quote:
    entry_id: str
    entry_title: str
    text: str
    paragraph_indices: list[int]
    # The concrete artefact the sentence documents, when the extractor typed
    # one: this is what "Draft new" compiles into a selection clause.
    observable_type: str | None = None
    observable_value: str | None = None
    # Where a defender would see the behavior (the non-endpoint bridge):
    # dns, netflow, identity, cloudtrail, ... — lets the workspace slice
    # "detectable in telemetry I actually have, off the endpoint".
    telemetry: str | None = None


@dataclass(frozen=True)
class Article:
    entry_id: str
    title: str
    url: str | None
    source: str
    published_at: str | None
    word_count: int | None
    technique_count: int
    new_technique_count: int
    contributed: bool


@dataclass(frozen=True)
class Behaviour:
    technique_id: str
    technique_name: str
    tactic: str | None
    entry_count: int
    first_seen: str | None
    is_new: bool
    quotes: list[Quote]
    # (channel, tier) for every ATT&CK data source on the technique.
    channels: list[tuple[str, str | None]]
    tier: str | None
    missing_channels: list[str]
    missing_categories: list[str]
    below_line: bool
    prior_rules: int
    prior_rules_strong: int


@dataclass(frozen=True)
class PriorRule:
    rule_id: str
    title: str
    rule_type: str
    repo: str
    license: str | None
    is_draft: bool
    # "technique" when the rule resolved to this behaviour, "threat" when it
    # resolved to the entity itself. Both are candidates; they are not the same
    # claim, so the UI can say which one it is.
    scope: str
    via: str
    confidence: str
    matched_on: str | None
    tier: str | None
    required: list[str]
    missing: list[str]
    # Upstream commit date where the importer recorded one, else our own row's.
    # The only ranking signal that reliably varies: a behaviour's candidates are
    # routinely all high-confidence, all technique-tagged and all satisfiable,
    # at which point every other key ties and the list falls back to alphabetical.
    maintained_at: str | None = None


@dataclass(frozen=True)
class PriorRuleSet:
    """One page of candidates plus what the page does not show.

    The counts matter because the strongest 40 rows are nearly always
    technique-tagged and high confidence: without them, a behaviour whose only
    inventory is 21 body-text hits looks identical to one with 47 tagged rules.
    """

    items: list[PriorRule]
    total_candidates: int
    strong: int
    weak: int
    technique_scope: int
    threat_scope: int


@dataclass(frozen=True)
class Workspace:
    entity_type: str
    entity_key: str
    label: str
    window: str
    articles: list[Article]
    behaviours: list[Behaviour]
    # Every article in the window, not just the capped page above.
    article_total: int = 0
    # Of those, the ones carrying at least one technique.
    article_contributed_total: int = 0
    # Categories the below-line behaviours need and the inventory does not have.
    missing_categories: list[str] = field(default_factory=list)
    # Rules resolving to the threat itself. They are candidates for every one of
    # its behaviours, so a technique with no tagged rule is still not "nothing
    # here" — the row said so and then opened onto 35 candidates.
    threat_prior_rules: int = 0
    threat_prior_rules_strong: int = 0
    # Exploitation context for the CVE face: severity/CVSS/EPSS/KEV/PoC state
    # plus affected products from cve_affected. None for every other face.
    cve: dict | None = None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _missing_categories(channels: list[str]) -> list[str]:
    """Telemetry categories the unmatched channels belong to.

    ``_expand_rule_token`` is private to detection_coverage because it is an
    implementation detail of the three-tier match, but it is the only thing that
    knows which category a channel comes from, and the divider is worthless
    without a name on it. Imported rather than duplicated so the two surfaces
    cannot drift apart.
    """
    cats: set[str] = set()
    for channel in channels:
        cats.update(_expand_rule_token(channel).categories)
    return sorted(cats)


def _source_label(url: str | None, feed_title: str | None) -> str:
    """Host of the article url, feed title as fallback — the outlet, not the row."""
    if url:
        host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if host:
            return host[4:] if host.startswith("www.") else host
    return feed_title or "unknown"


_ARTICLES_SQL = """
SELECT e.id, e.title, e.url, e.published_at, e.word_count, f.title AS feed_title,
       coalesce(array_agg(DISTINCT t.technique_id) FILTER (WHERE t.technique_id IS NOT NULL), '{{}}')
           AS technique_ids
FROM entries e
JOIN feeds f ON f.id = e.feed_id
JOIN {junction} j ON j.entry_id = e.id
LEFT JOIN entry_ttps et ON et.entry_id = e.id
LEFT JOIN ttps t ON t.id = et.ttp_id
WHERE j.{fk} = :entity_id AND e.published_at > :since
GROUP BY e.id, f.title
ORDER BY e.published_at DESC
LIMIT :article_limit
"""

# The article list is capped; the footnote that cites it is not allowed to be.
# Under "all" a busy actor has hundreds of entries and "40 articles" would be a
# lie told by a LIMIT.
_ARTICLE_TOTALS_SQL = """
SELECT count(*)                                            AS total,
       count(*) FILTER (WHERE e.id IN (
           SELECT et.entry_id FROM entry_ttps et
       ))                                                  AS contributed
FROM entries e
JOIN {junction} j ON j.entry_id = e.id
WHERE j.{fk} = :entity_id AND e.published_at > :since
"""

# first_seen is computed over the entity's whole history, not the window: a
# technique the threat has used for a year is not new tradecraft just because it
# was re-reported this week. Same definition the board's `new` count uses.
_BEHAVIOURS_SQL = """
WITH pairs AS (
    SELECT t.technique_id, t.technique_name, t.tactic, t.data_sources,
           e.id AS entry_id, e.published_at
    FROM entries e
    JOIN {junction} j ON j.entry_id = e.id
    JOIN entry_ttps et ON et.entry_id = e.id
    JOIN ttps t ON t.id = et.ttp_id
    WHERE j.{fk} = :entity_id
)
SELECT technique_id, technique_name, tactic, data_sources,
       min(published_at)                                              AS first_seen,
       count(DISTINCT entry_id) FILTER (WHERE published_at > :since)  AS entry_count
FROM pairs
GROUP BY technique_id, technique_name, tactic, data_sources
HAVING count(*) FILTER (WHERE published_at > :since) > 0
"""

# 8,785 of the 20,097 populated source_text values are the autolinker's
# "auto_link:T1059" provenance marker rather than a sentence. Rendering one as a
# quote would put a machine token where the analyst expects the article's words.
_QUOTES_SQL = """
SELECT t.technique_id, e.id, e.title, et.source_text, et.paragraph_indices, e.published_at,
       et.observable_type, et.observable_value, et.telemetry
FROM entries e
JOIN {junction} j ON j.entry_id = e.id
JOIN entry_ttps et ON et.entry_id = e.id
JOIN ttps t ON t.id = et.ttp_id
WHERE j.{fk} = :entity_id
  AND e.published_at > :since
  AND et.source_text IS NOT NULL
  AND et.source_text NOT LIKE 'auto\\_link:%'
ORDER BY e.published_at DESC
"""

# Candidate counts for the whole behaviour list in one pass, so the centre column
# does not issue a query per row.
_TECHNIQUE_RULE_COUNTS_SQL = text("""
SELECT entity_key,
       count(*)                                                   AS total,
       count(*) FILTER (WHERE confidence IN ('high', 'medium'))    AS strong
FROM rule_coverage
WHERE entity_type = :ttp_type AND entity_key = ANY(:keys)
GROUP BY entity_key
""")

# Both scopes in one read: rules that resolved to the behaviour, and rules that
# resolved to the threat itself. A signature-base rule whose title names APT29 is
# a candidate for any APT29 behaviour even though it carries no ATT&CK tag.
_PRIOR_RULES_SQL = text("""
SELECT r.id, r.title, r.rule_type, r.is_draft, r.license, r.data_sources, r.log_sources,
       coalesce(r.metadata->>'repo', 'local')          AS repo,
       coalesce(r.upstream_updated_at, r.updated_at)   AS maintained_at,
       rc.entity_type, rc.via, rc.confidence, rc.matched_on
FROM rule_coverage rc
JOIN detection_rules r ON r.id = rc.rule_id
WHERE (rc.entity_type = :ttp_type AND rc.entity_key = :technique_id)
   OR (rc.entity_type = :entity_type AND rc.entity_key = :entity_key)
-- Strong claims first, then draft-last inside each tier, so the cap below cuts
-- the weakest rows. T1059.001-class techniques resolve to hundreds of rules;
-- fetching them all to rank 40 in Python was an unbounded read per click.
ORDER BY CASE rc.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
         r.is_draft, r.title
LIMIT :cap
""")

# Hard ceiling on the prior-rules read. Python-side ranking still orders the
# final list; this only bounds what leaves the database.
_PRIOR_RULES_CAP = 300


@dataclass(frozen=True)
class ResolvedEntity:
    """One entity, addressed three ways.

    ``row_id`` joins the entry junction; ``coverage_key`` is what
    ``rule_coverage`` stores (the uuid for threats, the CVE id or technique id
    for the rest); ``label`` is what the header renders. Profiles pass uuids and
    the board passes canonical ids — both must land on the same workspace and
    the same saved sets, so everything downstream uses the canonical key.
    """

    row_id: str
    coverage_key: str
    label: str


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


async def resolve_entity(db: AsyncSession, entity_type: str, entity_key: str) -> ResolvedEntity | None:
    """Resolve a path key (uuid or canonical id) for any supported entity."""
    if entity_type in _ENTITY_TABLE:
        if not _is_uuid(entity_key):
            # The key is a path segment; a malformed one is a 404, not a DataError.
            return None
        table = _ENTITY_TABLE[entity_type]
        row = (
            await db.execute(text(f"SELECT name FROM {table} WHERE id = :id"), {"id": entity_key})  # noqa: S608
        ).first()
        return ResolvedEntity(entity_key, entity_key, row[0]) if row else None

    if entity_type == entity_types.CVE:
        if _is_uuid(entity_key):
            row = (
                await db.execute(
                    text("SELECT id, cve_id FROM cves WHERE id = :id"),
                    {"id": entity_key},
                )
            ).first()
        elif _CVE_RE.match(entity_key):
            row = (
                await db.execute(
                    text("SELECT id, cve_id FROM cves WHERE cve_id = :cid"),
                    {"cid": entity_key.upper()},
                )
            ).first()
        else:
            return None
        return ResolvedEntity(str(row[0]), row[1], row[1]) if row else None

    if entity_type == entity_types.TTP:
        if _is_uuid(entity_key):
            row = (
                await db.execute(
                    text("SELECT id, technique_id, technique_name FROM ttps WHERE id = :id"),
                    {"id": entity_key},
                )
            ).first()
        elif _TECHNIQUE_RE.match(entity_key):
            row = (
                await db.execute(
                    text("SELECT id, technique_id, technique_name FROM ttps WHERE technique_id = :tid"),
                    {"tid": entity_key.upper()},
                )
            ).first()
        else:
            return None
        return ResolvedEntity(str(row[0]), row[1], f"{row[1]} {row[2]}") if row else None

    return None


async def entity_label(db: AsyncSession, entity_type: str, entity_key: str) -> str | None:
    """Display name for a supported entity, or None when it does not exist."""
    resolved = await resolve_entity(db, entity_type, entity_key)
    return resolved.label if resolved else None


# Exploitation context for the CVE face — what a threat row's fold is to an
# actor, the exploitation state is to a vulnerability.
_CVE_CONTEXT_SQL = text("""
SELECT c.severity, c.cvss_score, c.epss_score, c.epss_percentile, c.is_kev,
       c.kev_date_added, c.kev_due_date, c.exploit_status, c.exploit_availability,
       c.github_poc_count, c.metasploit_module,
       coalesce((SELECT array_agg(DISTINCT coalesce(p.name, v.name))
                 FROM cve_affected ca
                 LEFT JOIN products p ON p.id = ca.product_id
                 LEFT JOIN vendors v ON v.id = ca.vendor_id
                 WHERE ca.cve_id = c.id AND coalesce(p.name, v.name) IS NOT NULL), '{}') AS affected
FROM cves c WHERE c.id = :id
""")


async def _cve_context(db: AsyncSession, row_id: str) -> dict | None:
    row = (await db.execute(_CVE_CONTEXT_SQL, {"id": row_id})).first()
    if row is None:
        return None
    return {
        "severity": row.severity,
        "cvss_score": float(row.cvss_score) if row.cvss_score is not None else None,
        "epss_score": float(row.epss_score) if row.epss_score is not None else None,
        "epss_percentile": (float(row.epss_percentile) if row.epss_percentile is not None else None),
        "is_kev": bool(row.is_kev),
        # Date columns, not datetimes — isoformat directly.
        "kev_date_added": (row.kev_date_added.isoformat() if row.kev_date_added else None),
        "kev_due_date": row.kev_due_date.isoformat() if row.kev_due_date else None,
        "exploit_status": row.exploit_status,
        "exploit_availability": row.exploit_availability,
        "github_poc_count": row.github_poc_count or 0,
        "metasploit_module": bool(row.metasploit_module),
        "affected": sorted(row.affected or [])[:12],
    }


def _behaviour_sort_key(b: Behaviour) -> tuple:
    # Below-line rows last; inside each half, new tradecraft first, then the
    # techniques the window reported most.
    return (b.below_line, not b.is_new, -b.entry_count, b.technique_id)


async def build_workspace(
    db: AsyncSession,
    entity_type: str,
    entity_key: str,
    window: str = "14d",
    article_limit: int = 40,
) -> Workspace | None:
    """Assemble the workspace for one entity over the window. No AI, no writes."""
    if entity_type not in ENTITY_SOURCES:
        return None
    resolved = await resolve_entity(db, entity_type, entity_key)
    if resolved is None:
        return None
    label = resolved.label

    junction, fk = ENTITY_SOURCES[entity_type]
    now = datetime.now(UTC)
    hours = WORKSPACE_WINDOW_HOURS.get(window, WORKSPACE_WINDOW_HOURS["14d"])
    since = EPOCH if hours is None else now - timedelta(hours=hours)
    # Under a bounded window the two floors are the same date, so `is_new` keeps
    # exactly the meaning it had before "all" existed.
    new_since = since if hours else now - timedelta(hours=NEW_HORIZON_HOURS)
    params = {"entity_id": resolved.row_id, "since": since}
    fmt = {"junction": junction, "fk": fk}

    profile = await get_available_telemetry(db)

    behaviour_rows = (
        await db.execute(text(_BEHAVIOURS_SQL.format(**fmt)), params)  # noqa: S608 — table names are literals above
    ).all()

    quotes: dict[str, list[Quote]] = {}
    for (
        tid,
        entry_id,
        entry_title,
        source_text,
        para,
        _published,
        obs_type,
        obs_value,
        quote_telemetry,
    ) in (
        await db.execute(text(_QUOTES_SQL.format(**fmt)), params)  # noqa: S608
    ).all():
        bucket = quotes.setdefault(tid, [])
        if len(bucket) < MAX_QUOTES:
            bucket.append(
                Quote(
                    entry_id=str(entry_id),
                    entry_title=entry_title,
                    text=source_text.strip(),
                    paragraph_indices=list(para or []),
                    observable_type=obs_type,
                    observable_value=obs_value,
                    telemetry=quote_telemetry,
                )
            )

    # The prior-rules panel reads technique scope OR threat scope; the row only
    # read technique scope, so a behaviour whose only inventory was threat-scope
    # rendered as "nothing here" and then opened onto 35 candidates. Carry the
    # threat-scope count on the workspace so the row can say so.
    threat_total, threat_strong = (
        await db.execute(
            text(
                "SELECT count(*), count(*) FILTER (WHERE confidence IN ('high','medium')) "
                "FROM rule_coverage WHERE entity_type = :etype AND entity_key = :ekey"
            ),
            {"etype": entity_type, "ekey": resolved.coverage_key},
        )
    ).one()

    technique_ids = [r[0] for r in behaviour_rows]
    counts: dict[str, tuple[int, int]] = {}
    if technique_ids:
        counts = {
            key: (total, strong)
            for key, total, strong in (
                await db.execute(
                    _TECHNIQUE_RULE_COUNTS_SQL,
                    {"ttp_type": entity_types.TTP, "keys": technique_ids},
                )
            ).all()
        }

    behaviours: list[Behaviour] = []
    for tid, name, tactic, data_sources, first_seen, entry_count in behaviour_rows:
        channels = classify_data_sources(list(data_sources or []), profile)
        tier = _best_tier([t for _, t in channels])
        missing = [ds for ds, t in channels if t is None]
        total, strong = counts.get(tid, (0, 0))
        behaviours.append(
            Behaviour(
                technique_id=tid,
                technique_name=name,
                tactic=tactic,
                entry_count=entry_count,
                first_seen=_iso(first_seen),
                is_new=bool(first_seen and first_seen > new_since),
                quotes=quotes.get(tid, []),
                channels=channels,
                tier=tier,
                missing_channels=missing,
                missing_categories=_missing_categories(missing),
                # A technique ATT&CK never gave channels for (342 of 1,198) is
                # unassessed, not unsourced — it stays above the line rather than
                # being counted as telemetry we do not have.
                below_line=bool(channels) and tier is None,
                prior_rules=total,
                prior_rules_strong=strong,
            )
        )
    behaviours.sort(key=_behaviour_sort_key)

    # The technique face is a bench for ONE technique. The junction join above
    # returns everything co-extracted alongside it; keep only the technique
    # itself so the centre column is its coverage, not its neighbourhood.
    if entity_type == entity_types.TTP:
        behaviours = [b for b in behaviours if b.technique_id == resolved.coverage_key]

    new_ids = {b.technique_id for b in behaviours if b.is_new}
    articles = [
        Article(
            entry_id=str(entry_id),
            title=title,
            url=url,
            source=_source_label(url, feed_title),
            published_at=_iso(published_at),
            word_count=word_count,
            technique_count=len(tids),
            new_technique_count=sum(1 for t in tids if t in new_ids),
            contributed=bool(tids),
        )
        for entry_id, title, url, published_at, word_count, feed_title, tids in (
            await db.execute(
                text(_ARTICLES_SQL.format(**fmt)),  # noqa: S608
                {**params, "article_limit": article_limit},
            )
        ).all()
    ]

    article_total, article_contributed_total = (
        await db.execute(text(_ARTICLE_TOTALS_SQL.format(**fmt)), params)  # noqa: S608
    ).one()

    missing_categories = sorted({c for b in behaviours if b.below_line for c in b.missing_categories})

    return Workspace(
        entity_type=entity_type,
        entity_key=resolved.coverage_key,
        label=label,
        window=window,
        articles=articles,
        behaviours=behaviours,
        article_total=article_total,
        article_contributed_total=article_contributed_total,
        missing_categories=missing_categories,
        threat_prior_rules=threat_total,
        threat_prior_rules_strong=threat_strong,
        cve=(await _cve_context(db, resolved.row_id) if entity_type == entity_types.CVE else None),
    )


def _best_tier(tiers: list[str | None]) -> str | None:
    """Strongest tier any of a technique's channels reached."""
    best: str | None = None
    for tier in tiers:
        if _TIER_RANK[tier] < _TIER_RANK[best]:
            best = tier
    return best


class _RuleShim:
    """Duck-type for telemetry_tokens_from_rule, which reads four attributes.

    Prior rules come back as a raw row rather than a DetectionRule so the list
    does not load 36 rule bodies to render three fields each.
    """

    __slots__ = ("data_sources", "log_sources", "rule_type")

    def __init__(self, rule_type: str, data_sources, log_sources):
        self.rule_type = rule_type
        self.data_sources = data_sources
        self.log_sources = log_sources


async def get_prior_rules(
    db: AsyncSession,
    entity_type: str,
    entity_key: str,
    technique_id: str,
    limit: int = 40,
    profile: TelemetryProfile | None = None,
) -> PriorRuleSet:
    """Candidate rules for one behaviour, strongest telemetry tier first."""
    if entity_type not in ENTITY_SOURCES:
        return PriorRuleSet([], 0, 0, 0, 0, 0)
    resolved = await resolve_entity(db, entity_type, entity_key)
    if resolved is None:
        return PriorRuleSet([], 0, 0, 0, 0, 0)
    if profile is None:
        profile = await get_available_telemetry(db)

    rows = (
        await db.execute(
            _PRIOR_RULES_SQL,
            {
                "ttp_type": entity_types.TTP,
                "technique_id": technique_id,
                "entity_type": entity_type,
                "entity_key": resolved.coverage_key,
                "cap": _PRIOR_RULES_CAP,
            },
        )
    ).all()

    seen: dict[str, PriorRule] = {}
    for row in rows:
        required = telemetry_tokens_from_rule(_RuleShim(row.rule_type, row.data_sources, row.log_sources))
        classified = classify_data_sources(required, profile)
        candidate = PriorRule(
            rule_id=str(row.id),
            title=row.title,
            rule_type=row.rule_type,
            repo=row.repo,
            license=row.license,
            is_draft=row.is_draft,
            scope="technique" if row.entity_type == entity_types.TTP else "threat",
            via=row.via,
            confidence=row.confidence,
            matched_on=row.matched_on,
            tier=_best_tier([t for _, t in classified]) if classified else None,
            required=required,
            missing=[ds for ds, t in classified if t is None],
            maintained_at=_iso(row.maintained_at),
        )
        # A rule can resolve twice — tagged with the technique AND naming the
        # threat. Keep the stronger claim so one rule is one row.
        existing = seen.get(candidate.rule_id)
        if existing is None or _rule_sort_key(candidate) < _rule_sort_key(existing):
            seen[candidate.rule_id] = candidate

    ranked = sorted(seen.values(), key=_rule_sort_key)
    return PriorRuleSet(
        items=ranked[:limit],
        total_candidates=len(ranked),
        strong=sum(1 for r in ranked if r.confidence in ("high", "medium")),
        weak=sum(1 for r in ranked if r.confidence == "low"),
        technique_scope=sum(1 for r in ranked if r.scope == "technique"),
        threat_scope=sum(1 for r in ranked if r.scope == "threat"),
    )


def _rule_sort_key(rule: PriorRule) -> tuple:
    # Telemetry first — a rule that cannot fire here is not the one to adopt,
    # however well it matched — then evidence strength, then the tagged scope.
    #
    # The last two keys exist because the first four tie constantly: T1486's 27
    # candidates are all source-tier, all high confidence and all technique-
    # tagged, so without them the "best" rule was whichever one started with an
    # A. Unmet channels split a clean fire from a partial one, and maintenance
    # date splits a rule the community still touches from one abandoned in 2022.
    return (
        _TIER_RANK[rule.tier],
        len(rule.missing),
        _CONFIDENCE_RANK.get(rule.confidence, 3),
        0 if rule.scope == "technique" else 1,
        rule.is_draft,
        _staleness(rule.maintained_at),
        rule.title.lower(),
    )


def _staleness(iso: str | None) -> float:
    """Negated epoch seconds, so ascending order reads newest-maintained first.

    An undated rule sorts last rather than being treated as ancient — we do not
    know that it is stale, only that the importer recorded no date for it.
    """
    if not iso:
        return float("inf")
    try:
        return -datetime.fromisoformat(iso).timestamp()
    except ValueError:
        return float("inf")


async def resolve_set_items(db: AsyncSession, items: list[dict]) -> list[dict]:
    """Carry repo, licence and format onto every adopted/extended rule.

    Provenance is read from the library at save time rather than trusted from
    the client, so an adopted rule keeps its attribution wherever the set is
    later exported.
    """
    rule_ids = [i["rule_id"] for i in items if i.get("rule_id")]
    facts: dict[str, dict] = {}
    if rule_ids:
        rows = (
            await db.execute(
                text("""
                    SELECT id, title, rule_type, license, is_draft,
                           coalesce(metadata->>'repo', 'local') AS repo, "references"
                    FROM detection_rules WHERE id = ANY(:ids)
                    """),
                {"ids": rule_ids},
            )
        ).all()
        facts = {
            str(r.id): {
                "title": r.title,
                "rule_type": r.rule_type,
                "license": r.license,
                "is_draft": r.is_draft,
                "repo": r.repo,
                "references": list(r.references or []),
            }
            for r in rows
        }

    resolved: list[dict] = []
    for item in items:
        entry = {
            "op": item["op"],
            "rule_id": str(item["rule_id"]) if item.get("rule_id") else None,
            "technique_id": item.get("technique_id"),
            "title": item.get("title") or "",
            "note": item.get("note"),
            # skip only: why the rule was passed over — exports render it as a
            # known gap, which is the whole point of persisting the judgement.
            "reason": item.get("reason"),
            "rule_type": item.get("rule_type"),
            "repo": None,
            "license": None,
        }
        if (rid := item.get("rule_id")) and (fact := facts.get(str(rid))):
            entry.update(
                {
                    "title": item.get("title") or fact["title"],
                    # The library wins for a rule that exists. Taking the
                    # client's value first let an adopted splunk_spl rule be
                    # persisted as "kql", which is a lie about somebody else's
                    # work that then rides the export.
                    "rule_type": fact["rule_type"],
                    "license": fact["license"],
                    "repo": fact["repo"],
                    "is_draft": fact["is_draft"],
                    "references": fact["references"],
                }
            )
        resolved.append(entry)
    return resolved


async def save_set(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_key: str,
    label: str,
    window: str,
    title: str,
    items: list[dict],
    entry_ids: list[uuid.UUID],
    summary_id: uuid.UUID | None = None,
) -> DetectionSummary:
    """Persist the assembled set into ``detection_summaries``.

    The table's other writer generates with AI first and persists second
    (`POST /intelligence/detection-summaries`), which is why it has never held a
    row — nobody wants a 5-second provider call in the middle of assembling a
    set. The same store, written directly: the set is the user's own work, and
    the AI path stays a separate, explicit action.
    """
    resolved = await resolve_set_items(db, items)
    content = {
        "kind": SET_KIND,
        "entity_type": entity_type,
        "entity_key": entity_key,
        "label": label,
        "window": window,
        "items": resolved,
    }

    summary = None
    if summary_id is not None:
        summary = await db.get(DetectionSummary, summary_id)
        # An id arriving from the client is a claim, not a capability. Without
        # these three checks any authenticated caller can name any row in
        # detection_summaries and have its title, entry_ids, analysis_focus and
        # summary_content overwritten — including AI summaries written by the
        # other writer of this table, whose output is not reproducible.
        if summary is not None:
            content_kind = (summary.summary_content or {}).get("kind")
            same_entity = (summary.summary_content or {}).get("entity_key") == entity_key and (
                summary.summary_content or {}
            ).get("entity_type") == entity_type
            if content_kind != SET_KIND or not same_entity or summary.created_by != user_id:
                raise AppError(
                    code="not_found",
                    message="No coverage set with that id for this entity",
                    status_code=404,
                )
    if summary is None:
        summary = DetectionSummary(created_by=user_id)
        db.add(summary)
    summary.title = title
    summary.entry_ids = list(entry_ids)
    summary.analysis_focus = "coverage_set"
    summary.summary_content = content

    await db.flush()
    await db.refresh(summary)
    await db.commit()
    return summary


async def list_sets(
    db: AsyncSession,
    user_id: uuid.UUID,
    entity_type: str,
    entity_key: str,
    limit: int = 20,
) -> list[DetectionSummary]:
    """The caller's saved sets for one threat, newest first.

    Scoped by created_by: a set is working notes, and save_set only lets you
    overwrite your own, so listing someone else's would only ever produce ids
    you cannot use.
    """
    rows = (
        (
            await db.execute(
                text("""
                SELECT id FROM detection_summaries
                WHERE summary_content->>'kind' = :kind
                  AND summary_content->>'entity_type' = :etype
                  AND summary_content->>'entity_key' = :ekey
                  AND created_by = :uid
                ORDER BY created_at DESC
                LIMIT :limit
                """),
                {
                    "kind": SET_KIND,
                    "etype": entity_type,
                    "ekey": entity_key,
                    "uid": user_id,
                    "limit": limit,
                },
            )
        )
        .scalars()
        .all()
    )
    out = []
    for sid in rows:
        if summary := await db.get(DetectionSummary, sid):
            out.append(summary)
    return out


# ── Package writers ──────────────────────────────────────────────────────────
# The deliverable a detection engineer hands over is a write-up plus a ruleset.
# Both fall out of a saved set: the markdown report cites its evidence and
# renders skips as known gaps; the bundle carries every rule body with its
# attribution header. No AI, no new serialisation formats — the set content and
# the library rows are the only inputs.

_RULE_EXT: dict[str, str] = {
    "sigma": "yml",
    "yara": "yar",
    "kql": "kql",
    "elastic_ql": "json",
    "splunk_spl": "spl",
    "crowdstrike_ql": "cql",
    "nuclei": "yaml",
    "snort_suricata": "rules",
    "panther": "py",
}

_COMMENT: dict[str, str] = {
    "sigma": "#",
    "yara": "//",
    "kql": "//",
    "elastic_ql": "//",
    "splunk_spl": "```",
    "crowdstrike_ql": "//",
    "nuclei": "#",
    "snort_suricata": "#",
    "panther": "#",
}


def _safe_filename(title: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9 _-]+", "", title).strip().replace(" ", "_")
    return (cleaned or "rule")[:80]


async def _set_rules(db: AsyncSession, content: dict) -> dict[str, dict]:
    """Rule bodies + provenance for every item in the set, one query."""
    rule_ids = [i["rule_id"] for i in content.get("items", []) if i.get("rule_id")]
    if not rule_ids:
        return {}
    rows = (
        await db.execute(
            text("""
                SELECT id, title, rule_type, rule_content, description, license, is_draft,
                       derived_from, coalesce(metadata->>'repo', 'local') AS repo,
                       coalesce(metadata->>'commit_author', '') AS author
                FROM detection_rules WHERE id = ANY(:ids)
                """),
            {"ids": rule_ids},
        )
    ).all()
    return {str(r.id): dict(r._mapping) for r in rows}


async def render_set_markdown(db: AsyncSession, summary: DetectionSummary) -> str:
    """The research report: what happened, what covers it, what was passed over.

    Every claim carries its source — the ¶-cited quotes are what
    entry_ttps.source_text was stored for.
    """
    content = summary.summary_content or {}
    label = content.get("label", "threat")
    window = content.get("window", "14d")
    items = content.get("items", [])
    rules = await _set_rules(db, content)

    ws = await build_workspace(db, content.get("entity_type", ""), content.get("entity_key", ""), window=window)

    lines = [
        f"# {summary.title}",
        "",
        f"Coverage set for **{label}** over the last {window}. ",
    ]

    if ws and ws.articles:
        lines += ["## Intelligence", ""]
        for a in ws.articles[:12]:
            src = f" — {a.source}" if a.source else ""
            link = f"[{a.title}]({a.url})" if a.url else a.title
            lines.append(f"- {link}{src}" + (f" · {a.published_at[:10]}" if a.published_at else ""))
        lines.append("")

    if ws and ws.behaviours:
        lines += ["## Behaviours", ""]
        for b in ws.behaviours:
            flag = " *(new this window)*" if b.is_new else ""
            gap = " — **below the line: no matching telemetry source**" if b.below_line else ""
            lines.append(f"### {b.technique_id} {b.technique_name}{flag}{gap}")
            for q in b.quotes:
                cite = f"{q.entry_title}" + (f" ¶{q.paragraph_indices[0]}" if q.paragraph_indices else "")
                lines.append(f'> "{q.text}" — {cite}')
                if q.observable_value:
                    lines.append(f"> observable ({q.observable_type or 'artefact'}): `{q.observable_value}`")
            lines.append("")

    active = [i for i in items if i.get("op") != "skip"]
    skips = [i for i in items if i.get("op") == "skip"]

    if active:
        lines += [
            "## Ruleset",
            "",
            "| Action | Rule | Format | Source | Licence |",
            "|---|---|---|---|---|",
        ]
        for i in active:
            fact = rules.get(str(i.get("rule_id") or ""), {})
            lines.append(
                f"| {i['op']} | {i.get('title') or fact.get('title', '—')} "
                f"| {i.get('rule_type') or fact.get('rule_type', '—')} "
                f"| {i.get('repo') or fact.get('repo', 'local')} "
                f"| {i.get('license') or fact.get('license') or '—'} |"
            )
        lines.append("")

    if skips:
        lines += ["## Known gaps", ""]
        for i in skips:
            reason = i.get("reason") or "skipped"
            lines.append(f"- **{i.get('title', 'rule')}** — {reason}")
        lines += [
            "",
            "_A skip is a judgement, recorded so the next person doesn't re-litigate it._",
            "",
        ]

    if ws and ws.missing_categories:
        lines += [
            "## Collection gaps",
            "",
            "Behaviours below the line need telemetry the inventory does not have: "
            + ", ".join(c.replace("_", " ") for c in ws.missing_categories)
            + ". That is a sourcing job, not a detection gap.",
            "",
        ]

    return "\n".join(lines)


def _attribution_header(fact: dict) -> str:
    c = _COMMENT.get(fact.get("rule_type", ""), "#")
    parts = [f"{c} {fact.get('title', 'rule')}"]
    parts.append(f"{c} source: {fact.get('repo', 'local')}" + (f" · {fact['author']}" if fact.get("author") else ""))
    if fact.get("license"):
        parts.append(f"{c} license: {fact['license']}")
    if fact.get("derived_from"):
        parts.append(f"{c} extended from upstream rule {fact['derived_from']}")
    parts.append(f"{c} exported from IntelFeed")
    return "\n".join(parts) + "\n\n"


async def build_set_bundle(db: AsyncSession, summary: DetectionSummary) -> list[tuple[str, str]]:
    """(path, content) pairs for the .zip: one file per rule, grouped by format,
    attribution header on every one, manifest on top."""
    content = summary.summary_content or {}
    rules = await _set_rules(db, content)
    files: list[tuple[str, str]] = []
    seen: set[str] = set()

    for item in content.get("items", []):
        if item.get("op") == "skip":
            continue
        fact = rules.get(str(item.get("rule_id") or ""))
        if not fact or fact["id"] is None or str(fact["id"]) in seen:
            continue
        seen.add(str(fact["id"]))
        rtype = fact["rule_type"]
        path = f"rules/{rtype}/{_safe_filename(fact['title'])}.{_RULE_EXT.get(rtype, 'txt')}"
        files.append((path, _attribution_header(fact) + (fact["rule_content"] or "")))

    manifest = await render_set_markdown(db, summary)
    files.insert(0, ("MANIFEST.md", manifest))
    return files
