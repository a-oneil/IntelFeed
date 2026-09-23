"""Intel → Rules threat board — Recently reported, ranked.

Replaces the coverage board's ranking, which ordered by ``count(distinct
Entry.id)`` over the window. That count is ``feed_echo``: the signal the entry
scorer subtracts, because it measures how many aggregators re-reported a story.
On real data it returns a Patch-Tuesday batch every week.

Three counts per threat, kept separate and never blended into a score:

``attention``   distinct source domains in the window. The independent-outlet
                unit, not the feed-row unit — one outlet publishing through four
                feeds is one source. Mirrors ``_source_key`` in
                ``app.intelligence.signals``.
``new``         techniques whose first-ever appearance for this threat falls
                inside the window. This is the "is there anything to write?"
                number.
``on_record``   distinct techniques ever extracted for this threat. A loud week
                with no new tradecraft still leaves this body of work unaudited,
                which is a different job, not a lower-priority one.
``stories``     distinct *stories* behind those outlets, from story threads. One
                wave carried by eleven outlets is one story; three separate
                intrusions carried by five are three. This is what the ranking
                counts, because "how many things happened" is the question a
                triage board is actually asking. Where no thread holds an
                article it contributes its own source domain instead, so a
                corpus with no embeddings scores exactly as it did before.

A coverage percentage is deliberately absent. ``source_ttps`` tag equality
returns 88-90% for every actor in the database (median 90 over the 147 actors
with >= 10 observed techniques), so it carries no information. ``prior_rules``
is an inventory to open, not a verdict.
"""

import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import entity_types

# Windows the board offers. Anything shorter than a week loses slow-moving
# research; anything longer stops being "what the field is working on".
WINDOW_HOURS: dict[str, int] = {"7d": 168, "14d": 336, "30d": 720}

# Entity names that are categories rather than threats. These reach the top of
# any outlet-count ranking ("Infostealer": 32 outlets, 73 entries) and are
# extraction noise, not intelligence. Held out of the ranking and surfaced to
# the merge queue instead of silently dropped.
GENERIC_ENTITY_NAMES: frozenset[str] = frozenset(
    {
        "infostealer",
        "ransomware",
        "malware",
        "backdoor",
        "trojan",
        "loader",
        "stealer",
        "botnet",
        "rootkit",
        "wiper",
        "webshell",
        "web shell",
        "cryptominer",
        "spyware",
        "adware",
        "worm",
        "keylogger",
        "rat",
        "apt",
        "phishing kit",
        "exploit kit",
        # Detection formats the extractor has taken for malware families.
        "sigma",
        "yara",
        "snort",
        "suricata",
        "nuclei",
    }
)

# Ranking weight. Story units alone put an arrest story at the top of the week;
# new tradecraft alone buries a genuinely hot threat whose techniques were
# already on record. Both counts stay visible in the payload so a bad rank is
# arguable rather than opaque.
#
# _W_ATTENTION keeps its name and its value because story units *are* the
# attention unit once threading has an opinion: a thread replaces the outlets
# that carried it, and an article no thread holds still counts as its domain.
_W_ATTENTION = 1.0
_W_NEW = 2.5

# Outlets still say something after the story count has said the main thing —
# eleven outlets on one wave is more corroborated than two. Capped, because
# uncapped it is feed_echo again under another name.
_W_OUTLET = 0.25
_OUTLET_CAP = 2.0

# A pseudo entity type: a row backed by a story thread that resolved to no
# actor, malware or CVE. Not in app.entity_types on purpose — nothing in the
# database is keyed by it, and it must never reach an entity lookup.
STORY = "story"

# Two rows fold into one when a single thread holds this much of each row's
# window coverage. An operator row and a payload row drawing from the same
# story are one job; a threat that merely appears in someone else's story is
# not, which is what the share floor and the minimum overlap enforce.
THREAD_MERGE_SHARE = 0.75
THREAD_MERGE_MIN_ENTRIES = 2

# A thread speaks for a row — supplies its headline, its beat count, and the
# story its precedent is measured from — only once it holds half of what the
# row was written about in the window. Below that it is one of several stories
# the row appears in, and the article that opened it is not this row's lede.
THREAD_LEAD_SHARE = 0.5

# An entity row's tradecraft term counts techniques first seen *for that
# entity*. A story row has no entity to have seen them before, so every
# technique on it is new to it — which is the honest analogue, and without it
# a story row can only ever score its beats and sit at the floor of the board
# no matter what it carries. Capped, so that a technique-dense write-up cannot
# buy the top of the board on volume alone.
STORY_TECHNIQUE_CAP = 6

# Row types whose lead article a thread can speak for.
_LEAD_TYPES = (entity_types.THREAT_ACTOR, entity_types.MALWARE, entity_types.CVE)


@dataclass(frozen=True)
class ThreatRow:
    entity_type: str
    entity_key: str
    label: str
    facets: list[str]  # ["threat_actor", "malware"] when the name exists as both
    attention: int
    new_techniques: int
    on_record: int
    prior_rules: int
    # High/medium only. A story:-tag or body-text hit is real inventory but weak
    # evidence, and one of them must not read as "this threat is covered".
    prior_rules_strong: int
    prior_rule_repos: dict[str, int]
    last_seen: str | None
    state: str
    is_generic: bool
    score: float
    # The evidence a collapsed briefing row leads with. Filled for the final
    # ranked rows only — computing headlines for every candidate would be wasted
    # work on rows the LIMIT is about to drop.
    # Distinct stories behind the window's coverage: one per thread, plus one
    # per source domain no thread has claimed. Equal to ``attention`` when
    # nothing is threaded, which is what makes this safe to rank on.
    stories: int = 0
    # Window articles this row's stories folded — articles minus their
    # representatives. The caption's "14 echoes folded".
    echoes_folded: int = 0
    articles: int = 0
    headline: dict | None = None  # {entry_id, title, url, source, published_at}
    sources: list[str] = field(default_factory=list)  # top distinct hosts, for "why"
    # In-window technique links carrying a real observable sentence (source_text
    # that is not an autolinker marker). This is the "is there something to
    # write" number the counts can't see: fresh observables on an old technique
    # are writable work even when new_techniques is zero.
    writable_observables: int = 0
    # ── Vulnerability-row extras. A CVE is a board citizen, not a transplant
    # from another page: same row shape, same state machine, its exploitation
    # state where an actor row has its tradecraft counts. None/False elsewhere.
    product: str | None = None
    in_stack: bool = False
    is_kev: bool = False
    cvss_score: float | None = None
    epss_score: float | None = None
    exploit_status: str | None = None
    # blind (rule exists, telemetry doesn't) | no_rule | defended — from
    # classify_cves against the enabled inventory, same as Vendor Watch used.
    posture: str | None = None
    # ── Story-thread context. The thread holding most of this row's window
    # coverage: its slug opens the story, its beat count says whether the
    # story is still developing or merely being repeated.
    thread_slug: str | None = None
    thread_title: str | None = None
    beats: int = 0
    # Rows this one absorbed because one thread holds both — {entity_type,
    # entity_key, label}. The name-merge path leaves this empty; it folds two
    # spellings of one name, which needs no attribution.
    merged_from: list[dict] = field(default_factory=list)
    # CVE rows are keyed by cve_id everywhere (rule_coverage, state, workspace)
    # but the entity profile routes on the row uuid — carry it for navigation.
    profile_id: str | None = None
    # Your surface, or the landscape? A CVE affecting nothing you run and
    # nothing you can observe is context, not your write-queue — it sorts
    # below a divider, the same honesty as the workspace's below-the-line
    # rule. Threat rows are always on-surface.
    on_surface: bool = True

    @property
    def is_story(self) -> bool:
        """A thread the board can show but extraction never named."""
        return self.entity_type == STORY

    @property
    def action(self) -> str:
        """The job this row represents, derived from the counts.

        Named rather than generic: today every row renders "Author from intel",
        and on an actor row that navigates to /workbench/rule/new with no
        parameters at all.
        """
        if self.is_generic:
            return "merge"
        if self.entity_type == STORY:
            # Nothing to extend or audit against: the story has no entity yet.
            # Collecting it is the job — read it, and name what it is about.
            return "collect"
        if self.entity_type == entity_types.CVE:
            # Posture decides the verb: nothing authored → write; authored but
            # blocked by missing telemetry → collect (a sourcing job, the same
            # honesty as the workspace's below-the-line divider); authored and
            # fireable → adopt.
            if self.prior_rules == 0:
                return "write"
            if self.posture == "blind":
                return "collect"
            return "adopt"
        if self.prior_rules_strong == 0:
            # Weak-only inventory is worth opening, but it is not something to
            # extend — there is no rule here that names this threat outright.
            return "diff" if self.prior_rules else "write"
        if self.new_techniques > 0:
            return "extend"
        if self.on_record > 0:
            return "audit"
        return "review"


# Collective nouns and malware-class words the same threat is written with and
# without. Stripped before folding facets together, or one threat holds two rows
# and splits its own evidence: "Medusa Group" (actor) / "MEDUSA" (malware),
# "The Gentlemen" (actor) / "Gentlemen Ransomware" (malware), "Shai-Hulud" /
# "Mini Shai-Hulud worm" — the last pair reports the same 65 techniques on
# record from two rows.
_COLLECTIVE_SUFFIXES = (
    "group",
    "gang",
    "team",
    "crew",
    "collective",
    "syndicate",
    "ransomware",
    "worm",
    "stealer",
    "loader",
    "backdoor",
)

# Articles and size qualifiers that vary between write-ups of one threat.
_LEADING_NOISE = ("the", "mini", "new", "a")

# Stripping is only safe while it leaves something distinctive. "The Com" and
# "Com Loader" both reduce to "com", which would fold two unrelated threats into
# one row; below this length the unstripped name is the safer key.
_MIN_STEM = 4

# Entity names that are an identifier for something else entirely — a CVE id
# extracted as a malware family, for instance. Extraction artefacts, not threats.
_ID_SHAPED = re.compile(r"^(cve-\d{4}-\d{4,}|t\d{4}(\.\d{3})?|s\d{4}|g\d{4})$", re.I)


def _normalize_name(name: str) -> str:
    norm = re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()
    full = "".join(norm.split())
    parts = norm.split()
    while len(parts) > 1 and parts[-1] in _COLLECTIVE_SUFFIXES:
        parts.pop()
    while len(parts) > 1 and parts[0] in _LEADING_NOISE:
        parts.pop(0)
    stem = "".join(parts)
    return stem if len(stem) >= _MIN_STEM else full


_GENERIC_NORMALIZED: frozenset[str] = frozenset(_normalize_name(n) for n in GENERIC_ENTITY_NAMES)


# One threat is one row. Qilin, Cl0p, Settra, Medusa and Shai-Hulud each exist
# in both threat_actors and malware_families today, so each splits its own
# evidence across two rows and neither reaches its true outlet count.
_RANKING_SQL = text("""
WITH src AS (
    SELECT e.id                                              AS entry_id,
           -- Host of the ARTICLE url, feed id as fallback. Same unit as
           -- _source_key in app.intelligence.signals: counting feed ids lets one
           -- outlet publishing through four feeds read as four sources.
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text))                                  AS source_key,
           e.published_at
    FROM entries e
    JOIN feeds f ON f.id = e.feed_id
    WHERE e.published_at > :since
      -- Repo mirrors are ingested as feeds; their commits are not coverage.
      AND f.title !~* 'rules|signatures|templates|detections|security content'
),
links AS (
    SELECT :actor_type AS entity_type, a.id::text AS entity_key, a.name AS label,
           s.entry_id, s.source_key, s.published_at
    FROM threat_actors a
    JOIN entry_threat_actors ea ON ea.threat_actor_id = a.id
    JOIN src s ON s.entry_id = ea.entry_id
    UNION ALL
    SELECT :malware_type, m.id::text, m.name,
           s.entry_id, s.source_key, s.published_at
    FROM malware_families m
    JOIN entry_malware em ON em.malware_family_id = m.id
    JOIN src s ON s.entry_id = em.entry_id
),
agg AS (
    SELECT entity_type, entity_key, label,
           count(DISTINCT source_key) AS attention,
           count(DISTINCT entry_id)   AS entries,
           max(published_at)          AS last_seen
    FROM links
    GROUP BY 1, 2, 3
)
SELECT entity_type, entity_key, label, attention, entries, last_seen
FROM agg
WHERE attention >= :min_attention
ORDER BY attention DESC
LIMIT :candidate_limit
""")

# Second candidate source: entities whose window entries carry many technique
# links. The attention-ordered cut above can drop a quiet threat with heavy new
# tradecraft — the exact case _W_NEW exists to promote — before it is ever
# scored. Window technique volume is a cheap proxy for "might have first-seen
# pairs" (new tradecraft requires window technique activity by definition);
# the real first-seen test still happens in _TECHNIQUE_SQL for every candidate.
_TECHNIQUE_CANDIDATE_SQL = text("""
WITH src AS (
    SELECT e.id AS entry_id,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text))                                  AS source_key,
           e.published_at
    FROM entries e
    JOIN feeds f ON f.id = e.feed_id
    WHERE e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
      AND EXISTS (SELECT 1 FROM entry_ttps j WHERE j.entry_id = e.id)
),
links AS (
    SELECT :actor_type AS entity_type, a.id::text AS entity_key, a.name AS label,
           s.entry_id, s.source_key, s.published_at
    FROM threat_actors a
    JOIN entry_threat_actors ea ON ea.threat_actor_id = a.id
    JOIN src s ON s.entry_id = ea.entry_id
    UNION ALL
    SELECT :malware_type, m.id::text, m.name,
           s.entry_id, s.source_key, s.published_at
    FROM malware_families m
    JOIN entry_malware em ON em.malware_family_id = m.id
    JOIN src s ON s.entry_id = em.entry_id
)
SELECT l.entity_type, l.entity_key, l.label,
       count(DISTINCT l.source_key) AS attention,
       count(DISTINCT l.entry_id)   AS entries,
       max(l.published_at)          AS last_seen,
       count(DISTINCT j.ttp_id)     AS window_techniques
FROM links l
JOIN entry_ttps j ON j.entry_id = l.entry_id
GROUP BY 1, 2, 3
HAVING count(DISTINCT l.source_key) >= :min_attention
ORDER BY count(DISTINCT j.ttp_id) DESC
LIMIT :candidate_limit
""")

# ── Story threads ───────────────────────────────────────────────────────────
# What the ranking counts. ``story_units`` is one per thread holding this row's
# window coverage, plus one per source domain no thread has claimed — so a
# corpus with no embeddings returns exactly the old attention count, and a
# threaded corpus collapses a wave of re-reports into the one story it is.
# ``echoes_folded`` is what that collapse hid, kept visible in the caption.
#
# A domain that carried one of the threads is *not* also counted for its
# unthreaded articles: it is already represented by that thread, and counting
# it twice let the story count climb above the outlet count, which is the one
# thing this number must never do.
_STORY_UNITS_SQL = text("""
WITH src AS (
    SELECT e.id AS entry_id,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source_key
    FROM entries e
    JOIN feeds f ON f.id = e.feed_id
    WHERE e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
),
links AS (
    SELECT :actor_type AS entity_type, a.id::text AS entity_key, s.entry_id, s.source_key
    FROM threat_actors a
    JOIN entry_threat_actors ea ON ea.threat_actor_id = a.id
    JOIN src s ON s.entry_id = ea.entry_id
    WHERE a.id::text = ANY(:actor_keys)
    UNION ALL
    SELECT :malware_type, m.id::text, s.entry_id, s.source_key
    FROM malware_families m
    JOIN entry_malware em ON em.malware_family_id = m.id
    JOIN src s ON s.entry_id = em.entry_id
    WHERE m.id::text = ANY(:malware_keys)
),
joined AS (
    SELECT l.entity_type, l.entity_key, l.entry_id, l.source_key, ste.thread_id
    FROM links l
    LEFT JOIN story_thread_entries ste ON ste.entry_id = l.entry_id
),
per_thread AS (
    SELECT entity_type, entity_key, thread_id, count(DISTINCT entry_id) AS members
    FROM joined
    WHERE thread_id IS NOT NULL
    GROUP BY 1, 2, 3
),
dominant AS (
    SELECT DISTINCT ON (entity_type, entity_key)
           entity_type, entity_key, thread_id, members
    FROM per_thread
    ORDER BY entity_type, entity_key, members DESC, thread_id
)
SELECT j.entity_type, j.entity_key,
       count(DISTINCT j.thread_id)
         + count(DISTINCT j.source_key) FILTER (
               WHERE j.thread_id IS NULL AND NOT EXISTS (
                   SELECT 1 FROM joined t
                   WHERE t.entity_type = j.entity_type AND t.entity_key = j.entity_key
                     AND t.thread_id IS NOT NULL AND t.source_key = j.source_key)
           )                                                                 AS story_units,
       count(DISTINCT j.entry_id) FILTER (WHERE j.thread_id IS NOT NULL)
         - count(DISTINCT j.thread_id)                                       AS echoes_folded,
       d.thread_id                                                           AS dominant_thread_id,
       d.members                                                             AS dominant_members,
       t.slug                                                                AS thread_slug,
       t.title                                                               AS thread_title
FROM joined j
LEFT JOIN dominant d ON d.entity_type = j.entity_type AND d.entity_key = j.entity_key
LEFT JOIN story_threads t ON t.id = d.thread_id
GROUP BY j.entity_type, j.entity_key, d.thread_id, d.members, t.slug, t.title
""")

# The same question for CVE rows, which are keyed by cve_id rather than a uuid.
_CVE_STORY_UNITS_SQL = text("""
WITH src AS (
    SELECT e.id AS entry_id,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source_key
    FROM entries e
    JOIN feeds f ON f.id = e.feed_id
    WHERE e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
),
joined AS (
    SELECT c.cve_id AS entity_key, s.entry_id, s.source_key, ste.thread_id
    FROM cves c
    JOIN entry_cves ec ON ec.cve_id = c.id
    JOIN src s ON s.entry_id = ec.entry_id
    LEFT JOIN story_thread_entries ste ON ste.entry_id = s.entry_id
    WHERE c.cve_id = ANY(:keys)
),
per_thread AS (
    SELECT entity_key, thread_id, count(DISTINCT entry_id) AS members
    FROM joined
    WHERE thread_id IS NOT NULL
    GROUP BY 1, 2
),
dominant AS (
    SELECT DISTINCT ON (entity_key) entity_key, thread_id, members
    FROM per_thread
    ORDER BY entity_key, members DESC, thread_id
)
SELECT j.entity_key,
       count(DISTINCT j.thread_id)
         + count(DISTINCT j.source_key) FILTER (
               WHERE j.thread_id IS NULL AND NOT EXISTS (
                   SELECT 1 FROM joined t
                   WHERE t.entity_key = j.entity_key
                     AND t.thread_id IS NOT NULL AND t.source_key = j.source_key)
           )                                                                 AS story_units,
       count(DISTINCT j.entry_id) FILTER (WHERE j.thread_id IS NOT NULL)
         - count(DISTINCT j.thread_id)                                       AS echoes_folded,
       d.thread_id                                                           AS dominant_thread_id,
       d.members                                                             AS dominant_members,
       t.slug                                                                AS thread_slug,
       t.title                                                               AS thread_title
FROM joined j
LEFT JOIN dominant d ON d.entity_key = j.entity_key
LEFT JOIN story_threads t ON t.id = d.thread_id
GROUP BY j.entity_key, d.thread_id, d.members, t.slug, t.title
""")

# The article that broke the story, and how many waves it has had since.
# Restricted to the window: a thread that started in March is not represented
# by its March article on a 14-day board, and the same ordering then picks the
# earliest article the window does hold. The role preference is what makes an
# origin inside the window beat a louder re-report of it.
_THREAD_LEAD_SQL = text("""
WITH members AS (
    SELECT ste.thread_id, ste.role, e.id AS entry_id, e.title, e.url, e.published_at,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source_key
    FROM story_thread_entries ste
    JOIN entries e ON e.id = ste.entry_id
    JOIN feeds f ON f.id = e.feed_id
    WHERE ste.thread_id = ANY(:thread_ids) AND e.published_at > :since
)
SELECT m.thread_id,
       (array_agg(m.entry_id ORDER BY (m.role = 'origin') DESC, m.published_at))[1]      AS entry_id,
       (array_agg(m.title ORDER BY (m.role = 'origin') DESC, m.published_at))[1]         AS title,
       (array_agg(m.url ORDER BY (m.role = 'origin') DESC, m.published_at))[1]           AS url,
       (array_agg(m.source_key ORDER BY (m.role = 'origin') DESC, m.published_at))[1]    AS source,
       (array_agg(m.published_at ORDER BY (m.role = 'origin') DESC, m.published_at))[1]  AS published_at,
       bool_or(m.role = 'origin')                                                        AS has_origin,
       count(DISTINCT m.source_key)                                                      AS outlets,
       (array_agg(DISTINCT m.source_key))[1:6]                                           AS sources,
       (SELECT count(*) FROM story_thread_beats b WHERE b.thread_id = m.thread_id)       AS beats
FROM members m
GROUP BY m.thread_id
""")


# The row's own first report of its story. Where the thread-wide lead is used
# instead, three rows that appear in one story all print the same quote — true,
# but unreadable, and it buries what each row is actually about. So the article
# has to be both the earliest in the story *and* linked to this entity.
_ENTITY_LEAD_SQL = text("""
WITH src AS (
    SELECT e.id AS entry_id, e.title, e.url, e.published_at,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source_key
    FROM entries e
    JOIN feeds f ON f.id = e.feed_id
    WHERE e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
),
links AS (
    SELECT :actor_type AS entity_type, a.id::text AS entity_key,
           (position(lower(a.name) in lower(coalesce(s.title, ''))) > 0) AS names_entity, s.*
    FROM threat_actors a
    JOIN entry_threat_actors ea ON ea.threat_actor_id = a.id
    JOIN src s ON s.entry_id = ea.entry_id
    WHERE a.id::text = ANY(:actor_keys)
    UNION ALL
    SELECT :malware_type, m.id::text,
           (position(lower(m.name) in lower(coalesce(s.title, ''))) > 0), s.*
    FROM malware_families m
    JOIN entry_malware em ON em.malware_family_id = m.id
    JOIN src s ON s.entry_id = em.entry_id
    WHERE m.id::text = ANY(:malware_keys)
    UNION ALL
    SELECT :cve_type, c.cve_id,
           (position(lower(c.cve_id) in lower(coalesce(s.title, ''))) > 0), s.*
    FROM cves c
    JOIN entry_cves ec ON ec.cve_id = c.id
    JOIN src s ON s.entry_id = ec.entry_id
    WHERE c.cve_id = ANY(:cve_keys)
),
joined AS (
    SELECT l.*, ste.thread_id, ste.role
    FROM links l
    JOIN story_thread_entries ste ON ste.entry_id = l.entry_id
),
per_thread AS (
    SELECT entity_type, entity_key, thread_id,
           count(DISTINCT entry_id)  AS members,
           count(DISTINCT source_key) AS outlets
    FROM joined
    GROUP BY 1, 2, 3
),
dominant AS (
    SELECT DISTINCT ON (entity_type, entity_key) entity_type, entity_key, thread_id, members, outlets
    FROM per_thread
    ORDER BY entity_type, entity_key, members DESC, thread_id
)
SELECT DISTINCT ON (j.entity_type, j.entity_key)
       j.entity_type, j.entity_key, j.entry_id, j.title, j.url, j.source_key AS source,
       j.published_at, (j.role = 'origin') AS has_origin, d.outlets,
       (SELECT count(*) FROM story_thread_beats b WHERE b.thread_id = d.thread_id) AS beats
FROM joined j
JOIN dominant d
  ON d.entity_type = j.entity_type AND d.entity_key = j.entity_key AND d.thread_id = j.thread_id
-- Inside the story, the article that names this row wins; among those, the
-- earliest. One write-up that introduces three threats would otherwise be the
-- lede on all three rows, which reads as a rendering bug even though it is
-- true. Earliest still beats loudest — that is the change this pass exists for.
ORDER BY j.entity_type, j.entity_key, j.names_entity DESC, (j.role = 'origin') DESC, j.published_at
""")


async def _threads_in_window(db: AsyncSession, since: datetime) -> bool:
    """Is there any threaded coverage in this window at all?

    One index probe that lets the whole feature cost nothing where it has
    nothing to say — an instance with embeddings switched off, or one still
    working through its first backfill. Without it every board request pays
    for four thread queries to be told, at length, that there are no threads.
    """
    return bool(
        (
            await db.execute(
                text("SELECT 1 FROM story_threads t WHERE t.last_seen > :since LIMIT 1"),
                {"since": since},
            )
        ).scalar_one_or_none()
    )


def _rank_score(story_units: int, attention: int, new_techniques: int) -> float:
    """The board's ranking, in one place.

    Stories, not articles and not outlets: a wave carried by eleven outlets is
    one thing that happened. Outlets still earn a capped corroboration bump —
    uncapped, that term is ``feed_echo`` wearing a different name.
    """
    return _W_ATTENTION * story_units + _W_NEW * new_techniques + min(_W_OUTLET * attention, _OUTLET_CAP)


# ── Vulnerability rows ──────────────────────────────────────────────────────
# The same board, asked about CVEs. Attention is the same distinct-host unit;
# exploitation state stands where an actor row has its tradecraft counts.
# A KEV joins at any attention — active exploitation doesn't need a second
# outlet to matter — everything else needs the same floor as the threats.
_CVE_RANKING_SQL = text("""
WITH src AS (
    SELECT e.id AS entry_id, e.published_at,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source_key
    FROM entries e
    JOIN feeds f ON f.id = e.feed_id
    WHERE e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
)
SELECT c.cve_id, c.id AS entity_uuid, c.severity, c.cvss_score, c.epss_score, c.is_kev,
       c.kev_date_added, c.epss_changed_at, c.exploit_status, c.exploit_availability,
       count(DISTINCT s.source_key) AS attention,
       count(DISTINCT s.entry_id)   AS entries,
       max(s.published_at)          AS last_seen
FROM cves c
JOIN entry_cves ec ON ec.cve_id = c.id
JOIN src s ON s.entry_id = ec.entry_id
GROUP BY c.id
HAVING count(DISTINCT s.source_key) >= :min_attention OR bool_or(c.is_kev)
ORDER BY bool_or(c.is_kev) DESC, count(DISTINCT s.source_key) DESC
LIMIT :candidate_limit
""")

# Lead article + hosts for the final CVE rows. A title that prints the CVE id
# beats a technique-dense roundup that merely links it.
_CVE_EVIDENCE_SQL = text("""
WITH links AS (
    SELECT c.cve_id AS entity_key, e.id AS entry_id, e.title, e.url, e.published_at,
           (position(lower(c.cve_id) in lower(coalesce(e.title, ''))) > 0) AS names_cve,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source_key
    FROM cves c
    JOIN entry_cves ec ON ec.cve_id = c.id
    JOIN entries e ON e.id = ec.entry_id
    JOIN feeds f ON f.id = e.feed_id
    WHERE c.cve_id = ANY(:keys) AND e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
),
scored AS (
    SELECT l.*,
           row_number() OVER (
               PARTITION BY l.entity_key
               ORDER BY l.names_cve DESC, l.published_at DESC
           ) AS rn
    FROM links l
)
SELECT entity_key,
       (array_agg(entry_id ORDER BY rn))[1]      AS top_entry_id,
       (array_agg(title ORDER BY rn))[1]         AS top_title,
       (array_agg(url ORDER BY rn))[1]           AS top_url,
       (array_agg(source_key ORDER BY rn))[1]    AS top_source,
       (array_agg(published_at ORDER BY rn))[1]  AS top_published_at,
       (array_agg(DISTINCT source_key))[1:6]     AS sources
FROM scored
GROUP BY entity_key
""")

# Affected product/vendor names + whether any of them is in the caller's stack
# (user_entity_watches mode='stack' — Vendor Watch's own join, finally read by
# the board).
_CVE_AFFECTED_SQL = text("""
SELECT c.cve_id,
       (array_agg(DISTINCT coalesce(p.name, v.name)) FILTER (WHERE coalesce(p.name, v.name) IS NOT NULL))[1:3]
           AS affected,
       bool_or(ca.vendor_id = ANY(:vendor_ids) OR ca.product_id = ANY(:product_ids)) AS in_stack
FROM cves c
JOIN cve_affected ca ON ca.cve_id = c.id
LEFT JOIN products p ON p.id = ca.product_id
LEFT JOIN vendors v ON v.id = ca.vendor_id
WHERE c.cve_id = ANY(:keys)
GROUP BY c.cve_id
""")

# Evidence for the final ranked rows: the window's lead article per entity
# (most technique-dense, then latest — the write-up, not the aggregator echo),
# the distinct hosts behind the attention count, and the number of technique
# links carrying a real observable sentence.
_EVIDENCE_SQL = text("""
WITH links AS (
    SELECT :actor_type AS entity_type, a.id::text AS entity_key, e.id AS entry_id,
           e.title, e.url, e.published_at,
           -- A title that names the threat beats a technique-dense monthly
           -- roundup that merely mentions it.
           (position(lower(a.name) in lower(coalesce(e.title, ''))) > 0) AS names_threat,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source_key
    FROM threat_actors a
    JOIN entry_threat_actors ea ON ea.threat_actor_id = a.id
    JOIN entries e ON e.id = ea.entry_id
    JOIN feeds f ON f.id = e.feed_id
    WHERE a.id::text = ANY(:actor_keys) AND e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
    UNION ALL
    SELECT :malware_type, m.id::text, e.id, e.title, e.url, e.published_at,
           (position(lower(m.name) in lower(coalesce(e.title, ''))) > 0),
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text))
    FROM malware_families m
    JOIN entry_malware em ON em.malware_family_id = m.id
    JOIN entries e ON e.id = em.entry_id
    JOIN feeds f ON f.id = e.feed_id
    WHERE m.id::text = ANY(:malware_keys) AND e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
),
scored AS (
    SELECT l.*,
           (SELECT count(*) FROM entry_ttps j WHERE j.entry_id = l.entry_id) AS tech_count,
           (SELECT count(*) FROM entry_ttps j
            WHERE j.entry_id = l.entry_id
              AND j.source_text IS NOT NULL
              AND j.source_text NOT LIKE 'auto_link:%') AS observable_count,
           row_number() OVER (
               PARTITION BY l.entity_type, l.entity_key
               ORDER BY l.names_threat DESC,
                        (SELECT count(*) FROM entry_ttps j WHERE j.entry_id = l.entry_id) DESC,
                        l.published_at DESC
           ) AS rn
    FROM links l
)
SELECT entity_type, entity_key,
       (array_agg(entry_id ORDER BY rn))[1]      AS top_entry_id,
       (array_agg(title ORDER BY rn))[1]         AS top_title,
       (array_agg(url ORDER BY rn))[1]           AS top_url,
       (array_agg(source_key ORDER BY rn))[1]    AS top_source,
       (array_agg(published_at ORDER BY rn))[1]  AS top_published_at,
       (array_agg(DISTINCT source_key))[1:6]     AS sources,
       sum(observable_count)                     AS writable_observables
FROM scored
GROUP BY 1, 2
""")

# min(published_at) per (entity, technique) is the first-ever sighting, so a
# pair whose minimum lands inside the window is new tradecraft rather than a
# technique the threat has been using for a year.
_TECHNIQUE_SQL = text("""
WITH pairs AS (
    SELECT :actor_type AS entity_type, a.id::text AS entity_key,
           t.technique_id, min(e.published_at) AS first_seen
    FROM threat_actors a
    JOIN entry_threat_actors ea ON ea.threat_actor_id = a.id
    JOIN entries e ON e.id = ea.entry_id
    JOIN entry_ttps j ON j.entry_id = e.id
    JOIN ttps t ON t.id = j.ttp_id
    WHERE a.id::text = ANY(:actor_keys)
    GROUP BY 1, 2, 3
    UNION ALL
    SELECT :malware_type, m.id::text, t.technique_id, min(e.published_at)
    FROM malware_families m
    JOIN entry_malware em ON em.malware_family_id = m.id
    JOIN entries e ON e.id = em.entry_id
    JOIN entry_ttps j ON j.entry_id = e.id
    JOIN ttps t ON t.id = j.ttp_id
    WHERE m.id::text = ANY(:malware_keys)
    GROUP BY 1, 2, 3
)
SELECT entity_type, entity_key,
       count(*)                                        AS on_record,
       count(*) FILTER (WHERE first_seen > :since)      AS new_techniques
FROM pairs
GROUP BY 1, 2
""")

# rule_coverage replaces the per-row COUNT the coverage board issues against
# source_actors, which is empty on every row in the library.
_PRIOR_RULES_SQL = text("""
SELECT rc.entity_type, rc.entity_key,
       coalesce(r.metadata->>'repo', 'local')                      AS repo,
       count(*)                                                    AS repo_count,
       count(*) FILTER (WHERE rc.confidence IN ('high', 'medium'))  AS strong_count
FROM rule_coverage rc
JOIN detection_rules r ON r.id = rc.rule_id
WHERE rc.entity_type = ANY(:types) AND rc.entity_key = ANY(:keys)
GROUP BY rc.entity_type, rc.entity_key, repo
""")


def _merge_by_thread(
    rows: list[ThreatRow],
    dominant_thread: dict[tuple[str, str], tuple[object, int]],
) -> list[ThreatRow]:
    """Fold rows that one story thread holds into a single row.

    The name path folds two spellings of one threat. This folds two *threats*
    whose window coverage is one story — an operator and the payload it drops,
    where every article covering one covers the other. The bar is deliberately
    high: one thread has to hold three quarters of each row's window articles,
    and at least two of them, or a threat that merely turns up in someone
    else's story would vanish into it.

    Only open rows fold. A handled row absorbing an open one would hide work
    behind a decision that was never made about it.
    """
    groups: dict[object, list[ThreatRow]] = {}
    out: list[ThreatRow] = []
    for row in rows:
        thread = dominant_thread.get((row.entity_type, row.entity_key))
        share = (thread[1] / row.articles) if thread and row.articles else 0.0
        if (
            thread is None
            or row.is_generic
            or row.state != "open"
            or thread[1] < THREAD_MERGE_MIN_ENTRIES
            or share < THREAD_MERGE_SHARE
        ):
            out.append(row)
            continue
        groups.setdefault(thread[0], []).append(row)

    for members in groups.values():
        if len(members) == 1:
            out.append(members[0])
            continue
        members.sort(key=lambda r: -r.score)
        primary, *absorbed = members
        repos = dict(primary.prior_rule_repos)
        for other in absorbed:
            for repo, n in other.prior_rule_repos.items():
                repos[repo] = repos.get(repo, 0) + n
        out.append(
            replace(
                primary,
                facets=sorted({*primary.facets, *(f for o in absorbed for f in o.facets)}),
                # Counts are maxima, not sums: the same articles carry every
                # member of the group, so summing would count one outlet twice.
                attention=max(r.attention for r in members),
                articles=max(r.articles for r in members),
                stories=max(r.stories for r in members),
                echoes_folded=max(r.echoes_folded for r in members),
                new_techniques=max(r.new_techniques for r in members),
                on_record=max(r.on_record for r in members),
                # Rule inventories are genuinely separate per entity, as in the
                # name-merge path, so those do sum.
                prior_rules=sum(r.prior_rules for r in members),
                prior_rules_strong=sum(r.prior_rules_strong for r in members),
                prior_rule_repos=repos,
                merged_from=[
                    {"entity_type": o.entity_type, "entity_key": o.entity_key, "label": o.label} for o in absorbed
                ],
                score=max(r.score for r in members),
            )
        )
    return out


async def _apply_thread_lead(db: AsyncSession, rows: list[ThreatRow], since: datetime) -> list[ThreatRow]:
    """Headline from the story rather than from the loudest write-up.

    ``_EVIDENCE_SQL`` picks the article that names the threat and carries the
    most techniques. That is the right answer when nothing knows what the story
    is, and the wrong one once something does: the fourth outlet to pick a
    story up routinely out-scores the one that broke it. Where a thread speaks
    for the row (``thread_slug`` — see ``THREAD_LEAD_SHARE``), the row's own
    earliest article in that story wins instead, and the row says so.
    """
    keyed = {t: [r.entity_key for r in rows if r.thread_slug and r.entity_type == t] for t in _LEAD_TYPES}
    if not any(keyed.values()):
        return rows
    leads = {
        (r.entity_type, r.entity_key): r
        for r in (
            await db.execute(
                _ENTITY_LEAD_SQL,
                {
                    "since": since,
                    "actor_type": entity_types.THREAT_ACTOR,
                    "malware_type": entity_types.MALWARE,
                    "cve_type": entity_types.CVE,
                    "actor_keys": keyed[entity_types.THREAT_ACTOR] or [""],
                    "malware_keys": keyed[entity_types.MALWARE] or [""],
                    "cve_keys": keyed[entity_types.CVE] or [""],
                },
            )
        ).all()
    }
    out: list[ThreatRow] = []
    for row in rows:
        lead = leads.get((row.entity_type, row.entity_key)) if row.thread_slug else None
        if lead is None or lead.entry_id is None:
            out.append(row)
            continue
        out.append(
            replace(
                row,
                beats=int(lead.beats or 0),
                headline={
                    "entry_id": str(lead.entry_id),
                    "title": lead.title,
                    "url": lead.url,
                    "source": lead.source,
                    "published_at": lead.published_at.isoformat() if lead.published_at else None,
                    # The thread knows this article opened the story; without an
                    # origin member among the row's articles it is merely the
                    # earliest one here, and the row must not claim otherwise.
                    "is_origin": bool(lead.has_origin),
                    "outlets": int(lead.outlets or 0),
                },
            )
        )
    return out


async def build_threat_board(
    db: AsyncSession,
    window: str = "14d",
    limit: int = 25,
    min_attention: int = 3,
    include_handled: bool = False,
) -> list[ThreatRow]:
    """Rank threats by attention and new tradecraft over the window."""
    hours = WINDOW_HOURS.get(window, WINDOW_HOURS["14d"])
    since = datetime.now(UTC) - timedelta(hours=hours)

    params = {
        "since": since,
        "actor_type": entity_types.THREAT_ACTOR,
        "malware_type": entity_types.MALWARE,
    }

    attention_rows = (
        await db.execute(
            _RANKING_SQL,
            {**params, "min_attention": min_attention, "candidate_limit": limit * 4},
        )
    ).all()
    # Union in the technique-active candidates so a quiet threat with heavy new
    # tradecraft survives to the scoring stage instead of dying on the
    # attention-ordered LIMIT above.
    technique_rows = (
        await db.execute(
            _TECHNIQUE_CANDIDATE_SQL,
            {**params, "min_attention": min_attention, "candidate_limit": limit * 4},
        )
    ).all()
    by_key = {(r.entity_type, r.entity_key): r for r in attention_rows}
    for r in technique_rows:
        by_key.setdefault((r.entity_type, r.entity_key), r)

    # The pull path: tracked threats enter the board regardless of the
    # attention floor — you arrived with the name, the ranking doesn't get a
    # veto. Quiet tracked rows get zero-count aggregates and real labels.
    tracked_rows = (
        await db.execute(
            text("""
                SELECT s.entity_type, s.entity_key,
                       coalesce(a.name, m.name) AS label
                FROM threat_board_state s
                LEFT JOIN threat_actors a
                  ON s.entity_type = :actor_type AND a.id::text = s.entity_key
                LEFT JOIN malware_families m
                  ON s.entity_type = :malware_type AND m.id::text = s.entity_key
                WHERE s.state = 'tracked' AND coalesce(a.name, m.name) IS NOT NULL
                """),
            {
                "actor_type": entity_types.THREAT_ACTOR,
                "malware_type": entity_types.MALWARE,
            },
        )
    ).all()
    for t in tracked_rows:
        key = (t.entity_type, t.entity_key)
        if key not in by_key:
            by_key[key] = SimpleNamespace(
                entity_type=t.entity_type,
                entity_key=t.entity_key,
                label=t.label,
                attention=0,
                entries=0,
                last_seen=None,
            )

    rows = list(by_key.values())
    if not rows:
        return []

    actor_keys = [r.entity_key for r in rows if r.entity_type == entity_types.THREAT_ACTOR]
    malware_keys = [r.entity_key for r in rows if r.entity_type == entity_types.MALWARE]

    tech = {
        (r.entity_type, r.entity_key): (r.on_record, r.new_techniques)
        for r in (
            await db.execute(
                _TECHNIQUE_SQL,
                {
                    **params,
                    "actor_keys": actor_keys or [""],
                    "malware_keys": malware_keys or [""],
                },
            )
        ).all()
    }

    # What the ranking counts. Rows the query does not answer for (a tracked
    # threat with no window coverage) keep their outlet count as their story
    # count, which is what it means: nothing folded, nothing to fold.
    story_units = (
        {
            (r.entity_type, r.entity_key): r
            for r in (
                await db.execute(
                    _STORY_UNITS_SQL,
                    {
                        **params,
                        "actor_keys": actor_keys or [""],
                        "malware_keys": malware_keys or [""],
                    },
                )
            ).all()
        }
        if await _threads_in_window(db, since)
        else {}
    )
    # (entity_type, entity_key) -> (thread_id, members in the window). The
    # merge pass reads this; the row payload carries only the slug.
    dominant_thread: dict[tuple[str, str], tuple[object, int]] = {
        k: (v.dominant_thread_id, int(v.dominant_members or 0))
        for k, v in story_units.items()
        if v.dominant_thread_id is not None
    }

    prior: dict[tuple[str, str], dict[str, int]] = {}
    strong: dict[tuple[str, str], int] = {}
    if rows:
        for r in (
            await db.execute(
                _PRIOR_RULES_SQL,
                {
                    "types": [r.entity_type for r in rows],
                    "keys": [r.entity_key for r in rows],
                },
            )
        ).all():
            key = (r.entity_type, r.entity_key)
            prior.setdefault(key, {})[r.repo] = r.repo_count
            strong[key] = strong.get(key, 0) + r.strong_count

    states = {
        (r.entity_type, r.entity_key): (r.state, r.new_count_at_decision)
        for r in (
            await db.execute(
                text(
                    "SELECT entity_type, entity_key, state, new_count_at_decision "
                    "FROM threat_board_state WHERE entity_key = ANY(:keys)"
                ),
                {"keys": [r.entity_key for r in rows]},
            )
        ).all()
    }

    # Fold the actor and malware facets of one threat into a single row, keeping
    # the larger attention count rather than summing: the same article usually
    # links both entities, so summing would double-count its outlet.
    merged: dict[str, ThreatRow] = {}
    for r in rows:
        key = (r.entity_type, r.entity_key)
        on_record, new_techniques = tech.get(key, (0, 0))
        repos = prior.get(key, {})
        state, new_at_decision = states.get(key, ("open", 0))

        # A handled threat reopens once new tradecraft arrives that postdates
        # the decision. That is why no snooze date is needed.
        if state == "handled" and new_techniques > new_at_decision:
            state = "open"

        is_generic = _normalize_name(r.label) in _GENERIC_NORMALIZED or bool(_ID_SHAPED.match(r.label.strip()))
        su = story_units.get(key)
        # Story units are counted over every article linked to this entity in
        # the window, while a row that arrived through the technique-candidate
        # path carries an outlet count over the TTP-bearing subset of those.
        # The number that ranks must never exceed the outlets the row shows.
        stories = min(int(su.story_units or 0), r.attention) if su is not None else r.attention
        # A thread speaks for the row only if it holds half its coverage.
        leads = (
            su is not None
            and su.dominant_thread_id is not None
            and int(su.dominant_members or 0) >= THREAD_LEAD_SHARE * max(r.entries or 0, 1)
        )
        row = ThreatRow(
            entity_type=r.entity_type,
            entity_key=r.entity_key,
            label=r.label,
            facets=[r.entity_type],
            attention=r.attention,
            new_techniques=new_techniques,
            on_record=on_record,
            prior_rules=sum(repos.values()),
            prior_rules_strong=strong.get(key, 0),
            prior_rule_repos=repos,
            last_seen=r.last_seen.isoformat() if r.last_seen else None,
            state=state,
            is_generic=is_generic,
            score=(0.0 if is_generic else _rank_score(stories, r.attention, new_techniques)),
            articles=r.entries,
            stories=stories,
            echoes_folded=max(0, int(su.echoes_folded or 0)) if su is not None else 0,
            thread_slug=su.thread_slug if leads else None,
            thread_title=su.thread_title if leads else None,
        )

        norm = _normalize_name(r.label)
        existing = merged.get(norm)
        if existing is None:
            merged[norm] = row
            continue
        # Repo counts are summed per repo, matching the summed prior_rules line
        # above — a dict merge would keep only one facet's count for a repo that
        # holds rules under both facets, and the chips would stop adding up to
        # the headline number.
        merged_repos = dict(existing.prior_rule_repos)
        for repo, n in row.prior_rule_repos.items():
            merged_repos[repo] = merged_repos.get(repo, 0) + n
        merged[norm] = ThreatRow(
            entity_type=existing.entity_type,
            entity_key=existing.entity_key,
            label=existing.label,
            facets=sorted({*existing.facets, r.entity_type}),
            attention=max(existing.attention, row.attention),
            new_techniques=max(existing.new_techniques, row.new_techniques),
            on_record=max(existing.on_record, row.on_record),
            prior_rules=existing.prior_rules + row.prior_rules,
            prior_rules_strong=existing.prior_rules_strong + row.prior_rules_strong,
            prior_rule_repos=merged_repos,
            last_seen=max(filter(None, [existing.last_seen, row.last_seen]), default=None),
            state=existing.state if existing.state != "open" else row.state,
            is_generic=existing.is_generic or row.is_generic,
            score=max(existing.score, row.score),
            articles=max(existing.articles, row.articles),
            stories=max(existing.stories, row.stories),
            echoes_folded=max(existing.echoes_folded, row.echoes_folded),
            thread_slug=existing.thread_slug or row.thread_slug,
            thread_title=existing.thread_title or row.thread_title,
        )

    folded = _merge_by_thread(list(merged.values()), dominant_thread)
    out = [r for r in folded if include_handled or r.state in ("open", "tracked") or r.is_generic]
    # Tracked rows are pinned above the ranking and never cut by the limit —
    # the whole point of tracking is that the score doesn't get a veto.
    out.sort(key=lambda r: (r.is_generic, r.state != "tracked", -r.score))
    tracked_count = sum(1 for r in out if r.state == "tracked")
    out = out[: max(limit, tracked_count)]

    # Evidence pass for the surviving rows only: lead headline, attention hosts,
    # writable-observable count. Non-generic rows only — a genre word's
    # "headline" would just be whatever echoed loudest.
    evid_actor = [r.entity_key for r in out if r.entity_type == entity_types.THREAT_ACTOR and not r.is_generic]
    evid_malware = [r.entity_key for r in out if r.entity_type == entity_types.MALWARE and not r.is_generic]
    if evid_actor or evid_malware:
        evidence = {
            (e.entity_type, e.entity_key): e
            for e in (
                await db.execute(
                    _EVIDENCE_SQL,
                    {
                        **params,
                        "actor_keys": evid_actor or [""],
                        "malware_keys": evid_malware or [""],
                    },
                )
            ).all()
        }
        out = [
            replace(
                r,
                headline=(
                    {
                        "entry_id": str(e.top_entry_id),
                        "title": e.top_title,
                        "url": e.top_url,
                        "source": e.top_source,
                        "published_at": (e.top_published_at.isoformat() if e.top_published_at else None),
                    }
                    if e is not None and e.top_entry_id is not None
                    else None
                ),
                sources=list(e.sources or []) if e is not None else [],
                writable_observables=(int(e.writable_observables or 0) if e is not None else 0),
            )
            for r in out
            for e in [evidence.get((r.entity_type, r.entity_key))]
        ]
    return await _apply_thread_lead(db, out, since)


async def build_cve_board(
    db: AsyncSession,
    window: str = "14d",
    limit: int = 25,
    min_attention: int = 3,
    include_handled: bool = False,
    user_id=None,
) -> list[ThreatRow]:
    """Vulnerability rows for the board: exploitation-ranked CVEs of the window.

    The same question the threat rows answer — which of these deserves
    detection work — asked about CVEs. Ranking is attention x the exposure
    severity lift (KEV / EPSS / weaponized), reusing Vendor Watch's own
    multipliers rather than growing a second scorer; posture comes from
    ``classify_cves`` against the enabled inventory; the board's state machine
    applies unchanged, with escalation (a KEV listing or an EPSS move after the
    decision) standing in for "new tradecraft" in the reopen contract.
    """
    from app.services.detection_coverage import classify_cves
    from app.services.exposure import (
        EPSS_MULT,
        EXPOSURE_BASE,
        KEV_MULT,
        WEAPONIZED_MULT,
        WEAPONIZED_STATES,
        get_user_stack,
    )

    hours = WINDOW_HOURS.get(window, WINDOW_HOURS["14d"])
    since = datetime.now(UTC) - timedelta(hours=hours)
    # The Vendor Watch UI's own "EPSS >= 50%" bar; a settings-driven threshold
    # can replace it when the exposure page's does.
    epss_threshold = 0.5

    rows = (
        await db.execute(
            _CVE_RANKING_SQL,
            {
                "since": since,
                "min_attention": min_attention,
                "candidate_limit": limit * 4,
            },
        )
    ).all()
    if not rows:
        return []

    keys = [r.cve_id for r in rows]

    story_units = (
        {r.entity_key: r for r in (await db.execute(_CVE_STORY_UNITS_SQL, {"since": since, "keys": keys})).all()}
        if await _threads_in_window(db, since)
        else {}
    )
    dominant_thread: dict[tuple[str, str], tuple[object, int]] = {
        (entity_types.CVE, k): (v.dominant_thread_id, int(v.dominant_members or 0))
        for k, v in story_units.items()
        if v.dominant_thread_id is not None
    }

    prior: dict[str, tuple[int, int, dict[str, int]]] = {}
    for r in (
        await db.execute(
            _PRIOR_RULES_SQL,
            {"types": [entity_types.CVE] * len(keys), "keys": keys},
        )
    ).all():
        total, strong, repos = prior.get(r.entity_key, (0, 0, {}))
        repos = dict(repos)
        repos[r.repo] = repos.get(r.repo, 0) + r.repo_count
        prior[r.entity_key] = (total + r.repo_count, strong + r.strong_count, repos)

    states = {
        r.entity_key: (r.state, r.decided_at)
        for r in (
            await db.execute(
                text(
                    "SELECT entity_key, state, decided_at FROM threat_board_state "
                    "WHERE entity_type = 'cve' AND entity_key = ANY(:keys)"
                ),
                {"keys": keys},
            )
        ).all()
    }

    vendor_ids, product_ids = await get_user_stack(db, user_id) if user_id else ([], [])
    affected = {
        r.cve_id: (list(r.affected or []), bool(r.in_stack))
        for r in (
            await db.execute(
                _CVE_AFFECTED_SQL,
                {
                    "keys": keys,
                    "vendor_ids": vendor_ids or [uuid_nil()],
                    "product_ids": product_ids or [uuid_nil()],
                },
            )
        ).all()
    }

    postures = await classify_cves(db, keys)

    out: list[ThreatRow] = []
    for r in rows:
        state, decided_at = states.get(r.cve_id, ("open", None))
        # Reopen on escalation: the exploitation state moved after the human
        # decision. KEV listing and EPSS changes are both timestamped, so no
        # snapshot column is needed.
        if state == "handled" and decided_at is not None:
            kev_moved = r.kev_date_added is not None and _date_after(r.kev_date_added, decided_at)
            epss_moved = r.epss_changed_at is not None and r.epss_changed_at > decided_at
            if kev_moved or epss_moved:
                state = "open"

        total, strong, repos = prior.get(r.cve_id, (0, 0, {}))
        products, in_stack = affected.get(r.cve_id, ([], False))
        severity_mult = max(
            KEV_MULT if r.is_kev else 1.0,
            EPSS_MULT if (r.epss_score or 0) >= epss_threshold else 1.0,
            (WEAPONIZED_MULT if (r.exploit_availability or "") in WEAPONIZED_STATES else 1.0),
            1.0,
        )
        # The stack base multiplies only stack matches — exposure's own
        # semantics. Applying it to the whole landscape made every KEV read
        # as the caller's problem, which is exactly the complaint the
        # on_surface split answers.
        lift = severity_mult * (EXPOSURE_BASE if in_stack else 1.0)
        su = story_units.get(r.cve_id)
        stories = min(int(su.story_units or 0), r.attention) if su is not None else r.attention
        leads = (
            su is not None
            and su.dominant_thread_id is not None
            and int(su.dominant_members or 0) >= THREAD_LEAD_SHARE * max(r.entries or 0, 1)
        )
        posture_info = postures.get(r.cve_id) or {}
        posture = {
            "covered": "defended",
            "library_only": "blind",
            "no_rule": "no_rule",
        }.get(posture_info.get("status") or "")
        # On your surface: you run an affected vendor/product, or the library
        # already holds a rule your telemetry can fire (defended/blind both
        # prove observability of the rule's channel; blind still needs the
        # source, so only defended counts as observable today).
        on_surface = in_stack or posture == "defended"

        out.append(
            ThreatRow(
                entity_type=entity_types.CVE,
                entity_key=r.cve_id,
                label=r.cve_id,
                facets=[entity_types.CVE],
                attention=r.attention,
                new_techniques=0,
                on_record=0,
                prior_rules=total,
                prior_rules_strong=strong,
                prior_rule_repos=repos,
                last_seen=r.last_seen.isoformat() if r.last_seen else None,
                state=state,
                is_generic=False,
                # stories x severity lift: a quiet KEV outranks a loud
                # Patch-Tuesday rehash, which is the whole point — and one
                # advisory re-reported nine times is one story, not nine.
                score=round(max(stories, 1) * lift, 2),
                articles=r.entries,
                stories=stories,
                echoes_folded=max(0, int(su.echoes_folded or 0)) if su is not None else 0,
                thread_slug=su.thread_slug if leads else None,
                thread_title=su.thread_title if leads else None,
                product=products[0] if products else None,
                in_stack=in_stack,
                is_kev=bool(r.is_kev),
                cvss_score=float(r.cvss_score) if r.cvss_score is not None else None,
                epss_score=float(r.epss_score) if r.epss_score is not None else None,
                exploit_status=r.exploit_availability or r.exploit_status,
                posture=posture,
                profile_id=str(r.entity_uuid),
                on_surface=on_surface,
            )
        )

    # Two CVEs chained in one intrusion are one wave and one adoption decision,
    # not two rows competing for the same slot.
    out = _merge_by_thread(out, dominant_thread)
    out = [r for r in out if include_handled or r.state in ("open", "tracked")]
    out.sort(key=lambda r: (r.state != "tracked", not r.on_surface, -r.score))
    tracked_count = sum(1 for r in out if r.state == "tracked")
    out = out[: max(limit, tracked_count)]

    # Evidence pass for survivors only, as on the threat side.
    if out:
        evidence = {
            e.entity_key: e
            for e in (
                await db.execute(
                    _CVE_EVIDENCE_SQL,
                    {"keys": [r.entity_key for r in out], "since": since},
                )
            ).all()
        }
        out = [
            replace(
                r,
                headline=(
                    {
                        "entry_id": str(e.top_entry_id),
                        "title": e.top_title,
                        "url": e.top_url,
                        "source": e.top_source,
                        "published_at": (e.top_published_at.isoformat() if e.top_published_at else None),
                    }
                    if e is not None and e.top_entry_id is not None
                    else None
                ),
                sources=list(e.sources or []) if e is not None else [],
            )
            for r in out
            for e in [evidence.get(r.entity_key)]
        ]
    return await _apply_thread_lead(db, out, since)


# ── Story rows ──────────────────────────────────────────────────────────────
# A thread whose articles resolved to no actor, no malware and no CVE. The
# board is entity-keyed, so today this story cannot appear at all: there is
# nothing to key a row on until extraction names something. A thread needs no
# name, which makes it the only thing on the platform that can carry the story
# nobody has named yet — usually the one worth reading first.
_STORY_ROW_SQL = text("""
WITH candidates AS (
    SELECT t.id, t.slug, t.title
    FROM story_threads t
    WHERE t.last_seen > :since
      AND NOT EXISTS (
          SELECT 1
          FROM story_thread_entries ste
          WHERE ste.thread_id = t.id
            AND (EXISTS (SELECT 1 FROM entry_threat_actors x WHERE x.entry_id = ste.entry_id)
              OR EXISTS (SELECT 1 FROM entry_malware x WHERE x.entry_id = ste.entry_id)
              OR EXISTS (SELECT 1 FROM entry_cves x WHERE x.entry_id = ste.entry_id))
      )
),
members AS (
    SELECT c.id AS thread_id, c.slug, c.title, e.id AS entry_id, e.published_at,
           lower(coalesce(
               nullif(regexp_replace(
                   coalesce(e.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               nullif(regexp_replace(
                   coalesce(f.site_url, f.url, ''), '^https?://(www\\.)?([^/:]+).*$', '\\2'), ''),
               f.id::text)) AS source_key
    FROM candidates c
    JOIN story_thread_entries ste ON ste.thread_id = c.id
    JOIN entries e ON e.id = ste.entry_id
    JOIN feeds f ON f.id = e.feed_id
    WHERE e.published_at > :since
      AND f.title !~* 'rules|signatures|templates|detections|security content'
)
SELECT thread_id, slug, title,
       count(DISTINCT source_key) AS attention,
       count(DISTINCT entry_id)   AS entries,
       max(published_at)          AS last_seen
FROM members
GROUP BY 1, 2, 3
HAVING count(DISTINCT source_key) >= :min_attention
ORDER BY count(DISTINCT source_key) DESC, max(published_at) DESC
LIMIT :candidate_limit
""")

# Techniques on a story row are the thread's, and "new" keeps its meaning: a
# technique whose first sighting anywhere in the corpus falls inside the window.
# Without an entity there is no per-entity first sighting to measure against,
# and a global one is the honest substitute.
_STORY_TECH_SQL = text("""
WITH members AS (
    SELECT ste.thread_id, ste.entry_id
    FROM story_thread_entries ste
    WHERE ste.thread_id = ANY(:thread_ids)
),
links AS (
    SELECT m.thread_id, j.ttp_id, j.source_text
    FROM members m
    JOIN entry_ttps j ON j.entry_id = m.entry_id
),
firsts AS (
    SELECT j.ttp_id, min(e.published_at) AS first_seen
    FROM entry_ttps j
    JOIN entries e ON e.id = j.entry_id
    WHERE j.ttp_id IN (SELECT ttp_id FROM links)
    GROUP BY 1
)
SELECT l.thread_id,
       count(DISTINCT l.ttp_id)                                          AS on_record,
       count(DISTINCT l.ttp_id) FILTER (WHERE f.first_seen > :since)     AS new_techniques,
       count(*) FILTER (
           WHERE l.source_text IS NOT NULL AND l.source_text NOT LIKE 'auto_link:%'
       )                                                                 AS writable_observables
FROM links l
JOIN firsts f ON f.ttp_id = l.ttp_id
GROUP BY 1
""")

# What the story is about, when the only entities it resolved are products —
# which is the common shape for an exploitation story that predates its CVE.
_STORY_PRODUCT_SQL = text("""
WITH members AS (
    SELECT ste.thread_id, ste.entry_id
    FROM story_thread_entries ste
    WHERE ste.thread_id = ANY(:thread_ids)
),
tally AS (
    SELECT m.thread_id, p.id AS product_id, p.name, p.vendor_id, count(*) AS mentions
    FROM members m
    JOIN entry_products ep ON ep.entry_id = m.entry_id
    JOIN products p ON p.id = ep.product_id
    GROUP BY 1, 2, 3, 4
)
SELECT DISTINCT ON (thread_id) thread_id, product_id, name, vendor_id
FROM tally
ORDER BY thread_id, mentions DESC, name
""")


async def build_story_rows(
    db: AsyncSession,
    window: str = "14d",
    limit: int = 25,
    min_attention: int = 3,
    include_handled: bool = False,
    user_id=None,
) -> list[ThreatRow]:
    """Board rows for stories that resolved to no entity.

    Ranked on the same scale as everything else, with one substitution: a
    story's unit count is its *beats* — the waves of coverage its spine
    records — because "this has developed three times in eight days" is the
    only claim an unnamed story can make for itself. A thread with no spine yet
    counts as one.

    Not every entity-less story belongs here. A funding announcement, a policy
    statement and a webinar all resolve to no actor and no malware for the
    same boring reason: there is nothing in them to extract. The board is a
    queue of detection work, so a story earns a row by offering some — a
    technique the extractor found, an observable sentence, or a product the
    caller actually runs. Measured on the dev corpus this is the difference
    between 33 rows and a handful.
    """
    from app.services.exposure import EXPOSURE_BASE, get_user_stack

    hours = WINDOW_HOURS.get(window, WINDOW_HOURS["14d"])
    since = datetime.now(UTC) - timedelta(hours=hours)
    if not await _threads_in_window(db, since):
        return []

    rows = (
        await db.execute(
            _STORY_ROW_SQL,
            {"since": since, "min_attention": min_attention, "candidate_limit": limit * 2},
        )
    ).all()
    if not rows:
        return []

    thread_ids = [r.thread_id for r in rows]
    tech = {
        r.thread_id: r for r in (await db.execute(_STORY_TECH_SQL, {"thread_ids": thread_ids, "since": since})).all()
    }
    leads = {
        r.thread_id: r for r in (await db.execute(_THREAD_LEAD_SQL, {"thread_ids": thread_ids, "since": since})).all()
    }
    products = {r.thread_id: r for r in (await db.execute(_STORY_PRODUCT_SQL, {"thread_ids": thread_ids})).all()}
    states = {
        r.entity_key: (r.state, r.new_count_at_decision)
        for r in (
            await db.execute(
                text(
                    "SELECT entity_key, state, new_count_at_decision FROM threat_board_state "
                    "WHERE entity_type = :story AND entity_key = ANY(:keys)"
                ),
                {"story": STORY, "keys": [r.slug for r in rows]},
            )
        ).all()
    }
    vendor_ids, product_ids = await get_user_stack(db, user_id) if user_id else ([], [])

    out: list[ThreatRow] = []
    for r in rows:
        t = tech.get(r.thread_id)
        lead = leads.get(r.thread_id)
        product = products.get(r.thread_id)
        new_techniques = int(t.new_techniques or 0) if t is not None else 0
        state, new_at_decision = states.get(r.slug, ("open", 0))
        if state == "handled" and new_techniques > (new_at_decision or 0):
            state = "open"
        in_stack = bool(product is not None and (product.product_id in product_ids or product.vendor_id in vendor_ids))
        on_record = int(t.on_record or 0) if t is not None else 0
        writable = int(t.writable_observables or 0) if t is not None else 0
        if not (on_record or writable or in_stack):
            continue
        beats = int(lead.beats or 0) if lead is not None else 0
        score = _rank_score(max(beats, 1), r.attention, min(on_record, STORY_TECHNIQUE_CAP))
        out.append(
            ThreatRow(
                entity_type=STORY,
                entity_key=r.slug,
                label=r.title,
                facets=[STORY],
                attention=r.attention,
                new_techniques=new_techniques,
                on_record=on_record,
                # Nothing in the library can resolve to a story that has no
                # entity — an empty inventory here is a fact, not a gap.
                prior_rules=0,
                prior_rules_strong=0,
                prior_rule_repos={},
                last_seen=r.last_seen.isoformat() if r.last_seen else None,
                state=state,
                is_generic=False,
                # Exposure's own multiplier, for the same reason the CVE rows
                # use it: a story about something you run is not landscape.
                score=round(score * (EXPOSURE_BASE if in_stack else 1.0), 2),
                articles=r.entries,
                stories=1,
                echoes_folded=max(0, int(r.entries or 0) - 1),
                beats=beats,
                thread_slug=r.slug,
                thread_title=r.title,
                writable_observables=writable,
                sources=list(lead.sources or []) if lead is not None else [],
                headline=(
                    {
                        "entry_id": str(lead.entry_id),
                        "title": lead.title,
                        "url": lead.url,
                        "source": lead.source,
                        "published_at": lead.published_at.isoformat() if lead.published_at else None,
                        "is_origin": bool(lead.has_origin),
                        "outlets": int(lead.outlets or 0),
                    }
                    if lead is not None and lead.entry_id is not None
                    else None
                ),
                product=product.name if product is not None else None,
                in_stack=in_stack,
            )
        )

    out = [r for r in out if include_handled or r.state in ("open", "tracked")]
    out.sort(key=lambda r: (r.state != "tracked", -r.score))
    return out[:limit]


def uuid_nil():
    import uuid as _uuid

    return _uuid.UUID(int=0)


def _date_after(d, ts) -> bool:
    """date column vs timestamptz decision time."""
    try:
        return d > ts.date()
    except (AttributeError, TypeError):
        return False


# A CVE that shares this many window entries with a visible threat row is that
# threat's vuln thread, not a standalone story — on the All view it rides the
# cluster and never gets its own line.
CVE_FOLD_SHARED_ENTRIES = 2


async def fold_claimed_cves(
    db: AsyncSession,
    threats: list[ThreatRow],
    cves: list[ThreatRow],
    window: str = "14d",
) -> list[ThreatRow]:
    """Drop CVE rows already claimed by a visible threat row's window."""
    if not threats or not cves:
        return cves
    hours = WINDOW_HOURS.get(window, WINDOW_HOURS["14d"])
    since = datetime.now(UTC) - timedelta(hours=hours)
    actor_keys = [t.entity_key for t in threats if t.entity_type == entity_types.THREAT_ACTOR]
    malware_keys = [t.entity_key for t in threats if t.entity_type == entity_types.MALWARE]
    claimed = {
        r.cve_id
        for r in (
            await db.execute(
                text("""
                    SELECT c.cve_id
                    FROM cves c
                    JOIN entry_cves ec ON ec.cve_id = c.id
                    JOIN entries e ON e.id = ec.entry_id
                    LEFT JOIN entry_threat_actors ea ON ea.entry_id = e.id AND ea.threat_actor_id::text = ANY(:akeys)
                    LEFT JOIN entry_malware em ON em.entry_id = e.id AND em.malware_family_id::text = ANY(:mkeys)
                    WHERE c.cve_id = ANY(:ckeys) AND e.published_at > :since
                      AND (ea.entry_id IS NOT NULL OR em.entry_id IS NOT NULL)
                    GROUP BY c.cve_id
                    HAVING count(DISTINCT e.id) >= :shared
                    """),
                {
                    "akeys": actor_keys or [""],
                    "mkeys": malware_keys or [""],
                    "ckeys": [c.entity_key for c in cves],
                    "since": since,
                    "shared": CVE_FOLD_SHARED_ENTRIES,
                },
            )
        ).all()
    }
    # A tracked CVE is a human pin and never folds away.
    return [c for c in cves if c.entity_key not in claimed or c.state == "tracked"]
