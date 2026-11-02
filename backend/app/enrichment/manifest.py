"""What an enrichment source declares about itself.

Each source class (an adapter, or a catalog-only class for job-only sources)
carries these as class attributes: what it applies to, what it needs, how hard
it may be called, what it sends off the box, its license, its scheduled jobs,
and what its results write. The seed rows, the job registry and the entity
field map are all generated from them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Egress(StrEnum):
    """What a source's requests reveal about the entity looked up."""

    NONE = "none"  # downloads a whole catalog; nothing entity-specific leaves
    LOW = "low"  # sends public identifiers (a CVE id, a group name)
    SHARES_IOC = "shares_ioc"  # sends an observable's value to a third party


class Display(StrEnum):
    FACT = "fact"
    CHIPS = "chips"
    TABLE = "table"
    TIMELINE = "timeline"
    LINK = "link"
    BADGE = "badge"


class Policy(StrEnum):
    """How a ``Column`` output writes its value.

    - ``FILL_BLANK``: only into a blank column.
    - ``RANK``: the lowest ``rank`` wins. A source fills a blank column,
      replaces a value held by a lower-ranked source, and may update or clear
      its own value; a "not found" answer clears it only when the output
      ``clears``. An analyst's value is never replaced. Every source's
      value is recorded as a claim, including the ones that lose.
    - ``UNION``: list columns; adds the items the column doesn't hold yet,
      outputs in ``rank`` order.
    - ``NEWER_WINS``: a value replaces whatever the column holds. A missing
      value leaves the column alone unless the output ``clears``.

    A column that ``follows`` a target is written, empty or not, whenever its
    source writes that target (a score's severity goes with the score).
    """

    FILL_BLANK = "fill_blank"
    UNION = "union"
    NEWER_WINS = "newer_wins"
    RANK = "rank"


@dataclass(frozen=True)
class License:
    name: str
    attribution: str | None = None
    commercial_ok: bool = True


@dataclass(frozen=True)
class Quota:
    """How hard a source may be called, per credential.

    ``requests_per_period`` per ``period_seconds`` is a hard rolling window:
    no stretch of ``period_seconds`` ever holds more requests than that.
    ``concurrency`` is how many requests may be in flight at once, across
    every worker. ``keyed`` is used instead when an API key is set.
    """

    requests_per_period: int
    period_seconds: int
    daily_budget: int | None
    ceiling_per_period: int | None = None  # an admin can't save a rate above this
    keyed: Quota | None = None  # used instead when an API key is set
    concurrency: int = 2

    @property
    def rate_limit_config(self) -> dict:
        """The ``enrichment_sources.rate_limit_config`` shape."""
        return {"requests_per_period": self.requests_per_period, "period_seconds": self.period_seconds}


@dataclass(frozen=True)
class Match:
    """An ``applies_to`` entry: the observable ``kinds`` taken (None = every
    value), plus ``column``, the entity column whose value is looked up (sent
    to the source, or matched against its records), e.g. ``"domain"`` for a
    ransomware victim; None takes the type's default
    (``Source.lookup_column``).

    ``applies_to = {"ransomware_victim": Match(column="domain")}`` and the
    plain ``{"cve": None}`` / ``{"observable": ("ipv4",)}`` forms both work:
    ``Source`` keeps ``applies_to`` as entity_type → kinds and moves the
    Match to ``Source.match``.
    """

    kinds: tuple[str, ...] | None = None
    column: str | None = None


@dataclass(frozen=True)
class Key:
    """A requirement: an API key. ``group`` names a key shared by several
    sources (``Key("abuse_ch")``); None is the source's own key."""

    group: str | None = None


@dataclass(frozen=True)
class Job:
    key: str
    task: str
    schedule: dict  # the JOB_REGISTRY default_schedule shape
    description: str
    settings_keys: tuple[str, ...] = ()
    #: Whether the job's result reports fetched / changed / written (under
    #: those names or an alias in ``task_tracking.COUNT_KEYS``). False for a
    #: catalog job whose result is counted in its own terms.
    counts: bool = True


@dataclass(frozen=True)
class Column:
    """A parsed_data value written onto an entity column.

    ``key`` is a parsed_data key (a dot path reads nested dicts); ``target`` is
    ``<entity_type>.<column>``, or ``<entity_type>.<column>.<key>`` for a key
    inside a JSON column. ``filter`` names a transform in the field map
    (``app/enrichment/entity_updater.py``), e.g. ``"aliases"`` → filter_aliases.
    ``resolve`` names a database lookup there that turns the value into what
    the column holds, e.g. ``"vendor"`` → the id of an existing vendor; with no
    match nothing is written.
    """

    key: str
    target: str
    policy: Policy = Policy.FILL_BLANK
    rank: int | None = None
    filter: str | None = None
    follows: str | None = None  # written whenever its source writes this target
    resolve: str | None = None
    clears: bool = False  # an answer without a value empties the column, a "not found" one too

    @property
    def entity_type(self) -> str:
        return self.target.split(".", 1)[0]

    @property
    def path(self) -> str:
        """The target without its entity type: ``column`` or ``column.key``."""
        return self.target.split(".", 1)[1]


@dataclass(frozen=True)
class Context:
    """A parsed_data value shown on the entity's profile, not written to a column.

    Values are stored in ``entity_context`` shaped for their display
    (``app/enrichment/context.py``). ``item`` maps each TABLE column (or the
    TIMELINE ``date`` and ``text``) to a key of every listed row; a key of
    ``None`` takes the row itself, for a list of plain values. ``tones`` maps
    a BADGE's value to its tone; a value it doesn't list shows no badge.
    """

    key: str
    label: str
    display: Display
    item: dict | None = None
    entity_types: tuple[str, ...] = ()  # () = every applies_to type
    tones: dict | None = None


@dataclass(frozen=True)
class Relation:
    """A parsed_data list naming entities this one is connected to: each item
    becomes a ``relation`` claim from the entity to an existing entity of one
    of ``target_types`` (``app/enrichment/relations.py``). Targets are only
    ever resolved, never created; one the source names but IntelFeed doesn't
    have, or has more than one of, is held for review.

    ``item`` maps ``name`` (and optionally ``evidence``, and ``aliases``: a
    list of other names to try when ``name`` matches nothing) to a key of
    every listed row; with no ``item`` the list holds plain names.

    A triple the relationship matrix allows only the other way round (a
    malware family ``communicates_with`` an observable) is stored that way:
    an observable's source names the family, the connection runs from it.
    ``hold=False`` drops a name that resolves to nothing instead of holding
    it, for lists that only sometimes name an entity (free-form tags).
    """

    key: str
    relation: str
    target_types: tuple[str, ...]
    item: dict | None = None
    hold: bool = True
