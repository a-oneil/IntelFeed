"""Observable — the IOC ledger, and the sighting junction that feeds it.

An observable is an *atom*: a value that exact-matches in telemetry (an IP, a
hash, a cmdline, an implant URI path). Identity is the ``(kind, value)`` pair —
the first two-column identity in the platform; every other entity type has a
single unique name/id column, and the shared registries that assume one name
attribute treat ``value`` as that attribute.

The hard rule, learned from the removed v1 subsystem (migration
``060_remove_ioc_tables``): **regex never creates a row here.** Pattern
scanning only nominates candidates that stay on the entry
(``Entry.observable_candidates``). A row exists only when something with
judgment created it — the one-pass analysis AI (with a role and an evidence
sentence), a curated ``ioc_list`` feed, a TTP observable, or an analyst.
The observables pipeline stage may then *sight* a
known value in new entries (exact match against this table is safe; regex
discovery was the trap).

Confidence decays per kind: infrastructure rotates (ips fastest), behavior
persists (hashes and host artifacts never decay). A new sighting resets the
clock. ``scripts/`` rows are hash-keyed: ``value`` is the sha256 of the
normalized snippet and ``content`` holds the code itself.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, SmallInteger, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

# ---------------------------------------------------------------------------
# Kind vocabulary
# ---------------------------------------------------------------------------
# Network kinds are stored refanged/canonical (the defanged surface form lives
# on the sighting). Host kinds map from EntryTTP.observable_type's vocabulary.
NETWORK_KINDS = frozenset({"ipv4", "ipv6", "domain", "url", "uri_path", "ja3", "ja4", "cert_fingerprint", "email"})
HASH_KINDS = frozenset({"md5", "sha1", "sha256"})
HOST_KINDS = frozenset(
    {
        "cmdline",
        "registry",
        "path",
        "mutex",
        "named_pipe",
        "service_name",
        "scheduled_task",
        "user_agent",
        "http_header",
    }
)
SCRIPT_KIND = "script"
ALL_KINDS = NETWORK_KINDS | HASH_KINDS | HOST_KINDS | {SCRIPT_KIND}

#: Confidence half-life in days, per kind. None = never decays (behavior and
#: math persist; infrastructure rotates).
DECAY_HALF_LIFE_DAYS: dict[str, int | None] = {
    "ipv4": 30,
    "ipv6": 30,
    "url": 60,
    "uri_path": 120,
    "domain": 90,
    "email": 90,
    "ja3": None,
    "ja4": None,
    "cert_fingerprint": None,
    **{k: None for k in HASH_KINDS},
    **{k: None for k in HOST_KINDS},
    SCRIPT_KIND: None,
}

#: Lifecycle states derived from current confidence (see observables service).
STATUS_ACTIVE = "active"
STATUS_AGING = "aging"
STATUS_EXPIRED = "expired"

#: How a row came to exist — the judgment doors. There is intentionally no
#: value meaning "regex".
VIA_AI = "ai_extraction"  # entry_analysis iocs array (network kinds)
VIA_TTP = "ttp_observable"  # EntryTTP.observable_value upsert (host kinds)
VIA_FEED = "ioc_list"  # curated indicator-list feed body
VIA_MANUAL = "manual"  # analyst promote / create
VIA_PUBLISHER = "publisher_ioc"  # the indicator file a write-up links to (Talos/Bitdefender/Datadog repos)

#: What the indicator was doing, per the analysis AI. Network roles name the
#: infrastructure's job; host roles are tactic-shaped (what the artifact did on
#: the box) so a cmdline or scheduled task carries context without a TTP link.
NETWORK_ROLES = frozenset({"c2", "delivery", "payload", "phishing", "exfil", "exploit", "scanning"})
HOST_ROLES = frozenset(
    {"persistence", "execution", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection"}
)
ROLES = NETWORK_ROLES | HOST_ROLES


class Observable(Base):
    __tablename__ = "observables"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_observable_kind_value"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    #: Canonical (refanged) value. For kind="script" this is the sha256 of the
    #: normalized snippet; the snippet itself lives in ``content``.
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    #: Short human label, mainly for scripts ("AMSI bypass loader").
    label: Mapped[str | None] = mapped_column(String(200))
    #: Script body (kind="script" only).
    content: Mapped[str | None] = mapped_column(Text)
    #: Script language (kind="script" only): ps1, sh, py, js, vbs, other.
    language: Mapped[str | None] = mapped_column(String(20))
    #: Network role per the analysis AI; host kinds carry a technique link on
    #: the sighting instead.
    role: Mapped[str | None] = mapped_column(String(20), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    #: The sentence the capturing door quoted as its reason.
    evidence: Mapped[str | None] = mapped_column(Text)

    # --- confidence & lifecycle (resurrected from IOC v1's schema, this time
    # with surfaces that read it) ---
    base_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.8)
    current_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.8)
    confidence_pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    status: Mapped[str] = mapped_column(
        String(12), nullable=False, default=STATUS_ACTIVE, server_default=STATUS_ACTIVE, index=True
    )
    #: Analyst hard-exclude: never re-capture and never export this value.
    is_denied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    #: Dual-use infrastructure label (vpn, proxy, tor, rmm, kvm, scanner,
    #: phish_sim), set by the feed door from the source file's path. Tagged
    #: rows stay in the ledger — an attack from a VPN exit is context worth
    #: keeping — but never publish to blocklists/TAXII.
    infra_tag: Mapped[str | None] = mapped_column(String(20), index=True)
    #: Compact reputation summary written by the enrichment updater
    #: (``asn``, ``country``, ``ports``, ``tags``, ``vt_ratio``,
    #: ``gn_classification``, ``gn_riot``, ``enriched_at``). Read-only context;
    #: the updater also fills ``infra_tag`` from it (Shodan vpn/proxy/tor tags,
    #: GreyNoise RIOT → ``benign_service``).
    reputation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # --- AI-extraction provenance (shared extraction-management column quad) ---
    created_via: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    created_from_entry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="SET NULL"), nullable=True
    )
    created_confidence: Mapped[str | None] = mapped_column(String(10), nullable=True)
    needs_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    # --- counters & dates. ``sighting_count`` is the raw junction count (and
    # ``article_count`` mirrors it for the shared entity-table convention).
    # The two corroboration counters are what the UI reads as "sources":
    # ``report_count`` = distinct non-indicator-list entries (articles,
    # advisories, rule files) carrying the value; ``feed_source_count`` =
    # distinct feeds among the indicator-list entries carrying it, so a feed
    # that publishes one list as eighteen CSV variants counts once. ---
    article_count: Mapped[int] = mapped_column(Integer, default=0)
    sighting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    report_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0", index=True)
    feed_source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    entry_observables = relationship("EntryObservable", back_populates="observable", cascade="all, delete-orphan")


class EntryObservable(Base):
    """One sighting: this value appeared in this entry, captured by this door."""

    __tablename__ = "entry_observables"

    entry_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entries.id", ondelete="CASCADE"), primary_key=True
    )
    observable_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("observables.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    confidence: Mapped[str | None] = mapped_column(String(10))
    #: Which door recorded it: ai | ttp | feed | publisher | manual | sighting.
    #: (A rule-body door was removed on 2026-09-19: rules consume IOCs, they
    #: are not a source of them.)
    #: "sighting" is the pipeline exact-matching a known value in a new entry —
    #: the one source that isn't a creation door.
    source: Mapped[str | None] = mapped_column(String(20))
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paragraph_indices: Mapped[list[int] | None] = mapped_column(ARRAY(SmallInteger), nullable=True)
    #: The exact string as the article printed it (possibly defanged).
    surface_form: Mapped[str | None] = mapped_column(Text)
    was_defanged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    #: Technique context for host kinds (the EntryTTP this value arrived on).
    ttp_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ttps.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    entry = relationship("Entry", back_populates="entry_observables")
    observable = relationship("Observable", back_populates="entry_observables")
