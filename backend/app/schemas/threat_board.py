from pydantic import BaseModel, ConfigDict, Field


class ThreatBoardItem(BaseModel):
    entity_type: str
    entity_key: str
    label: str
    # ["threat_actor", "malware"] when the same threat exists as both entities.
    facets: list[str]
    attention: int = Field(description="Distinct source domains in the window")
    stories: int = Field(
        default=0,
        description=(
            "Distinct stories behind that coverage: one per story thread, plus one per source "
            "domain no thread has claimed. Equals `attention` where nothing is threaded"
        ),
    )
    echoes_folded: int = Field(default=0, description="Window articles the row's stories folded as re-reports")
    beats: int = Field(default=0, description="Number of updates on this row's story thread (its timeline length)")
    new_techniques: int = Field(description="Techniques first seen for this threat inside the window")
    on_record: int = Field(description="Distinct techniques ever extracted for this threat")
    prior_rules: int = Field(description="Library rules resolving to this threat, from rule_coverage")
    prior_rules_strong: int = Field(description="Of those, resolved at high or medium confidence")
    prior_rule_repos: dict[str, int] = Field(description="Prior-rule count per upstream repo")
    last_seen: str | None
    state: str = Field(description="open | tracked | handled | muted")
    is_generic: bool = Field(description="Held out of the ranking as an extraction artefact")
    score: float
    action: str = Field(description="write | extend | diff | audit | merge | review")
    articles: int = Field(default=0, description="Distinct window entries behind the attention count")
    headline: dict | None = Field(
        default=None,
        description=(
            "The window's lead article: the story thread's first in-window report where a thread "
            "holds the row (`is_origin` true when the thread marks it the origin), otherwise the "
            "most technique-dense then latest: {entry_id, title, url, source, published_at}"
        ),
    )
    sources: list[str] = Field(
        default_factory=list, description="Distinct source hosts behind the attention count (top 6)"
    )
    writable_observables: int = Field(
        default=0,
        description=(
            "In-window technique links carrying a real observable sentence: writable evidence, old techniques included"
        ),
    )
    brief: str | None = Field(
        default=None,
        description=(
            "Nightly AI story line built only from the window's entries; "
            "null until generated; render headline as fallback"
        ),
    )
    brief_sources: list[str] = Field(
        default_factory=list, description="Entry ids the brief was built from (its audit trail)"
    )
    # Vulnerability-row extras — None/False on actor and malware rows.
    product: str | None = Field(None, description="First affected product/vendor, from cve_affected")
    in_stack: bool = Field(False, description="Affects a vendor/product in the caller's stack watches")
    is_kev: bool = Field(False, description="On the CISA KEV list")
    cvss_score: float | None = None
    epss_score: float | None = None
    exploit_status: str | None = Field(None, description="none | poc | weaponized | active_exploitation | kev")
    posture: str | None = Field(
        None, description="blind (rule blocked by telemetry) | no_rule | defended, from classify_cves"
    )
    profile_id: str | None = Field(None, description="Entity uuid for profile navigation on CVE rows")
    thread_slug: str | None = Field(None, description="Slug of the story thread holding this row's window coverage")
    thread_title: str | None = Field(None, description="Title of that thread")
    is_story: bool = Field(
        False,
        description=(
            "A row backed only by a story thread: the articles resolved to no actor, malware "
            "or CVE. entity_key is the thread slug; open it at /priority-queue?thread=<slug>"
        ),
    )
    merged_from: list[dict] = Field(
        default_factory=list,
        description=(
            "Rows grouped into this one, as {entity_type, entity_key, label}: actor/malware rows a single "
            "thread holds together, and on the all facet the CVEs this threat's window articles claim "
            "(entity_type cve, with is_kev / product / in_stack so the row can name them)"
        ),
    )
    on_surface: bool = Field(
        True,
        description=(
            "False for CVE rows affecting nothing in your stack with no fireable rule. "
            "Informational: it never changes the row's rank or visibility"
        ),
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "threat_actor",
                "entity_key": "f648c678-251d-447b-8461-5f2b2ec06395",
                "label": "APT29",
                "facets": ["threat_actor"],
                "attention": 7,
                "new_techniques": 18,
                "on_record": 126,
                "prior_rules": 36,
                "prior_rules_strong": 36,
                "prior_rule_repos": {"signature-base": 32, "sigma": 3, "security_content": 1},
                "last_seen": "2026-09-01T02:33:45.825697+00:00",
                "state": "open",
                "is_generic": False,
                "score": 52.0,
                "action": "extend",
            }
        }
    )


class ThreatBoardResponse(BaseModel):
    window: str
    items: list[ThreatBoardItem]
    total: int


class ThreatStateUpdate(BaseModel):
    state: str = Field(
        pattern=r"^(open|handled|muted|tracked)$",
        description="tracked pins the threat above the ranking regardless of how many sources report it",
    )
    note: str | None = None

    model_config = ConfigDict(json_schema_extra={"example": {"state": "handled", "note": "adopted 3 sigma rules"}})


class HuntTelemetry(BaseModel):
    source: str = Field(description="Canonical log-type id the query needs (e.g. auth.mfa)")
    have: bool = Field(description="Whether an enabled telemetry source covers it today")


class HuntTechniqueRef(BaseModel):
    technique_id: str
    name: str | None = Field(None, description="Catalog name; null when the catalog has no such technique")
    id: str | None = Field(None, description="The technique's profile uuid, for a link; null when not in the catalog")


class HuntHypothesis(BaseModel):
    id: str = Field(description="H1..H3 within the pack")
    title: str
    hypothesis: str = Field(description="ATHF form: 'Adversaries use [behavior] to [goal] on [target]'")
    tactic: str | None = None
    techniques: list[str] = Field(default_factory=list, description="ATT&CK technique ids")
    platform: str | None = None
    data_sources: list[str] = Field(default_factory=list, description="Canonical log-type ids the query needs")
    telemetry: list[HuntTelemetry] = Field(
        default_factory=list, description="data_sources checked against the telemetry inventory"
    )
    runnable: bool = Field(True, description="Every needed source is collected")
    query: str = Field(description="The hunting query, in the pack's language")
    query_notes: str | None = None
    false_positives: str | None = None
    evidence: str | None = Field(None, description="Why this hunt: the claim or quote it rests on (profile packs)")
    log_source: str | None = Field(None, description="The log the query reads and how it reaches the SIEM")
    source_name: str | None = Field(None, description="The telemetry inventory source holding that log; empty if none")
    source_have: bool | None = Field(
        None, description="Whether source_name is an enabled telemetry source (null on packs without log_source)"
    )
    technique_refs: list[HuntTechniqueRef] = Field(
        default_factory=list, description="techniques with their catalog names and profile ids, read live"
    )


class HuntPack(BaseModel):
    entity_type: str
    entity_key: str
    label: str
    window: str = Field(description="Scope the pack was drafted from: a board window (7d, 14d, 30d) or all")
    language: str = Field(description="Query language id, e.g. kql, spl, esql (see app.ai.query_language)")
    language_name: str
    generated_at: str | None = None
    model: str | None = None
    entry_ids: list[str] = Field(default_factory=list, description="Entries the pack was drafted from")
    hypotheses: list[HuntHypothesis]


class HuntPackResponse(BaseModel):
    status: str = Field(
        description=(
            "none | drafting | ready | failed. none until a pack is drafted for this entity, scope and "
            "language; drafting while the AI worker writes one (pack holds the previous one, if any); "
            "failed when the last draft did, with the reason in error"
        )
    )
    language: str
    language_name: str
    pack: HuntPack | None = None
    started_at: str | None = Field(None, description="When the draft in flight started (status drafting)")
    error: str | None = Field(None, description="Why the last draft failed (status failed)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "ready",
                "language": "kql",
                "language_name": "KQL (Microsoft Sentinel / Defender XDR)",
                "pack": {
                    "entity_type": "threat_actor",
                    "entity_key": "f648c678-251d-447b-8461-5f2b2ec06395",
                    "label": "Scattered Spider",
                    "window": "14d",
                    "language": "kql",
                    "language_name": "KQL (Microsoft Sentinel / Defender XDR)",
                    "generated_at": "2026-11-17T23:40:00+00:00",
                    "model": "claude-sonnet-5-5",
                    "entry_ids": ["3f1c…"],
                    "hypotheses": [
                        {
                            "id": "H1",
                            "title": "Help-desk reset followed by MFA enrollment",
                            "hypothesis": (
                                "Adversaries use help-desk password resets to register their own MFA method "
                                "on employee accounts."
                            ),
                            "tactic": "credential-access",
                            "techniques": ["T1621", "T1556.006"],
                            "platform": "Identity Provider",
                            "data_sources": ["auth.account", "auth.mfa"],
                            "telemetry": [
                                {"source": "auth.account", "have": True},
                                {"source": "auth.mfa", "have": True},
                            ],
                            "runnable": True,
                            "query": "AuditLogs | where TimeGenerated > ago(7d) | …",
                            "query_notes": "Join resets to security-info registrations within one hour.",
                            "false_positives": "New-hire onboarding resets then enrolls the same day from the office.",
                        }
                    ],
                },
            }
        }
    )
