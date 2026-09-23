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
    beats: int = Field(default=0, description="Waves of coverage on this row's story thread — its spine length")
    new_techniques: int = Field(description="Techniques first seen for this threat inside the window")
    on_record: int = Field(description="Distinct techniques ever extracted for this threat")
    prior_rules: int = Field(description="Library rules resolving to this threat, from rule_coverage")
    prior_rules_strong: int = Field(description="Of those, resolved at high or medium confidence")
    prior_rule_repos: dict[str, int] = Field(description="Prior-rule count per upstream repo")
    last_seen: str | None
    state: str = Field(description="open | handled | muted")
    is_generic: bool = Field(description="Held out of the ranking as an extraction artefact")
    score: float
    action: str = Field(description="write | extend | diff | audit | merge | review")
    articles: int = Field(default=0, description="Distinct window entries behind the attention count")
    headline: dict | None = Field(
        default=None,
        description=(
            "The window's lead article: the story thread's first in-window report where a thread "
            "holds the row (`is_origin` true when the thread marks it the origin), otherwise the "
            "most technique-dense then latest — {entry_id, title, url, source, published_at}"
        ),
    )
    sources: list[str] = Field(
        default_factory=list, description="Distinct source hosts behind the attention count (top 6)"
    )
    writable_observables: int = Field(
        default=0,
        description=(
            "In-window technique links carrying a real observable sentence — writable evidence, old techniques included"
        ),
    )
    brief: str | None = Field(
        default=None,
        description=(
            "Nightly AI story line built only from the window's entries; "
            "null until generated — render headline as fallback"
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
        None, description="blind (rule blocked by telemetry) | no_rule | defended — from classify_cves"
    )
    profile_id: str | None = Field(None, description="Entity uuid for profile navigation on CVE rows")
    thread_slug: str | None = Field(None, description="Slug of the story thread holding this row's window coverage")
    thread_title: str | None = Field(None, description="Title of that thread")
    is_story: bool = Field(
        False,
        description=(
            "A row backed only by a story thread — the articles resolved to no actor, malware "
            "or CVE. entity_key is the thread slug; open it at /priority-queue?thread=<slug>"
        ),
    )
    merged_from: list[dict] = Field(
        default_factory=list,
        description=("Rows folded into this one because a single thread holds both — {entity_type, entity_key, label}"),
    )
    on_surface: bool = Field(
        True,
        description=(
            "False for CVE rows affecting nothing in your stack with no fireable rule — "
            "landscape context that sorts below the divider, not your write-queue"
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
        description="tracked pins the threat above the ranking regardless of attention — the pull path",
    )
    note: str | None = None

    model_config = ConfigDict(json_schema_extra={"example": {"state": "handled", "note": "adopted 3 sigma rules"}})
