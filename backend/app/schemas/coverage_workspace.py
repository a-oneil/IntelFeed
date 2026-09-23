import uuid
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class WorkspaceQuote(BaseModel):
    entry_id: str
    entry_title: str
    text: str = Field(description="entry_ttps.source_text — the sentence the technique was read from")
    paragraph_indices: list[int] = Field(description="Paragraph offsets in the article body, where recorded")
    observable_type: str | None = Field(
        None, description="domain_pattern | path | cmdline | registry | client_id | header | hash | other"
    )
    observable_value: str | None = Field(
        None, description="The concrete artefact, verbatim — what a rule draft compiles into a selection clause"
    )


class WorkspaceArticle(BaseModel):
    entry_id: str
    title: str
    url: str | None
    source: str = Field(description="Article host, feed title as fallback")
    published_at: str | None
    word_count: int | None
    technique_count: int
    new_technique_count: int = Field(description="Of those, techniques first seen for this threat in the window")
    contributed: bool = Field(description="False for a recap that added no techniques")


class WorkspaceChannel(BaseModel):
    source: str = Field(description="ATT&CK channel name, e.g. 'WinEventLog:Sysmon'")
    tier: str | None = Field(description="source | log_type | category, or null when nothing matches")


class WorkspaceBehaviour(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str | None
    entry_count: int
    first_seen: str | None
    is_new: bool = Field(description="First seen for this threat inside the window")
    quotes: list[WorkspaceQuote]
    channels: list[WorkspaceChannel]
    tier: str | None = Field(description="Strongest tier any required channel reached")
    missing_channels: list[str]
    missing_categories: list[str]
    below_line: bool = Field(
        description="No required channel matches the inventory — a sourcing item, not a detection gap"
    )
    prior_rules: int
    prior_rules_strong: int

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "technique_id": "T1078.004",
                "technique_name": "Cloud Accounts",
                "tactic": "defense-evasion",
                "entry_count": 1,
                "first_seen": "2026-08-29T11:02:00+00:00",
                "is_new": True,
                "quotes": [
                    {
                        "entry_id": "0f1c...",
                        "entry_title": "Revisiting device-code flow abuse",
                        "text": "authentication used the device-code flow against a first-party client id",
                        "paragraph_indices": [4],
                    }
                ],
                "channels": [{"source": "m365:unified", "tier": "source"}],
                "tier": "source",
                "missing_channels": [],
                "missing_categories": [],
                "below_line": False,
                "prior_rules": 47,
                "prior_rules_strong": 47,
            }
        }
    )


class CoverageWorkspaceResponse(BaseModel):
    entity_type: str
    entity_key: str
    label: str
    window: str
    articles: list[WorkspaceArticle]
    behaviours: list[WorkspaceBehaviour]
    article_total: int = Field(0, description="Every article in the window; `articles` above is a capped page")
    article_contributed_total: int = Field(0, description="Of those, the ones that carried at least one technique")
    missing_categories: list[str] = Field(description="Categories the below-line behaviours need")
    below_line_count: int
    threat_prior_rules: int = Field(
        0, description="Rules resolving to the threat itself — candidates for every behaviour"
    )
    threat_prior_rules_strong: int = Field(0, description="Of those, high or medium confidence")
    cve: dict | None = Field(
        None,
        description=(
            "Exploitation context for the CVE face: severity, CVSS, EPSS, KEV state, "
            "PoC counts and affected products. Null for other entity types."
        ),
    )


class PriorRuleItem(BaseModel):
    rule_id: str
    title: str
    rule_type: str
    repo: str
    license: str | None
    is_draft: bool
    scope: str = Field(description="technique (tagged with this behaviour) | threat (names the threat itself)")
    via: str = Field(description="tag | meta | text — which resolver writer produced the match")
    confidence: str = Field(description="high | medium | low; low is a story-tag or body-text hit")
    matched_on: str | None = Field(description="The literal that matched, so a text row stays auditable")
    tier: str | None = Field(description="Strongest telemetry tier the rule's required sources reach")
    required: list[str]
    missing: list[str]
    maintained_at: str | None = Field(
        None,
        description="Upstream commit date where recorded, else our row's — ranks a live rule above an abandoned one",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "rule_id": "3f2a...",
                "title": "Device Code Authentication Flow",
                "rule_type": "kql",
                "repo": "Azure-Sentinel",
                "license": "MIT",
                "is_draft": False,
                "scope": "technique",
                "via": "tag",
                "confidence": "high",
                "matched_on": "T1078.004",
                "tier": "source",
                "required": ["SigninLogs"],
                "missing": [],
            }
        }
    )


class PriorRulesResponse(BaseModel):
    technique_id: str
    items: list[PriorRuleItem]
    total: int = Field(description="Rows on this page")
    total_candidates: int = Field(description="Candidates before the page limit")
    strong: int = Field(description="Of all candidates, resolved at high or medium confidence")
    weak: int = Field(description="Of all candidates, low — a story tag or body-text hit")
    technique_scope: int
    threat_scope: int


class SetItem(BaseModel):
    op: str = Field(
        pattern="^(adopt|extend|new|skip)$",
        description=(
            "What is being done with the rule, not its state. A skip is a judgement "
            "worth keeping: it explains the gap to the next person who opens this threat."
        ),
    )
    rule_id: uuid.UUID | None = Field(None, description="Library rule for adopt/extend/skip; null for a new draft")
    technique_id: str | None = Field(None, description="Behaviour this item answers")
    title: str | None = Field(None, description="Overrides the library title; server fills it in when omitted")
    rule_type: str | None = None
    note: str | None = Field(None, description="Why this item is in the set — e.g. the clause an extend adds")
    reason: str | None = Field(
        None,
        description="skip only: cannot fire here | duplicate | low quality | other — renders as a known gap in exports",
    )


class SetSaveRequest(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    window: str = Field("14d", pattern="^(7d|14d|30d|90d|all)$")
    items: list[SetItem]
    entry_ids: list[UUID] = Field(default_factory=list, description="Articles the set was assembled from")
    summary_id: UUID | None = Field(None, description="Update this saved set instead of creating one")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "APT29 — device-code flow",
                "window": "14d",
                "items": [{"op": "adopt", "rule_id": "3f2a...", "technique_id": "T1078.004"}],
                "entry_ids": [],
            }
        }
    )


class SavedSet(BaseModel):
    id: UUID
    title: str
    created_at: datetime
    updated_at: datetime
    entry_ids: list[UUID]
    item_count: int
    content: dict
    upstream_moved: list[str] = Field(
        default_factory=list,
        description=(
            "Rules in this set whose upstream_updated_at postdates the save — "
            "the community changed a rule you adopted; worth a re-read"
        ),
    )


class SavedSetList(BaseModel):
    items: list[SavedSet]
    total: int


class SetExportResponse(BaseModel):
    format: str
    item_count: int
    payload: dict = Field(description="The assembled set, provenance included, ready for an export writer")
