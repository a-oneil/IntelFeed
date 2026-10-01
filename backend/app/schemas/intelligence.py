import uuid
from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExtractionResponse[T](BaseModel):
    """Wrapper for extraction endpoints with status information."""

    items: list[T]
    status: str = "success"  # success | ai_not_configured | provider_error | parse_error
    error_message: str | None = None


class BulkExtractRequest(BaseModel):
    entry_ids: list[uuid.UUID] | None = None
    feed_id: uuid.UUID | None = None
    category_id: uuid.UUID | None = None
    tag: str | None = None
    extract_types: list[str] = Field(default=["cves"])
    use_ai: bool = False
    limit: int = Field(default=100, le=500)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "feed_id": "d5b2f1a0-3c4e-4b6d-9a8f-1e2d3c4b5a69",
                "extract_types": ["cves", "ttps"],
                "use_ai": False,
                "limit": 100,
            }
        }
    )

    @model_validator(mode="after")
    def at_least_one_source(self):
        if not self.entry_ids and not self.feed_id and not self.category_id and not self.tag:
            raise ValueError("Provide entry_ids, feed_id, category_id, or tag")
        return self


class BulkTranslateRequest(BaseModel):
    entry_ids: list[uuid.UUID] | None = None
    feed_id: uuid.UUID | None = None
    category_id: uuid.UUID | None = None
    tag: str | None = None
    target_language: str | None = None
    limit: int = Field(default=100, le=500)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "feed_id": "d5b2f1a0-3c4e-4b6d-9a8f-1e2d3c4b5a69",
                "target_language": "en",
                "limit": 100,
            }
        }
    )

    @model_validator(mode="after")
    def at_least_one_source(self):
        if not self.entry_ids and not self.feed_id and not self.category_id and not self.tag:
            raise ValueError("Provide entry_ids, feed_id, category_id, or tag")
        return self


# --- TTP Schemas ---


class TTPResponse(BaseModel):
    id: uuid.UUID
    technique_id: str
    technique_name: str
    tactic: str | None
    tactics: list[str] = []
    description: str | None
    platforms: list[str] = []
    data_sources: list[str] = []
    mitre_url: str | None = None
    detection: str | None = None
    is_subtechnique: bool = False
    parent_technique_id: str | None = None
    is_deprecated: bool = False
    superseded_by: str | None = None
    matrix_domain: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    article_count: int
    # Entry-level fields (when returned per-entry)
    confidence: str | None = None
    source_text: str | None = None

    model_config = {"from_attributes": True}


class TTPFamilyRef(BaseModel):
    """Lightweight reference to a related technique (parent/sub/replacement)."""

    id: uuid.UUID
    technique_id: str
    technique_name: str
    is_deprecated: bool = False


class TTPRelatedTechniquesResponse(BaseModel):
    parent: TTPFamilyRef | None = None
    subtechniques: list[TTPFamilyRef] = []
    replacement: TTPFamilyRef | None = None


# --- CVE Schemas ---


class CVEResponse(BaseModel):
    id: uuid.UUID
    cve_id: str
    cvss_score: Decimal | None
    severity: str | None
    description: str | None
    affected_products: list
    exploit_status: str | None
    exploit_sources: list
    references_: list = []
    nvd_data: dict
    timeline: list | dict
    first_seen_at: datetime
    updated_at: datetime
    article_count: int = 0
    # EPSS scores
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_updated_at: datetime | None = None
    # Previous score + when it moved — what the epss_jump signal fires on. Kept
    # on the model but never surfaced, so a jump was invisible on the profile.
    epss_previous_score: float | None = None
    epss_changed_at: datetime | None = None
    # Exploit tracking
    exploit_availability: str | None = None
    exploit_status_source: str | None = None
    github_poc_count: int | None = None
    github_poc_urls: list[str] = []
    metasploit_module: str | None = None
    # CISA KEV membership
    is_kev: bool = False
    kev_date_added: date | None = None
    kev_due_date: date | None = None
    # Computed priority from CVSS + EPSS + KEV
    priority: str | None = None
    # Computed risk tier: critical (KEV) > high (EPSS/metasploit) > medium (PoC/CVSS) > low
    risk_tier: str | None = None

    model_config = {"from_attributes": True}


# --- CVE affected (authoritative NVD CPE links) ---


class AffectedProductRef(BaseModel):
    """A resolved product badge (vendor rollup) or version-carrying link row."""

    id: uuid.UUID | None = None
    name: str | None = None
    cpe_product: str
    version_start: str | None = None
    version_end: str | None = None


class AffectedCVEItem(BaseModel):
    id: uuid.UUID
    cve_id: str
    severity: str | None = None
    cvss_score: Decimal | None = None
    epss_score: float | None = None
    is_kev: bool = False
    exploited: bool = False
    description: str | None = None
    published_at: str | None = None
    vendor_level: bool = False
    #: Which weakness matched, on a CWE profile's list. Populated only there,
    #: and only interesting when the list includes descendants: a CVE surfacing
    #: under CWE-664 is really tagged CWE-416, and the row should say so.
    matched_cwe: str | None = None
    matched_cwe_name: str | None = None
    products: list[AffectedProductRef] = []


class AffectedByProduct(BaseModel):
    id: uuid.UUID
    name: str
    count: int


class AffectedCVECounts(BaseModel):
    severity: dict[str, int] = {}
    kev: int = 0
    exploited: int = 0


class AffectedCVEsResponse(BaseModel):
    items: list[AffectedCVEItem]
    total: int
    limit: int
    offset: int
    has_more: bool
    counts: AffectedCVECounts = AffectedCVECounts()
    by_product: list[AffectedByProduct] = []
    vendor_level_count: int = 0
    #: cwe mode only: how many catalog rows the query spanned (1 = this weakness
    #: alone). Lets the summary say "and everything below it" only when there is
    #: something below it — CWE-416 is a leaf, CWE-664 has 300+ descendants.
    subtree_size: int | None = None


class CVEAffectedEntityRow(BaseModel):
    """One parsed CPE pair on a CVE, with entity resolution when available."""

    cpe_vendor: str
    cpe_product: str
    vendor_id: uuid.UUID | None = None
    vendor_name: str | None = None
    product_id: uuid.UUID | None = None
    product_name: str | None = None
    version_start: str | None = None
    version_end: str | None = None


# --- Threat Actor Schemas ---


class ThreatActorResponse(BaseModel):
    id: uuid.UUID
    name: str
    aliases: list[str]
    description: str | None
    mitre_id: str | None
    country: str | None
    origin_country_id: uuid.UUID | None = None
    motivation: str | None
    actor_type: str | None = None
    associated_ttps: list
    targeted_sectors: list[str] = []
    first_seen_at: datetime
    last_seen_at: datetime
    article_count: int
    matched_names: list[str] | None = None
    wikipedia_url: str | None = None
    wikipedia_image_url: str | None = None
    # How this row got here — the workbench Source/Confidence columns read these
    # rather than the entry-junction fields, which are null outside per-entry context.
    created_via: str | None = None
    created_confidence: str | None = None
    needs_review: bool = False

    model_config = {"from_attributes": True}


# --- Country Schemas ---


class CountryResponse(BaseModel):
    id: uuid.UUID
    name: str
    iso_code: str | None
    aliases: list[str] = []
    region: str | None
    description: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    article_count: int
    # Actors with a ThreatActorTargetCountry link (batch-populated on the list endpoint)
    targeting_actor_count: int = 0

    model_config = {"from_attributes": True}


class EntryCountryResponse(BaseModel):
    """Country linked to an entry, including junction metadata."""

    id: uuid.UUID
    name: str
    iso_code: str | None
    aliases: list[str] = []
    region: str | None
    description: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    article_count: int
    role: str | None = None
    confidence: str | None = None
    source: str | None = None
    matched_names: list[str] | None = None
    wikipedia_url: str | None = None
    wikipedia_image_url: str | None = None

    model_config = {"from_attributes": True}


# --- Sector Schemas ---


class SectorResponse(BaseModel):
    """A victim-sector entity (closed vocabulary; see app.intelligence.sectors)."""

    id: uuid.UUID
    slug: str
    name: str
    aliases: list[str] = []
    description: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    article_count: int
    # Batch-populated on the list endpoint from the target junctions / leak-site victims
    targeting_actor_count: int = 0
    targeting_malware_count: int = 0
    victim_count: int = 0

    model_config = {"from_attributes": True}


class EntrySectorResponse(BaseModel):
    """Targeted victim sector linked to an entry.

    ``sector``/``label`` are the pre-entity names of ``slug``/``name`` and stay
    for existing readers; ``id`` is what links to the sector profile.
    """

    id: uuid.UUID | None = None
    slug: str | None = None
    name: str | None = None
    sector: str  # canonical slug, e.g. "financial-services"
    label: str  # display label, e.g. "Financial Services"
    confidence: str | None = None
    source: str | None = None


# --- Malware Family Schemas ---


class MalwareFamilyResponse(BaseModel):
    id: uuid.UUID
    name: str
    aliases: list[str]
    description: str | None
    malpedia_url: str | None
    malware_type: str | None
    mitre_id: str | None = None
    associated_actors: list
    targeted_sectors: list[str] = []
    first_seen_at: datetime
    last_seen_at: datetime
    article_count: int
    matched_names: list[str] | None = None
    wikipedia_url: str | None = None
    wikipedia_image_url: str | None = None
    created_via: str | None = None
    created_confidence: str | None = None
    needs_review: bool = False

    model_config = {"from_attributes": True}


# --- Detection Rule Schemas ---

RULE_TYPE_PATTERN = r"^(sigma|splunk_spl|crowdstrike_ql|elastic_ql|kql|snort_suricata|yara|nuclei|panther)$"


class RuleTelemetry(BaseModel):
    """Per-rule telemetry feasibility vs the enabled Telemetry Sources inventory."""

    required: list[str] = []
    collected: list[str] = []
    missing: list[str] = []
    coverage_pct: float | None = None


class DetectionRuleCreate(BaseModel):
    entry_id: uuid.UUID | None = None
    rule_type: str = Field(pattern=RULE_TYPE_PATTERN)
    title: str = Field(min_length=1, max_length=500)
    description: str | None = None
    rule_content: str = Field(min_length=1)
    severity: str | None = None
    tags: list[str] = []
    source_ttps: list = []
    source_cves: list = []
    is_draft: bool = True
    log_sources: dict | None = None
    mitre_tactics: list[str] = []
    data_sources: list[str] = []
    notes: str | None = None
    source_entries: list[uuid.UUID] = []
    source_actors: list[uuid.UUID] = []
    source_campaigns: list[uuid.UUID] = []
    metadata: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "rule_type": "sigma",
                "title": "LockBit Ransomware Shadow Copy Deletion",
                "description": "Detects vssadmin shadow copy deletion commonly used by LockBit before encryption.",
                "rule_content": (
                    "title: LockBit Shadow Copy Deletion\n"
                    "logsource:\n  category: process_creation\n  product: windows\n"
                    "detection:\n  selection:\n    Image|endswith: '\\vssadmin.exe'\n"
                    "    CommandLine|contains: 'delete shadows'\n  condition: selection\nlevel: high\n"
                ),
                "severity": "high",
                "tags": ["ransomware", "lockbit"],
                "source_ttps": ["T1490"],
                "is_draft": True,
                "mitre_tactics": ["impact"],
                "data_sources": ["process_creation"],
            }
        }
    )


class DetectionRuleUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = None
    rule_content: str | None = Field(default=None, min_length=1)
    rule_type: str | None = Field(default=None, pattern=RULE_TYPE_PATTERN)
    severity: str | None = None
    tags: list[str] | None = None
    is_draft: bool | None = None
    log_sources: dict | None = None
    mitre_tactics: list[str] | None = None
    data_sources: list[str] | None = None
    notes: str | None = None
    source_ttps: list | None = None
    source_entries: list[uuid.UUID] | None = None
    source_actors: list[uuid.UUID] | None = None
    source_cves: list | None = None
    source_campaigns: list[uuid.UUID] | None = None
    change_description: str | None = None
    metadata: dict | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity": "critical",
                "tags": ["ransomware", "lockbit", "reviewed"],
                "is_draft": False,
                "change_description": "Promoted after FP review; severity raised",
            }
        }
    )


class DetectionRuleResponse(BaseModel):
    id: uuid.UUID
    entry_id: uuid.UUID | None
    created_by: uuid.UUID | None
    rule_type: str
    title: str
    description: str | None
    rule_content: str
    severity: str | None
    tags: list[str]
    source_ttps: list
    source_cves: list
    is_draft: bool
    log_sources: dict | None
    mitre_tactics: list[str]
    data_sources: list[str]
    notes: str | None
    metadata: dict | None = Field(default=None, validation_alias="metadata_")
    source_entries: list[uuid.UUID]
    source_actors: list[uuid.UUID]
    source_campaigns: list[uuid.UUID]
    # Provenance / reuse (research redesign, phase 1)
    license: str | None = None
    upstream_updated_at: datetime | None = None
    references: list[str] = []
    source_products: list = []
    source_repo: str | None = None
    source_author: str | None = None
    is_authored_local: bool = False
    # Set when this rule is a format conversion of another; the parent's id.
    derived_from: uuid.UUID | None = None
    telemetry: RuleTelemetry | None = None
    created_at: datetime
    updated_at: datetime
    entry_title: str | None = None
    entry_url: str | None = None

    model_config = {"from_attributes": True, "populate_by_name": True}


class DetectionRuleListItem(BaseModel):
    """Lightweight list-row shape — omits full rule_content for fast, scannable lists."""

    id: uuid.UUID
    entry_id: uuid.UUID | None
    rule_type: str
    title: str
    severity: str | None
    tags: list[str]
    source_ttps: list
    source_cves: list
    source_products: list
    mitre_tactics: list[str]
    data_sources: list[str]
    is_draft: bool
    # Provenance / relevance
    source_repo: str | None = None
    source_author: str | None = None
    license: str | None = None
    is_authored_local: bool = False
    linked_entry_count: int = 0
    linked_actor_count: int = 0
    telemetry: RuleTelemetry | None = None
    created_at: datetime
    updated_at: datetime
    upstream_updated_at: datetime | None = None
    entry_title: str | None = None
    entry_url: str | None = None

    model_config = {"from_attributes": True}


class DetectionRuleVersionResponse(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID
    version_number: int
    rule_content: str
    rule_type: str | None
    change_description: str | None
    changed_by: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}


class DetectionRuleValidateRequest(BaseModel):
    rule_type: str = Field(pattern=RULE_TYPE_PATTERN)
    rule_content: str = Field(min_length=1)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "rule_type": "sigma",
                "rule_content": (
                    "title: Suspicious PowerShell Download\n"
                    "logsource:\n  category: process_creation\n  product: windows\n"
                    "detection:\n  selection:\n    CommandLine|contains: 'DownloadString'\n  condition: selection\n"
                    "level: medium\n"
                ),
            }
        }
    )


class BulkRuleUpdateRequest(BaseModel):
    rule_ids: list[uuid.UUID] = Field(min_length=1)
    is_draft: bool | None = None
    tags_add: list[str] | None = None
    tags_remove: list[str] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "rule_ids": ["d5b2f1a0-3c4e-4b6d-9a8f-1e2d3c4b5a69", "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"],
                "is_draft": False,
                "tags_add": ["reviewed"],
                "tags_remove": ["needs-triage"],
            }
        }
    )


class BulkRuleDeleteRequest(BaseModel):
    rule_ids: list[uuid.UUID] = Field(min_length=1)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"rule_ids": ["d5b2f1a0-3c4e-4b6d-9a8f-1e2d3c4b5a69", "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"]}
        }
    )


class RuleConvertRequest(BaseModel):
    target_type: str = Field(pattern=RULE_TYPE_PATTERN)

    model_config = ConfigDict(json_schema_extra={"example": {"target_type": "splunk_spl"}})


class RuleChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)
    rule_content: str = Field(default="")
    rule_type: str = Field(default="sigma", pattern=RULE_TYPE_PATTERN)
    title: str = Field(default="")
    severity: str | None = None
    mitre_tactics: list[str] = []
    data_sources: list[str] = []
    history: list[dict] = Field(default_factory=list, description="Previous chat messages [{role, content}]")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Tighten this rule to reduce false positives from admin scripts",
                "rule_type": "sigma",
                "rule_content": "title: Suspicious PowerShell Download\nlevel: medium\n",
                "title": "Suspicious PowerShell Download",
                "severity": "medium",
                "mitre_tactics": ["execution"],
                "history": [],
            }
        }
    )


class DetectionRuleGenerateRequest(BaseModel):
    rule_types: list[str] = Field(min_length=1)

    model_config = ConfigDict(json_schema_extra={"example": {"rule_types": ["sigma", "splunk_spl"]}})


# --- Mitigation Schemas ---


class MitigationResponse(BaseModel):
    id: uuid.UUID
    mitre_id: str | None
    name: str
    description: str | None
    mitre_url: str | None
    cis_controls: list[str] = []
    nist_controls: list[str] = []
    article_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    wikipedia_url: str | None = None
    wikipedia_image_url: str | None = None
    # Entry-level (when returned per-entry)
    confidence: str | None = None
    source: str | None = None

    model_config = {"from_attributes": True}


# --- CWE Schemas ---


class ObservableResponse(BaseModel):
    id: uuid.UUID
    kind: str
    value: str
    label: str | None = None
    content: str | None = None
    language: str | None = None
    role: str | None = None
    status: str = "active"
    description: str | None = None
    evidence: str | None = None
    base_confidence: float = 0.8
    current_confidence: float = 0.8
    confidence_pinned: bool = False
    is_denied: bool = False
    #: Dual-use infrastructure label (vpn/proxy/tor/rmm/kvm/scanner/phish_sim);
    #: tagged rows are context, not indicators, and never publish.
    infra_tag: str | None = None
    needs_review: bool = False
    created_via: str | None = None
    #: Raw junction count (every entry carrying the value, list files included).
    sighting_count: int = 0
    #: Corroboration: distinct reporting entries (articles, advisories, rule
    #: files) and distinct indicator feeds. "18 sightings" from one feed's
    #: eighteen CSV variants is report_count=0, feed_source_count=1.
    report_count: int = 0
    feed_source_count: int = 0
    #: Compact reputation summary from enrichment (Shodan / GreyNoise / VT):
    #: asn, country, ports, tags, vt_ratio, gn_classification, gn_riot, enriched_at.
    reputation: dict | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    #: Decay projection: half-life for the kind (None = never decays) and the
    #: date the row will cross into expired unless re-sighted.
    decay_half_life_days: int | None = None
    expires_at: datetime | None = None
    #: Per-entry link context, present only on entry-scoped listings.
    link_source: str | None = None
    link_confidence: str | None = None
    surface_form: str | None = None
    was_defanged: bool | None = None


class ObservableCandidateRow(BaseModel):
    """One aggregated candidate in the central review queue: a (kind, value)
    the regex scan nominated but no judgment door has confirmed."""

    kind: str
    value: str
    entry_count: int
    was_defanged: bool
    sample_surface: str | None = None
    latest_entry_id: uuid.UUID | None = None
    latest_entry_title: str | None = None
    latest_seen_at: datetime | None = None


class ObservableNeverCaptureRequest(BaseModel):
    kind: str
    value: str


class ObservableEntryPayload(BaseModel):
    """An entry's confirmed observables plus its Tier-0 candidates.

    Candidates are entry-local regex nominations — not entities — surfaced so
    the reader can offer one-click promotion.
    """

    items: list[ObservableResponse] = []
    candidates: list[dict] = []


class ObservablePromoteRequest(BaseModel):
    """The analyst door: promote a candidate (or any value) into the ledger.

    ``role`` / ``evidence`` / ``label`` are optional; when omitted and the
    entry holds a matching candidate, the candidate's own judgment (an AI
    shadow staging carries role + evidence) fills them in.
    """

    kind: str
    value: str
    surface_form: str | None = None
    role: str | None = None
    evidence: str | None = None
    label: str | None = None


class ObservableDismissRequest(BaseModel):
    """Drop one candidate from one entry's nomination list (entry-local: the
    value can nominate again elsewhere; never-capture is the global rung)."""

    kind: str
    value: str


class ObservableUpdateRequest(BaseModel):
    label: str | None = None
    role: str | None = None
    description: str | None = None
    confidence_pinned: bool | None = None
    #: Admin-only: flipping to False resurrects a never-capture tombstone.
    is_denied: bool | None = None


class CWEResponse(BaseModel):
    id: uuid.UUID
    cwe_id: str
    name: str
    kind: str
    abstraction: str | None = None
    status: str | None = None
    mapping_usage: str | None = None
    description: str | None = None
    extended_description: str | None = None
    parent_cwe_id: str | None = None
    likelihood_of_exploit: str | None = None
    alternate_terms: list[str] = []
    capec_ids: list[str] = []
    consequences: list[dict] = []
    mitigations: list[dict] = []
    detection_methods: list[dict] = []
    cwe_url: str | None = None
    is_deprecated: bool = False
    superseded_by: str | None = None
    article_count: int = 0
    first_seen_at: datetime
    last_seen_at: datetime
    wikipedia_url: str | None = None
    wikipedia_image_url: str | None = None
    #: Direct CVE links (this weakness only). `cve_count_rolled` adds every
    #: descendant, which is the number that means something at Class/Pillar
    #: level — NVD tags CVEs wherever the analyst chose on the ladder.
    cve_count: int = 0
    cve_count_rolled: int | None = None
    kev_count: int = 0
    #: Rolled KEV, so it can be read against cve_count_rolled. Showing a rolled
    #: CVE count beside a direct KEV count reads as a near-zero exploitation
    #: rate on exactly the Class/Pillar rows where the rollup matters most.
    kev_count_rolled: int | None = None
    #: Vendor shipping the most CVEs with this weakness, when the CPE strings
    #: resolved. Null is normal — cve_affected resolves only part of the corpus.
    top_vendor: str | None = None
    top_vendor_count: int | None = None
    # Entry-level (when returned per-entry)
    confidence: str | None = None
    source: str | None = None

    model_config = {"from_attributes": True}


class CWEFamilyRef(BaseModel):
    id: uuid.UUID | None = None
    cwe_id: str
    name: str
    abstraction: str | None = None
    cve_count: int = 0


class CWEFamilyResponse(BaseModel):
    """Where a weakness sits on the abstraction ladder.

    `lineage` runs root-first (pillar → … → parent) so the UI can render the
    path without re-walking it; `children` and `siblings` are one hop.
    """

    lineage: list[CWEFamilyRef] = []
    parent: CWEFamilyRef | None = None
    children: list[CWEFamilyRef] = []
    siblings: list[CWEFamilyRef] = []
    replacement: CWEFamilyRef | None = None


class CVEWeaknessRow(BaseModel):
    """One NVD weakness assignment on a CVE, resolved where possible."""

    cwe_ref: str
    cwe_id: uuid.UUID | None = None
    name: str | None = None
    description: str | None = None
    abstraction: str | None = None
    kind: str | None = None
    mapping_usage: str | None = None
    is_primary: bool = False
    assigner: str | None = None
    #: Root of the abstraction ladder for this weakness, so a CVE page can say
    #: "rolls up to CWE-664 Resource Lifetime" without a second request.
    pillar_cwe_id: str | None = None
    pillar_name: str | None = None


class CWEAffectedVendorRow(BaseModel):
    """A vendor whose products carry this weakness, derived through cve_affected.

    The inverse of CWEVendorRow: that answers "what does this vendor keep getting
    wrong", this answers "who ships this flaw". Both read the same two-hop join.
    """

    vendor_id: uuid.UUID
    name: str
    cve_count: int
    kev_count: int = 0


class CWEVendorRow(BaseModel):
    """A vendor's weakness profile row, derived through cve_affected."""

    cwe_id: str
    name: str
    abstraction: str | None = None
    cve_count: int
    share: float


# --- Offensive Tool Schemas ---


class ToolResponse(BaseModel):
    id: uuid.UUID
    name: str
    aliases: list[str] = []
    description: str | None
    tool_type: str | None
    platforms: list[str] = []
    malpedia_url: str | None
    github_url: str | None
    detection_artifacts: dict = {}
    article_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    mitre_id: str | None = None
    wikipedia_url: str | None = None
    wikipedia_image_url: str | None = None
    created_via: str | None = None
    created_confidence: str | None = None
    needs_review: bool = False
    # Entry-level (when returned per-entry)
    confidence: str | None = None
    matched_names: list[str] | None = None

    model_config = {"from_attributes": True}


# --- Vendor Schemas ---


class VendorResponse(BaseModel):
    id: uuid.UUID
    name: str
    aliases: list[str] = []
    description: str | None = None
    website: str | None = None
    vendor_type: str | None = None
    article_count: int = 0
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    confidence: str | None = None
    source: str | None = None
    matched_names: list[str] | None = None
    wikipedia_url: str | None = None
    wikipedia_image_url: str | None = None

    model_config = {"from_attributes": True}


# --- Product Schemas ---


class ProductResponse(BaseModel):
    id: uuid.UUID
    vendor_id: uuid.UUID | None = None
    vendor_name: str | None = None
    name: str
    aliases: list[str] = []
    description: str | None = None
    product_type: str | None = None
    website: str | None = None
    article_count: int = 0
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    confidence: str | None = None
    source: str | None = None
    matched_names: list[str] | None = None
    wikipedia_url: str | None = None
    wikipedia_image_url: str | None = None

    model_config = {"from_attributes": True}


# --- Correlation Event Schemas ---


class CorrelationEventResponse(BaseModel):
    id: uuid.UUID
    event_type: str
    entry_id: uuid.UUID | None
    source_entity_type: str
    source_entity_id: uuid.UUID
    source_entity_label: str
    related_entity_type: str
    related_entity_id: uuid.UUID
    related_entity_label: str
    context: str
    is_read: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class CorrelationEventListResponse(BaseModel):
    items: list[CorrelationEventResponse]
    total: int
    unread_count: int


class GroupedCorrelationEventsEntry(BaseModel):
    """A group of correlation events sharing the same source article."""

    entry_id: uuid.UUID | None
    entry_title: str | None = None
    entry_url: str | None = None
    events: list[CorrelationEventResponse]
    unread_count: int
    highest_severity: str  # high, medium, low
    latest_at: datetime


class CategoryCount(BaseModel):
    category: str
    count: int
    unread: int


class GroupedCorrelationEventListResponse(BaseModel):
    groups: list[GroupedCorrelationEventsEntry]
    categories: list[CategoryCount]
    total: int
    unread_count: int


# --- Correlation Schemas ---


class PivotResponse(BaseModel):
    entity: dict
    related: dict
    related_counts: dict = {}
    # Library-wide detection coverage: {"ttps": {technique_id: rule_count},
    # "cves": {cve_id: rule_count}} over every related technique/CVE.
    rule_coverage: dict = {}
    entries: list[dict]


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    size: int = 10
    data: dict = {}


class GraphEdgeEntry(BaseModel):
    """An article/entry that links two entities in the graph."""

    entry_id: str
    title: str = ""
    score: float = 0


class GraphEdge(BaseModel):
    source: str
    target: str
    weight: float = 1
    label: str = "co-occurs"
    proximity_score: float | None = None
    # Trust facts the builder attaches — without these declared here the
    # response model silently stripped them and every edge rendered "inferred".
    confidence: str | None = None
    provenance: str | None = None
    relationship_id: str | None = None
    entries: list[GraphEdgeEntry] = []


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class EntitySearchResponse(BaseModel):
    results: list[dict]
    total: int


class TimelineEvent(BaseModel):
    entry_id: str | None = None
    title: str
    url: str | None = None
    date: str | None = None
    event_type: str = (
        "article"  # article, correlation, enrichment, detection_rule, relationship, campaign, milestone, status_change
    )
    severity: str | None = None
    event_subtype: str | None = None  # e.g. coverage_gap, new_malware_for_known_actor
    nav_context: dict | None = None  # optional navigation context for clickable events


class TimelineResponse(BaseModel):
    entity: dict
    events: list[TimelineEvent]


# --- Detection Summary Schemas ---


class DetectionSummaryRequest(BaseModel):
    entry_ids: list[uuid.UUID] = Field(min_length=1, max_length=25)
    include_existing_intelligence: bool = True
    rule_formats: list[str] = Field(default=["sigma", "splunk_spl"])
    focus: str = Field(default="campaign", pattern=r"^(campaign|vulnerability|malware|actor)$")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_ids": ["d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e"],
                "include_existing_intelligence": True,
                "rule_formats": ["sigma", "splunk_spl"],
                "focus": "campaign",
            }
        }
    )


class AttackChainStep(BaseModel):
    step: int
    phase: str
    technique: str
    description: str
    detection_opportunity: str
    log_sources: list[str] = []
    detection_feasibility: str = "medium"


class GeneratedRule(BaseModel):
    rule_type: str
    title: str
    content: str
    severity: str | None = None


class DetectionSummaryResponse(BaseModel):
    executive_summary: str = ""
    attack_chain: list[AttackChainStep] = []
    indicators: dict = {}
    generated_rules: list[GeneratedRule] = []
    related_intelligence: dict = {}
    gaps_and_recommendations: list[str] = []


class DetectionSummaryCreateRequest(BaseModel):
    """Request to generate and persist a detection summary."""

    entry_ids: list[uuid.UUID] = Field(min_length=1, max_length=25)
    title: str = Field(min_length=1, max_length=500)
    include_existing_intelligence: bool = True
    rule_formats: list[str] = Field(default=["sigma", "splunk_spl"])
    focus: str = Field(default="campaign", pattern=r"^(campaign|vulnerability|malware|actor)$")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_ids": ["d5b2f1c8-3a4e-4b6d-9c2f-8e7a1b3c5d4e"],
                "title": "LockBit healthcare campaign — detection summary",
                "rule_formats": ["sigma", "splunk_spl"],
                "focus": "campaign",
            }
        }
    )


class DetectionSummarySavedResponse(BaseModel):
    """A persisted detection summary."""

    id: uuid.UUID
    created_by: uuid.UUID | None
    title: str
    entry_ids: list[uuid.UUID]
    analysis_focus: str
    summary_content: dict
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
