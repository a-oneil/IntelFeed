import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

VALID_CATEGORIES = (
    "endpoint_edr",
    "windows_events",
    "linux_macos",
    "network_security",
    "ndr",
    "ids_ips",
    "dns_security",
    "web_proxy",
    "email",
    "identity",
    "cloud",
    "saas",
    "container",
    "siem",
    "vuln_management",
    "waf_appsec",
    "vpn_remote_access",
    "database",
    "endpoint_mgmt",
    "dlp",
    "threat_intel",
    "physical_iot",
    # Legacy categories kept for backward compat
    "endpoint",
    "network",
    "virtualization",
    "application",
)

_CATEGORY_PATTERN = r"^(" + "|".join(VALID_CATEGORIES) + r")$"


class TelemetrySourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    category: str = Field(pattern=_CATEGORY_PATTERN)
    vendor: str | None = Field(default=None, max_length=100)
    product: str | None = Field(default=None, max_length=100)
    log_types: list[str] = []
    ingested_into: str | None = Field(default=None, max_length=50)
    enabled: bool = True
    notes: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "CrowdStrike Falcon",
                "category": "endpoint_edr",
                "vendor": "CrowdStrike",
                "product": "Falcon",
                "log_types": ["process_creation", "network_connection", "dns_query"],
                "ingested_into": "Splunk",
                "enabled": True,
                "notes": "Full fleet coverage: servers and workstations",
            }
        }
    )


class TelemetrySourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    category: str | None = Field(default=None, pattern=_CATEGORY_PATTERN)
    vendor: str | None = None
    product: str | None = None
    log_types: list[str] | None = None
    ingested_into: str | None = None
    enabled: bool | None = None
    notes: str | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"ingested_into": "Elastic", "enabled": False, "notes": "Migrating to Elastic in Q3"}
        }
    )


class TelemetrySourceResponse(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID | None
    name: str
    category: str
    vendor: str | None
    product: str | None
    log_types: list[str]
    ingested_into: str | None
    enabled: bool
    notes: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FeasibilityCheckRequest(BaseModel):
    data_sources: list[str] = Field(min_length=1)

    model_config = ConfigDict(
        json_schema_extra={"example": {"data_sources": ["process_creation", "dns_query", "netflow"]}}
    )


class FeasibilityCheckResponse(BaseModel):
    feasible: list[str]
    missing: list[str]
    coverage_pct: float


class TelemetrySyncRequest(BaseModel):
    """Request to sync telemetry sources from catalog checkbox selections."""

    selected_names: list[str] = Field(
        min_length=0,
        description="List of catalog item names that the user has checked/selected",
    )
    ingested_into: str | None = Field(
        default=None,
        max_length=50,
        description="Optional: which SIEM/data lake these sources are ingested into",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "selected_names": ["CrowdStrike Falcon", "Microsoft Defender for Endpoint"],
                "ingested_into": "Splunk",
            }
        }
    )


class TelemetrySyncItem(BaseModel):
    id: uuid.UUID
    name: str
    category: str
    vendor: str | None
    product: str | None
    enabled: bool
    action: str = Field(description="Action taken: created, enabled, disabled, unchanged")


class TelemetrySyncResponse(BaseModel):
    synced: list[TelemetrySyncItem]
    created_count: int
    enabled_count: int
    disabled_count: int
    unchanged_count: int
    total: int
