import uuid

from fastapi import APIRouter, Body, Depends, Path, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.pagination import PaginatedResponse
from app.core.security import get_admin_user, get_current_user
from app.database import get_db
from app.models.telemetry_source import TelemetrySource
from app.models.user import User
from app.schemas.telemetry_source import (
    FeasibilityCheckRequest,
    FeasibilityCheckResponse,
    TelemetrySourceCreate,
    TelemetrySourceResponse,
    TelemetrySourceUpdate,
    TelemetrySyncItem,
    TelemetrySyncRequest,
    TelemetrySyncResponse,
)

router = APIRouter()


def _canonical_log_types(log_types: list[str] | None) -> list[str]:
    """Behaviour ids for the raw vendor strings a source declares.

    Written on every path that sets log_types so a source is matchable the
    moment it is saved, rather than after the next
    scripts/seed/seed_log_type_aliases.py run.
    """
    from app.services.detection_coverage import canonical_log_type

    return sorted({c for lt in (log_types or []) if (c := canonical_log_type(lt))})


@router.get("", response_model=PaginatedResponse[TelemetrySourceResponse])
async def list_telemetry_sources(
    category: str | None = Query(None, description="Filter by category slug (e.g. endpoint_edr, dns_security)"),
    enabled: bool | None = Query(None, description="Filter by enabled state; omit for both"),
    sort_by: str = Query(
        "category",
        pattern="^(name|category|vendor|product|ingested_into|enabled)$",
        description="Column to sort by",
    ),
    sort_order: str = Query("asc", pattern="^(asc|desc)$", description="Sort direction"),
    limit: int = Query(100, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Rows to skip for pagination"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Paginated telemetry source inventory with optional category/enabled filters and column sorting."""
    base = select(TelemetrySource)
    count_base = select(func.count()).select_from(TelemetrySource)

    if category:
        base = base.where(TelemetrySource.category == category)
        count_base = count_base.where(TelemetrySource.category == category)
    if enabled is not None:
        base = base.where(TelemetrySource.enabled == enabled)
        count_base = count_base.where(TelemetrySource.enabled == enabled)

    total = (await db.execute(count_base)).scalar() or 0

    col = getattr(TelemetrySource, sort_by)
    order = col.asc() if sort_order == "asc" else col.desc()
    query = base.order_by(order).limit(limit).offset(offset)
    result = await db.execute(query)
    sources = result.scalars().all()

    items = [TelemetrySourceResponse.model_validate(s) for s in sources]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset, has_more=(offset + limit) < total)


@router.post("", response_model=TelemetrySourceResponse, status_code=201)
async def create_telemetry_source(
    body: TelemetrySourceCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a telemetry source record in the inventory (used by detection-rule feasibility checks)."""
    source = TelemetrySource(
        created_by=user.id,
        name=body.name,
        category=body.category,
        vendor=body.vendor,
        product=body.product,
        log_types=body.log_types,
        log_types_canonical=_canonical_log_types(body.log_types),
        ingested_into=body.ingested_into,
        enabled=body.enabled,
        notes=body.notes,
    )
    db.add(source)
    await db.flush()
    await db.refresh(source)
    return TelemetrySourceResponse.model_validate(source)


@router.put("/{source_id}", response_model=TelemetrySourceResponse)
async def update_telemetry_source(
    source_id: uuid.UUID = Path(..., description="Telemetry source UUID"),
    body: TelemetrySourceUpdate = Body(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partial update of a telemetry source — only non-null fields in the body are applied."""
    result = await db.execute(select(TelemetrySource).where(TelemetrySource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise AppError(code="not_found", message="Telemetry source not found", status_code=404)

    for field in ["name", "category", "vendor", "product", "log_types", "ingested_into", "enabled", "notes"]:
        value = getattr(body, field, None)
        if value is not None:
            setattr(source, field, value)
            if field == "log_types":
                source.log_types_canonical = _canonical_log_types(value)

    db.add(source)
    await db.flush()
    await db.refresh(source)
    return TelemetrySourceResponse.model_validate(source)


@router.delete("/{source_id}", status_code=204)
async def delete_telemetry_source(
    source_id: uuid.UUID = Path(..., description="Telemetry source UUID"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a telemetry source from the inventory."""
    result = await db.execute(select(TelemetrySource).where(TelemetrySource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise AppError(code="not_found", message="Telemetry source not found", status_code=404)
    await db.delete(source)
    await db.flush()


@router.post("/check-feasibility", response_model=FeasibilityCheckResponse)
async def check_feasibility(
    body: FeasibilityCheckRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Check which data sources are covered by the user's telemetry inventory."""
    from app.services.detection_coverage import get_available_telemetry, split_data_sources

    available = await get_available_telemetry(db)
    feasible, missing = split_data_sources(body.data_sources, available)

    total = len(body.data_sources)
    coverage_pct = len(feasible) / total if total > 0 else 0.0
    return FeasibilityCheckResponse(feasible=feasible, missing=missing, coverage_pct=round(coverage_pct, 2))


@router.get("/telemetry-gaps")
async def get_telemetry_gaps(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Find detection rules that require data sources not in the user's telemetry inventory."""
    from app.models.detection_rule import DetectionRule
    from app.services.detection_coverage import get_available_telemetry, split_data_sources

    available = await get_available_telemetry(db)

    # Get all rules with data sources for this user
    rules_result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.data_sources != {},  # has data sources
        )
    )
    rules = rules_result.scalars().all()

    gaps = []
    all_missing_sources: dict[str, int] = {}

    for rule in rules:
        if not rule.data_sources:
            continue

        _, missing = split_data_sources(rule.data_sources, available)
        for ds in missing:
            all_missing_sources[ds] = all_missing_sources.get(ds, 0) + 1

        if missing:
            gaps.append(
                {
                    "rule_id": str(rule.id),
                    "rule_title": rule.title,
                    "rule_type": rule.rule_type,
                    "severity": rule.severity,
                    "is_draft": rule.is_draft,
                    "required_sources": rule.data_sources,
                    "missing_sources": missing,
                    "coverage_pct": round((len(rule.data_sources) - len(missing)) / len(rule.data_sources), 2)
                    if rule.data_sources
                    else 0,
                }
            )

    # Sort by most impacted (lowest coverage)
    gaps.sort(key=lambda g: g["coverage_pct"])

    return {
        "rules_with_gaps": gaps,
        "total_rules_checked": len(rules),
        "rules_with_gaps_count": len(gaps),
        "most_needed_sources": sorted(all_missing_sources.items(), key=lambda x: -x[1])[:20],
    }


# ---------------------------------------------------------------------------
# Legacy taxonomy (kept for backward compatibility)
# ---------------------------------------------------------------------------
DATA_SOURCE_TAXONOMY: dict[str, list[str]] = {
    "endpoint": [
        "process_creation",
        "file_creation",
        "file_modification",
        "file_deletion",
        "registry_modification",
        "network_connection",
        "dns_query",
        "image_load",
        "driver_load",
        "script_block",
        "wmi_event",
        "service_creation",
        "scheduled_task",
        "logon_event",
        "privilege_escalation",
    ],
    "network": [
        "firewall_log",
        "ids_alert",
        "netflow",
        "dns_log",
        "proxy_log",
        "web_gateway",
        "packet_capture",
        "vpn_log",
        "waf_log",
    ],
    "email": [
        "email_delivery",
        "email_trace",
        "email_attachment",
        "phishing_report",
    ],
    "identity": [
        "authentication",
        "authorization",
        "mfa_event",
        "account_modification",
        "group_modification",
        "password_change",
        "privileged_access",
    ],
    "cloud": [
        "api_call",
        "resource_creation",
        "resource_modification",
        "iam_change",
        "storage_access",
        "compute_event",
        "vpc_flow",
    ],
    "saas": [
        "audit_log",
        "file_share",
        "admin_activity",
        "user_activity",
    ],
    "container": [
        "container_start",
        "container_stop",
        "k8s_audit",
        "pod_event",
        "image_pull",
        "runtime_event",
    ],
    "database": [
        "query_log",
        "admin_operation",
        "schema_change",
        "access_audit",
    ],
    "application": [
        "web_access_log",
        "application_error",
        "api_request",
        "custom_event",
    ],
}


# ---------------------------------------------------------------------------
# Comprehensive Data Source Catalog
# ---------------------------------------------------------------------------
# Each entry represents a real-world product/platform that generates security
# telemetry.  Users checkbox the ones they have to build their telemetry
# inventory.
# ---------------------------------------------------------------------------

DATA_SOURCE_CATALOG: list[dict] = [
    # -----------------------------------------------------------------------
    # Endpoint Detection & Response (EDR)
    # -----------------------------------------------------------------------
    {
        "category": "endpoint_edr",
        "name": "CrowdStrike Falcon",
        "vendor": "CrowdStrike",
        "product": "Falcon",
        "log_types": [
            "process_creation",
            "process_injection",
            "file_creation",
            "file_modification",
            "file_deletion",
            "registry_modification",
            "network_connection",
            "dns_query",
            "image_load",
            "driver_load",
            "script_execution",
            "credential_access",
            "lateral_movement",
            "persistence",
            "defense_evasion",
            "command_and_control",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Microsoft Defender for Endpoint",
        "vendor": "Microsoft",
        "product": "Defender for Endpoint",
        "log_types": [
            "process_creation",
            "file_creation",
            "file_modification",
            "file_deletion",
            "registry_modification",
            "network_connection",
            "dns_query",
            "image_load",
            "driver_load",
            "script_execution",
            "logon_event",
            "email_link_click",
            "exploit_guard",
            "attack_surface_reduction",
            "tamper_protection",
            "device_discovery",
            "vulnerability_assessment",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "SentinelOne Singularity",
        "vendor": "SentinelOne",
        "product": "Singularity",
        "log_types": [
            "process_creation",
            "process_injection",
            "file_creation",
            "file_modification",
            "file_deletion",
            "registry_modification",
            "network_connection",
            "dns_query",
            "image_load",
            "script_execution",
            "persistence",
            "lateral_movement",
            "credential_access",
            "storyline_event",
            "threat_indicator",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Carbon Black (VMware)",
        "vendor": "VMware",
        "product": "Carbon Black Cloud",
        "log_types": [
            "process_creation",
            "file_modification",
            "registry_modification",
            "network_connection",
            "cross_process",
            "module_load",
            "script_execution",
            "binary_info",
            "sensor_event",
            "watchlist_hit",
            "threat_alert",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Cortex XDR",
        "vendor": "Palo Alto Networks",
        "product": "Cortex XDR",
        "log_types": [
            "process_creation",
            "process_injection",
            "file_creation",
            "file_modification",
            "file_deletion",
            "registry_modification",
            "network_connection",
            "dns_query",
            "image_load",
            "script_execution",
            "behavioral_threat",
            "xdr_alert",
            "causality_chain",
            "action_taken",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Cybereason",
        "vendor": "Cybereason",
        "product": "Cybereason EDR",
        "log_types": [
            "process_creation",
            "file_creation",
            "file_modification",
            "network_connection",
            "registry_modification",
            "malop",
            "suspicion",
            "evidence",
            "lateral_movement",
            "persistence",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Elastic Defend",
        "vendor": "Elastic",
        "product": "Elastic Defend",
        "log_types": [
            "process_creation",
            "file_creation",
            "file_modification",
            "file_deletion",
            "registry_modification",
            "network_connection",
            "dns_query",
            "image_load",
            "driver_load",
            "script_execution",
            "memory_threat",
            "behavior_alert",
            "ransomware_prevention",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Trellix EDR",
        "vendor": "Trellix",
        "product": "Trellix EDR",
        "log_types": [
            "process_creation",
            "file_creation",
            "file_modification",
            "network_connection",
            "registry_modification",
            "script_execution",
            "threat_detection",
            "behavioral_analysis",
            "exploit_detection",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Tanium",
        "vendor": "Tanium",
        "product": "Tanium Threat Response",
        "log_types": [
            "process_creation",
            "file_creation",
            "file_modification",
            "network_connection",
            "registry_modification",
            "driver_load",
            "image_load",
            "real_time_query",
            "incident_response",
            "live_response",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Trend Micro Vision One",
        "vendor": "Trend Micro",
        "product": "Vision One",
        "log_types": [
            "process_creation",
            "file_creation",
            "file_modification",
            "network_connection",
            "registry_modification",
            "script_execution",
            "xdr_detection",
            "workbench_alert",
            "observed_attack_technique",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Sophos Intercept X",
        "vendor": "Sophos",
        "product": "Intercept X",
        "log_types": [
            "process_creation",
            "file_creation",
            "network_connection",
            "exploit_prevention",
            "cryptoguard",
            "deep_learning_detection",
            "malware_detection",
            "web_threat",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "WatchGuard EPDR",
        "vendor": "WatchGuard",
        "product": "EPDR",
        "log_types": [
            "process_creation",
            "file_creation",
            "network_connection",
            "malware_detection",
            "exploit_detection",
            "zero_trust_application",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Cisco Secure Endpoint",
        "vendor": "Cisco",
        "product": "Secure Endpoint (AMP)",
        "log_types": [
            "process_creation",
            "file_creation",
            "file_modification",
            "network_connection",
            "device_trajectory",
            "file_trajectory",
            "threat_detected",
            "retrospective_detection",
            "malware_quarantine",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Bitdefender GravityZone",
        "vendor": "Bitdefender",
        "product": "GravityZone",
        "log_types": [
            "process_creation",
            "file_creation",
            "network_connection",
            "malware_detection",
            "advanced_threat_control",
            "hyperdetect",
            "sandbox_analysis",
            "network_attack_defense",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "ESET PROTECT",
        "vendor": "ESET",
        "product": "ESET PROTECT",
        "log_types": [
            "process_creation",
            "file_creation",
            "network_connection",
            "malware_detection",
            "firewall_event",
            "hips_event",
            "web_access",
            "device_control",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Malwarebytes EDR",
        "vendor": "Malwarebytes",
        "product": "EDR",
        "log_types": [
            "process_creation",
            "file_creation",
            "network_connection",
            "malware_detection",
            "ransomware_rollback",
            "exploit_protection",
            "suspicious_activity",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Huntress",
        "vendor": "Huntress",
        "product": "Huntress",
        "log_types": [
            "process_creation",
            "persistence_detection",
            "autorun_analysis",
            "ransomware_canary",
            "managed_detection",
            "incident_report",
        ],
    },
    {
        "category": "endpoint_edr",
        "name": "Harfanglab",
        "vendor": "Harfanglab",
        "product": "Harfanglab EDR",
        "log_types": [
            "process_creation",
            "file_creation",
            "file_modification",
            "network_connection",
            "registry_modification",
            "driver_load",
            "script_execution",
            "threat_detection",
            "sigma_rule_match",
        ],
    },
    # -----------------------------------------------------------------------
    # Windows Event Logs
    # -----------------------------------------------------------------------
    {
        "category": "windows_events",
        "name": "Windows Security Events",
        "vendor": "Microsoft",
        "product": "Windows",
        "log_types": [
            "logon_event",
            "logoff_event",
            "failed_logon",
            "account_lockout",
            "privilege_use",
            "object_access",
            "policy_change",
            "system_event",
            "process_creation",
            "process_termination",
            "audit_policy_change",
            "security_group_modification",
            "user_account_management",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows System Events",
        "vendor": "Microsoft",
        "product": "Windows",
        "log_types": [
            "service_start",
            "service_stop",
            "service_failure",
            "driver_load",
            "system_shutdown",
            "system_startup",
            "crash_dump",
            "time_change",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Application Events",
        "vendor": "Microsoft",
        "product": "Windows",
        "log_types": [
            "application_error",
            "application_hang",
            "application_install",
            "application_crash",
            "msi_installer",
            "runtime_error",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Sysmon",
        "vendor": "Microsoft",
        "product": "Sysmon",
        "log_types": [
            "process_creation",
            "process_changed_file_creation_time",
            "network_connection",
            "sysmon_state_changed",
            "process_terminated",
            "driver_loaded",
            "image_loaded",
            "create_remote_thread",
            "raw_access_read",
            "process_access",
            "file_create",
            "registry_event",
            "file_create_stream_hash",
            "registry_key_value_rename",
            "pipe_created",
            "pipe_connected",
            "wmi_event_filter",
            "wmi_event_consumer",
            "wmi_event_consumer_filter",
            "dns_query",
            "file_delete",
            "clipboard_change",
            "process_tampering",
            "file_block_executable",
            "file_block_shredding",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows PowerShell Logging",
        "vendor": "Microsoft",
        "product": "PowerShell",
        "log_types": [
            "script_block_logging",
            "module_logging",
            "transcription",
            "constrained_language_mode",
            "command_invocation",
            "pipeline_execution",
            "remote_session",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows DNS Server",
        "vendor": "Microsoft",
        "product": "Windows DNS Server",
        "log_types": [
            "dns_query",
            "dns_response",
            "zone_transfer",
            "dynamic_update",
            "dns_analytical",
            "dns_audit",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows DHCP Server",
        "vendor": "Microsoft",
        "product": "Windows DHCP Server",
        "log_types": [
            "dhcp_lease",
            "dhcp_release",
            "dhcp_renew",
            "dhcp_nack",
            "dhcp_scope_event",
            "dhcp_failover",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Active Directory",
        "vendor": "Microsoft",
        "product": "Active Directory",
        "log_types": [
            "directory_service_access",
            "directory_service_changes",
            "directory_service_replication",
            "ldap_query",
            "group_policy_application",
            "kerberos_authentication",
            "ntlm_authentication",
            "account_management",
            "trust_modification",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Group Policy",
        "vendor": "Microsoft",
        "product": "Group Policy",
        "log_types": [
            "gpo_application",
            "gpo_failure",
            "gpo_processing",
            "security_policy_applied",
            "software_installation",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Certificate Services",
        "vendor": "Microsoft",
        "product": "AD CS",
        "log_types": [
            "certificate_issued",
            "certificate_revoked",
            "certificate_request",
            "certificate_denied",
            "template_modification",
            "ca_audit",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Firewall",
        "vendor": "Microsoft",
        "product": "Windows Firewall",
        "log_types": [
            "firewall_allow",
            "firewall_block",
            "rule_modification",
            "profile_change",
            "connection_security",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Task Scheduler",
        "vendor": "Microsoft",
        "product": "Task Scheduler",
        "log_types": [
            "task_created",
            "task_deleted",
            "task_updated",
            "task_executed",
            "task_completed",
            "task_failed",
            "task_disabled",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows WMI Events",
        "vendor": "Microsoft",
        "product": "WMI",
        "log_types": [
            "wmi_query",
            "wmi_method_invocation",
            "wmi_event_subscription",
            "wmi_consumer_binding",
            "wmi_provider_load",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Remote Desktop Services",
        "vendor": "Microsoft",
        "product": "RDS",
        "log_types": [
            "rdp_connection",
            "rdp_disconnection",
            "rdp_authentication",
            "rdp_session_logon",
            "rdp_reconnection",
            "network_level_auth",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows NTLM Authentication",
        "vendor": "Microsoft",
        "product": "Windows NTLM",
        "log_types": [
            "ntlm_authentication",
            "ntlm_pass_through",
            "ntlm_blocked",
            "ntlm_audit",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Kerberos Authentication",
        "vendor": "Microsoft",
        "product": "Windows Kerberos",
        "log_types": [
            "tgt_request",
            "tgs_request",
            "kerberos_error",
            "kerberos_pre_authentication",
            "ticket_renewal",
            "constrained_delegation",
            "unconstrained_delegation",
        ],
    },
    {
        "category": "windows_events",
        "name": "Windows Defender Antivirus",
        "vendor": "Microsoft",
        "product": "Windows Defender",
        "log_types": [
            "malware_detected",
            "malware_action_taken",
            "scan_completed",
            "scan_failed",
            "signature_update",
            "real_time_protection",
            "potentially_unwanted_app",
            "behavior_monitoring",
        ],
    },
    # -----------------------------------------------------------------------
    # Linux / macOS Logs
    # -----------------------------------------------------------------------
    {
        "category": "linux_macos",
        "name": "Linux Auditd",
        "vendor": "Linux",
        "product": "auditd",
        "log_types": [
            "syscall",
            "execve",
            "file_access",
            "file_modification",
            "user_auth",
            "user_login",
            "user_logout",
            "avc_denial",
            "socket_connect",
            "socket_bind",
            "module_load",
            "mount",
            "chown",
            "chmod",
            "proctitle",
        ],
    },
    {
        "category": "linux_macos",
        "name": "Linux Syslog",
        "vendor": "Linux",
        "product": "syslog",
        "log_types": [
            "system_message",
            "daemon_event",
            "kernel_message",
            "cron_execution",
            "mail_event",
            "facility_message",
        ],
    },
    {
        "category": "linux_macos",
        "name": "Linux Auth Log",
        "vendor": "Linux",
        "product": "auth.log",
        "log_types": [
            "ssh_login",
            "ssh_failed_login",
            "sudo_command",
            "su_command",
            "pam_authentication",
            "account_modification",
            "session_open",
            "session_close",
            "public_key_auth",
        ],
    },
    {
        "category": "linux_macos",
        "name": "Linux systemd Journal",
        "vendor": "Linux",
        "product": "systemd-journald",
        "log_types": [
            "service_start",
            "service_stop",
            "service_failure",
            "unit_activation",
            "coredump",
            "boot_event",
            "slice_event",
            "timer_event",
        ],
    },
    {
        "category": "linux_macos",
        "name": "Linux iptables/nftables",
        "vendor": "Linux",
        "product": "netfilter",
        "log_types": [
            "firewall_allow",
            "firewall_drop",
            "firewall_reject",
            "nat_translation",
            "connection_tracking",
            "rate_limit",
        ],
    },
    {
        "category": "linux_macos",
        "name": "Linux SELinux/AppArmor",
        "vendor": "Linux",
        "product": "MAC Framework",
        "log_types": [
            "avc_denial",
            "policy_load",
            "boolean_change",
            "type_enforcement",
            "role_transition",
            "profile_violation",
            "apparmor_denied",
            "apparmor_allowed",
        ],
    },
    {
        "category": "linux_macos",
        "name": "macOS Unified Logging",
        "vendor": "Apple",
        "product": "macOS Unified Logging",
        "log_types": [
            "process_creation",
            "file_access",
            "network_connection",
            "user_authentication",
            "tcc_access",
            "authorization_event",
            "xpc_event",
            "kernel_event",
            "signpost",
        ],
    },
    {
        "category": "linux_macos",
        "name": "macOS Endpoint Security Framework",
        "vendor": "Apple",
        "product": "Endpoint Security",
        "log_types": [
            "process_exec",
            "process_fork",
            "file_open",
            "file_close",
            "file_rename",
            "file_unlink",
            "mmap",
            "mount",
            "signal",
            "kextload",
            "iokit_open",
        ],
    },
    {
        "category": "linux_macos",
        "name": "macOS XProtect",
        "vendor": "Apple",
        "product": "XProtect",
        "log_types": [
            "malware_detected",
            "scan_result",
            "signature_update",
            "gatekeeper_event",
            "notarization_check",
        ],
    },
    {
        "category": "linux_macos",
        "name": "Linux Falco",
        "vendor": "Sysdig",
        "product": "Falco",
        "log_types": [
            "syscall_event",
            "container_event",
            "k8s_audit_event",
            "file_access",
            "process_creation",
            "network_connection",
            "privilege_escalation",
            "shell_in_container",
        ],
    },
    {
        "category": "linux_macos",
        "name": "Linux OSSEC/Wazuh Agent",
        "vendor": "Wazuh",
        "product": "Wazuh Agent",
        "log_types": [
            "file_integrity",
            "rootkit_detection",
            "log_analysis",
            "vulnerability_detection",
            "sca_check",
            "active_response",
            "syscollector",
            "agent_event",
        ],
    },
    # -----------------------------------------------------------------------
    # Network Security (Firewalls)
    # -----------------------------------------------------------------------
    {
        "category": "network_security",
        "name": "Palo Alto Networks Firewall",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "log_types": [
            "traffic_log",
            "threat_log",
            "url_filtering",
            "wildfire_submission",
            "data_filtering",
            "globalprotect",
            "authentication_log",
            "decryption_log",
            "tunnel_inspection",
            "hip_match",
            "system_log",
            "configuration_log",
            "correlated_event",
        ],
    },
    {
        "category": "network_security",
        "name": "Fortinet FortiGate",
        "vendor": "Fortinet",
        "product": "FortiGate",
        "log_types": [
            "traffic_log",
            "utm_log",
            "ips_log",
            "antivirus_log",
            "web_filter_log",
            "application_control",
            "dns_filter",
            "ssl_vpn_log",
            "ipsec_vpn_log",
            "system_event",
            "ha_event",
            "waf_log",
        ],
    },
    {
        "category": "network_security",
        "name": "Cisco ASA/Firepower",
        "vendor": "Cisco",
        "product": "ASA/Firepower",
        "log_types": [
            "connection_event",
            "intrusion_event",
            "file_event",
            "malware_event",
            "access_control",
            "ssl_decryption",
            "vpn_event",
            "failover_event",
            "nat_translation",
            "system_log",
            "security_intelligence",
        ],
    },
    {
        "category": "network_security",
        "name": "Check Point Firewall",
        "vendor": "Check Point",
        "product": "Check Point NGFW",
        "log_types": [
            "firewall_accept",
            "firewall_drop",
            "firewall_reject",
            "vpn_log",
            "ips_log",
            "threat_prevention",
            "url_filtering",
            "application_control",
            "anti_bot",
            "threat_emulation",
            "identity_awareness",
        ],
    },
    {
        "category": "network_security",
        "name": "Juniper SRX",
        "vendor": "Juniper",
        "product": "SRX",
        "log_types": [
            "traffic_log",
            "ips_log",
            "utm_log",
            "screen_log",
            "nat_log",
            "vpn_log",
            "apptrack",
            "session_close",
            "system_log",
        ],
    },
    {
        "category": "network_security",
        "name": "pfSense/OPNsense",
        "vendor": "Netgate/Deciso",
        "product": "pfSense/OPNsense",
        "log_types": [
            "firewall_pass",
            "firewall_block",
            "nat_log",
            "dhcp_lease",
            "dns_resolver",
            "vpn_log",
            "system_event",
            "gateway_event",
        ],
    },
    {
        "category": "network_security",
        "name": "Sophos XG Firewall",
        "vendor": "Sophos",
        "product": "XG Firewall",
        "log_types": [
            "firewall_log",
            "ips_log",
            "web_filter",
            "application_filter",
            "atp_log",
            "sandstorm",
            "vpn_log",
            "authentication_log",
            "system_health",
        ],
    },
    {
        "category": "network_security",
        "name": "WatchGuard Firebox",
        "vendor": "WatchGuard",
        "product": "Firebox",
        "log_types": [
            "traffic_log",
            "proxy_log",
            "ips_log",
            "apt_blocker",
            "gateway_antivirus",
            "reputation_enabled_defense",
            "botnet_detection",
            "geolocation",
        ],
    },
    {
        "category": "network_security",
        "name": "Meraki MX",
        "vendor": "Cisco",
        "product": "Meraki MX",
        "log_types": [
            "flows",
            "urls",
            "ids_alerts",
            "security_event",
            "vpn_connectivity",
            "content_filtering",
            "amp_event",
        ],
    },
    {
        "category": "network_security",
        "name": "Barracuda CloudGen",
        "vendor": "Barracuda",
        "product": "CloudGen Firewall",
        "log_types": [
            "firewall_activity",
            "ips_log",
            "url_filter",
            "application_control",
            "vpn_log",
            "atp_log",
            "threat_log",
        ],
    },
    # -----------------------------------------------------------------------
    # Network Detection & Response (NDR)
    # -----------------------------------------------------------------------
    {
        "category": "ndr",
        "name": "Darktrace",
        "vendor": "Darktrace",
        "product": "Darktrace DETECT",
        "log_types": [
            "model_breach",
            "anomalous_connection",
            "unusual_activity",
            "device_event",
            "ai_analyst_incident",
            "compliance_violation",
            "enhanced_monitoring",
        ],
    },
    {
        "category": "ndr",
        "name": "Vectra AI",
        "vendor": "Vectra",
        "product": "Vectra AI Platform",
        "log_types": [
            "detection",
            "host_scoring",
            "account_scoring",
            "lockdown_event",
            "campaign_detection",
            "privileged_access_analytics",
            "network_metadata",
        ],
    },
    {
        "category": "ndr",
        "name": "ExtraHop Reveal(x)",
        "vendor": "ExtraHop",
        "product": "Reveal(x)",
        "log_types": [
            "detection",
            "transaction_record",
            "flow_record",
            "protocol_metadata",
            "file_transfer",
            "certificate_event",
            "device_discovery",
        ],
    },
    {
        "category": "ndr",
        "name": "Corelight (Zeek)",
        "vendor": "Corelight",
        "product": "Corelight Sensor",
        "log_types": [
            "conn_log",
            "dns_log",
            "http_log",
            "ssl_log",
            "files_log",
            "x509_log",
            "smtp_log",
            "ssh_log",
            "rdp_log",
            "smb_log",
            "kerberos_log",
            "ntlm_log",
            "pe_log",
            "notice_log",
            "weird_log",
            "dpd_log",
            "software_log",
            "intel_log",
            "suricata_corelight",
        ],
    },
    {
        "category": "ndr",
        "name": "Cisco Secure Network Analytics",
        "vendor": "Cisco",
        "product": "Secure Network Analytics (Stealthwatch)",
        "log_types": [
            "netflow",
            "security_event",
            "host_alarm",
            "exfiltration_detection",
            "command_and_control_detection",
            "insider_threat",
            "encrypted_traffic_analytics",
        ],
    },
    {
        "category": "ndr",
        "name": "Gigamon",
        "vendor": "Gigamon",
        "product": "GigaVUE",
        "log_types": [
            "application_metadata",
            "network_metadata",
            "ssl_decryption",
            "flow_record",
            "threat_insight",
        ],
    },
    {
        "category": "ndr",
        "name": "Arista NDR",
        "vendor": "Arista",
        "product": "Arista NDR (Awake)",
        "log_types": [
            "situation",
            "activity",
            "device_profile",
            "protocol_analysis",
            "threat_detection",
        ],
    },
    # -----------------------------------------------------------------------
    # IDS/IPS
    # -----------------------------------------------------------------------
    {
        "category": "ids_ips",
        "name": "Snort",
        "vendor": "Cisco/Community",
        "product": "Snort",
        "log_types": [
            "ids_alert",
            "packet_log",
            "unified2_event",
            "appid_event",
            "file_event",
            "rule_match",
        ],
    },
    {
        "category": "ids_ips",
        "name": "Suricata",
        "vendor": "OISF",
        "product": "Suricata",
        "log_types": [
            "alert",
            "anomaly",
            "dns",
            "http",
            "tls",
            "flow",
            "fileinfo",
            "smtp",
            "ssh",
            "stats",
            "dhcp",
            "mqtt",
            "quic",
            "rfb",
            "sip",
        ],
    },
    {
        "category": "ids_ips",
        "name": "Cisco Firepower IPS",
        "vendor": "Cisco",
        "product": "Firepower IPS",
        "log_types": [
            "intrusion_event",
            "impact_flag",
            "inline_result",
            "rule_match",
            "preprocessor_event",
            "rate_based_event",
        ],
    },
    {
        "category": "ids_ips",
        "name": "Palo Alto Threat Prevention",
        "vendor": "Palo Alto Networks",
        "product": "Threat Prevention",
        "log_types": [
            "threat_log",
            "vulnerability_exploit",
            "spyware_detection",
            "virus_detection",
            "flood_detection",
            "scan_detection",
        ],
    },
    {
        "category": "ids_ips",
        "name": "Trend Micro TippingPoint",
        "vendor": "Trend Micro",
        "product": "TippingPoint",
        "log_types": [
            "ips_alert",
            "block_event",
            "quarantine_event",
            "rate_limit_event",
            "reputation_event",
            "dv_filter_match",
        ],
    },
    # -----------------------------------------------------------------------
    # DNS Security
    # -----------------------------------------------------------------------
    {
        "category": "dns_security",
        "name": "Cisco Umbrella",
        "vendor": "Cisco",
        "product": "Umbrella",
        "log_types": [
            "dns_request",
            "dns_block",
            "proxy_log",
            "ip_log",
            "firewall_log",
            "amp_retrospective",
            "intelligent_proxy",
        ],
    },
    {
        "category": "dns_security",
        "name": "Infoblox BloxOne Threat Defense",
        "vendor": "Infoblox",
        "product": "BloxOne Threat Defense",
        "log_types": [
            "dns_query",
            "dns_block",
            "dns_redirect",
            "rpz_hit",
            "threat_feed_match",
            "data_exfiltration_detection",
            "dga_detection",
            "lookalike_domain",
        ],
    },
    {
        "category": "dns_security",
        "name": "Akamai Enterprise Threat Protector",
        "vendor": "Akamai",
        "product": "Enterprise Threat Protector",
        "log_types": [
            "dns_query",
            "dns_block",
            "threat_event",
            "policy_event",
            "acceptable_use_violation",
        ],
    },
    {
        "category": "dns_security",
        "name": "Cloudflare Gateway DNS",
        "vendor": "Cloudflare",
        "product": "Gateway DNS",
        "log_types": [
            "dns_query",
            "dns_block",
            "policy_match",
            "category_block",
            "security_block",
        ],
    },
    {
        "category": "dns_security",
        "name": "Quad9",
        "vendor": "Quad9",
        "product": "Quad9 DNS",
        "log_types": [
            "dns_query",
            "dns_block",
            "threat_block",
        ],
    },
    {
        "category": "dns_security",
        "name": "Zscaler DNS Security",
        "vendor": "Zscaler",
        "product": "DNS Security",
        "log_types": [
            "dns_query",
            "dns_block",
            "dns_tunnel_detection",
            "dga_detection",
            "dns_category",
        ],
    },
    # -----------------------------------------------------------------------
    # Web Proxy / Secure Web Gateway
    # -----------------------------------------------------------------------
    {
        "category": "web_proxy",
        "name": "Zscaler Internet Access",
        "vendor": "Zscaler",
        "product": "ZIA",
        "log_types": [
            "web_log",
            "url_filtering",
            "ssl_inspection",
            "cloud_firewall",
            "sandbox_report",
            "dlp_log",
            "bandwidth_control",
            "browser_isolation",
        ],
    },
    {
        "category": "web_proxy",
        "name": "Netskope",
        "vendor": "Netskope",
        "product": "Netskope SSE",
        "log_types": [
            "page_event",
            "application_event",
            "alert_event",
            "infrastructure_event",
            "audit_event",
            "incident_event",
            "dlp_event",
            "malware_event",
            "uba_alert",
        ],
    },
    {
        "category": "web_proxy",
        "name": "Broadcom ProxySG",
        "vendor": "Broadcom (Symantec)",
        "product": "ProxySG",
        "log_types": [
            "access_log",
            "ssl_log",
            "policy_log",
            "authentication_log",
            "streaming_log",
            "performance_log",
        ],
    },
    {
        "category": "web_proxy",
        "name": "McAfee Web Gateway",
        "vendor": "Trellix (McAfee)",
        "product": "Web Gateway",
        "log_types": [
            "access_log",
            "block_log",
            "ssl_scanner_log",
            "antimalware_log",
            "url_filter_log",
            "media_type_filter",
        ],
    },
    {
        "category": "web_proxy",
        "name": "Cisco Secure Web Appliance",
        "vendor": "Cisco",
        "product": "Secure Web Appliance (WSA)",
        "log_types": [
            "access_log",
            "w3c_log",
            "malware_scan_log",
            "decryption_log",
            "avc_log",
            "amp_log",
        ],
    },
    {
        "category": "web_proxy",
        "name": "Menlo Security",
        "vendor": "Menlo Security",
        "product": "Menlo Security",
        "log_types": [
            "web_log",
            "isolation_event",
            "file_download",
            "credential_phishing_block",
            "url_categorization",
        ],
    },
    {
        "category": "web_proxy",
        "name": "iboss",
        "vendor": "iboss",
        "product": "iboss Cloud Platform",
        "log_types": [
            "web_log",
            "malware_detection",
            "url_category",
            "ssl_inspection",
            "bandwidth_log",
            "dlp_event",
        ],
    },
    # -----------------------------------------------------------------------
    # Email Security
    # -----------------------------------------------------------------------
    {
        "category": "email",
        "name": "Microsoft Defender for Office 365",
        "vendor": "Microsoft",
        "product": "Defender for Office 365",
        "log_types": [
            "email_delivery",
            "email_block",
            "phishing_detection",
            "malware_detection",
            "safe_links_click",
            "safe_attachments_scan",
            "zap_event",
            "spoof_detection",
            "impersonation_detection",
            "campaign_detection",
            "threat_explorer_event",
        ],
    },
    {
        "category": "email",
        "name": "Proofpoint Email Protection",
        "vendor": "Proofpoint",
        "product": "Email Protection",
        "log_types": [
            "message_log",
            "filter_log",
            "spam_detection",
            "phishing_detection",
            "malware_detection",
            "url_defense_click",
            "attachment_defense",
            "impostor_detection",
            "dlp_event",
            "trap_event",
        ],
    },
    {
        "category": "email",
        "name": "Mimecast",
        "vendor": "Mimecast",
        "product": "Mimecast Email Security",
        "log_types": [
            "receipt_log",
            "process_log",
            "delivery_log",
            "rejection_log",
            "spam_event",
            "impersonation_protect",
            "url_protect_click",
            "attachment_protect",
            "internal_email_protect",
        ],
    },
    {
        "category": "email",
        "name": "Cisco Secure Email",
        "vendor": "Cisco",
        "product": "Secure Email (IronPort)",
        "log_types": [
            "mail_log",
            "amp_event",
            "spam_quarantine",
            "outbreak_filter",
            "dlp_event",
            "graymail_event",
            "sender_reputation",
            "content_filter",
        ],
    },
    {
        "category": "email",
        "name": "Barracuda Email Security Gateway",
        "vendor": "Barracuda",
        "product": "Email Security Gateway",
        "log_types": [
            "message_log",
            "action_log",
            "spam_log",
            "virus_log",
            "atp_log",
            "outbound_quarantine",
            "encryption_event",
        ],
    },
    {
        "category": "email",
        "name": "Abnormal Security",
        "vendor": "Abnormal Security",
        "product": "Abnormal Security",
        "log_types": [
            "threat_log",
            "case_event",
            "abuse_mailbox_event",
            "account_takeover_detection",
            "vendor_fraud_detection",
            "remediation_event",
        ],
    },
    {
        "category": "email",
        "name": "Cofense",
        "vendor": "Cofense",
        "product": "Cofense Triage",
        "log_types": [
            "phishing_report",
            "triage_result",
            "indicator_match",
            "cluster_event",
            "integration_event",
        ],
    },
    {
        "category": "email",
        "name": "Google Workspace Email Logs",
        "vendor": "Google",
        "product": "Google Workspace",
        "log_types": [
            "email_log",
            "spam_log",
            "phishing_log",
            "delivery_log",
            "policy_log",
            "dlp_event",
        ],
    },
    {
        "category": "email",
        "name": "KnowBe4 PhishER",
        "vendor": "KnowBe4",
        "product": "PhishER",
        "log_types": [
            "phishing_report",
            "disposition_event",
            "auto_disposition",
            "phishrip_event",
            "threat_feed_event",
        ],
    },
    # -----------------------------------------------------------------------
    # Identity & Access Management
    # -----------------------------------------------------------------------
    {
        "category": "identity",
        "name": "Microsoft Entra ID",
        "vendor": "Microsoft",
        "product": "Entra ID (Azure AD)",
        "log_types": [
            "sign_in_log",
            "audit_log",
            "provisioning_log",
            "risky_sign_in",
            "risky_user",
            "service_principal_sign_in",
            "managed_identity_sign_in",
            "conditional_access_evaluation",
            "mfa_event",
            "password_change",
            "group_modification",
            "application_consent",
            "directory_role_change",
        ],
    },
    {
        "category": "identity",
        "name": "Okta",
        "vendor": "Okta",
        "product": "Okta Identity Cloud",
        "log_types": [
            "authentication",
            "mfa_challenge",
            "mfa_verify",
            "session_start",
            "session_end",
            "user_lifecycle",
            "group_membership",
            "application_access",
            "admin_event",
            "policy_evaluation",
            "threat_insight",
            "system_event",
        ],
    },
    {
        "category": "identity",
        "name": "Ping Identity",
        "vendor": "Ping Identity",
        "product": "PingOne / PingFederate",
        "log_types": [
            "authentication",
            "sso_event",
            "mfa_event",
            "user_management",
            "policy_decision",
            "audit_log",
        ],
    },
    {
        "category": "identity",
        "name": "CyberArk Privileged Access",
        "vendor": "CyberArk",
        "product": "Privileged Access Manager",
        "log_types": [
            "privileged_session",
            "password_retrieval",
            "password_rotation",
            "session_recording",
            "account_management",
            "safe_access",
            "policy_violation",
            "threat_analytics",
        ],
    },
    {
        "category": "identity",
        "name": "BeyondTrust",
        "vendor": "BeyondTrust",
        "product": "Privilege Management",
        "log_types": [
            "privilege_elevation",
            "session_event",
            "password_safe_event",
            "remote_access_session",
            "policy_event",
            "discovery_event",
        ],
    },
    {
        "category": "identity",
        "name": "Duo Security",
        "vendor": "Cisco",
        "product": "Duo Security",
        "log_types": [
            "authentication_log",
            "telephony_log",
            "admin_log",
            "trust_monitor_event",
            "device_health",
            "policy_event",
        ],
    },
    {
        "category": "identity",
        "name": "OneLogin",
        "vendor": "OneLogin",
        "product": "OneLogin",
        "log_types": [
            "login_event",
            "mfa_event",
            "provisioning_event",
            "admin_event",
            "policy_event",
            "user_event",
        ],
    },
    {
        "category": "identity",
        "name": "JumpCloud",
        "vendor": "JumpCloud",
        "product": "JumpCloud Directory",
        "log_types": [
            "directory_event",
            "authentication",
            "radius_event",
            "ldap_event",
            "mdm_event",
            "admin_event",
            "sso_event",
        ],
    },
    {
        "category": "identity",
        "name": "SailPoint",
        "vendor": "SailPoint",
        "product": "IdentityNow",
        "log_types": [
            "access_request",
            "certification_event",
            "provisioning_event",
            "policy_violation",
            "role_change",
            "entitlement_change",
            "identity_change",
        ],
    },
    {
        "category": "identity",
        "name": "Delinea",
        "vendor": "Delinea (Thycotic)",
        "product": "Secret Server",
        "log_types": [
            "secret_access",
            "password_change",
            "session_recording",
            "discovery_event",
            "heartbeat_event",
            "admin_event",
        ],
    },
    {
        "category": "identity",
        "name": "ForgeRock",
        "vendor": "ForgeRock",
        "product": "ForgeRock Identity Platform",
        "log_types": [
            "authentication",
            "authorization",
            "audit_event",
            "session_event",
            "user_lifecycle",
            "policy_decision",
        ],
    },
    {
        "category": "identity",
        "name": "Auth0",
        "vendor": "Okta (Auth0)",
        "product": "Auth0",
        "log_types": [
            "login_success",
            "login_failure",
            "mfa_event",
            "token_exchange",
            "anomaly_detection",
            "brute_force_protection",
            "breached_password",
            "user_management",
        ],
    },
    {
        "category": "identity",
        "name": "RADIUS/TACACS+ Servers",
        "vendor": "Various",
        "product": "RADIUS/TACACS+",
        "log_types": [
            "authentication",
            "authorization",
            "accounting",
            "nas_event",
            "session_event",
        ],
    },
    # -----------------------------------------------------------------------
    # Cloud Platforms — AWS
    # -----------------------------------------------------------------------
    {
        "category": "cloud",
        "name": "AWS CloudTrail",
        "vendor": "Amazon",
        "product": "CloudTrail",
        "log_types": [
            "management_event",
            "data_event",
            "insight_event",
            "api_call",
            "console_login",
            "assume_role",
            "iam_change",
            "s3_object_event",
            "lambda_invocation",
            "organization_event",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS VPC Flow Logs",
        "vendor": "Amazon",
        "product": "VPC Flow Logs",
        "log_types": [
            "accepted_traffic",
            "rejected_traffic",
            "all_traffic",
            "flow_record",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS GuardDuty",
        "vendor": "Amazon",
        "product": "GuardDuty",
        "log_types": [
            "reconnaissance",
            "instance_compromise",
            "account_compromise",
            "trojan",
            "unauthorized_access",
            "cryptocurrency_mining",
            "credential_exfiltration",
            "s3_compromise",
            "kubernetes_finding",
            "malware_finding",
            "runtime_monitoring",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS Security Hub",
        "vendor": "Amazon",
        "product": "Security Hub",
        "log_types": [
            "finding",
            "insight",
            "standard_result",
            "action_target",
            "aggregated_finding",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS WAF",
        "vendor": "Amazon",
        "product": "AWS WAF",
        "log_types": [
            "waf_allow",
            "waf_block",
            "waf_count",
            "rule_group_match",
            "rate_based_rule",
            "bot_control",
            "account_takeover_prevention",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS S3 Access Logs",
        "vendor": "Amazon",
        "product": "S3",
        "log_types": [
            "get_object",
            "put_object",
            "delete_object",
            "list_bucket",
            "bucket_acl_change",
            "rest_api_request",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS Lambda Logs",
        "vendor": "Amazon",
        "product": "Lambda",
        "log_types": [
            "invocation",
            "duration",
            "error",
            "cold_start",
            "timeout",
            "memory_exceeded",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS EKS Audit Logs",
        "vendor": "Amazon",
        "product": "EKS",
        "log_types": [
            "k8s_audit",
            "authenticator",
            "controller_manager",
            "scheduler",
            "api_server",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS Config",
        "vendor": "Amazon",
        "product": "AWS Config",
        "log_types": [
            "configuration_change",
            "compliance_change",
            "snapshot_delivery",
            "config_rule_evaluation",
        ],
    },
    {
        "category": "cloud",
        "name": "AWS Route 53 DNS Logs",
        "vendor": "Amazon",
        "product": "Route 53",
        "log_types": [
            "dns_query",
            "resolver_query",
            "health_check_status",
            "dns_firewall_event",
        ],
    },
    # -----------------------------------------------------------------------
    # Cloud Platforms — Azure
    # -----------------------------------------------------------------------
    {
        "category": "cloud",
        "name": "Azure Activity Log",
        "vendor": "Microsoft",
        "product": "Azure Activity Log",
        "log_types": [
            "administrative",
            "service_health",
            "resource_health",
            "alert",
            "autoscale",
            "recommendation",
            "security",
            "policy",
        ],
    },
    {
        "category": "cloud",
        "name": "Azure Monitor",
        "vendor": "Microsoft",
        "product": "Azure Monitor",
        "log_types": [
            "metric_alert",
            "log_alert",
            "diagnostic_log",
            "activity_log",
            "change_analysis",
            "workbook_event",
        ],
    },
    {
        "category": "cloud",
        "name": "Azure NSG Flow Logs",
        "vendor": "Microsoft",
        "product": "NSG Flow Logs",
        "log_types": [
            "inbound_allowed",
            "inbound_denied",
            "outbound_allowed",
            "outbound_denied",
            "flow_record",
        ],
    },
    {
        "category": "cloud",
        "name": "Azure Key Vault Logs",
        "vendor": "Microsoft",
        "product": "Key Vault",
        "log_types": [
            "vault_access",
            "key_operation",
            "secret_operation",
            "certificate_operation",
            "policy_change",
        ],
    },
    {
        "category": "cloud",
        "name": "Azure Storage Analytics",
        "vendor": "Microsoft",
        "product": "Azure Storage",
        "log_types": [
            "read_operation",
            "write_operation",
            "delete_operation",
            "storage_access",
            "anonymous_access",
            "sas_token_use",
        ],
    },
    {
        "category": "cloud",
        "name": "Azure Kubernetes Service Audit",
        "vendor": "Microsoft",
        "product": "AKS",
        "log_types": [
            "kube_audit",
            "kube_audit_admin",
            "guard",
            "cluster_autoscaler",
            "cloud_controller_manager",
        ],
    },
    {
        "category": "cloud",
        "name": "Azure Firewall Logs",
        "vendor": "Microsoft",
        "product": "Azure Firewall",
        "log_types": [
            "application_rule",
            "network_rule",
            "nat_rule",
            "threat_intelligence",
            "idps_signature",
            "dns_proxy",
        ],
    },
    {
        "category": "cloud",
        "name": "Azure Front Door / WAF Logs",
        "vendor": "Microsoft",
        "product": "Azure Front Door",
        "log_types": [
            "access_log",
            "waf_log",
            "health_probe_log",
            "waf_block",
            "waf_allow",
            "bot_protection",
        ],
    },
    # -----------------------------------------------------------------------
    # Cloud Platforms — GCP
    # -----------------------------------------------------------------------
    {
        "category": "cloud",
        "name": "GCP Cloud Audit Logs",
        "vendor": "Google",
        "product": "Cloud Audit Logs",
        "log_types": [
            "admin_activity",
            "data_access",
            "system_event",
            "policy_denied",
            "iam_change",
            "resource_change",
        ],
    },
    {
        "category": "cloud",
        "name": "GCP VPC Flow Logs",
        "vendor": "Google",
        "product": "VPC Flow Logs",
        "log_types": [
            "flow_record",
            "accepted_traffic",
            "denied_traffic",
            "gke_flow",
        ],
    },
    {
        "category": "cloud",
        "name": "GCP Cloud Armor",
        "vendor": "Google",
        "product": "Cloud Armor",
        "log_types": [
            "waf_allow",
            "waf_deny",
            "rate_limit",
            "adaptive_protection",
            "preconfigured_rule_match",
        ],
    },
    {
        "category": "cloud",
        "name": "GCP Cloud DNS Logs",
        "vendor": "Google",
        "product": "Cloud DNS",
        "log_types": [
            "dns_query",
            "response_policy_hit",
            "dns_change",
        ],
    },
    {
        "category": "cloud",
        "name": "GCP GKE Audit Logs",
        "vendor": "Google",
        "product": "GKE",
        "log_types": [
            "k8s_audit",
            "admin_activity",
            "data_access",
            "node_event",
            "pod_event",
        ],
    },
    {
        "category": "cloud",
        "name": "GCP Cloud Storage Logs",
        "vendor": "Google",
        "product": "Cloud Storage",
        "log_types": [
            "data_access",
            "storage_read",
            "storage_write",
            "iam_policy_change",
            "bucket_update",
        ],
    },
    {
        "category": "cloud",
        "name": "Google Workspace Audit Logs",
        "vendor": "Google",
        "product": "Workspace",
        "log_types": [
            "admin_audit",
            "login_audit",
            "drive_audit",
            "calendar_audit",
            "groups_audit",
            "mobile_audit",
            "token_audit",
            "saml_audit",
            "context_aware_access",
        ],
    },
    # -----------------------------------------------------------------------
    # SaaS / Collaboration
    # -----------------------------------------------------------------------
    {
        "category": "saas",
        "name": "Microsoft 365 Unified Audit Log",
        "vendor": "Microsoft",
        "product": "Microsoft 365",
        "log_types": [
            "exchange_audit",
            "sharepoint_audit",
            "general_audit",
            "azure_ad_audit",
            "dlp_event",
            "threat_intelligence_event",
            "compliance_event",
            "power_platform_event",
        ],
    },
    {
        "category": "saas",
        "name": "Microsoft Teams Audit",
        "vendor": "Microsoft",
        "product": "Teams",
        "log_types": [
            "team_created",
            "channel_created",
            "member_added",
            "member_removed",
            "message_sent",
            "file_shared",
            "meeting_started",
            "app_installed",
            "bot_event",
        ],
    },
    {
        "category": "saas",
        "name": "SharePoint Online Audit",
        "vendor": "Microsoft",
        "product": "SharePoint Online",
        "log_types": [
            "file_accessed",
            "file_modified",
            "file_shared",
            "file_downloaded",
            "file_deleted",
            "site_collection_change",
            "permission_change",
            "search_query",
        ],
    },
    {
        "category": "saas",
        "name": "OneDrive Audit",
        "vendor": "Microsoft",
        "product": "OneDrive",
        "log_types": [
            "file_accessed",
            "file_modified",
            "file_shared",
            "file_synced",
            "file_downloaded",
            "file_deleted",
            "sharing_link_created",
        ],
    },
    {
        "category": "saas",
        "name": "Salesforce Event Monitoring",
        "vendor": "Salesforce",
        "product": "Salesforce",
        "log_types": [
            "login_event",
            "logout_event",
            "api_event",
            "report_export",
            "bulk_api_event",
            "uri_event",
            "lightning_interaction",
            "apex_execution",
            "credential_stuffing",
            "session_hijacking_detection",
        ],
    },
    {
        "category": "saas",
        "name": "Slack Enterprise Audit",
        "vendor": "Slack (Salesforce)",
        "product": "Slack Enterprise Grid",
        "log_types": [
            "user_login",
            "user_logout",
            "message_posted",
            "file_uploaded",
            "file_downloaded",
            "channel_created",
            "app_installed",
            "workspace_setting_changed",
            "idp_event",
            "anomaly_event",
        ],
    },
    {
        "category": "saas",
        "name": "Zoom Audit",
        "vendor": "Zoom",
        "product": "Zoom",
        "log_types": [
            "sign_in",
            "sign_out",
            "meeting_created",
            "meeting_started",
            "meeting_ended",
            "recording_event",
            "user_activity",
            "admin_activity",
        ],
    },
    {
        "category": "saas",
        "name": "Box Audit",
        "vendor": "Box",
        "product": "Box",
        "log_types": [
            "login",
            "upload",
            "download",
            "preview",
            "delete",
            "share",
            "collaboration",
            "admin_event",
            "shield_alert",
            "access_event",
        ],
    },
    {
        "category": "saas",
        "name": "Dropbox Business Audit",
        "vendor": "Dropbox",
        "product": "Dropbox Business",
        "log_types": [
            "login",
            "file_add",
            "file_edit",
            "file_delete",
            "file_share",
            "folder_event",
            "member_event",
            "team_activity",
            "device_event",
        ],
    },
    {
        "category": "saas",
        "name": "GitHub Audit Log",
        "vendor": "GitHub (Microsoft)",
        "product": "GitHub Enterprise",
        "log_types": [
            "authentication",
            "repository_event",
            "organization_event",
            "team_event",
            "push_event",
            "pull_request_event",
            "webhook_event",
            "secret_scanning_alert",
            "code_scanning_alert",
            "dependabot_alert",
            "copilot_event",
        ],
    },
    {
        "category": "saas",
        "name": "GitLab Audit Events",
        "vendor": "GitLab",
        "product": "GitLab",
        "log_types": [
            "authentication",
            "project_event",
            "group_event",
            "user_event",
            "push_event",
            "merge_request_event",
            "pipeline_event",
            "runner_event",
            "deploy_event",
        ],
    },
    {
        "category": "saas",
        "name": "Atlassian Audit",
        "vendor": "Atlassian",
        "product": "Jira/Confluence",
        "log_types": [
            "user_login",
            "user_creation",
            "permission_change",
            "project_event",
            "issue_event",
            "page_event",
            "space_event",
            "app_event",
            "admin_event",
        ],
    },
    {
        "category": "saas",
        "name": "ServiceNow Logs",
        "vendor": "ServiceNow",
        "product": "ServiceNow",
        "log_types": [
            "login_event",
            "transaction_log",
            "sys_audit",
            "security_event",
            "configuration_change",
            "workflow_event",
            "integration_event",
        ],
    },
    {
        "category": "saas",
        "name": "Workday Audit",
        "vendor": "Workday",
        "product": "Workday",
        "log_types": [
            "sign_on_event",
            "user_activity",
            "system_activity",
            "integration_event",
            "security_configuration_change",
            "business_process_event",
        ],
    },
    # -----------------------------------------------------------------------
    # Container & Kubernetes
    # -----------------------------------------------------------------------
    {
        "category": "container",
        "name": "Kubernetes Audit Logs",
        "vendor": "CNCF",
        "product": "Kubernetes",
        "log_types": [
            "request_received",
            "response_started",
            "response_complete",
            "panic",
            "pod_create",
            "pod_delete",
            "deployment_change",
            "secret_access",
            "configmap_change",
            "rbac_change",
            "service_account_event",
            "namespace_event",
        ],
    },
    {
        "category": "container",
        "name": "Docker Daemon Logs",
        "vendor": "Docker",
        "product": "Docker Engine",
        "log_types": [
            "container_create",
            "container_start",
            "container_stop",
            "container_kill",
            "container_die",
            "image_pull",
            "image_push",
            "volume_mount",
            "network_connect",
            "daemon_event",
        ],
    },
    {
        "category": "container",
        "name": "Aqua Security",
        "vendor": "Aqua Security",
        "product": "Aqua Platform",
        "log_types": [
            "image_scan",
            "runtime_policy",
            "network_firewall",
            "drift_prevention",
            "vulnerability_finding",
            "compliance_check",
            "secret_detection",
        ],
    },
    {
        "category": "container",
        "name": "Sysdig Secure",
        "vendor": "Sysdig",
        "product": "Sysdig Secure",
        "log_types": [
            "runtime_policy_event",
            "image_scan_result",
            "benchmark_result",
            "activity_audit",
            "capture_event",
            "falco_alert",
            "network_policy",
        ],
    },
    {
        "category": "container",
        "name": "Prisma Cloud Compute",
        "vendor": "Palo Alto Networks",
        "product": "Prisma Cloud Compute (Twistlock)",
        "log_types": [
            "image_scan",
            "container_runtime",
            "host_runtime",
            "compliance_finding",
            "vulnerability_finding",
            "cloud_native_firewall",
            "waas_event",
            "admission_audit",
        ],
    },
    {
        "category": "container",
        "name": "Falco",
        "vendor": "Sysdig/CNCF",
        "product": "Falco",
        "log_types": [
            "syscall_event",
            "k8s_audit_event",
            "cloud_trail_event",
            "rule_match",
            "priority_alert",
            "macro_event",
        ],
    },
    {
        "category": "container",
        "name": "StackRox (Red Hat ACS)",
        "vendor": "Red Hat",
        "product": "Advanced Cluster Security",
        "log_types": [
            "policy_violation",
            "vulnerability_finding",
            "compliance_result",
            "network_flow",
            "process_event",
            "admission_controller_event",
        ],
    },
    {
        "category": "container",
        "name": "Anchore",
        "vendor": "Anchore",
        "product": "Anchore Enterprise",
        "log_types": [
            "image_analysis",
            "policy_evaluation",
            "vulnerability_scan",
            "secret_scan",
            "malware_scan",
            "compliance_check",
        ],
    },
    {
        "category": "container",
        "name": "Lacework",
        "vendor": "Fortinet (Lacework)",
        "product": "Lacework",
        "log_types": [
            "anomaly_detection",
            "compliance_event",
            "vulnerability_finding",
            "host_event",
            "container_event",
            "cloud_activity",
            "polygraph_alert",
        ],
    },
    {
        "category": "container",
        "name": "Wiz Runtime",
        "vendor": "Wiz",
        "product": "Wiz Runtime Sensor",
        "log_types": [
            "runtime_event",
            "file_integrity",
            "process_event",
            "network_event",
            "vulnerability_context",
            "threat_detection",
        ],
    },
    # -----------------------------------------------------------------------
    # SIEM / Security Analytics (as data sources for a data lake)
    # -----------------------------------------------------------------------
    {
        "category": "siem",
        "name": "Splunk",
        "vendor": "Cisco (Splunk)",
        "product": "Splunk Enterprise / Cloud",
        "log_types": [
            "notable_event",
            "correlation_search",
            "adaptive_response",
            "data_model_acceleration",
            "search_audit",
            "forwarder_event",
            "hec_event",
            "alert",
        ],
    },
    {
        "category": "siem",
        "name": "Microsoft Sentinel",
        "vendor": "Microsoft",
        "product": "Microsoft Sentinel",
        "log_types": [
            "security_alert",
            "security_incident",
            "hunting_query_result",
            "watchlist_event",
            "analytics_rule_match",
            "automation_event",
            "ti_indicator_match",
            "ueba_anomaly",
        ],
    },
    {
        "category": "siem",
        "name": "Elastic Security",
        "vendor": "Elastic",
        "product": "Elastic Security",
        "log_types": [
            "detection_alert",
            "timeline_event",
            "exception_event",
            "rule_execution",
            "indicator_match",
            "ml_anomaly",
            "threshold_alert",
        ],
    },
    {
        "category": "siem",
        "name": "IBM QRadar",
        "vendor": "IBM",
        "product": "QRadar SIEM",
        "log_types": [
            "offense",
            "event",
            "flow",
            "asset_event",
            "rule_match",
            "anomaly_detection",
            "reference_set_event",
        ],
    },
    {
        "category": "siem",
        "name": "CrowdStrike LogScale",
        "vendor": "CrowdStrike",
        "product": "LogScale (Humio)",
        "log_types": [
            "ingest_event",
            "alert",
            "scheduled_search_result",
            "dashboard_query",
            "parser_event",
        ],
    },
    {
        "category": "siem",
        "name": "Exabeam",
        "vendor": "Exabeam",
        "product": "Exabeam Fusion",
        "log_types": [
            "notable_event",
            "smart_timeline",
            "session_event",
            "anomaly",
            "rule_trigger",
            "threat_hunter_event",
        ],
    },
    {
        "category": "siem",
        "name": "Securonix",
        "vendor": "Securonix",
        "product": "Securonix SNYPR",
        "log_types": [
            "policy_violation",
            "threat_model_match",
            "risk_score_event",
            "peer_group_anomaly",
            "spotter_query",
            "incident_event",
        ],
    },
    {
        "category": "siem",
        "name": "Google Chronicle",
        "vendor": "Google",
        "product": "Chronicle (SecOps)",
        "log_types": [
            "detection",
            "alert",
            "ioc_match",
            "rule_execution",
            "reference_list_match",
            "entity_context",
            "udm_event",
        ],
    },
    {
        "category": "siem",
        "name": "Sumo Logic",
        "vendor": "Sumo Logic",
        "product": "Sumo Logic",
        "log_types": [
            "log_search_result",
            "metrics_event",
            "cse_signal",
            "cse_insight",
            "threat_intel_match",
            "anomaly_detection",
        ],
    },
    {
        "category": "siem",
        "name": "Devo",
        "vendor": "Devo",
        "product": "Devo Platform",
        "log_types": [
            "alert",
            "correlation_event",
            "activeboards_query",
            "flow_event",
            "lookup_event",
        ],
    },
    {
        "category": "siem",
        "name": "LogRhythm",
        "vendor": "LogRhythm",
        "product": "LogRhythm SIEM",
        "log_types": [
            "alarm",
            "ai_engine_rule",
            "log_event",
            "case_event",
            "smartresponse_action",
            "list_event",
        ],
    },
    {
        "category": "siem",
        "name": "Rapid7 InsightIDR",
        "vendor": "Rapid7",
        "product": "InsightIDR",
        "log_types": [
            "detection",
            "investigation",
            "alert",
            "user_behavior_analytics",
            "deception_event",
            "honeypot_event",
            "network_traffic_analysis",
        ],
    },
    # -----------------------------------------------------------------------
    # Vulnerability Management
    # -----------------------------------------------------------------------
    {
        "category": "vuln_management",
        "name": "Tenable Nessus / Tenable.io",
        "vendor": "Tenable",
        "product": "Tenable.io / Nessus",
        "log_types": [
            "vulnerability_finding",
            "compliance_check",
            "scan_result",
            "host_audit",
            "plugin_output",
            "remediation_scan",
            "asset_discovery",
        ],
    },
    {
        "category": "vuln_management",
        "name": "Qualys VMDR",
        "vendor": "Qualys",
        "product": "VMDR",
        "log_types": [
            "vulnerability_detection",
            "asset_inventory",
            "patch_assessment",
            "compliance_scan",
            "threat_protection",
            "continuous_monitoring",
        ],
    },
    {
        "category": "vuln_management",
        "name": "Rapid7 InsightVM",
        "vendor": "Rapid7",
        "product": "InsightVM",
        "log_types": [
            "vulnerability_finding",
            "asset_assessment",
            "exploit_exposure",
            "risk_score",
            "remediation_project",
            "scan_event",
        ],
    },
    {
        "category": "vuln_management",
        "name": "CrowdStrike Falcon Spotlight",
        "vendor": "CrowdStrike",
        "product": "Falcon Spotlight",
        "log_types": [
            "vulnerability_finding",
            "exploit_detection",
            "zero_day_assessment",
            "patch_status",
            "host_assessment",
        ],
    },
    {
        "category": "vuln_management",
        "name": "Microsoft Defender Vulnerability Management",
        "vendor": "Microsoft",
        "product": "Defender Vulnerability Management",
        "log_types": [
            "vulnerability_finding",
            "security_recommendation",
            "software_inventory",
            "exposure_score",
            "remediation_activity",
        ],
    },
    {
        "category": "vuln_management",
        "name": "Wiz",
        "vendor": "Wiz",
        "product": "Wiz",
        "log_types": [
            "vulnerability_finding",
            "misconfiguration",
            "secret_finding",
            "malware_finding",
            "identity_risk",
            "attack_path",
            "toxic_combination",
            "data_finding",
        ],
    },
    {
        "category": "vuln_management",
        "name": "Orca Security",
        "vendor": "Orca Security",
        "product": "Orca Platform",
        "log_types": [
            "vulnerability_finding",
            "misconfiguration",
            "lateral_movement_risk",
            "malware_finding",
            "authentication_risk",
            "sensitive_data_exposure",
        ],
    },
    {
        "category": "vuln_management",
        "name": "Snyk",
        "vendor": "Snyk",
        "product": "Snyk",
        "log_types": [
            "open_source_vulnerability",
            "code_vulnerability",
            "container_vulnerability",
            "iac_misconfiguration",
            "license_issue",
            "dependency_finding",
        ],
    },
    # -----------------------------------------------------------------------
    # WAF / Application Security
    # -----------------------------------------------------------------------
    {
        "category": "waf_appsec",
        "name": "AWS WAF (AppSec)",
        "vendor": "Amazon",
        "product": "AWS WAF",
        "log_types": [
            "waf_allow",
            "waf_block",
            "waf_count",
            "rule_group_match",
            "rate_based_rule",
            "bot_control",
            "account_takeover_prevention",
        ],
    },
    {
        "category": "waf_appsec",
        "name": "Cloudflare WAF",
        "vendor": "Cloudflare",
        "product": "Cloudflare WAF",
        "log_types": [
            "firewall_event",
            "managed_rule_match",
            "rate_limit_event",
            "bot_management_event",
            "page_shield_event",
            "ddos_event",
            "custom_rule_match",
        ],
    },
    {
        "category": "waf_appsec",
        "name": "Akamai Kona Site Defender",
        "vendor": "Akamai",
        "product": "Kona Site Defender",
        "log_types": [
            "waf_event",
            "rate_control",
            "slow_post_protection",
            "application_layer_control",
            "bot_manager_event",
            "client_reputation",
        ],
    },
    {
        "category": "waf_appsec",
        "name": "Imperva WAF",
        "vendor": "Imperva",
        "product": "Cloud WAF (Incapsula)",
        "log_types": [
            "waf_alert",
            "ddos_event",
            "bot_access_control",
            "account_takeover",
            "api_security_event",
            "client_classification",
            "access_control_event",
        ],
    },
    {
        "category": "waf_appsec",
        "name": "F5 Advanced WAF",
        "vendor": "F5",
        "product": "Advanced WAF / BIG-IP ASM",
        "log_types": [
            "waf_violation",
            "bot_defense",
            "credential_stuffing",
            "brute_force_attack",
            "dos_attack",
            "protocol_violation",
            "session_tracking",
            "ip_intelligence",
        ],
    },
    {
        "category": "waf_appsec",
        "name": "Azure WAF (AppSec)",
        "vendor": "Microsoft",
        "product": "Azure WAF",
        "log_types": [
            "waf_block",
            "waf_allow",
            "managed_rule_match",
            "custom_rule_match",
            "bot_protection",
            "anomaly_scoring",
        ],
    },
    {
        "category": "waf_appsec",
        "name": "Barracuda WAF",
        "vendor": "Barracuda",
        "product": "WAF-as-a-Service",
        "log_types": [
            "waf_log",
            "access_log",
            "audit_log",
            "bot_mitigation",
            "ddos_event",
            "api_protection",
        ],
    },
    {
        "category": "waf_appsec",
        "name": "Fastly WAF",
        "vendor": "Fastly",
        "product": "Next-Gen WAF (Signal Sciences)",
        "log_types": [
            "request_event",
            "attack_signal",
            "anomaly_signal",
            "rate_limit",
            "bot_event",
            "api_discovery",
            "account_takeover",
        ],
    },
    # -----------------------------------------------------------------------
    # VPN & Remote Access
    # -----------------------------------------------------------------------
    {
        "category": "vpn_remote_access",
        "name": "Cisco AnyConnect",
        "vendor": "Cisco",
        "product": "AnyConnect",
        "log_types": [
            "vpn_connect",
            "vpn_disconnect",
            "vpn_reconnect",
            "authentication_event",
            "posture_assessment",
            "split_tunnel_event",
            "session_event",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "Palo Alto GlobalProtect",
        "vendor": "Palo Alto Networks",
        "product": "GlobalProtect",
        "log_types": [
            "vpn_connect",
            "vpn_disconnect",
            "authentication_event",
            "hip_check",
            "gateway_selection",
            "portal_event",
            "satellite_event",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "Fortinet FortiClient VPN",
        "vendor": "Fortinet",
        "product": "FortiClient",
        "log_types": [
            "vpn_connect",
            "vpn_disconnect",
            "ssl_vpn_event",
            "ipsec_vpn_event",
            "endpoint_compliance",
            "web_filter_event",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "Zscaler Private Access",
        "vendor": "Zscaler",
        "product": "ZPA",
        "log_types": [
            "user_activity",
            "app_connector_status",
            "authentication_event",
            "policy_evaluation",
            "browser_access_event",
            "machine_tunnel",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "Cloudflare Access / WARP",
        "vendor": "Cloudflare",
        "product": "Cloudflare Access / WARP",
        "log_types": [
            "access_request",
            "policy_evaluation",
            "warp_connection",
            "device_posture_check",
            "gateway_network_session",
            "tunnel_event",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "Citrix Gateway",
        "vendor": "Citrix (Cloud Software Group)",
        "product": "Citrix Gateway",
        "log_types": [
            "vpn_session",
            "ica_session",
            "authentication_event",
            "endpoint_analysis",
            "clientless_access",
            "app_launch",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "Pulse Secure / Ivanti Connect Secure",
        "vendor": "Ivanti",
        "product": "Ivanti Connect Secure",
        "log_types": [
            "vpn_connect",
            "vpn_disconnect",
            "authentication_event",
            "host_checker",
            "web_access",
            "file_access",
            "session_event",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "WireGuard Logs",
        "vendor": "WireGuard",
        "product": "WireGuard",
        "log_types": [
            "handshake_event",
            "peer_connect",
            "peer_disconnect",
            "interface_event",
            "allowed_ips_update",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "OpenVPN Logs",
        "vendor": "OpenVPN",
        "product": "OpenVPN",
        "log_types": [
            "client_connect",
            "client_disconnect",
            "authentication_event",
            "tls_handshake",
            "route_event",
            "management_event",
        ],
    },
    {
        "category": "vpn_remote_access",
        "name": "Tailscale Logs",
        "vendor": "Tailscale",
        "product": "Tailscale",
        "log_types": [
            "network_flow",
            "acl_evaluation",
            "device_authorization",
            "key_expiry",
            "exit_node_event",
            "admin_console_event",
        ],
    },
    # -----------------------------------------------------------------------
    # Database Activity Monitoring
    # -----------------------------------------------------------------------
    {
        "category": "database",
        "name": "Imperva Data Security",
        "vendor": "Imperva",
        "product": "Data Security",
        "log_types": [
            "query_audit",
            "privileged_operation",
            "schema_change",
            "data_access_violation",
            "failed_login",
            "policy_violation",
            "sensitive_data_access",
        ],
    },
    {
        "category": "database",
        "name": "IBM Guardium",
        "vendor": "IBM",
        "product": "Guardium",
        "log_types": [
            "access_audit",
            "exception_event",
            "policy_violation",
            "outlier_detection",
            "vulnerability_assessment",
            "entitlement_report",
            "classification_event",
        ],
    },
    {
        "category": "database",
        "name": "Oracle Audit Vault",
        "vendor": "Oracle",
        "product": "Audit Vault and Database Firewall",
        "log_types": [
            "sql_audit",
            "stored_procedure_audit",
            "schema_change",
            "privilege_analysis",
            "data_pump_event",
            "policy_event",
        ],
    },
    {
        "category": "database",
        "name": "AWS RDS/Aurora Logs",
        "vendor": "Amazon",
        "product": "RDS / Aurora",
        "log_types": [
            "slow_query_log",
            "error_log",
            "general_log",
            "audit_log",
            "pgaudit_log",
            "performance_insights",
        ],
    },
    {
        "category": "database",
        "name": "Azure SQL Audit",
        "vendor": "Microsoft",
        "product": "Azure SQL Database",
        "log_types": [
            "sql_audit",
            "threat_detection",
            "vulnerability_assessment",
            "data_discovery",
            "dynamic_data_masking",
        ],
    },
    {
        "category": "database",
        "name": "PostgreSQL Audit Logs",
        "vendor": "PostgreSQL",
        "product": "PostgreSQL (pgAudit)",
        "log_types": [
            "read_audit",
            "write_audit",
            "ddl_audit",
            "role_audit",
            "function_audit",
            "misc_audit",
            "connection_event",
            "error_event",
        ],
    },
    {
        "category": "database",
        "name": "MySQL Audit Logs",
        "vendor": "Oracle",
        "product": "MySQL",
        "log_types": [
            "general_log",
            "slow_query_log",
            "error_log",
            "audit_log",
            "connection_event",
            "query_event",
            "table_access_event",
        ],
    },
    {
        "category": "database",
        "name": "MongoDB Audit Logs",
        "vendor": "MongoDB",
        "product": "MongoDB",
        "log_types": [
            "authentication_event",
            "authorization_event",
            "ddl_event",
            "dml_event",
            "admin_command",
            "slow_query",
            "connection_event",
        ],
    },
    {
        "category": "database",
        "name": "Snowflake Access History",
        "vendor": "Snowflake",
        "product": "Snowflake",
        "log_types": [
            "login_history",
            "query_history",
            "access_history",
            "data_transfer_history",
            "session_history",
            "warehouse_metering",
            "stage_access",
        ],
    },
    # -----------------------------------------------------------------------
    # Endpoint Management / Asset
    # -----------------------------------------------------------------------
    {
        "category": "endpoint_mgmt",
        "name": "Microsoft Intune",
        "vendor": "Microsoft",
        "product": "Intune",
        "log_types": [
            "device_compliance",
            "device_enrollment",
            "app_install",
            "configuration_profile",
            "conditional_access",
            "wipe_event",
            "policy_assignment",
        ],
    },
    {
        "category": "endpoint_mgmt",
        "name": "JAMF Pro",
        "vendor": "JAMF",
        "product": "JAMF Pro",
        "log_types": [
            "device_enrollment",
            "policy_execution",
            "script_execution",
            "package_install",
            "configuration_profile",
            "inventory_update",
            "smart_group_change",
        ],
    },
    {
        "category": "endpoint_mgmt",
        "name": "CrowdStrike Falcon Discover",
        "vendor": "CrowdStrike",
        "product": "Falcon Discover",
        "log_types": [
            "asset_discovery",
            "application_inventory",
            "account_inventory",
            "unmanaged_asset",
            "iot_device",
            "rogue_asset",
        ],
    },
    {
        "category": "endpoint_mgmt",
        "name": "Tanium Asset",
        "vendor": "Tanium",
        "product": "Tanium Asset",
        "log_types": [
            "asset_inventory",
            "software_inventory",
            "hardware_inventory",
            "sensor_data",
            "compliance_check",
            "configuration_state",
        ],
    },
    {
        "category": "endpoint_mgmt",
        "name": "ServiceNow CMDB",
        "vendor": "ServiceNow",
        "product": "CMDB",
        "log_types": [
            "ci_change",
            "discovery_event",
            "relationship_change",
            "reconciliation_event",
            "health_check",
        ],
    },
    {
        "category": "endpoint_mgmt",
        "name": "Lansweeper",
        "vendor": "Lansweeper",
        "product": "Lansweeper",
        "log_types": [
            "asset_scan",
            "software_inventory",
            "os_inventory",
            "network_discovery",
            "vulnerability_scan",
        ],
    },
    {
        "category": "endpoint_mgmt",
        "name": "Axonius",
        "vendor": "Axonius",
        "product": "Axonius",
        "log_types": [
            "asset_aggregation",
            "adapter_event",
            "query_result",
            "enforcement_action",
            "coverage_gap",
        ],
    },
    {
        "category": "endpoint_mgmt",
        "name": "Rumble (runZero)",
        "vendor": "runZero",
        "product": "runZero",
        "log_types": [
            "asset_discovery",
            "service_discovery",
            "fingerprint_event",
            "scan_result",
            "unmanaged_asset",
        ],
    },
    # -----------------------------------------------------------------------
    # DLP / Data Security
    # -----------------------------------------------------------------------
    {
        "category": "dlp",
        "name": "Microsoft Purview DLP",
        "vendor": "Microsoft",
        "product": "Purview DLP",
        "log_types": [
            "dlp_policy_match",
            "sensitive_info_detection",
            "endpoint_dlp_event",
            "email_dlp_event",
            "teams_dlp_event",
            "sharepoint_dlp_event",
            "override_event",
        ],
    },
    {
        "category": "dlp",
        "name": "Symantec DLP",
        "vendor": "Broadcom (Symantec)",
        "product": "Symantec DLP",
        "log_types": [
            "policy_violation",
            "incident_event",
            "endpoint_discover",
            "network_monitor",
            "network_prevent",
            "storage_discover",
            "cloud_prevent",
        ],
    },
    {
        "category": "dlp",
        "name": "Digital Guardian",
        "vendor": "Fortra (Digital Guardian)",
        "product": "Digital Guardian",
        "log_types": [
            "data_egress",
            "policy_violation",
            "classification_event",
            "endpoint_event",
            "network_event",
            "cloud_event",
            "discovery_event",
        ],
    },
    {
        "category": "dlp",
        "name": "Forcepoint DLP",
        "vendor": "Forcepoint",
        "product": "Forcepoint DLP",
        "log_types": [
            "policy_violation",
            "incident_event",
            "endpoint_event",
            "email_event",
            "web_event",
            "discovery_event",
            "fingerprint_match",
        ],
    },
    {
        "category": "dlp",
        "name": "Netskope DLP",
        "vendor": "Netskope",
        "product": "Netskope DLP",
        "log_types": [
            "dlp_alert",
            "policy_violation",
            "file_exposure",
            "cloud_app_event",
            "exact_match",
            "ml_classification",
        ],
    },
    {
        "category": "dlp",
        "name": "Zscaler DLP",
        "vendor": "Zscaler",
        "product": "Zscaler DLP",
        "log_types": [
            "dlp_event",
            "policy_match",
            "icap_event",
            "endpoint_dlp",
            "exact_data_match",
            "idm_event",
        ],
    },
    {
        "category": "dlp",
        "name": "Code42 Incydr",
        "vendor": "Code42",
        "product": "Incydr",
        "log_types": [
            "file_exfiltration",
            "insider_risk_indicator",
            "removable_media_event",
            "cloud_sync_event",
            "browser_upload",
            "airdrop_event",
            "git_push_event",
        ],
    },
    {
        "category": "dlp",
        "name": "Nightfall AI",
        "vendor": "Nightfall",
        "product": "Nightfall AI",
        "log_types": [
            "sensitive_data_detection",
            "policy_violation",
            "saas_scan_finding",
            "api_scan_finding",
            "remediation_event",
        ],
    },
    # -----------------------------------------------------------------------
    # Threat Intelligence Platforms (as log/alert sources)
    # -----------------------------------------------------------------------
    {
        "category": "threat_intel",
        "name": "CrowdStrike Falcon Intelligence",
        "vendor": "CrowdStrike",
        "product": "Falcon Intelligence",
        "log_types": [
            "threat_report",
            "indicator_feed",
            "malware_analysis",
            "adversary_profile",
            "vulnerability_intel",
            "sandbox_result",
        ],
    },
    {
        "category": "threat_intel",
        "name": "Recorded Future",
        "vendor": "Recorded Future",
        "product": "Recorded Future Intelligence Cloud",
        "log_types": [
            "alert",
            "indicator_feed",
            "risk_score",
            "threat_lead",
            "vulnerability_intel",
            "identity_intel",
            "brand_intel",
            "third_party_risk",
        ],
    },
    {
        "category": "threat_intel",
        "name": "Mandiant Advantage",
        "vendor": "Google (Mandiant)",
        "product": "Mandiant Advantage",
        "log_types": [
            "threat_report",
            "indicator_feed",
            "campaign_intel",
            "malware_profile",
            "vulnerability_intel",
            "attack_surface_intel",
            "digital_risk_alert",
        ],
    },
    {
        "category": "threat_intel",
        "name": "VirusTotal",
        "vendor": "Google (Chronicle)",
        "product": "VirusTotal",
        "log_types": [
            "file_scan_result",
            "url_scan_result",
            "domain_report",
            "ip_report",
            "livehunt_notification",
            "retrohunt_result",
            "graph_analysis",
        ],
    },
    {
        "category": "threat_intel",
        "name": "AbuseIPDB",
        "vendor": "AbuseIPDB",
        "product": "AbuseIPDB",
        "log_types": [
            "ip_report",
            "check_result",
            "blacklist_entry",
            "report_submission",
        ],
    },
    {
        "category": "threat_intel",
        "name": "Shodan",
        "vendor": "Shodan",
        "product": "Shodan",
        "log_types": [
            "host_scan",
            "vulnerability_finding",
            "service_banner",
            "monitor_alert",
            "honeypot_detection",
        ],
    },
    {
        "category": "threat_intel",
        "name": "GreyNoise",
        "vendor": "GreyNoise",
        "product": "GreyNoise Intelligence",
        "log_types": [
            "ip_context",
            "riot_classification",
            "mass_scanner_detection",
            "tag_match",
            "trend_event",
        ],
    },
    {
        "category": "threat_intel",
        "name": "AlienVault OTX",
        "vendor": "AT&T Cybersecurity",
        "product": "AlienVault OTX",
        "log_types": [
            "pulse_indicator",
            "indicator_match",
            "community_pulse",
            "threat_feed",
        ],
    },
    {
        "category": "threat_intel",
        "name": "MISP",
        "vendor": "MISP Project",
        "product": "MISP",
        "log_types": [
            "event_publication",
            "attribute_creation",
            "sighting",
            "correlation_event",
            "feed_import",
            "taxonomy_tag",
            "galaxy_cluster",
        ],
    },
    # -----------------------------------------------------------------------
    # Physical Security / IoT
    # -----------------------------------------------------------------------
    {
        "category": "physical_iot",
        "name": "Badge/Access Control Logs",
        "vendor": "Various",
        "product": "Physical Access Control",
        "log_types": [
            "badge_in",
            "badge_out",
            "door_forced",
            "door_held",
            "access_denied",
            "tailgating_alert",
            "visitor_access",
            "elevator_access",
        ],
    },
    {
        "category": "physical_iot",
        "name": "CCTV/Camera Logs",
        "vendor": "Various",
        "product": "Video Surveillance",
        "log_types": [
            "motion_detected",
            "camera_tamper",
            "recording_start",
            "recording_stop",
            "analytics_alert",
            "face_recognition",
            "license_plate_recognition",
        ],
    },
    {
        "category": "physical_iot",
        "name": "IoT Device Logs",
        "vendor": "Various",
        "product": "IoT Devices",
        "log_types": [
            "device_telemetry",
            "firmware_update",
            "anomaly_detection",
            "connectivity_event",
            "configuration_change",
            "health_status",
        ],
    },
    {
        "category": "physical_iot",
        "name": "OT/SCADA Logs",
        "vendor": "Various",
        "product": "OT/ICS/SCADA",
        "log_types": [
            "plc_event",
            "hmi_event",
            "historian_data",
            "protocol_anomaly",
            "process_alarm",
            "safety_event",
            "engineering_workstation_event",
            "firmware_change",
        ],
    },
    {
        "category": "physical_iot",
        "name": "Cisco ISE",
        "vendor": "Cisco",
        "product": "Identity Services Engine",
        "log_types": [
            "radius_authentication",
            "radius_accounting",
            "tacacs_authentication",
            "tacacs_authorization",
            "profiler_event",
            "posture_assessment",
            "guest_access",
            "device_admin",
            "trustsec_event",
            "byod_event",
        ],
    },
]

# Build a lookup dict for fast access by name
_CATALOG_BY_NAME: dict[str, dict] = {item["name"]: item for item in DATA_SOURCE_CATALOG}


@router.get("/taxonomy")
async def get_taxonomy(
    user: User = Depends(get_current_user),
):
    """Return the legacy data source taxonomy for the picker UI."""
    return DATA_SOURCE_TAXONOMY


@router.get("/catalog")
async def get_catalog(
    user: User = Depends(get_current_user),
):
    """Return the prepopulated data source catalog for checkbox selection."""
    return DATA_SOURCE_CATALOG


@router.post("/sync", response_model=TelemetrySyncResponse)
async def sync_telemetry_sources(
    body: TelemetrySyncRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Sync telemetry sources from catalog selections.

    Creates / enables / disables TelemetrySource records to match the
    provided list of selected catalog item names.
    """
    selected_set = set(body.selected_names)

    # Fetch all existing telemetry sources for this user
    result = await db.execute(select(TelemetrySource))
    existing = {s.name: s for s in result.scalars().all()}

    synced: list[TelemetrySyncItem] = []
    created_count = 0
    enabled_count = 0
    disabled_count = 0
    unchanged_count = 0

    # 1. Process selected items — create or enable
    for name in selected_set:
        if name in existing:
            source = existing[name]
            if not source.enabled:
                source.enabled = True
                db.add(source)
                synced.append(
                    TelemetrySyncItem(
                        id=source.id,
                        name=source.name,
                        category=source.category,
                        vendor=source.vendor,
                        product=source.product,
                        enabled=True,
                        action="enabled",
                    )
                )
                enabled_count += 1
            else:
                synced.append(
                    TelemetrySyncItem(
                        id=source.id,
                        name=source.name,
                        category=source.category,
                        vendor=source.vendor,
                        product=source.product,
                        enabled=True,
                        action="unchanged",
                    )
                )
                unchanged_count += 1
        else:
            # Look up catalog metadata
            catalog_entry = _CATALOG_BY_NAME.get(name)
            if catalog_entry:
                source = TelemetrySource(
                    created_by=user.id,
                    name=catalog_entry["name"],
                    category=catalog_entry["category"],
                    vendor=catalog_entry["vendor"],
                    product=catalog_entry["product"],
                    log_types=catalog_entry["log_types"],
                    log_types_canonical=_canonical_log_types(catalog_entry["log_types"]),
                    ingested_into=body.ingested_into,
                    enabled=True,
                )
                db.add(source)
                await db.flush()
                await db.refresh(source)
                synced.append(
                    TelemetrySyncItem(
                        id=source.id,
                        name=source.name,
                        category=source.category,
                        vendor=source.vendor,
                        product=source.product,
                        enabled=True,
                        action="created",
                    )
                )
                created_count += 1
            # If name not in catalog, silently skip (it's not a valid catalog item)

    # 2. Disable existing items NOT in the selected set
    for name, source in existing.items():
        if name not in selected_set:
            if source.enabled:
                source.enabled = False
                db.add(source)
                synced.append(
                    TelemetrySyncItem(
                        id=source.id,
                        name=source.name,
                        category=source.category,
                        vendor=source.vendor,
                        product=source.product,
                        enabled=False,
                        action="disabled",
                    )
                )
                disabled_count += 1
            else:
                synced.append(
                    TelemetrySyncItem(
                        id=source.id,
                        name=source.name,
                        category=source.category,
                        vendor=source.vendor,
                        product=source.product,
                        enabled=False,
                        action="unchanged",
                    )
                )
                unchanged_count += 1

    await db.flush()

    return TelemetrySyncResponse(
        synced=synced,
        created_count=created_count,
        enabled_count=enabled_count,
        disabled_count=disabled_count,
        unchanged_count=unchanged_count,
        total=len(synced),
    )
