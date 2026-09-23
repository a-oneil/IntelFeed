"""Telemetry-aware detection coverage classification.

Coverage is deliberately NOT a rule-lifecycle concept. A technique (or CVE) is:
- ``covered``       — at least one non-draft rule references it AND that rule's
                      required data sources are all satisfiable by the enabled
                      telemetry inventory (rules with no data_sources are
                      treated as satisfiable).
- ``library_only``  — rules exist in the library, but every one of them
                      requires data sources missing from the enabled telemetry.
- ``no_rule``       — no non-draft rule references it at all.

The data-source <-> telemetry match runs in three tiers (see
``match_data_source``): a ticked product name, a canonical behaviour id, or a
category that has at least one ticked source. The tiers exist because the two
sides of the comparison are written in different languages — rules name Elastic
index patterns and Sentinel connector ids, the inventory names products, and
ATT&CK names log channels — so a literal string test reported 1,995 of 3,053
rules as blocked while the products they need were ticked.

The matching logic mirrors the rule-detail "check feasibility" behaviour (see
app/api/telemetry_sources.py, which now delegates here) so both surfaces agree
on what "satisfiable" means.
"""

import uuid
from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule
from app.models.telemetry_source import TelemetrySource

STATUS_COVERED = "covered"
STATUS_LIBRARY_ONLY = "library_only"
STATUS_NO_RULE = "no_rule"

# Match tiers, strongest first. See match_data_source().
TIER_SOURCE = "source"
TIER_LOG_TYPE = "log_type"
TIER_CATEGORY = "category"

# How many matching rules to include per technique in classification payloads.
MAX_RULES_PER_TECHNIQUE = 5


def _normalize(token: str) -> str:
    return token.lower().replace(" ", "_").replace("-", "_")


# ---------------------------------------------------------------------------
# Canonical behaviour vocabulary
# ---------------------------------------------------------------------------
# telemetry_sources.log_types is vendor free text: 864 distinct strings over
# 1,124 assignments, 721 used exactly once. One idea has eleven spellings
# (authentication / authentication_event / login_event / login_success / ...),
# so a rule asking for one of them matched a fraction of the products that
# actually emit it. Everything below collapses those spellings onto a single
# behaviour axis that both sides of the match speak.
#
# scripts/seed/seed_log_type_aliases.py materialises this function into the
# log_type_alias table and telemetry_sources.log_types_canonical, which is what
# get_available_telemetry() reads; the rule side has no table to read, so it
# calls the function directly on its own free-text tokens.

CANONICAL_LOG_TYPES: frozenset[str] = frozenset(
    {
        "auth.login",
        "auth.logout",
        "auth.failure",
        "auth.mfa",
        "auth.token",
        "auth.session",
        "auth.risk",
        "auth.privilege",
        "auth.account",
        "auth.group",
        "process.creation",
        "process.injection",
        "script.execution",
        "image.load",
        "driver.load",
        "file.write",
        "file.delete",
        "file.read",
        "file.share",
        "file.transfer",
        "registry.write",
        "net.connection",
        "net.flow",
        "net.firewall",
        "net.traffic",
        "net.anomaly",
        "dns.query",
        "dns.block",
        "http.request",
        "web.filter",
        "proxy.session",
        "tls.session",
        "vpn.session",
        "ids.alert",
        "waf.event",
        "bot.detection",
        "ddos.event",
        "cloud.api",
        "cloud.resource",
        "cloud.iam",
        "cloud.storage",
        "cloud.config",
        "container.lifecycle",
        "container.runtime",
        "k8s.audit",
        "email.message",
        "email.delivery",
        "email.threat",
        "email.attachment",
        "email.url",
        "email.spam",
        "email.quarantine",
        "db.query",
        "db.admin",
        "db.access",
        "dlp.event",
        "data.classification",
        "data.access",
        "data.exfiltration",
        "vuln.finding",
        "vuln.scan",
        "compliance.check",
        "asset.inventory",
        "patch.status",
        "physical.access",
        "secret.detection",
        "malware.detection",
        "threat.detection",
        "threat.intel",
        "anomaly.detection",
        "insider.risk",
        "admin.audit",
        "config.change",
        "policy.event",
        "policy.violation",
        "saas.activity",
        "device.mgmt",
        "system.health",
        "audit.generic",
    }
)


# Vendor spellings for the axis above. Grouped by target id so a wrong one is
# easy to spot; the keyword rules below cover whatever is not listed here.
_LOG_TYPE_EXACT: dict[str, str] = {
    # admin.audit
    "management_event": "admin.audit",
    # anomaly.detection
    "attack_signal": "anomaly.detection",
    "attack_signal_intelligence": "anomaly.detection",
    "behavioral_analysis": "anomaly.detection",
    "cse_insight": "anomaly.detection",
    "cse_signal": "anomaly.detection",
    "graph_analysis": "anomaly.detection",
    "host_alarm": "anomaly.detection",
    "host_scoring": "anomaly.detection",
    "insight": "anomaly.detection",
    "lateral_movement": "anomaly.detection",
    "lateral_movement_risk": "anomaly.detection",
    "ml_classification": "anomaly.detection",
    "model_breach": "anomaly.detection",
    "outlier_detection": "anomaly.detection",
    "polygraph_alert": "anomaly.detection",
    "reconnaissance": "anomaly.detection",
    "scan_detection": "anomaly.detection",
    "trust_monitor_event": "anomaly.detection",
    "uba_alert": "anomaly.detection",
    "unusual_activity": "anomaly.detection",
    "user_behavior_analytics": "anomaly.detection",
    # asset.inventory
    "account_inventory": "asset.inventory",
    "adapter_event": "asset.inventory",
    "api_discovery": "asset.inventory",
    "application_install": "asset.inventory",
    "application_metadata": "asset.inventory",
    "ci_change": "asset.inventory",
    "coverage_gap": "asset.inventory",
    "endpoint_discover": "asset.inventory",
    "iot_device": "asset.inventory",
    "msi_installer": "asset.inventory",
    "network_discovery": "asset.inventory",
    "package_install": "asset.inventory",
    "profiler_event": "asset.inventory",
    "relationship_change": "asset.inventory",
    "service_banner": "asset.inventory",
    "shadow_it": "asset.inventory",
    "software_installation": "asset.inventory",
    "software_log": "asset.inventory",
    "syscollector": "asset.inventory",
    # audit.generic
    "action_target": "audit.generic",
    "activity_log": "audit.generic",
    "plugin_output": "audit.generic",
    "preview": "audit.generic",
    "signpost": "audit.generic",
    "system_activity": "audit.generic",
    # auth.account
    "directory_event": "auth.account",
    "directory_service_access": "auth.account",
    "directory_service_replication": "auth.account",
    "guest_access": "auth.account",
    "identity_change": "auth.account",
    "idm_event": "auth.account",
    "ldap_event": "auth.account",
    "provisioning_event": "auth.account",
    "provisioning_log": "auth.account",
    "user_creation": "auth.account",
    "user_lifecycle": "auth.account",
    "user_management": "auth.account",
    # auth.failure
    "ntlm_blocked": "auth.failure",
    # auth.group
    "member_added": "auth.group",
    "member_event": "auth.group",
    "member_removed": "auth.group",
    # auth.login
    "access_event": "auth.login",
    "application_access": "auth.login",
    "identity_awareness": "auth.login",
    "idp_event": "auth.login",
    "ntlm_log": "auth.login",
    "ntlm_pass_through": "auth.login",
    "public_key_auth": "auth.login",
    "saml_audit": "auth.login",
    "tgs_request": "auth.login",
    "tgt_request": "auth.login",
    "ticket_renewal": "auth.login",
    "user_auth": "auth.login",
    # auth.mfa
    "authenticator": "auth.mfa",
    "device_authorization": "auth.mfa",
    # auth.privilege
    "access_control": "auth.privilege",
    "access_denied": "auth.privilege",
    "access_request": "auth.privilege",
    "acl_evaluation": "auth.privilege",
    "application_consent": "auth.privilege",
    "certificate_denied": "auth.privilege",
    "certificate_event": "auth.privilege",
    "certificate_issued": "auth.privilege",
    "certificate_operation": "auth.privilege",
    "certificate_request": "auth.privilege",
    "certificate_revoked": "auth.privilege",
    "constrained_delegation": "auth.privilege",
    "device_admin": "auth.privilege",
    "directory_role_change": "auth.privilege",
    "key_expiry": "auth.privilege",
    "key_operation": "auth.privilege",
    "password_retrieval": "auth.privilege",
    "password_safe_event": "auth.privilege",
    "role_audit": "auth.privilege",
    "role_change": "auth.privilege",
    "role_transition": "auth.privilege",
    "secret_access": "auth.privilege",
    "secret_operation": "auth.privilege",
    "su_command": "auth.privilege",
    "sudo_command": "auth.privilege",
    "toxic_combination": "auth.privilege",
    "trust_modification": "auth.privilege",
    "trustsec_event": "auth.privilege",
    "unconstrained_delegation": "auth.privilege",
    "vault_access": "auth.privilege",
    "zero_trust_application": "auth.privilege",
    # auth.risk
    "account_compromise": "auth.risk",
    "account_scoring": "auth.risk",
    "account_takeover": "auth.risk",
    "account_takeover_prevention": "auth.risk",
    "adaptive_protection": "auth.risk",
    "breached_password": "auth.risk",
    "conditional_access": "auth.risk",
    "conditional_access_evaluation": "auth.risk",
    "context_aware_access": "auth.risk",
    "credential_access": "auth.risk",
    "risky_sign_in": "auth.risk",
    "session_hijacking_detection": "auth.risk",
    # auth.session
    "accounting": "auth.session",
    "privileged_session": "auth.session",
    "radius_accounting": "auth.session",
    "screen_log": "auth.session",
    # bot.detection
    "anti_bot": "bot.detection",
    "client_classification": "bot.detection",
    "fingerprint_event": "bot.detection",
    "fingerprint_match": "bot.detection",
    # cloud.config
    "configuration_state": "cloud.config",
    "snapshot_delivery": "cloud.config",
    # cloud.iam
    "assume_role": "cloud.iam",
    # cloud.resource
    "autoscale": "cloud.resource",
    "cold_start": "cloud.resource",
    "function_audit": "cloud.resource",
    "infrastructure_event": "cloud.resource",
    "invocation": "cloud.resource",
    "lambda_invocation": "cloud.resource",
    "memory_exceeded": "cloud.resource",
    "scheduler": "cloud.resource",
    "warehouse_metering": "cloud.resource",
    # cloud.storage
    "delete_object": "cloud.storage",
    "get_object": "cloud.storage",
    "put_object": "cloud.storage",
    "s3_object_event": "cloud.storage",
    "stage_access": "cloud.storage",
    # compliance.check
    "benchmark_result": "compliance.check",
    "certification_event": "compliance.check",
    "check_result": "compliance.check",
    "compliance_scan": "compliance.check",
    "config_rule_evaluation": "compliance.check",
    "continuous_monitoring": "compliance.check",
    "drift_prevention": "compliance.check",
    "iac_misconfiguration": "compliance.check",
    "misconfiguration": "compliance.check",
    "sca_check": "compliance.check",
    # config.change
    "allowed_ips_update": "config.change",
    "deploy_event": "config.change",
    "dns_change": "config.change",
    "dynamic_update": "config.change",
    "gpo_application": "config.change",
    "gpo_failure": "config.change",
    "interface_event": "config.change",
    "pipeline_event": "config.change",
    "pipeline_execution": "config.change",
    "reconciliation_event": "config.change",
    "route_event": "config.change",
    "rule_modification": "config.change",
    "runner_event": "config.change",
    "signature_update": "config.change",
    "template_modification": "config.change",
    # container.lifecycle
    "image_pull": "container.lifecycle",
    "image_push": "container.lifecycle",
    # container.runtime
    "cloud_controller_manager": "container.runtime",
    "cluster_autoscaler": "container.runtime",
    "cluster_event": "container.runtime",
    "container_runtime": "container.runtime",
    "controller_manager": "container.runtime",
    "daemon_event": "container.runtime",
    "falco_alert": "container.runtime",
    "node_event": "container.runtime",
    "volume_mount": "container.runtime",
    # data.access
    "sensitive_data_access": "data.access",
    # data.classification
    "data_discovery": "data.classification",
    "dynamic_data_masking": "data.classification",
    "encryption_event": "data.classification",
    "exact_data_match": "data.classification",
    "exact_match": "data.classification",
    "storage_discover": "data.classification",
    # data.exfiltration
    "data_egress": "data.exfiltration",
    "data_transfer_history": "data.exfiltration",
    "file_exposure": "data.exfiltration",
    "removable_media_event": "data.exfiltration",
    "report_export": "data.exfiltration",
    "sensitive_data_exposure": "data.exfiltration",
    # db.access
    "access_audit": "db.access",
    "access_history": "db.access",
    "delete_operation": "db.access",
    "read_audit": "db.access",
    "read_operation": "db.access",
    "table_access_event": "db.access",
    "write_audit": "db.access",
    "write_operation": "db.access",
    # db.admin
    "data_pump_event": "db.admin",
    "ddl_audit": "db.admin",
    "ddl_event": "db.admin",
    "stored_procedure_audit": "db.admin",
    "sys_audit": "db.admin",
    # db.query
    "dml_event": "db.query",
    "general_log": "db.query",
    "pgaudit_log": "db.query",
    "sql_audit": "db.query",
    "transaction_log": "db.query",
    "transaction_record": "db.query",
    # ddos.event
    "dos_attack": "ddos.event",
    "flood_detection": "ddos.event",
    "shield_alert": "ddos.event",
    "slow_post_protection": "ddos.event",
    # device.mgmt
    "byod_event": "device.mgmt",
    "configuration_profile": "device.mgmt",
    "endpoint_analysis": "device.mgmt",
    "hip_check": "device.mgmt",
    "hip_match": "device.mgmt",
    "host_check": "device.mgmt",
    "host_checker": "device.mgmt",
    "mdm_event": "device.mgmt",
    "mobile_audit": "device.mgmt",
    "wipe_event": "device.mgmt",
    # dlp.event
    "cloud_prevent": "dlp.event",
    "data_filtering": "dlp.event",
    "network_prevent": "dlp.event",
    # dns.block
    "dns_block": "dns.block",
    "dns_filter": "dns.block",
    "dns_firewall_event": "dns.block",
    "dns_redirect": "dns.block",
    "intelligent_proxy": "dns.block",
    "response_policy_hit": "dns.block",
    "rpz_hit": "dns.block",
    # dns.query
    "dga_detection": "dns.query",
    "resolver_query": "dns.query",
    # driver.load
    "iokit_open": "driver.load",
    "kextload": "driver.load",
    # email.delivery
    "delivery_log": "email.delivery",
    "email_delivery": "email.delivery",
    "receipt_log": "email.delivery",
    # email.message
    "exchange_audit": "email.message",
    "message_log": "email.message",
    # email.quarantine
    "auto_disposition": "email.quarantine",
    "disposition_event": "email.quarantine",
    "spam_quarantine": "email.quarantine",
    # email.spam
    "graymail_event": "email.spam",
    "outbreak_filter": "email.spam",
    "sender_reputation": "email.spam",
    # email.threat
    "email_block": "email.threat",
    "impersonation_detection": "email.threat",
    "impersonation_protect": "email.threat",
    "impostor_detection": "email.threat",
    "internal_email_protect": "email.threat",
    "lookalike_domain": "email.threat",
    "report_submission": "email.threat",
    "sandstorm": "email.threat",
    "spoof_detection": "email.threat",
    "vendor_fraud_detection": "email.threat",
    # email.url
    "safe_links_click": "email.url",
    "url_defense_click": "email.url",
    "url_protect_click": "email.url",
    # file.read
    "file_access": "file.read",
    "file_accessed": "file.read",
    "object_access": "file.read",
    "raw_access_read": "file.read",
    # file.share
    "folder_event": "file.share",
    "nas_event": "file.share",
    "sharing_link_created": "file.share",
    "smb_log": "file.share",
    # file.transfer
    "airdrop_event": "file.transfer",
    "file_synced": "file.transfer",
    # file.write
    "attribute_creation": "file.write",
    "binary_info": "file.write",
    "chmod": "file.write",
    "chown": "file.write",
    "mount": "file.write",
    "pe_log": "file.write",
    # http.request
    "access_log": "http.request",
    "request_event": "http.request",
    "request_received": "http.request",
    "response_complete": "http.request",
    "response_started": "http.request",
    "rest_api_request": "http.request",
    "uri_event": "http.request",
    "w3c_log": "http.request",
    # ids.alert
    "idps_signature": "ids.alert",
    "notice_log": "ids.alert",
    "preprocessor_event": "ids.alert",
    "suricata_corelight": "ids.alert",
    "threat_block": "ids.alert",
    "threat_prevention": "ids.alert",
    "unified2_event": "ids.alert",
    # image.load
    "wmi_provider_load": "image.load",
    # insider.risk
    "insider_risk_indicator": "insider.risk",
    "insider_threat": "insider.risk",
    # k8s.audit
    "admission_audit": "k8s.audit",
    "admission_controller_event": "k8s.audit",
    "api_server": "k8s.audit",
    "configmap_change": "k8s.audit",
    "namespace_event": "k8s.audit",
    "network_policy": "k8s.audit",
    # malware.detection
    "amp_event": "malware.detection",
    "amp_log": "malware.detection",
    "amp_retrospective": "malware.detection",
    "apt_blocker": "malware.detection",
    "atp_log": "malware.detection",
    "cryptoguard": "malware.detection",
    "hyperdetect": "malware.detection",
    "potentially_unwanted_app": "malware.detection",
    "ransomware_canary": "malware.detection",
    "ransomware_rollback": "malware.detection",
    "real_time_protection": "malware.detection",
    "sandbox_analysis": "malware.detection",
    "sandbox_report": "malware.detection",
    "sandbox_result": "malware.detection",
    "spyware_detection": "malware.detection",
    "threat_emulation": "malware.detection",
    "trojan": "malware.detection",
    "wildfire_submission": "malware.detection",
    # net.anomaly
    "weird_log": "net.anomaly",
    # net.connection
    "conn_log": "net.connection",
    "dhcp": "net.connection",
    "dhcp_failover": "net.connection",
    "dhcp_lease": "net.connection",
    "dhcp_nack": "net.connection",
    "dhcp_release": "net.connection",
    "dhcp_renew": "net.connection",
    "gateway_network_session": "net.connection",
    "geolocation": "net.connection",
    "ip_log": "net.connection",
    "mqtt": "net.connection",
    "peer_connect": "net.connection",
    "peer_disconnect": "net.connection",
    "quic": "net.connection",
    "rfb": "net.connection",
    "sip": "net.connection",
    "socket_bind": "net.connection",
    "socket_connect": "net.connection",
    "ssh": "net.connection",
    # net.firewall
    "accepted_traffic": "net.firewall",
    "block_event": "net.firewall",
    "block_log": "net.firewall",
    "denied_traffic": "net.firewall",
    "dv_filter_match": "net.firewall",
    "gateway_event": "net.firewall",
    "inbound_allowed": "net.firewall",
    "inbound_denied": "net.firewall",
    "nat_log": "net.firewall",
    "nat_rule": "net.firewall",
    "nat_translation": "net.firewall",
    "network_rule": "net.firewall",
    "outbound_allowed": "net.firewall",
    "outbound_denied": "net.firewall",
    "rejected_traffic": "net.firewall",
    "rejection_log": "net.firewall",
    "security_block": "net.firewall",
    "utm_log": "net.firewall",
    # net.traffic
    "appid_event": "net.traffic",
    "apptrack": "net.traffic",
    "avc_log": "net.traffic",
    "bandwidth_log": "net.traffic",
    "capture_event": "net.traffic",
    "network_metadata": "net.traffic",
    "network_monitor": "net.traffic",
    "protocol_analysis": "net.traffic",
    "protocol_metadata": "net.traffic",
    # patch.status
    "firmware_update": "patch.status",
    "remediation": "patch.status",
    "remediation_project": "patch.status",
    # physical.access
    "badge_in": "physical.access",
    "badge_out": "physical.access",
    "camera_tamper": "physical.access",
    "door_forced": "physical.access",
    "door_held": "physical.access",
    "elevator_access": "physical.access",
    "face_recognition": "physical.access",
    "facility_message": "physical.access",
    "license_plate_recognition": "physical.access",
    "motion_detected": "physical.access",
    "recording_start": "physical.access",
    "recording_stop": "physical.access",
    "visitor_access": "physical.access",
    # policy.event
    "action_taken": "policy.event",
    "apparmor_allowed": "policy.event",
    "application_control": "policy.event",
    "application_layer_control": "policy.event",
    "application_rule": "policy.event",
    "attack_surface_reduction": "policy.event",
    "bandwidth_control": "policy.event",
    "enforcement_action": "policy.event",
    "guard_rail": "policy.event",
    "notarization_check": "policy.event",
    "override_event": "policy.event",
    "rule_match": "policy.event",
    "tag_match": "policy.event",
    "tcc_access": "policy.event",
    "type_enforcement": "policy.event",
    # policy.violation
    "anonymous_access": "policy.violation",
    "apparmor_denied": "policy.violation",
    "avc_denial": "policy.violation",
    "compliance_violation": "policy.violation",
    "data_access_violation": "policy.violation",
    "tamper_protection": "policy.violation",
    "unauthorized_access": "policy.violation",
    # process.creation
    "causality_chain": "process.creation",
    "endpoint_event": "process.creation",
    "host_event": "process.creation",
    "proctitle": "process.creation",
    "service_start": "process.creation",
    "service_stop": "process.creation",
    "syscall": "process.creation",
    "syscall_event": "process.creation",
    "task_created": "process.creation",
    "task_disabled": "process.creation",
    "task_executed": "process.creation",
    "task_updated": "process.creation",
    "unit_activation": "process.creation",
    # process.injection
    "create_remote_thread": "process.injection",
    "mmap": "process.injection",
    "pipe_connected": "process.injection",
    "pipe_created": "process.injection",
    "process_injection": "process.injection",
    # proxy.session
    "icap_event": "proxy.session",
    # saas.activity
    "apex_execution": "saas.activity",
    "app_install": "saas.activity",
    "app_installed": "saas.activity",
    "app_launch": "saas.activity",
    "bulk_api_event": "saas.activity",
    "business_process_event": "saas.activity",
    "calendar_audit": "saas.activity",
    "channel_created": "saas.activity",
    "cloud_app_event": "saas.activity",
    "collaboration": "saas.activity",
    "copilot_event": "saas.activity",
    "drive_audit": "saas.activity",
    "git_push_event": "saas.activity",
    "integration_event": "saas.activity",
    "issue_event": "saas.activity",
    "license_issue": "saas.activity",
    "lightning_interaction": "saas.activity",
    "meeting_created": "saas.activity",
    "meeting_ended": "saas.activity",
    "meeting_started": "saas.activity",
    "merge_request_event": "saas.activity",
    "message_posted": "saas.activity",
    "message_sent": "saas.activity",
    "organization_event": "saas.activity",
    "page_event": "saas.activity",
    "portal_event": "saas.activity",
    "power_platform_event": "saas.activity",
    "project_event": "saas.activity",
    "pull_request_event": "saas.activity",
    "push_event": "saas.activity",
    "recording_event": "saas.activity",
    "repository_event": "saas.activity",
    "sharepoint_audit": "saas.activity",
    "site_collection_change": "saas.activity",
    "space_event": "saas.activity",
    "team_created": "saas.activity",
    "team_event": "saas.activity",
    "telephony_log": "saas.activity",
    "user_event": "saas.activity",
    "webhook_event": "saas.activity",
    "workbook_event": "saas.activity",
    "workflow_event": "saas.activity",
    # script.execution
    "command_invocation": "script.execution",
    "constrained_language_mode": "script.execution",
    "cron_execution": "script.execution",
    "macro_event": "script.execution",
    "wmi_consumer_binding": "script.execution",
    "wmi_method_invocation": "script.execution",
    # secret.detection
    "secret_scan": "secret.detection",
    "secret_scanning_alert": "secret.detection",
    # system.health
    "app_connector_status": "system.health",
    "application_crash": "system.health",
    "application_hang": "system.health",
    "coredump": "system.health",
    "crash_dump": "system.health",
    "data_model_acceleration": "system.health",
    "diagnostic_log": "system.health",
    "duration": "system.health",
    "enhanced_monitoring": "system.health",
    "exception_event": "system.health",
    "failover_event": "system.health",
    "ha_event": "system.health",
    "heartbeat_event": "system.health",
    "historian_data": "system.health",
    "kernel_message": "system.health",
    "metric_alert": "system.health",
    "panic": "system.health",
    "performance_insights": "system.health",
    "performance_log": "system.health",
    "resource_health": "system.health",
    "satellite_event": "system.health",
    "sensor_data": "system.health",
    "service_failure": "system.health",
    "stats": "system.health",
    "system_message": "system.health",
    "system_shutdown": "system.health",
    "system_startup": "system.health",
    "task_completed": "system.health",
    "task_failed": "system.health",
    "timeout": "system.health",
    "trap_event": "system.health",
    # threat.detection
    "active_response": "threat.detection",
    "adaptive_response": "threat.detection",
    "ai_analyst_incident": "threat.detection",
    "ai_engine_rule": "threat.detection",
    "alarm": "threat.detection",
    "analytics_rule_match": "threat.detection",
    "autorun_analysis": "threat.detection",
    "behavior_monitoring": "threat.detection",
    "case_event": "threat.detection",
    "command_and_control": "threat.detection",
    "correlated_event": "threat.detection",
    "correlation_search": "threat.detection",
    "cryptocurrency_mining": "threat.detection",
    "defense_evasion": "threat.detection",
    "evidence": "threat.detection",
    "guard": "threat.detection",
    "guard_duty": "threat.detection",
    "impact_flag": "threat.detection",
    "incident_event": "threat.detection",
    "incident_report": "threat.detection",
    "incident_response": "threat.detection",
    "instance_compromise": "threat.detection",
    "investigation": "threat.detection",
    "isolation_event": "threat.detection",
    "live_response": "threat.detection",
    "lockdown_event": "threat.detection",
    "malop": "threat.detection",
    "observed_attack_technique": "threat.detection",
    "offense": "threat.detection",
    "persistence": "threat.detection",
    "rule_execution": "threat.detection",
    "rule_trigger": "threat.detection",
    "s3_compromise": "threat.detection",
    "scheduled_search_result": "threat.detection",
    "security": "threat.detection",
    "security_incident": "threat.detection",
    "sigma_rule_match": "threat.detection",
    "signal": "threat.detection",
    "situation": "threat.detection",
    "smart_timeline": "threat.detection",
    "smartresponse_action": "threat.detection",
    "suspicion": "threat.detection",
    "triage_result": "threat.detection",
    # threat.intel
    "attack_surface_intel": "threat.intel",
    "blacklist_entry": "threat.intel",
    "brand_intel": "threat.intel",
    "campaign_intel": "threat.intel",
    "client_reputation": "threat.intel",
    "community_pulse": "threat.intel",
    "domain_report": "threat.intel",
    "entity_context": "threat.intel",
    "feed_import": "threat.intel",
    "galaxy_cluster": "threat.intel",
    "identity_intel": "threat.intel",
    "indicator_feed": "threat.intel",
    "indicator_match": "threat.intel",
    "intel_log": "threat.intel",
    "ioc_match": "threat.intel",
    "ip_context": "threat.intel",
    "ip_intelligence": "threat.intel",
    "ip_report": "threat.intel",
    "livehunt_notification": "threat.intel",
    "pulse_indicator": "threat.intel",
    "reference_list_match": "threat.intel",
    "reputation_enabled_defense": "threat.intel",
    "reputation_event": "threat.intel",
    "retrohunt_result": "threat.intel",
    "security_intelligence": "threat.intel",
    "sighting": "threat.intel",
    "taxonomy_tag": "threat.intel",
    "threat_feed_event": "threat.intel",
    "threat_feed_match": "threat.intel",
    "threat_insight": "threat.intel",
    "ti_indicator_match": "threat.intel",
    "watchlist_hit": "threat.intel",
    # tls.session
    "decryption_log": "tls.session",
    "handshake_event": "tls.session",
    "tunnel_inspection": "tls.session",
    "x509_log": "tls.session",
    # vpn.session
    "client_connect": "vpn.session",
    "client_disconnect": "vpn.session",
    "clientless_access": "vpn.session",
    "dpd_log": "vpn.session",
    "exit_node_event": "vpn.session",
    "gateway_selection": "vpn.session",
    "globalprotect": "vpn.session",
    "ica_session": "vpn.session",
    "warp_connection": "vpn.session",
    # vuln.finding
    "api_scan_finding": "vuln.finding",
    "attack_path": "vuln.finding",
    "code_scanning_alert": "vuln.finding",
    "container_vulnerability": "vuln.finding",
    "dependabot_alert": "vuln.finding",
    "exploit_exposure": "vuln.finding",
    "exposure_score": "vuln.finding",
    "kubernetes_finding": "vuln.finding",
    "recommendation": "vuln.finding",
    "saas_scan_finding": "vuln.finding",
    "security_recommendation": "vuln.finding",
    "standard_result": "vuln.finding",
    "vulnerability_exploit": "vuln.finding",
    "zero_day_assessment": "vuln.finding",
    # vuln.scan
    "asset_assessment": "vuln.scan",
    "host_assessment": "vuln.scan",
    "image_analysis": "vuln.scan",
    "posture_assessment": "vuln.scan",
    "vulnerability_assessment": "vuln.scan",
    # waf.event
    "api_protection": "waf.event",
    "api_security_event": "waf.event",
    "custom_rule_match": "waf.event",
    "inline_result": "waf.event",
    "managed_rule_match": "waf.event",
    "page_shield_event": "waf.event",
    "preconfigured_rule_match": "waf.event",
    "protocol_violation": "waf.event",
    "rate_based_event": "waf.event",
    "rate_based_rule": "waf.event",
    "rate_control": "waf.event",
    "rate_limit": "waf.event",
    "rule_group_match": "waf.event",
    "virtual_patch": "waf.event",
    "waas_event": "waf.event",
    # web.filter
    "application_filter": "web.filter",
    "browser_access_event": "web.filter",
    "browser_isolation": "web.filter",
    "category_block": "web.filter",
    "content_filter": "web.filter",
    "content_filtering": "web.filter",
    "dns_category": "web.filter",
    "media_type_filter": "web.filter",
    "safe_access": "web.filter",
}


# Long-tail rules for strings the table above doesn't name. Ordered: the first
# substring hit wins, so the specific compounds come before the bare words.
_LOG_TYPE_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("brute_force", "auth.failure"),
    ("credential_stuffing", "auth.failure"),
    ("failed_login", "auth.failure"),
    ("login_failure", "auth.failure"),
    ("phish", "email.threat"),
    ("spam", "email.spam"),
    ("quarantine", "email.quarantine"),
    ("attachment", "email.attachment"),
    ("mailbox", "email.threat"),
    ("dlp", "dlp.event"),
    ("email", "email.message"),
    ("mail", "email.message"),
    ("smtp", "email.message"),
    ("mfa", "auth.mfa"),
    ("logout", "auth.logout"),
    ("sign_out", "auth.logout"),
    ("sign_in", "auth.login"),
    ("signin", "auth.login"),
    ("sign_on", "auth.login"),
    ("logon", "auth.login"),
    ("login", "auth.login"),
    ("authentication", "auth.login"),
    ("kerberos", "auth.login"),
    ("token", "auth.token"),
    ("privileg", "auth.privilege"),
    ("entitlement", "auth.privilege"),
    ("authoriz", "auth.privilege"),
    ("rbac", "auth.privilege"),
    ("permission", "auth.privilege"),
    ("password", "auth.account"),
    ("group", "auth.group"),
    ("account", "auth.account"),
    ("session", "auth.session"),
    ("takeover", "auth.risk"),
    ("risk", "auth.risk"),
    ("process", "process.creation"),
    ("injection", "process.injection"),
    ("script", "script.execution"),
    ("powershell", "script.execution"),
    ("driver", "driver.load"),
    ("module_load", "image.load"),
    ("image_load", "image.load"),
    ("registry", "registry.write"),
    ("k8s", "k8s.audit"),
    ("kube", "k8s.audit"),
    ("pod_", "container.lifecycle"),
    ("container", "container.lifecycle"),
    ("runtime", "container.runtime"),
    ("firewall", "net.firewall"),
    ("waf", "waf.event"),
    ("bot_", "bot.detection"),
    ("ddos", "ddos.event"),
    ("ips_", "ids.alert"),
    ("ids_", "ids.alert"),
    ("intrusion", "ids.alert"),
    ("dns", "dns.query"),
    ("netflow", "net.flow"),
    ("flow", "net.flow"),
    ("proxy", "proxy.session"),
    ("url_filter", "web.filter"),
    ("web_filter", "web.filter"),
    ("url", "web.filter"),
    ("ssl", "tls.session"),
    ("tls", "tls.session"),
    ("vpn", "vpn.session"),
    ("ipsec", "vpn.session"),
    ("tunnel", "vpn.session"),
    ("radius", "auth.login"),
    ("tacacs", "auth.login"),
    ("traffic", "net.traffic"),
    ("packet", "net.traffic"),
    ("network", "net.connection"),
    ("connection", "net.connection"),
    ("http", "http.request"),
    ("web", "http.request"),
    ("api", "cloud.api"),
    ("iam", "cloud.iam"),
    ("bucket", "cloud.storage"),
    ("storage", "cloud.storage"),
    ("resource", "cloud.resource"),
    ("cloud", "cloud.api"),
    ("malware", "malware.detection"),
    ("virus", "malware.detection"),
    ("exploit", "threat.detection"),
    ("threat", "threat.detection"),
    ("anomal", "anomaly.detection"),
    ("insider", "insider.risk"),
    ("exfiltration", "data.exfiltration"),
    ("classification", "data.classification"),
    ("sensitive", "data.classification"),
    ("data_access", "data.access"),
    ("vulnerability", "vuln.finding"),
    ("cve", "vuln.finding"),
    ("scan", "vuln.scan"),
    ("compliance", "compliance.check"),
    ("patch", "patch.status"),
    ("secret", "secret.detection"),
    ("inventory", "asset.inventory"),
    ("discovery", "asset.inventory"),
    ("asset", "asset.inventory"),
    ("device", "device.mgmt"),
    ("query", "db.query"),
    ("schema", "db.admin"),
    ("file", "file.write"),
    ("delete", "file.delete"),
    ("upload", "file.transfer"),
    ("download", "file.transfer"),
    ("share", "file.share"),
    ("transfer", "file.transfer"),
    ("violation", "policy.violation"),
    ("policy", "policy.event"),
    ("config", "config.change"),
    ("change", "config.change"),
    ("admin", "admin.audit"),
    ("audit", "audit.generic"),
    ("health", "system.health"),
    ("error", "system.health"),
    ("alert", "threat.detection"),
    ("detection", "threat.detection"),
    ("finding", "vuln.finding"),
    ("activity", "saas.activity"),
    ("event", "audit.generic"),
    ("log", "audit.generic"),
)

# Vendor suffixes that carry no meaning; stripping them lets a long tail like
# "authentication_log" fall onto the same id as "authentication".
_LOG_TYPE_SUFFIXES: tuple[str, ...] = (
    "_logs",
    "_log",
    "_events",
    "_event",
    "_audit",
    "_alerts",
    "_alert",
    "_detection",
    "_activity",
    "_record",
    "_history",
)


def canonical_log_type(raw: str) -> str | None:
    """Map one free-text log-type string onto the canonical behaviour axis.

    Deterministic on purpose — the seeder writes exactly what this returns, so
    the table in the database and the rule-side matcher can never disagree.
    """
    token = _normalize(raw).strip("_")
    if not token:
        return None
    if token in _LOG_TYPE_EXACT:
        return _LOG_TYPE_EXACT[token]
    for suffix in _LOG_TYPE_SUFFIXES:
        if token.endswith(suffix) and len(token) > len(suffix):
            stem = token[: -len(suffix)]
            if stem in _LOG_TYPE_EXACT:
                return _LOG_TYPE_EXACT[stem]
    for needle, canonical in _LOG_TYPE_KEYWORDS:
        if needle in token:
            return canonical
    return None


# Category each behaviour belongs to, for the tier-3 answer. Ids that no single
# category owns (threat.detection, config.change, audit.generic ...) are absent
# on purpose — "some product somewhere logs it" is not a coverage claim.
_CANONICAL_CATEGORY: dict[str, str] = {
    "auth.login": "identity",
    "auth.logout": "identity",
    "auth.failure": "identity",
    "auth.mfa": "identity",
    "auth.token": "identity",
    "auth.session": "identity",
    "auth.risk": "identity",
    "auth.privilege": "identity",
    "auth.account": "identity",
    "auth.group": "identity",
    "process.creation": "endpoint_edr",
    "process.injection": "endpoint_edr",
    "script.execution": "endpoint_edr",
    "image.load": "endpoint_edr",
    "driver.load": "endpoint_edr",
    "malware.detection": "endpoint_edr",
    "file.write": "endpoint_edr",
    "file.delete": "endpoint_edr",
    "file.read": "endpoint_edr",
    "registry.write": "endpoint_edr",
    "file.share": "saas",
    "file.transfer": "dlp",
    "net.connection": "network_security",
    "net.firewall": "network_security",
    "tls.session": "network_security",
    "net.flow": "ndr",
    "net.traffic": "ndr",
    "net.anomaly": "ndr",
    "anomaly.detection": "ndr",
    "dns.query": "dns_security",
    "dns.block": "dns_security",
    "http.request": "waf_appsec",
    "waf.event": "waf_appsec",
    "bot.detection": "waf_appsec",
    "ddos.event": "waf_appsec",
    "web.filter": "web_proxy",
    "proxy.session": "web_proxy",
    "vpn.session": "vpn_remote_access",
    "ids.alert": "ids_ips",
    "cloud.api": "cloud",
    "cloud.resource": "cloud",
    "cloud.iam": "cloud",
    "cloud.storage": "cloud",
    "cloud.config": "cloud",
    "container.lifecycle": "container",
    "container.runtime": "container",
    "k8s.audit": "container",
    "email.message": "email",
    "email.delivery": "email",
    "email.threat": "email",
    "email.attachment": "email",
    "email.url": "email",
    "email.spam": "email",
    "email.quarantine": "email",
    "db.query": "database",
    "db.admin": "database",
    "db.access": "database",
    "dlp.event": "dlp",
    "data.classification": "dlp",
    "data.access": "dlp",
    "data.exfiltration": "dlp",
    "insider.risk": "dlp",
    "vuln.finding": "vuln_management",
    "vuln.scan": "vuln_management",
    "compliance.check": "vuln_management",
    "secret.detection": "vuln_management",
    "asset.inventory": "endpoint_mgmt",
    "patch.status": "endpoint_mgmt",
    "device.mgmt": "endpoint_mgmt",
    "physical.access": "physical_iot",
    "admin.audit": "saas",
    "saas.activity": "saas",
}


# ---------------------------------------------------------------------------
# Rule-side token normalisation
# ---------------------------------------------------------------------------
# A rule's data_sources almost never name a product. They are Elastic index
# patterns (logs-crowdstrike.fdr*), Sentinel connector ids
# (AzureActiveDirectory), or ATT&CK log channels (WinEventLog:Sysmon) — three
# spellings for products the inventory already ticks. Matching them literally
# reported 1,995 of 3,053 rules as blocked, with CrowdStrike Falcon and Entra ID
# both enabled and both in the "most needed" list.

# What an EDR sensor's raw telemetry stream carries, whatever the vendor calls
# its index. Used for the agent datastreams that name a feed, not a behaviour.
_EDR_BEHAVIOURS = (
    "process.creation",
    "process.injection",
    "file.write",
    "net.connection",
    "registry.write",
    "image.load",
    "dns.query",
)

# Host-OS channels. They name neither a product in the inventory nor a
# behaviour a ticked product can stand in for — an EDR emitting process.creation
# is not the Windows Security event log — so they are answered from the category
# that holds OS log collection. Both are empty in the default selection, which
# is why Windows/Linux channels stay honestly blocked.
_OS_UNIX_MARKERS = (
    "auditd",
    "linux",
    "macos",
    "osquery",
    "unifiedlog",
    "ebpf",
    "filebeat",
    "auditbeat",
    "syslog",
)
_OS_WINDOWS_MARKERS = (
    "wineventlog",
    "winlogbeat",
    "windows",
    "sysmon",
    "powershell",
    "etw:",
    "windowssecurityevents",
    "windowsforwardedevents",
)

_RULE_TOKEN_ALIASES: dict[str, tuple[str, ...]] = {
    # Elastic index-pattern vendor segments
    "crowdstrike": ("crowdstrike", "falcon"),
    "sentinel_one": ("sentinelone", "singularity"),
    "sentinel_one_cloud_funnel": ("sentinelone", "singularity"),
    "cloud_defend": ("elastic_defend",),
    "aws": ("aws", "amazon"),
    "azure": ("azure", "microsoft"),
    "gcp": ("gcp", "google"),
    "google_workspace": ("google_workspace",),
    "o365": ("microsoft_365", "office_365"),
    "m365": ("microsoft_365", "office_365"),
    "m365_defender": ("microsoft_365", "defender"),
    "kubernetes": ("kubernetes",),
    "containerd": ("kubernetes",),
    "docker": ("docker",),
    "panw": ("palo_alto_networks", "pan_os"),
    "okta": ("okta",),
    "github": ("github",),
    "gitlab": ("gitlab",),
    "bitbucket": ("atlassian",),
    "nsm": ("corelight", "zeek"),
    # Sentinel connector ids: concatenated product names, not log types
    "azureactivedirectory": ("microsoft_entra_id", "entra_id", "azure_ad"),
    "azureactivity": ("azure_activity_log",),
    "azurefirewall": ("azure_firewall",),
    "azuremonitor": ("azure_monitor",),
    "office365": ("microsoft_365", "office_365"),
    "microsoftthreatprotection": ("microsoft_365", "defender"),
    "microsoftdefenderthreatintelligence": ("defender",),
    "paloaltonetworks": ("palo_alto_networks", "pan_os"),
    "ciscoasa": ("cisco_asa", "firepower"),
    "ciscoumbrelladataconnector": ("cisco_umbrella",),
    "gcpdnsdataconnector": ("gcp_cloud_dns",),
    "checkpoint": ("check_point",),
    "infobloxnios": ("infoblox",),
    "awss3": ("aws_s3",),
}

# Stems that name a telemetry feed rather than a behaviour; the feed's contents
# are what a rule reading it actually needs.
_RULE_TOKEN_CANONICAL: dict[str, tuple[str, ...]] = {
    "crowdstrike": _EDR_BEHAVIOURS,
    "endgame": _EDR_BEHAVIOURS,
    "endpoint": _EDR_BEHAVIOURS,
    "sentinel_one": _EDR_BEHAVIOURS,
    "sentinel_one_cloud_funnel": _EDR_BEHAVIOURS,
    "cloud_defend": ("process.creation", "file.write", "net.connection", "container.runtime"),
    "nsm": ("net.flow", "net.traffic"),
    "network_traffic": ("net.traffic", "net.flow"),
    "packetbeat": ("net.traffic",),
}

_INDEX_PREFIXES = ("logs_", "metrics_", "traces_")


@dataclass(frozen=True)
class _RuleNeed:
    """One rule data_source, resolved into everything that would satisfy it."""

    tokens: tuple[str, ...]
    canonical: tuple[str, ...]
    categories: tuple[str, ...]
    os_native: bool = False


def _index_stem(norm: str) -> str:
    """Strip Elastic index-pattern wrapping: logs-<stem>-* / <stem>(qualifier)."""
    stem = norm.rstrip("*").rstrip("_.").split("(")[0].rstrip("_.")
    for prefix in _INDEX_PREFIXES:
        if stem.startswith(prefix):
            return stem[len(prefix) :]
    return stem


def _os_platform(norm: str) -> str | None:
    # Unix first: "Sysmon for Linux" carries both markers and is not a Windows log.
    if any(marker in norm for marker in _OS_UNIX_MARKERS):
        return "linux_macos"
    if any(marker in norm for marker in _OS_WINDOWS_MARKERS):
        return "windows_events"
    return None


@lru_cache(maxsize=8192)
def _expand_rule_token(data_source: str) -> _RuleNeed:
    """Resolve one rule data_source into candidate product tokens + behaviour ids."""
    norm = _normalize(data_source)
    stem = _index_stem(norm)
    tokens = {t for t in (norm, stem) if t}
    canonical: set[str] = set()

    # ATT&CK / Splunk channels are "channel:dataset"; Elastic indices are dotted.
    head, sep, tail = stem.partition(":")
    if not sep:
        head, sep, tail = stem.partition(".")
    for key in (stem, head) if sep else (stem,):
        tokens.update(_RULE_TOKEN_ALIASES.get(key, ()))
        canonical.update(_RULE_TOKEN_CANONICAL.get(key, ()))
    if sep:
        for segment in tail.replace(":", ".").split("."):
            if resolved := canonical_log_type(segment):
                canonical.add(resolved)
    if not canonical and (resolved := canonical_log_type(stem)):
        canonical.add(resolved)

    if platform := _os_platform(norm):
        return _RuleNeed(tuple(sorted(tokens)), (), (platform,), os_native=True)

    # A product token fans out to every behaviour that product emits — an EDR
    # index yields process.creation AND dns.query AND net.connection. Mapping
    # each of those back to a category then claims the source could come from
    # endpoint_edr OR dns_security OR network_security, and tier 3 matches on
    # the loosest of them: "endpoint process events" reads as satisfied by a
    # firewall-only inventory. A category answer is only meaningful when the
    # expansion lands on exactly one category; more than one means we do not
    # actually know which category produces this source, so we do not guess.
    categories = {c for cid in canonical if (c := _CANONICAL_CATEGORY.get(cid))}
    if len(categories) > 1:
        categories = set()
    return _RuleNeed(tuple(sorted(tokens)), tuple(sorted(canonical)), tuple(sorted(categories)))


# ---------------------------------------------------------------------------
# The inventory side
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TelemetryProfile:
    """What the enabled telemetry inventory can answer, at three confidences.

    Behaves like the plain token set callers used to get, so anything that only
    forwards it (or tests membership) keeps working unchanged.
    """

    tokens: frozenset[str] = frozenset()
    canonical: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()

    def __contains__(self, token: object) -> bool:
        return token in self.tokens

    def __iter__(self):
        return iter(self.tokens)

    def __len__(self) -> int:
        return len(self.tokens)


def _as_profile(available: "TelemetryProfile | set[str] | frozenset[str]") -> TelemetryProfile:
    if isinstance(available, TelemetryProfile):
        return available
    return TelemetryProfile(tokens=frozenset(available))


async def get_available_telemetry(db: AsyncSession) -> TelemetryProfile:
    """Everything the enabled telemetry sources can answer.

    No user predicate: telemetry_sources.created_by exists but every verdict in
    the product comes from one shared inventory, so a tick moves everyone.
    """
    result = await db.execute(select(TelemetrySource).where(TelemetrySource.enabled.is_(True)))
    tokens: set[str] = set()
    canonical: set[str] = set()
    categories: set[str] = set()
    for source in result.scalars().all():
        for lt in source.log_types or []:
            tokens.add(_normalize(lt))
        tokens.add(_normalize(source.name))
        if source.product:
            tokens.add(_normalize(source.product))
        if source.category:
            categories.add(source.category)
        stored = source.log_types_canonical or []
        if stored:
            canonical.update(stored)
        else:
            # scripts/seed/seed_log_type_aliases.py has not run (or this source
            # was added since). Derive in place so behaviour matching still works.
            canonical.update(c for lt in source.log_types or [] if (c := canonical_log_type(lt)))
    return TelemetryProfile(frozenset(tokens), frozenset(canonical), frozenset(categories))


def match_data_source(data_source: str, available) -> str | None:
    """Strongest tier at which the inventory satisfies one required data source.

    - ``TIER_SOURCE``   the token resolves to a ticked product name/log type
    - ``TIER_LOG_TYPE`` some ticked source emits the behaviour it needs
    - ``TIER_CATEGORY`` no field-level match, but its category has a ticked
                        source — collectable, unverified
    - ``None``          nothing matches; a rule resting on this would not fire
    """
    return _match(data_source, _as_profile(available))


# The gaps sweep runs this over ~9k (rule, data_source) pairs drawing on a few
# hundred distinct tokens, against an inventory that only changes when someone
# ticks a box — so memoize on both.
@lru_cache(maxsize=16384)
def _match(data_source: str, profile: "TelemetryProfile") -> str | None:
    need = _expand_rule_token(data_source)
    for token in need.tokens:
        if token in profile.tokens:
            return TIER_SOURCE
        # The loose substring test is what lets "Zscaler" find "Zscaler DLP".
        # On an OS channel it only ever fires by accident — "security" sits
        # inside "WinEventLog:Security" — so an OS channel is answered by an OS
        # source or not at all.
        if not need.os_native and any(token in a or a in token for a in profile.tokens):
            return TIER_SOURCE
    if profile.canonical.intersection(need.canonical):
        return TIER_LOG_TYPE
    if profile.categories.intersection(need.categories):
        return TIER_CATEGORY
    return None


def classify_data_sources(data_sources: list[str], available) -> list[tuple[str, str | None]]:
    """(data_source, tier) for each required source, input order preserved."""
    profile = _as_profile(available)
    return [(ds, _match(ds, profile)) for ds in data_sources]


def split_data_sources(data_sources: list[str], available) -> tuple[list[str], list[str]]:
    """(feasible, missing) — the boolean view of classify_data_sources().

    Kept so check-feasibility and telemetry-gaps keep their response shapes;
    feasible is exactly the sources whose tier is not None.
    """
    feasible: list[str] = []
    missing: list[str] = []
    for ds, tier in classify_data_sources(data_sources, available):
        (feasible if tier is not None else missing).append(ds)
    return feasible, missing


# Sensible default required-telemetry tokens for rule types whose native format
# doesn't populate data_sources. Fixes the Sigma blind spot (Sigma fills the
# log_sources dict, not data_sources) and gives YARA/Nuclei/Snort a signal.
_YARA_TOKENS = ["file", "memory"]
_NUCLEI_TOKENS = ["http", "web", "waf"]
_SNORT_TOKENS = ["network", "ids"]


def telemetry_tokens_from_rule(rule) -> list[str]:
    """Best-effort required-telemetry tokens for a rule, across all rule types."""
    if rule.data_sources:
        return list(rule.data_sources)
    rt = rule.rule_type
    if rt == "sigma":
        ls = rule.log_sources or {}
        return [t for t in (ls.get("product"), ls.get("category"), ls.get("service")) if t]
    if rt == "yara":
        return list(_YARA_TOKENS)
    if rt == "nuclei":
        return list(_NUCLEI_TOKENS)
    if rt == "snort_suricata":
        return list(_SNORT_TOKENS)
    return []


def rule_telemetry_coverage(rule, available) -> dict:
    """Per-rule telemetry feasibility against the enabled inventory.

    coverage_pct is None when the rule declares no discernible telemetry need.
    """
    required = telemetry_tokens_from_rule(rule)
    if not required:
        return {"required": [], "collected": [], "missing": [], "coverage_pct": None}
    feasible, missing = split_data_sources(required, available)
    return {
        "required": required,
        "collected": feasible,
        "missing": missing,
        "coverage_pct": round(len(feasible) / len(required), 2),
    }


def _rule_summary(row, missing: list[str]) -> dict:
    return {
        "id": str(row.id),
        "name": row.title,
        "rule_type": row.rule_type,
        "missing_data_sources": missing,
    }


def _empty_classification() -> dict:
    return {
        "status": STATUS_NO_RULE,
        "rule_count": 0,
        "satisfiable_rule_count": 0,
        "missing_data_sources": [],
        "rules": [],
    }


def _finalize(info: dict) -> None:
    """Resolve status + best-rule missing sources, cap the rules list."""
    if info["satisfiable_rule_count"] > 0:
        info["status"] = STATUS_COVERED
        info["missing_data_sources"] = []
    elif info["rule_count"] > 0:
        info["status"] = STATUS_LIBRARY_ONLY
        # Best rule = fewest missing data sources → the cheapest telemetry unlock
        best = min(info["rules"], key=lambda r: len(r["missing_data_sources"]))
        info["missing_data_sources"] = best["missing_data_sources"]
    # Satisfiable rules first, then fewest missing sources
    info["rules"].sort(key=lambda r: len(r["missing_data_sources"]))
    info["rules"] = info["rules"][:MAX_RULES_PER_TECHNIQUE]


async def classify_techniques(
    db: AsyncSession,
    technique_ids: list[str],
    available=None,
) -> dict[str, dict]:
    """Classify ATT&CK technique IDs as covered / library_only / no_rule.

    Returns {technique_id: {status, rule_count, satisfiable_rule_count,
    missing_data_sources, rules[]}}. ``missing_data_sources`` is populated for
    library_only techniques with the best (fewest-missing) rule's gaps.
    """
    ids = [t for t in dict.fromkeys(technique_ids) if t]
    if not ids:
        return {}
    if available is None:
        available = await get_available_telemetry(db)

    id_array = cast(ids, PG_ARRAY(Text))
    result = await db.execute(
        select(
            DetectionRule.id,
            DetectionRule.title,
            DetectionRule.rule_type,
            DetectionRule.source_ttps,
            DetectionRule.mitre_tactics,
            DetectionRule.data_sources,
        ).where(
            DetectionRule.is_draft.is_(False),
            or_(
                # source_ttps is a JSONB array of technique IDs
                func.jsonb_exists_any(DetectionRule.source_ttps, id_array),
                # legacy fallback: technique IDs sometimes land in mitre_tactics
                DetectionRule.mitre_tactics.overlap(id_array),
            ),
        )
    )

    out: dict[str, dict] = {tid: _empty_classification() for tid in ids}
    id_set = set(ids)
    for row in result.all():
        referenced = (set(row.source_ttps or []) | set(row.mitre_tactics or [])) & id_set
        if not referenced:
            continue
        _, missing = split_data_sources(row.data_sources or [], available)
        summary = _rule_summary(row, missing)
        for tid in referenced:
            info = out[tid]
            info["rule_count"] += 1
            if not missing:
                info["satisfiable_rule_count"] += 1
            info["rules"].append(summary)

    for info in out.values():
        _finalize(info)
    return out


async def classify_cves(
    db: AsyncSession,
    cve_ids: list[str],
    available=None,
) -> dict[str, dict]:
    """Classify CVE IDs (e.g. "CVE-2024-1234") with the same 3-way statuses.

    A rule references a CVE when source_cves contains it or the title mentions it.
    """
    ids = [c for c in dict.fromkeys(cve_ids) if c]
    if not ids:
        return {}
    if available is None:
        available = await get_available_telemetry(db)

    result = await db.execute(
        select(
            DetectionRule.id,
            DetectionRule.title,
            DetectionRule.rule_type,
            DetectionRule.source_cves,
            DetectionRule.data_sources,
        ).where(
            DetectionRule.is_draft.is_(False),
            or_(
                func.jsonb_exists_any(DetectionRule.source_cves, cast(ids, PG_ARRAY(Text))),
                *[DetectionRule.title.ilike(f"%{cid}%") for cid in ids],
            ),
        )
    )

    out: dict[str, dict] = {cid: _empty_classification() for cid in ids}
    for row in result.all():
        source_cves = {c.upper() for c in (row.source_cves or [])}
        title_upper = (row.title or "").upper()
        _, missing = split_data_sources(row.data_sources or [], available)
        summary = _rule_summary(row, missing)
        for cid in ids:
            if cid.upper() in source_cves or cid.upper() in title_upper:
                info = out[cid]
                info["rule_count"] += 1
                if not missing:
                    info["satisfiable_rule_count"] += 1
                info["rules"].append(summary)

    for info in out.values():
        _finalize(info)
    return out


def summarize(classification: dict[str, dict]) -> dict:
    """Aggregate counts for a classification map."""
    covered = sum(1 for c in classification.values() if c["status"] == STATUS_COVERED)
    library_only = sum(1 for c in classification.values() if c["status"] == STATUS_LIBRARY_ONLY)
    no_rule = sum(1 for c in classification.values() if c["status"] == STATUS_NO_RULE)
    total = len(classification)
    return {
        "total": total,
        "covered": covered,
        "library_only": library_only,
        "no_rule": no_rule,
        "coverage_percentage": round(covered / total * 100, 1) if total else 0,
    }


async def entry_opportunity_tiers(
    db: AsyncSession,
    entry_techniques: dict[uuid.UUID, set[str]],
    available=None,
) -> dict[uuid.UUID, str | None]:
    """Batch opportunity tier per entry from its technique classifications.

    Tier is "actionable_gap" when any technique has no rule at all (write one
    and it can fire today), "telemetry_gap" when the only rules that exist are
    blocked by missing telemetry, and None when everything is covered.
    """
    all_ids = sorted({tid for tids in entry_techniques.values() for tid in tids})
    classification = await classify_techniques(db, all_ids, available=available)

    tiers: dict[uuid.UUID, str | None] = {}
    for entry_id, tids in entry_techniques.items():
        statuses = {classification[t]["status"] for t in tids if t in classification}
        if STATUS_NO_RULE in statuses:
            tiers[entry_id] = "actionable_gap"
        elif STATUS_LIBRARY_ONLY in statuses:
            tiers[entry_id] = "telemetry_gap"
        else:
            tiers[entry_id] = None
    return tiers
