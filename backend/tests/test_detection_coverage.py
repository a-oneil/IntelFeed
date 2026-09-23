"""Unit tests for the telemetry-aware detection coverage service."""

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule
from app.models.telemetry_source import TelemetrySource
from app.services.detection_coverage import (
    _CANONICAL_CATEGORY,
    _LOG_TYPE_EXACT,
    _LOG_TYPE_KEYWORDS,
    CANONICAL_LOG_TYPES,
    STATUS_COVERED,
    STATUS_LIBRARY_ONLY,
    STATUS_NO_RULE,
    TIER_CATEGORY,
    TIER_LOG_TYPE,
    TIER_SOURCE,
    TelemetryProfile,
    canonical_log_type,
    classify_cves,
    classify_data_sources,
    classify_techniques,
    entry_opportunity_tiers,
    get_available_telemetry,
    match_data_source,
    split_data_sources,
    summarize,
)

# ── Helpers ──────────────────────────────────────────────────────────


def _rule(title: str, **kwargs) -> DetectionRule:
    defaults = dict(
        rule_type="sigma",
        rule_content="title: test\nstatus: test",
        is_draft=False,
        source_ttps=[],
        data_sources=[],
    )
    defaults.update(kwargs)
    return DetectionRule(title=title, **defaults)


async def _add_telemetry(
    db: AsyncSession,
    name: str,
    log_types: list[str],
    enabled: bool = True,
    category: str = "endpoint_edr",
    product: str | None = None,
):
    ts = TelemetrySource(
        name=name,
        category=category,
        product=product,
        log_types=log_types,
        log_types_canonical=sorted({c for lt in log_types if (c := canonical_log_type(lt))}),
        enabled=enabled,
    )
    db.add(ts)
    await db.flush()
    return ts


# ── split_data_sources / get_available_telemetry ─────────────────────


async def test_available_telemetry_only_enabled(db_session: AsyncSession):
    await _add_telemetry(db_session, "EDR One", ["process_creation"])
    await _add_telemetry(db_session, "Disabled NDR", ["netflow"], enabled=False)

    available = await get_available_telemetry(db_session)
    assert "process_creation" in available
    assert "edr_one" in available  # source name is a match token too
    assert "netflow" not in available


def test_split_data_sources_normalization_and_substring():
    available = {"process_creation", "windows_security_events"}
    feasible, missing = split_data_sources(
        ["Process Creation", "process-creation", "dns_query", "security_events"],
        available,
    )
    # normalized exact + substring-in-either-direction matches
    assert feasible == ["Process Creation", "process-creation", "security_events"]
    assert missing == ["dns_query"]


def test_split_data_sources_empty():
    feasible, missing = split_data_sources([], {"anything"})
    assert feasible == []
    assert missing == []


# ── classify_techniques ──────────────────────────────────────────────


async def test_no_rule_when_nothing_references_technique(db_session: AsyncSession):
    result = await classify_techniques(db_session, ["T1059.001"])
    assert result["T1059.001"]["status"] == STATUS_NO_RULE
    assert result["T1059.001"]["rule_count"] == 0


async def test_empty_data_sources_is_satisfiable(db_session: AsyncSession):
    db_session.add(_rule("PS Exec", source_ttps=["T1059.001"], data_sources=[]))
    await db_session.flush()

    result = await classify_techniques(db_session, ["T1059.001"])
    info = result["T1059.001"]
    assert info["status"] == STATUS_COVERED
    assert info["rule_count"] == 1
    assert info["satisfiable_rule_count"] == 1
    assert info["missing_data_sources"] == []


async def test_covered_when_data_sources_subset_of_telemetry(db_session: AsyncSession):
    await _add_telemetry(db_session, "Sysmon", ["process_creation", "dns_query"])
    db_session.add(_rule("PS Exec", source_ttps=["T1059.001"], data_sources=["process_creation"]))
    await db_session.flush()

    result = await classify_techniques(db_session, ["T1059.001"])
    assert result["T1059.001"]["status"] == STATUS_COVERED


async def test_library_only_when_data_sources_missing(db_session: AsyncSession):
    await _add_telemetry(db_session, "Sysmon", ["process_creation"])
    db_session.add(
        _rule(
            "Cloud Rule",
            source_ttps=["T1078.004"],
            data_sources=["cloudtrail_management_events"],
        )
    )
    await db_session.flush()

    result = await classify_techniques(db_session, ["T1078.004"])
    info = result["T1078.004"]
    assert info["status"] == STATUS_LIBRARY_ONLY
    assert info["rule_count"] == 1
    assert info["satisfiable_rule_count"] == 0
    assert info["missing_data_sources"] == ["cloudtrail_management_events"]


async def test_draft_rules_are_excluded(db_session: AsyncSession):
    db_session.add(_rule("Draft Rule", source_ttps=["T1027"], is_draft=True))
    await db_session.flush()

    result = await classify_techniques(db_session, ["T1027"])
    assert result["T1027"]["status"] == STATUS_NO_RULE


async def test_best_rule_missing_sources_is_fewest(db_session: AsyncSession):
    db_session.add(_rule("Needs Two", source_ttps=["T1105"], data_sources=["netflow", "proxy_log"]))
    db_session.add(_rule("Needs One", source_ttps=["T1105"], data_sources=["dns_query"]))
    await db_session.flush()

    result = await classify_techniques(db_session, ["T1105"])
    info = result["T1105"]
    assert info["status"] == STATUS_LIBRARY_ONLY
    assert info["rule_count"] == 2
    # Best rule = fewest missing data sources
    assert info["missing_data_sources"] == ["dns_query"]
    # Rules sorted by fewest missing first
    assert info["rules"][0]["name"] == "Needs One"


async def test_one_satisfiable_rule_wins_over_blocked_ones(db_session: AsyncSession):
    await _add_telemetry(db_session, "Sysmon", ["process_creation"])
    db_session.add(_rule("Blocked", source_ttps=["T1059"], data_sources=["saas_audit_log"]))
    db_session.add(_rule("Deployable", source_ttps=["T1059"], data_sources=["process_creation"]))
    await db_session.flush()

    result = await classify_techniques(db_session, ["T1059"])
    info = result["T1059"]
    assert info["status"] == STATUS_COVERED
    assert info["rule_count"] == 2
    assert info["satisfiable_rule_count"] == 1


async def test_mitre_tactics_fallback_match(db_session: AsyncSession):
    # Legacy rules sometimes carry technique IDs in mitre_tactics
    db_session.add(_rule("Legacy", mitre_tactics=["T1566.001"]))
    await db_session.flush()

    result = await classify_techniques(db_session, ["T1566.001"])
    assert result["T1566.001"]["status"] == STATUS_COVERED


async def test_classify_techniques_empty_input(db_session: AsyncSession):
    assert await classify_techniques(db_session, []) == {}
    assert await classify_techniques(db_session, ["", None]) == {}


# ── classify_cves ────────────────────────────────────────────────────


async def test_classify_cves_source_and_title_match(db_session: AsyncSession):
    db_session.add(_rule("Exploit detect", source_cves=["CVE-2024-1111"]))
    db_session.add(_rule("CVE-2024-2222 exploitation attempt"))
    await db_session.flush()

    result = await classify_cves(db_session, ["CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333"])
    assert result["CVE-2024-1111"]["status"] == STATUS_COVERED
    assert result["CVE-2024-2222"]["status"] == STATUS_COVERED
    assert result["CVE-2024-3333"]["status"] == STATUS_NO_RULE


async def test_classify_cves_telemetry_blocked(db_session: AsyncSession):
    db_session.add(
        _rule(
            "CVE-2024-4444 exploit",
            source_cves=["CVE-2024-4444"],
            data_sources=["waf_log"],
        )
    )
    await db_session.flush()

    result = await classify_cves(db_session, ["CVE-2024-4444"])
    info = result["CVE-2024-4444"]
    assert info["status"] == STATUS_LIBRARY_ONLY
    assert info["missing_data_sources"] == ["waf_log"]


# ── summarize / entry_opportunity_tiers ──────────────────────────────


async def test_summarize_counts(db_session: AsyncSession):
    db_session.add(_rule("Covered", source_ttps=["T1001"]))
    db_session.add(_rule("Blocked", source_ttps=["T1002"], data_sources=["netflow"]))
    await db_session.flush()

    classification = await classify_techniques(db_session, ["T1001", "T1002", "T1003"])
    summary = summarize(classification)
    assert summary == {
        "total": 3,
        "covered": 1,
        "library_only": 1,
        "no_rule": 1,
        "coverage_percentage": 33.3,
    }


async def test_entry_opportunity_tiers(db_session: AsyncSession):
    db_session.add(_rule("Covered", source_ttps=["T1001"]))
    db_session.add(_rule("Blocked", source_ttps=["T1002"], data_sources=["netflow"]))
    await db_session.flush()

    e_covered, e_blocked, e_norule = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    tiers = await entry_opportunity_tiers(
        db_session,
        {
            e_covered: {"T1001"},
            e_blocked: {"T1001", "T1002"},
            e_norule: {"T1001", "T1002", "T1003"},
        },
    )
    assert tiers[e_covered] is None
    assert tiers[e_blocked] == "telemetry_gap"
    # no_rule outranks telemetry_gap
    assert tiers[e_norule] == "actionable_gap"


# ── POST /intelligence/detection-coverage ────────────────────────────


async def test_detection_coverage_endpoint(client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
    db_session.add(_rule("Covered", source_ttps=["T1059"]))
    db_session.add(_rule("Blocked", source_ttps=["T1105"], data_sources=["netflow"]))
    await db_session.flush()

    resp = await client.post(
        "/api/intelligence/detection-coverage",
        json=["T1059", "T1105", "T1027"],
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["total"] == 3
    assert data["summary"]["covered"] == 1
    assert data["summary"]["library_only"] == 1
    assert data["summary"]["no_rule"] == 1
    assert data["techniques"]["T1059"]["status"] == "covered"
    assert data["techniques"]["T1105"]["status"] == "library_only"
    assert data["techniques"]["T1105"]["missing_data_sources"] == ["netflow"]
    assert data["techniques"]["T1027"]["status"] == "no_rule"


async def test_detection_coverage_endpoint_caps_input(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/intelligence/detection-coverage",
        json=[f"T{i}" for i in range(501)],
        headers=auth_headers,
    )
    assert resp.status_code == 400


# ── canonical behaviour axis ─────────────────────────────────────────


def test_canonical_vocabulary_is_closed():
    """Every mapping target has to be a real id, or a source silently vanishes."""
    targets = set(_LOG_TYPE_EXACT.values()) | {c for _, c in _LOG_TYPE_KEYWORDS}
    assert targets <= CANONICAL_LOG_TYPES
    assert set(_CANONICAL_CATEGORY) <= CANONICAL_LOG_TYPES


def test_eleven_spellings_of_a_login_collapse():
    """The measured spread: 864 raw strings, 'authentication' matching 7 of the
    13 ticked identity products and 'login_success' matching 1."""
    assert {
        canonical_log_type(raw)
        for raw in (
            "authentication",
            "authentication_event",
            "authentication_log",
            "login_event",
            "login",
            "user_login",
            "login_success",
            "sign_in",
            "logon_event",
        )
    } == {"auth.login"}
    assert canonical_log_type("login_failure") == "auth.failure"
    assert canonical_log_type("mfa_challenge") == "auth.mfa"


def test_canonical_keyword_fallback_pins():
    """These resolve through the ordered keyword rules, not the exact table, so
    they break if the rules are reordered."""
    assert canonical_log_type("dns_tunnel_detection") == "dns.query"
    assert canonical_log_type("brute_force_attack") == "auth.failure"
    assert canonical_log_type("teams_dlp_event") == "dlp.event"
    assert canonical_log_type("container_start") == "container.lifecycle"
    assert canonical_log_type("waf_block") == "waf.event"
    assert canonical_log_type("Process Creation") == "process.creation"


def test_canonical_unknown_string_is_none():
    assert canonical_log_type("wholly_unmapped_vendor_string") is None
    assert canonical_log_type("") is None


# ── three-tier matching ──────────────────────────────────────────────


async def test_available_telemetry_carries_canonical_and_categories(db_session: AsyncSession):
    await _add_telemetry(db_session, "CrowdStrike Falcon", ["process_creation"], product="Falcon")
    await _add_telemetry(db_session, "Okta", ["authentication_event"], category="identity")

    profile = await get_available_telemetry(db_session)
    assert isinstance(profile, TelemetryProfile)
    assert "process_creation" in profile.tokens
    assert "falcon" in profile.tokens
    assert {"process.creation", "auth.login"} <= profile.canonical
    assert profile.categories == {"endpoint_edr", "identity"}


async def test_index_pattern_and_connector_id_resolve_to_the_ticked_product(db_session: AsyncSession):
    """The two false gaps: both products are ticked, both were reported missing
    (133 rules each) because the rule spells them as an Elastic index pattern
    and a Sentinel connector id."""
    await _add_telemetry(db_session, "CrowdStrike Falcon", ["process_creation"], product="Falcon")
    await _add_telemetry(db_session, "Microsoft Entra ID", ["sign_in_log"], category="identity", product="Entra ID")
    profile = await get_available_telemetry(db_session)

    assert match_data_source("logs-crowdstrike.fdr*", profile) == TIER_SOURCE
    assert match_data_source("AzureActiveDirectory", profile) == TIER_SOURCE


async def test_agent_datastream_falls_back_to_the_behaviour(db_session: AsyncSession):
    """Elastic Defend is not ticked, but the behaviour its index carries is."""
    await _add_telemetry(db_session, "CrowdStrike Falcon", ["process_creation"], product="Falcon")
    profile = await get_available_telemetry(db_session)

    assert match_data_source("logs-endpoint.events.process-*", profile) == TIER_LOG_TYPE
    assert match_data_source("endpoint.processes", profile) == TIER_LOG_TYPE


async def test_attack_channel_joins_the_same_vocabulary(db_session: AsyncSession):
    """ttps.data_sources names channels (NSM:Flow on 142 techniques); they have
    to land on the same ids as the inventory's own strings."""
    await _add_telemetry(db_session, "Corelight (Zeek)", ["network_flow"], category="ndr")
    profile = await get_available_telemetry(db_session)

    assert match_data_source("NSM:Flow", profile) == TIER_SOURCE  # alias names Corelight
    assert match_data_source("cisco:netflow", profile) == TIER_LOG_TYPE


async def test_category_tier_when_nothing_matches_at_field_level(db_session: AsyncSession):
    await _add_telemetry(db_session, "MailCo", ["email_delivery"], category="email")
    profile = await get_available_telemetry(db_session)

    assert match_data_source("email_quarantine", profile) == TIER_CATEGORY
    assert match_data_source("k8s_audit", profile) is None


async def test_os_channels_stay_blocked_without_an_os_source(db_session: AsyncSession):
    """An EDR emitting process.creation is not the Windows Security event log,
    and 'security' happening to sit inside 'WinEventLog:Security' is not a
    match. These are answered only by a windows_events / linux_macos source."""
    await _add_telemetry(db_session, "CrowdStrike Falcon", ["process_creation", "security_event"], product="Falcon")
    profile = await get_available_telemetry(db_session)

    for channel in (
        "WinEventLog:Security",
        "winlogbeat-*",
        "logs-windows.sysmon_operational-*",
        "auditd:SYSCALL",
        "linux:process_creation",
    ):
        assert match_data_source(channel, profile) is None, channel

    await _add_telemetry(db_session, "Windows Event Collector", ["logon_event"], category="windows_events")
    assert match_data_source("WinEventLog:Security", await get_available_telemetry(db_session)) == TIER_CATEGORY


def test_split_data_sources_shim_agrees_with_the_tier():
    """R6: the boolean callers (check-feasibility, telemetry-gaps) must stay a
    pure projection of the tier, or the two surfaces disagree."""
    profile = TelemetryProfile(
        tokens=frozenset({"crowdstrike_falcon", "falcon", "process_creation"}),
        canonical=frozenset({"process.creation"}),
        categories=frozenset({"endpoint_edr"}),
    )
    sources = [
        "logs-crowdstrike.fdr*",
        "logs-endpoint.events.process-*",
        "file_deletion",
        "WinEventLog:Security",
        "k8s_audit",
        "process_creation",
    ]
    feasible, missing = split_data_sources(sources, profile)
    tiers = classify_data_sources(sources, profile)

    assert [ds for ds, tier in tiers if tier is not None] == feasible
    assert [ds for ds, tier in tiers if tier is None] == missing
    assert len(feasible) + len(missing) == len(sources)


def test_split_data_sources_accepts_a_bare_token_set():
    """Callers outside this module still hand us the old set[str]."""
    feasible, missing = split_data_sources(["Process Creation", "dns_query"], {"process_creation"})
    assert feasible == ["Process Creation"]
    assert missing == ["dns_query"]


async def test_created_source_gets_canonical_ids(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/telemetry-sources",
        json={
            "name": "Test Identity Provider",
            "category": "identity",
            "log_types": ["authentication_event", "mfa_challenge"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    source_id = resp.json()["id"]

    resp = await client.post(
        "/api/telemetry-sources/check-feasibility",
        json={"data_sources": ["login_success"]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert sorted(body) == ["coverage_pct", "feasible", "missing"]
    assert body["feasible"] == ["login_success"]

    await client.delete(f"/api/telemetry-sources/{source_id}", headers=auth_headers)


# ── The rule library's telemetry filter ──────────────────────────────


def _clause(mode: str, vocabulary: list[str], profile: TelemetryProfile, monkeypatch) -> str | None:
    from app.api import intelligence
    from app.services import meilisearch_client

    monkeypatch.setattr(meilisearch_client, "rule_facet_values", lambda attr: vocabulary)
    return intelligence._telemetry_clause(mode, profile)


def test_telemetry_clause_splits_the_vocabulary_by_feasibility(monkeypatch):
    """`covered` demands every token collected; `missing` needs only one absent."""
    profile = TelemetryProfile(tokens=frozenset({"process_creation"}))
    vocab = ["process_creation", "zeek_dns"]

    covered = _clause("covered", vocab, profile, monkeypatch)
    assert covered == 'telemetry_tokens IN ["process_creation"] AND NOT telemetry_tokens IN ["zeek_dns"]'

    assert _clause("missing", vocab, profile, monkeypatch) == 'telemetry_tokens IN ["zeek_dns"]'


def test_telemetry_clause_drops_the_negation_when_nothing_is_absent(monkeypatch):
    profile = TelemetryProfile(tokens=frozenset({"process_creation"}))
    assert _clause("covered", ["process_creation"], profile, monkeypatch) == (
        'telemetry_tokens IN ["process_creation"]'
    )


def test_telemetry_clause_is_none_when_the_mode_cannot_match(monkeypatch):
    """None, not an empty IN []: the caller returns no rows rather than all of them."""
    empty = TelemetryProfile()
    assert _clause("covered", ["zeek_dns"], empty, monkeypatch) is None

    everything = TelemetryProfile(tokens=frozenset({"zeek_dns"}))
    assert _clause("missing", ["zeek_dns"], everything, monkeypatch) is None


def test_telemetry_clause_quotes_values_with_delimiters(monkeypatch):
    profile = TelemetryProfile(tokens=frozenset({'we"ird'}))
    clause = _clause("covered", ['we"ird'], profile, monkeypatch)
    assert clause == 'telemetry_tokens IN ["we\\"ird"]'


def test_indexed_rule_carries_the_tokens_the_filter_reads():
    """The index must see a Sigma rule's log_source, not its empty data_sources."""
    from app.services.entity_indexer import _rule_to_doc

    rule = _rule("Sigma", log_sources={"product": "windows", "category": "process_creation"})
    rule.id = uuid.uuid4()
    doc = _rule_to_doc(rule)
    assert doc["data_sources"] == []
    assert doc["telemetry_tokens"] == ["windows", "process_creation"]


async def test_telemetry_vocabulary_splits_the_rail_values(client: AsyncClient, auth_headers: dict, monkeypatch):
    """The one-click select needs the server's verdict: 'Windows Security' is
    collected by a ticked 'windows' source, which no client-side string compare
    would find."""
    from app.services import meilisearch_client

    monkeypatch.setattr(
        meilisearch_client,
        "rule_facet_values",
        lambda attr: ["process_creation", "zeek_dns"],
    )
    resp = await client.post(
        "/api/telemetry-sources",
        json={"name": "EDR", "category": "endpoint", "log_types": ["process_creation"]},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    source_id = resp.json()["id"]

    resp = await client.get("/api/detection-rules/telemetry-vocabulary", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["collected"] == ["process_creation"]
    assert body["missing"] == ["zeek_dns"]

    await client.delete(f"/api/telemetry-sources/{source_id}", headers=auth_headers)
