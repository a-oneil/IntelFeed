"""Non-entity names: concepts the extractor filed as tools, malware, actors or products.

Every junk name here was deleted from prod in the 2026-11 Review-queue triage.
The negative lists are the regression guard:
a rule that eats a real tool, family or group is worse than the junk it stops.
"""

import importlib.util
import pathlib

import pytest
from sqlalchemy import func, select

from app.config import settings
from app.intelligence.entity_resolution import (
    NON_ENTITY_REASONS,
    defender_operated,
    evidence_names,
    gate_aliases,
    generic_name_reason,
    non_entity_reason,
    resolve_entity_creation,
)
from app.models.tool import Tool

AMT = ("threat_actor", "malware", "tool")
ALL4 = (*AMT, "product")

# (name, expected reason, entity types it must be blocked for)
JUNK = [
    # protocols and standards — products are exempt
    ("WebRTC", "protocol", AMT),
    ("OpenID Connect", "protocol", AMT),
    ("WebSocket", "protocol", ("threat_actor", "malware")),  # tool: concept_term fires first
    ("Modbus TCP", "protocol", ("threat_actor",)),
    ("EtherNet/IP", "protocol", ("threat_actor",)),  # path_shape already takes malware/tool
    ("MQTT", "protocol", AMT),
    ("SCTP", "protocol", AMT),
    ("SFTP", "protocol", AMT),
    ("UPnP", "protocol", AMT),
    ("vxlan", "protocol", AMT),
    ("SOCKS5", "protocol", AMT),
    ("JWT", "protocol", AMT),
    # crypto algorithms
    ("RSA", "crypto_algorithm", ALL4),
    ("ChaCha20", "crypto_algorithm", ALL4),
    ("XChaCha20-Poly1305", "crypto_algorithm", ALL4),
    ("Ed25519", "crypto_algorithm", ALL4),
    ("SHA-256", "crypto_algorithm", ("threat_actor", "malware", "product")),
    # shell commands / install lines
    ("npm install", "shell_command", ALL4),
    ("pip install unsloth", "shell_command", ALL4),
    ("uv tool install", "shell_command", ALL4),
    ("git clone", "shell_command", ALL4),
    ("git checkout", "shell_command", ALL4),
    ("sudo apt-get install", "shell_command", ALL4),
    ("npx create-mcp-server", "shell_command", ALL4),
    # config flags / code tokens
    ("trust_remote_code=True", "code_token", ALL4),
    ("AutoMap", "code_token", ALL4),
    ("AutoConfig", "code_token", ALL4),
    ("CAP_NET_ADMIN", "code_token", ALL4),
    ("PROCESS_ALL_ACCESS", "code_token", ALL4),
    # OS APIs and kernel features
    ("BitBlt", "os_api", ALL4),
    ("CreateProcess", "os_api", ALL4),
    ("CreateProcessW", "os_api", ALL4),
    ("CreateProcess API", "os_api", ALL4),
    ("WriteFile", "os_api", ALL4),
    ("ReadDirectoryChangesW", "os_api", ALL4),
    ("ptrace", "os_api", ALL4),
    ("the ptrace syscall", "os_api", ALL4),
    ("inotify", "os_api", ALL4),
    ("FSEvents", "os_api", ALL4),
    ("Landlock", "os_api", ALL4),
    ("NFQUEUE", "os_api", ALL4),
    ("System V shared memory", "os_api", ALL4),
    ("AppDomainManager", "os_api", ALL4),
    # categories / descriptive phrases
    ("SIEM", "category_phrase", ALL4),
    ("EDR/XDR", "category_phrase", ("threat_actor", "product")),  # path_shape already takes malware/tool
    ("MDR", "category_phrase", ALL4),
    ("ZTNA", "category_phrase", ALL4),
    ("SSO", "category_phrase", ALL4),
    ("firewalls", "category_phrase", ALL4),
    ("reflective loader", "category_phrase", ("threat_actor", "tool", "product")),
    ("web shell", "category_phrase", ("threat_actor", "tool", "product")),
    ("PHP web shells", "category_phrase", ("threat_actor", "tool", "product")),
    ("Phishing Kit", "category_phrase", ("threat_actor", "tool", "product")),
    ("AI assistants", "category_phrase", ALL4),
    ("OpenAI models", "category_phrase", ALL4),
    ("Anthropic models", "category_phrase", ALL4),
    ("Content Inspection", "category_phrase", ALL4),
    ("real-time monitoring", "category_phrase", ALL4),
    # mainstream platforms filed as tools/actors — products are exempt
    ("Windows", "platform", AMT),
    ("Android", "platform", AMT),
    ("Telegram", "platform", AMT),
    ("Claude", "platform", AMT),
    ("WordPress", "platform", AMT),
    ("JavaScript", "platform", AMT),
    ("Microsoft 365", "platform", AMT),
    # techniques filed as tools/actors
    ("BYOVD", "technique_term", ALL4),
    ("Bring Your Own Vulnerable Driver (BYOVD)", "technique_term", ALL4),
    ("LLMjacking", "technique_term", ALL4),
    ("DNS tunneling", "technique_term", ALL4),
    ("digital skimming", "technique_term", ALL4),
    ("HVNC", "technique_term", ALL4),
    ("Process Hollowing", "technique_term", ("threat_actor", "malware", "product")),
    ("T1566.001", "mitre_technique", ("threat_actor", "malware", "product")),
    # hex literals are never a name, whatever the type
    ("0x00", "numeric_literal", ALL4),
]


@pytest.mark.parametrize(("name", "reason", "types"), JUNK)
def test_non_entity_names_blocked(name, reason, types):
    for entity_type in types:
        assert non_entity_reason(entity_type, name) == reason, (entity_type, name)
        assert generic_name_reason(entity_type, name) is not None, (entity_type, name)


@pytest.mark.parametrize(("name", "reason", "types"), JUNK)
def test_reasons_are_exported_for_the_purge_script(name, reason, types):
    assert reason in NON_ENTITY_REASONS


@pytest.mark.parametrize(
    "name",
    [
        "China-nexus",
        "Chinese-speaking threat actor",
        "North Korea-linked group",
        "Russia-aligned cluster",
        "Iran-based actors",
        "the China-nexus threat actor",
        "Russian submarine operation",
        "Chinese espionage campaign",
        "888",
        "0x00",
    ],
)
def test_descriptor_and_number_actors_blocked(name):
    assert generic_name_reason("threat_actor", name) is not None


@pytest.mark.parametrize("name", ["888", "0x00", "China-nexus", "Russian submarine operation"])
def test_number_and_descriptor_rules_hit_actors_only_or_hex(name):
    # Digits-only and attribution rules are actor rules; hex is everywhere.
    expected = name.startswith("0x")
    assert (non_entity_reason("malware", name) is not None) is expected
    assert (non_entity_reason("tool", name) is not None) is expected


@pytest.mark.parametrize("name", ["WebRTC", "Kerberos", "OpenID Connect", "Model Context Protocol", "MQTT"])
def test_protocols_may_be_products(name):
    assert non_entity_reason("product", name) is None


@pytest.mark.parametrize("name", ["Windows", "Android", "Telegram", "Claude", "WordPress", "Microsoft 365"])
def test_platforms_may_be_products(name):
    assert non_entity_reason("product", name) is None


@pytest.mark.parametrize("name", ["RSA", "SIEM", "npm install", "WebRTC", "BYOVD", "AutoMap"])
def test_vendors_are_never_checked(name):
    # RSA is a real vendor; vendor names are left to the vendor catalog.
    assert non_entity_reason("vendor", name) is None


REAL_TOOLS = [
    "PowerShell",
    "cmd",
    "cmd.exe",
    "Mimikatz",
    "Impacket",
    "Cobalt Strike",
    "AutoIt",
    "AutoHotkey",
    "git",
    "Git",
    "pip",
    "pip-audit",
    "git-dumper",
    "curl",
    "wget",
    "Docker Desktop",
    "GitHub Copilot",
    "Responder",
    "Rubeus",
    "Kerbrute",
    "SharpHound",
    "SharpHVNC",
    "TinyNuke",
    "DNSCat2",
    "Iodine",
    "SoftPerfect Network Scanner",
    "Advanced IP Scanner",
    "Cuckoo Sandbox",
    "EDRSandBlast",
    "EDRKillShifter",
    "AMSI.fail",
    "rclone",
    "ngrok",
    "Chisel",
    "Ligolo-ng",
    "3proxy",
    "Sliver",
    "Havoc",
    "Brute Ratel C4",
    "Remote Server Administration Tools (RSAT)",
    "XORIndex",
    "DCSyncer",
]


@pytest.mark.parametrize("name", REAL_TOOLS)
def test_real_tools_pass(name):
    assert non_entity_reason("tool", name) is None


REAL_MALWARE = [
    "LockBit",
    "Emotet",
    "HVNC Rat",
    "XWorm",
    "ChaCha",
    "Salsa",
    "Petya",
    "More_eggs",
    "PlugX",
    "ShadowPad",
    "China Chopper",
    "Godzilla",
    "Behinder",
    "Inferno Drainer",
    "Magecart",
    "3AM",
    "8Base",
    "FrostyGoop",
    "PIPEDREAM",
    "SSLoad",
    "NFQUEUEBot",
    "T9000",
]


@pytest.mark.parametrize("name", REAL_MALWARE)
def test_real_malware_passes(name):
    assert generic_name_reason("malware", name) is None


REAL_ACTORS = [
    "764",
    "7777",
    "8220 Gang",
    "APT28",
    "APT-C-36",
    "UNC5221",
    "Storm-0558",
    "Volt Typhoon",
    "Lazarus Group",
    "Iranian Cyber Army",
    "Russian Business Network",
    "Cyber Army of Russia Reborn",
    "North Korean IT workers",
    "Operation Aurora",
    "Operation Triangulation",
    "NoName057(16)",
    "0ktapus",
    "LAPSUS$",
    "Magecart",
    "The Com",
]


@pytest.mark.parametrize("name", REAL_ACTORS)
def test_real_actors_pass(name):
    assert generic_name_reason("threat_actor", name) is None


REAL_PRODUCTS = [
    "Kerberos",
    "WebRTC",
    "Cortex XDR",
    "SentinelOne Singularity XDR",
    "Sumo Logic Cloud SIEM",
    "Cloudflare WAF",
    "Okta SSO",
    "Duo MFA",
    "RSA SecurID",
    "RSA NetWitness",
    "OpenSSH",
    "OpenSSL",
    "Hugging Face Transformers",
    "Microsoft 365 Copilot",
    "Docker Engine",
    "npm",
]


@pytest.mark.parametrize("name", REAL_PRODUCTS)
def test_real_products_pass(name):
    assert generic_name_reason("product", name) is None


# ---------------------------------------------------------------------------
# Shape gates from the 2026-11-02 vet of every AI-created entity.
# Each junk name was minted on prod.
# ---------------------------------------------------------------------------

SHAPE_JUNK = [
    # IoC-table files and packages filed as malware
    ("malware", "shell.war", "filename"),
    ("malware", "DnsCommandBeacon.class", "filename"),
    ("malware", "tc9.dex", "filename"),
    ("malware", "zimlog.service", "filename"),
    ("malware", ".x11d", "filename"),
    ("malware", "btree-range-store", "package_name"),
    ("malware", "cdn-img-fetch", "package_name"),
    ("malware", "bot-linux-amd64", "package_name"),
    # vulnerability nicknames
    ("malware", "PHP2Shell", "vulnerability_nickname"),
    ("malware", "Spring4Shell", "vulnerability_nickname"),
    ("malware", "Kaltura mwEmbed RCE", "vulnerability_nickname"),
    ("tool", "React2Shell", "vulnerability_nickname"),
    # descriptions used as names
    ("malware", "Rust-based backdoors", "description_phrase"),
    ("malware", "Infostealer-type malware", "description_phrase"),
    ("malware", "Malicious ScreenConnect clients", "description_phrase"),
    ("malware", "Exodus Patched Installer", "description_phrase"),
    ("malware", "Turla's RPC backdoor", "description_phrase"),
    ("malware", "Gemini AI assistant (malicious extension)", "description_phrase"),
    ("malware", "Rust loader (embedded)", "description_phrase"),
    # actors: nationality plus generic nouns, campaigns
    ("threat_actor", "Chinese spies", "pure_descriptor"),
    ("threat_actor", "Iranian forces", "pure_descriptor"),
    ("threat_actor", "China APT", "pure_descriptor"),
    ("threat_actor", "Russian government cyberspies", "pure_descriptor"),
    ("threat_actor", "mysterious threat actor", "vague_qualifier"),
    ("threat_actor", "ArcaneDoor campaign", "campaign_name"),
    # tools: paths, commands, category phrases
    ("tool", "/bin/sh", "path_shape"),
    ("tool", "/j_security_check", "path_shape"),
    ("tool", "C:\\ProgramData\\Veeam\\Endpoint\\Svc.VeeamEndpointBackup.log", "path_shape"),
    ("tool", "aws s3 sync", "shell_command"),
    ("tool", "net user", "shell_command"),
    ("tool", "gzip -d -c", "shell_command"),
    ("tool", "git status --short", "shell_command"),
    ("tool", "VPN software", "category_phrase"),
    ("tool", "remote desktop sessions", "category_phrase"),
    ("tool", "email authentication protocols", "category_phrase"),
    ("tool", "comprehensive audit logging", "category_phrase"),
    ("tool", "vendor payment verification procedures", "category_phrase"),
]


@pytest.mark.parametrize(("entity_type", "name", "reason"), SHAPE_JUNK)
def test_shape_gates_block_vetted_junk(entity_type, name, reason):
    assert generic_name_reason(entity_type, name) == reason


SHAPE_REAL = [
    # families whose names look like the junk shapes
    ("malware", "S-Type"),
    ("malware", "Mis-Type"),
    ("malware", "cook.pth"),
    ("malware", "More_eggs"),
    ("malware", "Log4j"),
    # actors with a nationality, a possessive or "Operation" in the name
    ("threat_actor", "People's Liberation Army"),
    ("threat_actor", "Iranian Cyber Army"),
    ("threat_actor", "North Korean IT workers"),
    ("threat_actor", "Operation Aurora"),
    ("threat_actor", "@Exvicy"),
    # tools named like packages or commands
    ("tool", "git-dumper"),
    ("tool", "ligolo-ng"),
    ("tool", "net"),
    ("tool", "aws"),
    ("tool", "certutil"),
    ("tool", "Invoke-Mimikatz"),
    ("tool", "Brute Ratel C4"),
    ("tool", "John the Ripper"),
    # products the command rule must leave alone
    ("product", "AWS Lambda"),
    ("product", "Azure Kubernetes Service"),
]


@pytest.mark.parametrize(("entity_type", "name"), SHAPE_REAL)
def test_shape_gates_leave_real_names_alone(entity_type, name):
    assert generic_name_reason(entity_type, name) is None


@pytest.mark.parametrize(
    ("wielded_by", "defender"),
    [
        ("the defender", True),
        ("incident responders", True),
        ("Kaspersky researchers", True),
        ("security teams", True),
        ("Windows users", True),
        ("the attacker", False),
        ("APT29", False),
        ("XWorm malware", False),
        ("attackers posing as IT administrators", False),
        ("", False),
    ],
)
def test_defender_operated(wielded_by, defender):
    assert defender_operated(wielded_by) is defender


def test_evidence_names_the_entity_by_name_or_alias():
    assert evidence_names("APT29 deployed Cobalt-Strike beacons.", "Cobalt Strike")
    assert evidence_names("The group, tracked as UNC2452, ran it.", "APT29", ["UNC2452"])
    assert not evidence_names("APT29 ran SweepScan across the subnet.", "FreshKit")
    assert not evidence_names("", "Lazarus Group")
    assert not evidence_names(None, "Lazarus Group")


# ---------------------------------------------------------------------------
# Purge script helpers (pure)
# ---------------------------------------------------------------------------


def _purge_module():
    path = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "maintenance" / "purge_generic_entities.py"
    spec = importlib.util.spec_from_file_location("purge_generic_entities", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_purge_reason_slug_and_default_action():
    purge = _purge_module()
    assert purge.reason_slug("generic:protocol") == "protocol"
    assert purge.reason_slug("country:Iran") == "country"
    assert purge.reason_slug("denylist") == "denylist"
    # A heavily linked concept row waits for a read; light ones and old rules delete.
    assert purge.default_action("generic:protocol", 238, 20) == "review"
    assert purge.default_action("generic:protocol", 3, 20) == "delete"
    assert purge.default_action("generic:generic_head_noun", 500, 20) == "delete"


# ---------------------------------------------------------------------------
# Resolver wiring (DB — needs the test database)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entity_type", "name"),
    [
        ("tool", "npm install"),
        ("tool", "trust_remote_code=True"),
        ("tool", "BitBlt"),
        ("tool", "OpenAI models"),
        ("tool", "WebRTC"),
        ("malware", "reflective loader"),
        ("threat_actor", "China-nexus"),
        ("threat_actor", "888"),
        ("product", "SIEM"),
    ],
)
async def test_resolver_blocks_non_entity_names_when_gates_on(db_session, monkeypatch, entity_type, name):
    monkeypatch.setattr(settings, "entity_creation_gates", "on")
    decision = await resolve_entity_creation(db_session, entity_type, name, source="ai")
    assert decision.action == "blocked"
    assert decision.reason.startswith("generic_name:")


async def test_resolver_shadow_mode_logs_and_still_creates(db_session, monkeypatch):
    monkeypatch.setattr(settings, "entity_creation_gates", "shadow")
    decision = await resolve_entity_creation(db_session, "tool", "pip install unsloth", source="ai")
    assert decision.action == "create"
    assert decision.shadow_reason == "generic_name:shell_command"


async def test_resolver_manual_override_creates(db_session, monkeypatch):
    monkeypatch.setattr(settings, "entity_creation_gates", "on")
    decision = await resolve_entity_creation(db_session, "tool", "BYOVD", source="manual")
    assert decision.action == "blocked"
    decision = await resolve_entity_creation(db_session, "tool", "BYOVD", source="manual", override=True)
    assert decision.action == "create"


async def test_existing_row_still_resolves_before_the_gate(db_session, monkeypatch):
    monkeypatch.setattr(settings, "entity_creation_gates", "on")
    tool = Tool(name="HVNC", aliases=[])
    db_session.add(tool)
    await db_session.flush()
    decision = await resolve_entity_creation(db_session, "tool", "HVNC", source="ai")
    assert decision.action == "matched" and decision.entity.id == tool.id


async def test_real_tool_is_created(db_session, monkeypatch):
    monkeypatch.setattr(settings, "entity_creation_gates", "on")
    decision = await resolve_entity_creation(db_session, "tool", "Impacket", source="ai")
    assert decision.action == "create"
    assert (await db_session.execute(select(func.count()).select_from(Tool))).scalar() == 0


async def test_non_entity_aliases_are_dropped(db_session, monkeypatch):
    monkeypatch.setattr(settings, "entity_creation_gates", "on")
    kept = await gate_aliases(db_session, "malware", "China Chopper", ["web shell", "HVNC", "CNChopper"])
    assert "web shell" not in kept and "HVNC" not in kept
