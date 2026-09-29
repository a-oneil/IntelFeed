"""Entity creation guardrails (planning/entity-creation-guardrails.md Phases 1-2).

Fixtures are the actual prod examples from the plan's §1 failure-mode table:
F1 punctuation/spacing variants, F2 leetspeak, F3 descriptor variants, F5
generic names, F6 junk aliases, F7 cross-type, F8 version sprawl, F9
filename/AV-string names, F12 free-text type vocab, F13 code artifacts /
techniques / physical objects as tools.
"""

import pytest
from sqlalchemy import func, select
from sqlalchemy import text as sa_text

from app.config import settings
from app.intelligence.enrichment import store_malware, store_threat_actors
from app.intelligence.entity_resolution import (
    coerce_malware_type,
    coerce_tool_type,
    enrichment_content_ok,
    gate_aliases,
    generic_name_reason,
    normalize_entity_name,
    resolve_entity_creation,
)
from app.models.country import Country
from app.models.entity_index import EntityAliasIndex, EntityNameDenylist
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import Tool


@pytest.fixture
def gates_on(monkeypatch):
    monkeypatch.setattr(settings, "entity_creation_gates", "on")


@pytest.fixture
def gates_shadow(monkeypatch):
    monkeypatch.setattr(settings, "entity_creation_gates", "shadow")


# ---------------------------------------------------------------------------
# normalize_entity_name (pure)
# ---------------------------------------------------------------------------

F1_VARIANT_PAIRS = [
    ("Team PCP", "TeamPCP"),
    ("Nightmare-Eclipse", "Nightmare Eclipse"),
    ("Thegentlemen", "The Gentlemen"),
    ("Silentransomgroup", "Silent Ransom Group"),
    ("SilverFox", "Silver Fox"),
    ("Coinbasecartel", "Coinbase Cartel"),
]


@pytest.mark.parametrize("a,b", F1_VARIANT_PAIRS)
def test_f1_punctuation_spacing_variants_share_norm_exact(a, b):
    na = normalize_entity_name(a, "threat_actor")
    nb = normalize_entity_name(b, "threat_actor")
    assert na.norm_exact == nb.norm_exact


@pytest.mark.parametrize("a,b", [("Cl0p", "Clop"), ("CRPX0", "Crpxo"), ("L@zarus", "Lazarus")])
def test_f2_leetspeak_variants_share_norm_exact(a, b):
    assert normalize_entity_name(a).norm_exact == normalize_entity_name(b).norm_exact


@pytest.mark.parametrize(
    "name,entity_type,stem",
    [
        ("Gunra ransomware group", "threat_actor", "gunra"),
        ("Interlock ransomware group", "threat_actor", "interlock"),
        ("DOUBLECUP operators", "threat_actor", "doublecup"),
        ("xaknet team", "threat_actor", "xaknet"),
        ("764 splinter group", "threat_actor", "tea"),  # 7->t 6 stays... see note below
        ("Pegasus Spyware", "malware", "pegasus"),
        ("Mars Stealer", "malware", "mars"),
        ("Dysphoria Botnet", "malware", "dysphoria"),
        ("NetSupportManager RAT", "malware", "netsupportmanager"),
    ],
)
def test_f3_descriptor_variants_strip_to_stem(name, entity_type, stem):
    if name == "764 splinter group":
        # digits leet-fold: 7->t, 6 unchanged, 4->a — stem is the folded "764"
        stem = normalize_entity_name("764").norm_exact
    assert normalize_entity_name(name, entity_type).norm_stripped == stem


@pytest.mark.parametrize(
    "name,stem",
    [
        ("LockBit 3", "lockbit"),
        ("LockBit 5.0", "lockbit"),
        ("lockbit v3.0", "lockbit"),
        ("Stealc v2", "stealc"),
        ("ComRAT v4", "comrat"),
        ("XMRig Botnet", "xmrig"),
    ],
)
def test_f8_version_tokens_strip(name, stem):
    assert normalize_entity_name(name, "malware").norm_stripped == stem


def test_f8_codename_versions_are_candidates_only():
    n = normalize_entity_name("LockBit Black", "malware")
    # Black is not removed from norm_stripped — only offered as a candidate stem.
    assert n.norm_stripped == "lockbitblack"
    assert n.norm_codename_stripped == "lockbit"


def test_medusa_is_not_medusalocker():
    """The Medusa≠MedusaLocker trap: nothing strips MedusaLocker down to medusa."""
    n = normalize_entity_name("MedusaLocker", "malware")
    assert n.norm_exact == "medusalocker"
    assert n.norm_stripped == "medusalocker"
    assert normalize_entity_name("Medusa ransomware", "malware").norm_stripped == "medusa"


# ---------------------------------------------------------------------------
# Generic-name gate patterns (pure)
# ---------------------------------------------------------------------------

F5_ACTOR_JUNK = [
    "Iranian hackers",
    "Unknown APT",
    "attackers",
    "Russian threat actors",
    "Hackers-for-Hire",
    "John Doe",
    "Threat actors (unnamed)",
    "Nation-state actors",
    "unnamed global secret group",
    "state-sponsored hackers",
]


@pytest.mark.parametrize("name", F5_ACTOR_JUNK)
def test_f5_generic_actor_names_rejected(name):
    assert generic_name_reason("threat_actor", name) is not None


@pytest.mark.parametrize("name", ["Scattered Spider", "Lazarus Group", "Silent Ransom Group", "Cyber Av3ngers"])
def test_f5_real_actor_names_pass(name):
    assert generic_name_reason("threat_actor", name) is None


F9_MALWARE_JUNK = [
    "msi.dll",
    "payload.exe",
    "svhost.exe",
    "zoom-update.vbs",
    "emer-run.php",
    "Math_Symbol.js",
    "capture.Ps1",
    "ransom.linux.monti.thgocbc",
    "win32/korplug.ub",
    "Win.Dropper.Ap0calypseRAT-10004380-0",
    "Trojan.GenericFCA.Script.37952",
    "Ransomware",
    "Stealer",
    "remote access trojan",
    "crypto miner",
    "Rust-based malware loader",
    "malicious npm package",
    "LNK malware",
]


@pytest.mark.parametrize("name", F9_MALWARE_JUNK)
def test_f9_f5_malware_junk_rejected(name):
    assert generic_name_reason("malware", name) is not None


@pytest.mark.parametrize("name", ["Stealc", "LockBit", "GuLoader", "Emotet", "Anchor", "Mini Shai-Hulud 2.0"])
def test_f9_real_malware_names_pass(name):
    assert generic_name_reason("malware", name) is None


F13_TOOL_JUNK = [
    "--backup-dir",
    "-D",
    "absint()",
    "child_process.spawn()",
    "fscrypt_get_devices()",
    "bpf_override_return",
    "CVE-2026-58231",
    "DLL Sideloading",
    "Prompt Injection",
    "Indicator Removal on Host",
    "NTLM relay",
    "T1562",
    "D-30 howitzer",
    "X-59 missile",
    "ZALA drone",
    "{{Hostname}}",
    "masscan[.]cloud",
    "ksmbd_s...",
]


@pytest.mark.parametrize("name", F13_TOOL_JUNK)
def test_f13_non_software_tool_names_rejected(name):
    assert generic_name_reason("tool", name) is not None


# Semantic gates (2026-09). The F13 set above only rejects code-artifact
# shapes; these are the categories that flooded the catalog for eleven weeks —
# dependencies, vulnerable packages, API symbols and release strings. Every
# name here was taken from the prod tools table.
# See planning/tool-extraction-cleanup.md.
TOOL_SEMANTIC_JUNK = [
    # package coordinates
    "@fastify/middie",
    "@contentful/mcp-server",
    "golang.org/x/crypto/ssh",
    "biz44/id99-client",
    "org.apache.tomcat.dbcp.dbcp.datasources.PerUserPoolDataSource",
    # package names
    "libde265",
    "libzypp",
    "python-jwcrypto",
    "perl-XML-LibXML",
    "nbd-client",
    # API symbols
    "path.resolve",
    "ipaddress.is_global",
    "mlflow.pyfunc.load_model",
    "LogRule::matches",
    "workbench.extensions.installExtension",
    # file artefacts
    "epdlpdrv.sys",
    "DukeQt.dll",
    "fileupload.class.php",
    "nyx.ps1",
    "kramer_python_deobfuscator.py",
    "apk.go",
    # release strings
    ".NET 9.0",
    "Info-ZIP Zip 3.0",
    "TOTOLINK T6 4.1.5cu.748_B20211015",
]


@pytest.mark.parametrize("name", TOOL_SEMANTIC_JUNK)
def test_tool_semantic_gates_reject(name):
    assert generic_name_reason("tool", name) is not None


# The carve-outs the semantic gates must not swallow: the prompt's LOLBAS
# exception, and Impacket's suite, which really is named as .py scripts.
@pytest.mark.parametrize(
    "name",
    [
        "certutil.exe",
        "rundll32.exe",
        "mshta.exe",
        "regsvr32.exe",
        "cipher.exe",
        "ntdsutil.exe",
        "comsvcs.dll",
        "secretsdump.py",
        "psexec.py",
        "ntlmrelayx.py",
        "linpeas.sh",
        "linux-exploit-suggester.sh",
        "PowerView.ps1",
    ],
)
def test_tool_semantic_gates_allow_lolbas_and_script_tools(name):
    assert generic_name_reason("tool", name) is None


# Regression guard for the shapes real offensive tooling actually has. A gate
# that eats these is worse than the bloat it prevents.
@pytest.mark.parametrize(
    "name",
    [
        "CrackMapExec",
        "BloodHound",
        "SharpHound",
        "RustHound",
        "Ligolo-ng",
        "Seatbelt",
        "interactsh-url",
        "MimiPenguin",
        "SILENTTRINITY",
        "Invoke-PSImage",
        "forest druid",
        "John the Ripper",
        "Brute Ratel",
        "NetSupport Manager",
    ],
)
def test_tool_semantic_gates_allow_real_tools(name):
    assert generic_name_reason("tool", name) is None


@pytest.mark.parametrize(
    "name",
    [
        "Cobalt Strike",
        "Metasploit",
        "Node.js",
        "Bring Your Own Vulnerable Driver (BYOVD)",  # acronym-in-parens is a real name shape
        "PowerShell",
        "Tycoon 2FA",
    ],
)
def test_f13_real_tool_names_pass(name):
    assert generic_name_reason("tool", name) is None


# ---------------------------------------------------------------------------
# F12 — controlled type vocabulary coercion (pure)
# ---------------------------------------------------------------------------


def test_f12_tool_type_coercion():
    assert coerce_tool_type("c2_framework") == ("c2_framework", None)
    slug, raw = coerce_tool_type("exploitation framework")
    assert slug == "exploitation" and raw == "exploitation framework"
    slug, raw = coerce_tool_type("Large Language Model")
    assert slug == "ai_model" and raw == "Large Language Model"
    slug, raw = coerce_tool_type("Baseboard Management Controller")
    assert slug == "other" and raw == "Baseboard Management Controller"
    assert coerce_tool_type(None) == (None, None)


def test_f12_malware_type_coercion():
    assert coerce_malware_type("ransomware") == ("ransomware", None)
    slug, raw = coerce_malware_type("Remote Access Trojan (RAT) / Backdoor")
    assert slug == "rat" and raw is not None
    slug, raw = coerce_malware_type("Self-propagating npm worm")
    assert slug == "worm"
    slug, raw = coerce_malware_type("weird new thing")
    assert slug == "other" and raw == "weird new thing"


# ---------------------------------------------------------------------------
# Enrichment topical guard (pure) — F11
# ---------------------------------------------------------------------------


def test_f11_topical_guard_rejects_wrong_subjects():
    ok, reason = enrichment_content_ok("764", "Year 764 (DCCLXIV) was a common year starting on Sunday.")
    assert not ok and reason == "calendar_year"
    ok, reason = enrichment_content_ok("Blackwater", "Blackwater may refer to:\n\nBlackwater, a river")
    assert not ok and reason == "disambiguation_page"
    ok, reason = enrichment_content_ok("Anchor", "Anchor is a town in Illinois, United States.")
    assert not ok and reason == "geography"
    ok, reason = enrichment_content_ok("Justin", "Justin Doe (born 1990) is an American singer.")
    assert not ok and reason == "person_bio_no_cyber_context"


def test_f11_topical_guard_accepts_cyber_content():
    ok, _ = enrichment_content_ok("Turla", "Turla is a Russian-based threat actor known for cyber espionage.")
    assert ok
    # A person bio WITH cyber context passes (e.g. a named hacker).
    ok, _ = enrichment_content_ok("Person", "John Roe (born 1985) is a hacker convicted of malware distribution.")
    assert ok


# ---------------------------------------------------------------------------
# CVE identifiers are never entity names (issue #38)
#
# CVEs have their own entity type and ingest pipeline. A second row for the
# same id under another type puts the id in the autolinker vocabulary twice,
# so every mention links to both and the pair correlates with itself. The prod
# malware catalog had collected a run of these (CVE-2026-11332 ... -81642).
# ---------------------------------------------------------------------------

CVE_SHAPED_NAMES = [
    "CVE-2026-55193",
    "CVE-2026-11332",
    "cve-2026-81642",
    "CVE-2022-22965",
    "CVE-2026-55193 ransomware",
    "Exploit for CVE-2026-55193",
    "CVE 2026-55193",
    "CVE_2026-55193",
]


@pytest.mark.parametrize("name", CVE_SHAPED_NAMES)
@pytest.mark.parametrize("entity_type", ["threat_actor", "malware", "tool", "vendor", "product"])
def test_cve_shaped_names_rejected_for_every_type(entity_type, name):
    assert generic_name_reason(entity_type, name) == "cve_id"


@pytest.mark.parametrize(
    "name",
    [
        # Real tools whose names start with "CVE" — the gate requires digits
        # after the prefix, so none of these may be caught.
        "cve-search",
        "cvemap",
        "cve-bin-tool",
        "CVE Binary Tool",
        "Vulners",
        # A four-digit year alone is not an id, and a real family may carry one.
        "Spring4Shell",
        "Log4Shell",
    ],
)
def test_cve_lookalike_names_still_pass(name):
    assert generic_name_reason("tool", name) is None
    assert generic_name_reason("malware", name) is None


# ---------------------------------------------------------------------------
# DB resolution — normalized matching, candidates, gates, denylist, cross-type
# ---------------------------------------------------------------------------


async def _actor_count(db, name=None):
    q = select(func.count()).select_from(ThreatActor)
    if name:
        q = q.where(func.lower(ThreatActor.name) == name.lower())
    return (await db.execute(q)).scalar() or 0


async def test_entity_norm_sql_matches_python(db_session):
    """The SQL entity_norm() and Python norm_exact must stay in lockstep."""
    samples = [
        "Cl0p",
        "Silent Ransom Group",
        "L@zarus",
        "Team PCP",
        "n0_esc4pe",
        ".NET",
        "Café-Bräu 3.0",
        "Cyber Av3ngers",
    ]
    for name in samples:
        sql = (await db_session.execute(sa_text("SELECT entity_norm(:n)").bindparams(n=name))).scalar()
        assert sql == normalize_entity_name(name).norm_exact, name


async def test_alias_index_trigger_maintains_rows(db_session):
    actor = ThreatActor(name="Turla", aliases=["Secret Blizzard", "Venomous Bear"])
    db_session.add(actor)
    await db_session.flush()
    rows = (
        (await db_session.execute(select(EntityAliasIndex).where(EntityAliasIndex.entity_id == actor.id)))
        .scalars()
        .all()
    )
    forms = {r.normalized for r in rows}
    assert forms == {"turla", "secretblizzard", "venomousbear"}
    assert any(r.is_name for r in rows)


async def test_f1_f2_normalized_match_resolves_instead_of_creating(db_session):
    for name in ("Clop", "Silver Fox"):
        db_session.add(ThreatActor(name=name, aliases=[]))
    await db_session.flush()

    for variant, canonical in (("Cl0p", "Clop"), ("SilverFox", "Silver Fox"), ("silver-fox", "Silver Fox")):
        decision = await resolve_entity_creation(db_session, "threat_actor", variant)
        assert decision.action == "matched", variant
        assert decision.entity.name == canonical
        assert decision.match_kind == "normalized"


async def test_incoming_alias_normalized_match_falls_back(db_session):
    db_session.add(ThreatActor(name="MuddyWater", aliases=["Mango Sandstorm"]))
    await db_session.flush()
    decision = await resolve_entity_creation(db_session, "threat_actor", "Brand New Name", ["mango-sandstorm"])
    assert decision.action == "matched"
    assert decision.entity.name == "MuddyWater"


async def test_stripped_match_is_held_not_hard_matched(db_session, gates_on):
    """F3 candidate + the Medusa trap: a stripped-only hit never hard-matches."""
    db_session.add(MalwareFamily(name="Medusa", aliases=[]))
    db_session.add(MalwareFamily(name="MedusaLocker", aliases=[]))
    await db_session.flush()

    decision = await resolve_entity_creation(db_session, "malware", "Medusa ransomware")
    assert decision.action == "held"
    assert decision.reason == "stripped_match"
    # And MedusaLocker still resolves exactly, never to Medusa.
    decision = await resolve_entity_creation(db_session, "malware", "MedusaLocker")
    assert decision.action == "matched"
    assert decision.entity.name == "MedusaLocker"


async def test_ambiguous_normalized_match_is_held(db_session, gates_on):
    """.NET vs Net class: several same-type entities share a normalized form."""
    db_session.add(Tool(name=".NET", aliases=[]))
    db_session.add(Tool(name="Net", aliases=[]))
    await db_session.flush()
    decision = await resolve_entity_creation(db_session, "tool", "NET.")
    assert decision.action == "held"
    assert decision.reason == "ambiguous_normalized"


async def test_f5_generic_names_blocked_when_gates_on(db_session, gates_on, test_entry):
    stored = await store_threat_actors(
        db_session,
        test_entry.id,
        [{"name": "Iranian hackers"}, {"name": "Unknown APT"}, {"name": "attackers"}],
    )
    assert stored == []
    assert await _actor_count(db_session) == 0


async def test_f5_shadow_mode_logs_but_still_creates(db_session, gates_shadow, test_entry):
    stored = await store_threat_actors(db_session, test_entry.id, [{"name": "Iranian hackers"}])
    assert len(stored) == 1 and stored[0][1] is True
    assert await _actor_count(db_session, "Iranian hackers") == 1
    log = (
        (
            await db_session.execute(
                select(EntityMaintenanceLog).where(
                    EntityMaintenanceLog.action == "resolution_blocked", EntityMaintenanceLog.mode == "shadow"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(log) == 1
    assert log[0].applied is False
    assert "generic_name" in (log[0].after or {}).get("reason", "")


async def test_cve_named_malware_blocked_even_in_shadow(db_session, gates_shadow, test_entry):
    """The regression this guard exists for: shadow mode must not let it through.

    Every other generic-name gate downgrades to a log in shadow, which is how
    the prod catalog filled with CVE-named malware families. A CVE id has no
    legitimate reading as a malware name, so it is blocked like fp_name is.
    """
    stored = await store_malware(
        db_session,
        test_entry.id,
        [{"name": "CVE-2026-55193"}, {"name": "CVE-2026-55193 ransomware"}, {"name": "Stealc"}],
    )

    assert [m.name for m, _ in stored] == ["Stealc"]
    names = (await db_session.execute(select(MalwareFamily.name))).scalars().all()
    assert names == ["Stealc"]

    blocked = (
        (
            await db_session.execute(
                select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == "resolution_blocked")
            )
        )
        .scalars()
        .all()
    )
    assert len(blocked) == 2
    assert all(b.mode == "apply" and b.applied is True for b in blocked)
    assert all((b.after or {}).get("reason") == "generic_name:cve_id" for b in blocked)


async def test_cve_named_actor_and_tool_blocked_with_gates_off(db_session, monkeypatch, test_entry):
    """Enforced independently of the gate flag, like the fp-name block."""
    monkeypatch.setattr(settings, "entity_creation_gates", "off")

    decision = await resolve_entity_creation(db_session, "threat_actor", "CVE-2026-73066", source="ai")
    assert decision.action == "blocked" and decision.reason == "generic_name:cve_id"

    decision = await resolve_entity_creation(db_session, "tool", "Exploit for CVE-2026-73066", source="ai")
    assert decision.action == "blocked" and decision.reason == "generic_name:cve_id"

    assert await _actor_count(db_session) == 0


async def test_cve_named_manual_creation_is_overridable(db_session, gates_on):
    """The hard block is for automated sources only — an analyst still gets the
    warning-plus-override path rather than a wall."""
    decision = await resolve_entity_creation(db_session, "malware", "CVE-2026-18297", source="manual")
    assert decision.action == "blocked" and decision.reason == "generic_name:cve_id"

    decision = await resolve_entity_creation(db_session, "malware", "CVE-2026-18297", source="manual", override=True)
    assert decision.action == "create"


async def test_denylist_blocks_resurrection(db_session, gates_on):
    db_session.add(
        EntityNameDenylist(
            entity_type="threat_actor",
            normalized_name=normalize_entity_name("Shahed-136").norm_exact,
            display_name="Shahed-136",
            reason="physical weapon",
            source="cleanup_2026_08",
        )
    )
    await db_session.flush()
    decision = await resolve_entity_creation(db_session, "threat_actor", "Shahed-136")
    assert decision.action == "blocked"
    assert decision.reason == "denylist"
    # Punctuation/leetspeak variants hit via norm_exact...
    decision = await resolve_entity_creation(db_session, "threat_actor", "$hahed 136")
    assert decision.action == "blocked"
    # ...and descriptor-suffixed variants hit via norm_stripped.
    db_session.add(
        EntityNameDenylist(
            entity_type="threat_actor",
            normalized_name="darkviper",
            display_name="DarkViper",
            source="manual",
        )
    )
    await db_session.flush()
    decision = await resolve_entity_creation(db_session, "threat_actor", "DarkViper splinter group")
    assert decision.action == "blocked"
    assert decision.reason == "denylist"


async def test_f7_cross_type_check_is_bidirectional(db_session, gates_on):
    db_session.add(MalwareFamily(name="Havex", aliases=[]))
    db_session.add(ThreatActor(name="Salt Typhoon", aliases=[]))
    await db_session.flush()

    # malware name proposed as actor
    decision = await resolve_entity_creation(db_session, "threat_actor", "havex")
    assert decision.action == "held"
    assert decision.reason == "cross_type_hit"
    # actor name proposed as malware (the mirror image)
    decision = await resolve_entity_creation(db_session, "malware", "Salt Typhoon")
    assert decision.action == "held"
    assert decision.reason == "cross_type_hit"


async def test_f7_cross_type_hold_links_the_entry_to_the_survivor(db_session, gates_on, test_entry):
    """A held cross-type duplicate must not cost the entry its mention.

    "Qilin" the gang already exists; an article calling Qilin a ransomware
    family must not mint a second profile, but the entry still belongs on the
    actor — otherwise turning the gates on quietly drops links.
    """
    actor = ThreatActor(name="Qilin", aliases=[])
    db_session.add(actor)
    await db_session.flush()

    stored = await store_malware(db_session, test_entry.id, [{"name": "Qilin"}])
    assert stored == []
    assert (await db_session.execute(select(func.count()).select_from(MalwareFamily))).scalar() == 0

    link = (
        await db_session.execute(
            select(EntryThreatActor).where(
                EntryThreatActor.entry_id == test_entry.id,
                EntryThreatActor.threat_actor_id == actor.id,
            )
        )
    ).scalar_one_or_none()
    assert link is not None


async def test_f7_ambiguous_cross_type_hold_links_nothing(db_session, gates_on, test_entry):
    """Two different survivors share the name — there is no one right link."""
    db_session.add(ThreatActor(name="Medusa", aliases=[]))
    db_session.add(Tool(name="Medusa", aliases=[]))
    await db_session.flush()

    stored = await store_malware(db_session, test_entry.id, [{"name": "Medusa"}])
    assert stored == []
    assert (await db_session.execute(select(func.count()).select_from(EntryThreatActor))).scalar() == 0


async def test_alias_cannot_borrow_another_types_canonical_name(db_session, gates_on):
    """DEADWOOD must not carry "Agrius" — that is a relationship, not an alias.

    The two are genuinely different entities, so an alias tying them together
    makes the autolinker link every mention to both.
    """
    db_session.add(ThreatActor(name="Agrius", aliases=[]))
    await db_session.flush()

    kept = await gate_aliases(db_session, "malware", "DEADWOOD", ["Agrius", "SQLShred"])
    assert kept == ["SQLShred"]

    log = (
        (await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == "alias_conflict")))
        .scalars()
        .all()
    )
    assert len(log) == 1
    assert log[0].after["cross_type_owner"]["entity_type"] == "threat_actor"


async def test_alias_may_match_another_types_alias(db_session, gates_on):
    """Only a canonical name blocks — alias-vs-alias has no right answer, so the
    gate must not silently pick one."""
    db_session.add(ThreatActor(name="Pink Sandstorm", aliases=["Americium"]))
    await db_session.flush()

    kept = await gate_aliases(db_session, "malware", "DEADWOOD", ["Americium"])
    assert kept == ["Americium"]


async def test_gate_override_creates_and_logs(db_session, gates_on):
    decision = await resolve_entity_creation(
        db_session, "threat_actor", "Iranian hackers", source="manual", override=True
    )
    assert decision.action == "create"
    assert decision.shadow_reason and "generic_name" in decision.shadow_reason
    log = (
        (
            await db_session.execute(
                select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == "creation_override")
            )
        )
        .scalars()
        .all()
    )
    assert len(log) == 1


async def test_manual_api_gate_409_and_force(client, admin_headers, db_session, gates_on):
    resp = await client.post(
        "/api/entities/threat-actors", json={"name": "Russian threat actors"}, headers=admin_headers
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "entity_creation_gated"

    resp = await client.post(
        "/api/entities/threat-actors", json={"name": "Russian threat actors", "force": True}, headers=admin_headers
    )
    assert resp.status_code == 201
    assert await _actor_count(db_session, "Russian threat actors") == 1


async def test_ai_source_has_no_override(db_session, gates_on, test_entry):
    """Automated store paths never pass override — blocked stays blocked."""
    stored = await store_threat_actors(db_session, test_entry.id, [{"name": "unnamed global secret group"}])
    assert stored == []
    assert await _actor_count(db_session) == 0


# ---------------------------------------------------------------------------
# F6 — alias quality gate + cross-entity collision
# ---------------------------------------------------------------------------


async def test_f6_alias_collision_qilin_shinyhunters(db_session, gates_on):
    db_session.add(ThreatActor(name="ShinyHunters", aliases=[]))
    qilin = ThreatActor(name="Qilin", aliases=[])
    db_session.add(qilin)
    await db_session.flush()

    # "Water Galura" is multi-token (passes the dictionary-word rule); a bare
    # dictionary word like "Agenda" would be rejected by design.
    kept = await gate_aliases(db_session, "threat_actor", "Qilin", ["ShinyHunters", "Water Galura"], entity_id=qilin.id)
    assert kept == ["Water Galura"]
    conflicts = (
        (await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == "alias_conflict")))
        .scalars()
        .all()
    )
    assert len(conflicts) == 1


async def test_f6_alias_collision_dropped_even_in_shadow(db_session, gates_shadow):
    db_session.add(ThreatActor(name="APT28", aliases=["Forest Blizzard"]))
    apt29 = ThreatActor(name="APT29", aliases=[])
    db_session.add(apt29)
    await db_session.flush()

    kept = await gate_aliases(db_session, "threat_actor", "APT29", ["Forest Blizzard"], entity_id=apt29.id)
    assert kept == []


async def test_f6_generic_and_country_aliases_rejected(db_session, gates_on):
    db_session.add(Country(name="North Korea", aliases=["DPRK"]))
    lazarus = ThreatActor(name="Lazarus", aliases=[])
    db_session.add(lazarus)
    await db_session.flush()

    kept = await gate_aliases(
        db_session,
        "threat_actor",
        "Lazarus",
        ["DPRK", "North Korea", "Threat actors", "Hidden Cobra", "1e2d3c4b-5a69-4788-9695-a4b3c2d1e0f9"],
        entity_id=lazarus.id,
    )
    assert kept == ["Hidden Cobra"]


async def test_cve_aliases_dropped_even_in_shadow(db_session, gates_shadow):
    """Spring4Shell really is CVE-2022-22965 — but recording that as an alias
    is what makes every mention of the id link to the malware *and* the CVE.
    The connection belongs in entity_relationships."""
    spring = MalwareFamily(name="Spring4Shell", aliases=[])
    db_session.add(spring)
    await db_session.flush()

    kept = await gate_aliases(
        db_session,
        "malware",
        "Spring4Shell",
        ["CVE-2022-22965", "SpringShell"],
        entity_id=spring.id,
    )
    assert kept == ["SpringShell"]

    rejected = (
        (await db_session.execute(select(EntityMaintenanceLog).where(EntityMaintenanceLog.action == "alias_rejected")))
        .scalars()
        .all()
    )
    assert len(rejected) == 1
    assert rejected[0].applied is True
    assert (rejected[0].after or {}).get("reason") == "cve_id"


async def test_alias_gate_rejects_sentences(db_session, gates_on):
    kept = await gate_aliases(db_session, "threat_actor", "Foo", ["a seven token long alias phrase here", "RealAlias"])
    assert kept == ["RealAlias"]


# ---------------------------------------------------------------------------
# store integration — resolver wired into the AI store path
# ---------------------------------------------------------------------------


async def test_store_threat_actors_resolves_leet_variant(db_session, test_entry):
    db_session.add(ThreatActor(name="Clop", aliases=[]))
    await db_session.flush()

    stored = await store_threat_actors(db_session, test_entry.id, [{"name": "Cl0p"}])
    assert len(stored) == 1
    actor, is_new = stored[0]
    assert is_new is False
    assert actor.name == "Clop"
    assert await _actor_count(db_session) == 1


async def test_store_tools_coerces_type_and_keeps_raw(db_session, test_entry):
    from app.intelligence.tool import store_tools

    stored = await store_tools(
        db_session,
        test_entry.id,
        [
            {
                "name": "FrameSploit",
                "tool_type": "exploitation framework",
                "wielded_by": "APT29",
                "evidence": "APT29 deployed FrameSploit against the victim's perimeter.",
            }
        ],
    )
    assert len(stored) == 1
    tool, is_new = stored[0]
    assert is_new is True
    assert tool.tool_type == "exploitation"
    assert tool.metadata_.get("raw_tool_type") == "exploitation framework"


async def test_store_tools_evidence_gate_drops_unwielded(db_session, test_entry):
    """A tool the article never shows anyone using is not stored.

    This is the door that closes the advisory flood: an NVD entry names the
    affected package but no operator, so nothing should be created.
    """
    from app.intelligence.tool import store_tools

    stored = await store_tools(
        db_session,
        test_entry.id,
        [
            {"name": "libde265", "tool_type": "dev_tool"},
            {"name": "perl-XML-LibXML", "tool_type": "dev_tool", "wielded_by": "", "evidence": ""},
            {"name": "GhostPack", "wielded_by": "the attacker", "evidence": ""},
        ],
    )
    assert stored == []


# ---------------------------------------------------------------------------
# Phase 4 — reference alias knowledge (known_alias_map)
# ---------------------------------------------------------------------------


async def test_known_alias_cluster_resolves_vendor_name(db_session):
    """F4: 'Secret Blizzard' resolves to the stored Turla profile via the
    synonym cluster despite zero string overlap with stored name/aliases."""
    from app.intelligence.entity_resolution import upsert_known_aliases

    db_session.add(ThreatActor(name="Turla", aliases=["Snake"]))
    await db_session.flush()
    await upsert_known_aliases(db_session, "misp_galaxy", [("Turla", ["Secret Blizzard", "Venomous Bear", "Krypton"])])

    decision = await resolve_entity_creation(db_session, "threat_actor", "Secret Blizzard")
    assert decision.action == "matched"
    assert decision.entity.name == "Turla"
    assert decision.match_kind == "known_alias"


async def test_known_alias_ambiguous_cluster_does_not_match(db_session):
    """A cluster mapping onto several stored actors must never hard-match."""
    from app.intelligence.entity_resolution import upsert_known_aliases

    db_session.add(ThreatActor(name="Winnti Group", aliases=[]))
    db_session.add(ThreatActor(name="APT41", aliases=[]))
    await db_session.flush()
    await upsert_known_aliases(db_session, "misp_galaxy", [("APT41", ["Winnti Group", "Double Dragon"])])

    decision = await resolve_entity_creation(db_session, "threat_actor", "Double Dragon")
    # Cluster covers both stored profiles -> ambiguous -> no hard match.
    assert decision.match_kind != "known_alias"
    assert decision.action != "matched"


async def test_known_alias_upsert_is_full_replace(db_session):
    from app.intelligence.entity_resolution import upsert_known_aliases
    from app.models.entity_index import KnownAliasMap

    await upsert_known_aliases(db_session, "misp_galaxy", [("Turla", ["Krypton"])])
    await upsert_known_aliases(db_session, "misp_galaxy", [("Turla", ["Venomous Bear"])])
    rows = (
        (await db_session.execute(select(KnownAliasMap).where(KnownAliasMap.source == "misp_galaxy"))).scalars().all()
    )
    forms = {r.normalized_alias for r in rows}
    assert "krypton" not in forms
    assert "venomousbear" in forms


def test_misp_galaxy_parser():
    from app.workers.enrichment_tasks import parse_misp_galaxy_clusters

    data = {
        "values": [
            {"value": "Turla", "meta": {"synonyms": ["Secret Blizzard", "Venomous Bear", ""]}},
            {"value": "  ", "meta": {"synonyms": ["ignored"]}},
            {"value": "Sandworm"},
            "garbage",
        ]
    }
    assert parse_misp_galaxy_clusters(data) == [
        ("Turla", ["Secret Blizzard", "Venomous Bear"]),
        ("Sandworm", []),
    ]


# ---------------------------------------------------------------------------
# Manual create: re-linking an already-linked entity (prod GTG-87001 regression)
# ---------------------------------------------------------------------------


async def test_manual_create_by_alias_on_already_linked_entry(db_session, client, admin_headers, test_entry):
    """Creating by an alias of an actor already linked to the entry must not 500.

    Prod repro: "GTG-87001" was an alias of "Yemen Cell", which the AI had already
    linked to the entry. The resolver took the upsert path and the bare junction
    insert raised a duplicate-PK IntegrityError as an unhandled 500.
    """
    actor = ThreatActor(name="Yemen Cell", aliases=["GTG-87001"])
    db_session.add(actor)
    await db_session.flush()
    db_session.add(EntryThreatActor(entry_id=test_entry.id, threat_actor_id=actor.id, matched_names=["Yemen Cell"]))
    await db_session.flush()

    resp = await client.post(
        "/api/entities/threat-actors",
        json={"name": "GTG-87001", "entry_id": str(test_entry.id), "force": True},
        headers=admin_headers,
    )

    assert resp.status_code == 201
    # Upsert path: resolved to the existing actor, no duplicate minted.
    assert resp.json()["id"] == str(actor.id)
    assert await _actor_count(db_session, "Yemen Cell") == 1

    links = (
        await db_session.execute(
            select(func.count()).select_from(EntryThreatActor).where(EntryThreatActor.threat_actor_id == actor.id)
        )
    ).scalar()
    assert links == 1


async def test_manual_create_malware_by_alias_on_already_linked_entry(db_session, client, admin_headers, test_entry):
    """Same guard on the malware endpoint, which shared the unguarded insert."""
    malware = MalwareFamily(name="SnakeKeylogger", aliases=["404 Keylogger"])
    db_session.add(malware)
    await db_session.flush()
    db_session.add(EntryMalware(entry_id=test_entry.id, malware_family_id=malware.id, source="ai"))
    await db_session.flush()

    resp = await client.post(
        "/api/entities/malware",
        json={"name": "404 Keylogger", "entry_id": str(test_entry.id), "force": True},
        headers=admin_headers,
    )

    assert resp.status_code == 201
    assert resp.json()["id"] == str(malware.id)

    links = (
        await db_session.execute(
            select(func.count()).select_from(EntryMalware).where(EntryMalware.malware_family_id == malware.id)
        )
    ).scalar()
    assert links == 1
