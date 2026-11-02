"""Hardened entity resolution + creation/alias gates.

Phases 1–2 of planning/entity-creation-guardrails.md. Every automated entity
creation path (AI extraction stores, Cybergeist sync, CLI write tools) and the
manual UI route through :func:`resolve_entity_creation` before minting a
profile; the gates and normalized matching live here so all call sites inherit
them. Phase 3 (pending tier / one-pass resolution) hooks into the ``held``
decisions this module already emits — a held decision today logs an advisory
and (in shadow) still creates; Phase 3 turns those into ``pending_entities``
rows.

Flags (system_settings-overridable via ``settings.get``):

  entity_resolution_normalized_match  (bool, default on)
      Phase 1 matcher: normalized exact matching via entity_alias_index.
      Safe — it can only *prevent* duplicate creations.

  entity_creation_gates  ('off' | 'shadow' | 'on', default 'shadow')
      Phase 2 gates. shadow = log the would-block/would-hold decision to
      EntityMaintenanceLog and still create; on = enforce.

Every decision (matched / blocked / held / created / tombstone) is written to
EntityMaintenanceLog with a ``resolution_*`` action so the whole system is
auditable from the Hygiene/maintenance-log UI.

No fuzzy auto-merge, ever: descriptor-stripped and trigram matches only route
to a ``held`` advisory. Entities are never auto-renamed.
"""

import re
import unicodedata
import uuid
from dataclasses import dataclass, field

from sqlalchemy import func, or_, select
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.intelligence.entity_dedup import (
    find_entity_by_name_or_alias,
    find_reclassify_tombstone,
)
from app.models.entity_index import EntityAliasIndex, EntityNameDenylist, KnownAliasMap
from app.models.entity_maintenance import EntityMaintenanceLog
from app.models.malware_family import MALWARE_TYPES, MalwareFamily
from app.models.product import Product
from app.models.threat_actor import ThreatActor
from app.models.tool import TOOL_TYPES, Tool
from app.models.vendor import Vendor

# ENTITY_TYPE_REGISTRY slugs → model. Order matters for the cross-type check
# (actor/malware/tool are the contaminating trio; vendor/product close the loop).
RESOLVED_MODELS: dict[str, type] = {
    "threat_actor": ThreatActor,
    "malware": MalwareFamily,
    "tool": Tool,
    "vendor": Vendor,
    "product": Product,
}

# ---------------------------------------------------------------------------
# Normalization (Phase 1)
# ---------------------------------------------------------------------------

# Single canonical leetspeak direction (plan §3.1): 0→o 1→l 3→e 4→a 5→s 7→t $→s @→a.
_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

# Descriptor vocabularies, per entity type. Multi-word phrases are matched
# longest-first; stripping iterates both ends until stable.
_ACTOR_LEADING = ("the", "team", "group", "operation")
_ACTOR_TRAILING = (
    "ransomware group",
    "ransomware gang",
    "splinter group",
    "and associates",
    "threat group",
    "hacking group",
    "group",
    "team",
    "gang",
    "crew",
    "apt",
    "ransomware",
    "operators",
    "operation",
    "campaign",
    "syndicate",
    "collective",
    "project",
)
_MALWARE_TRAILING = (
    "ransomware",
    "malware",
    "trojan",
    "stealer",
    "infostealer",
    "botnet",
    "backdoor",
    "rat",
    "loader",
    "virus",
    "worm",
    "spyware",
    "wiper",
    "rootkit",
    "miner",
    "coinminer",
    "implant",
    "dropper",
    "keylogger",
    "webshell",
    "variant",
    "family",
    "payload",
)
_TOOL_TRAILING = ("tool", "framework", "kit", "suite", "utility", "script")

_TYPE_DESCRIPTORS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "threat_actor": (_ACTOR_LEADING, _ACTOR_TRAILING),
    "malware": ((), _MALWARE_TRAILING),
    "tool": ((), _TOOL_TRAILING),
}

_VERSION_TOKEN_RE = re.compile(r"^v?\d+(\.\d+)*$")
# Color/codename version tokens (LockBit Black/Green/Red, Mini Shai-Hulud):
# these only strip into a *candidate* form — the resolver uses it solely when
# the stem already exists, and candidate matches are never hard matches.
_CODENAME_TOKENS = frozenset({"black", "green", "red", "ng", "mini"})


def _fold(text: str) -> str:
    """lowercase → NFKC → leetspeak fold → strip non-alphanumerics.

    Must stay byte-identical to the SQL ``entity_norm`` function in
    app/models/entity_index.py (a test asserts this)."""
    t = unicodedata.normalize("NFKC", (text or "").lower()).lower()
    return _NON_ALNUM_RE.sub("", t.translate(_LEET_MAP))


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT_RE.split((text or "").lower()) if t]


def _strip_phrases(tokens: list[str], leading: tuple[str, ...], trailing: tuple[str, ...]) -> list[str]:
    """Strip descriptor words/phrases from both ends until stable, never
    consuming the whole name."""
    lead_phrases = sorted((p.split() for p in leading), key=len, reverse=True)
    trail_phrases = sorted((p.split() for p in trailing), key=len, reverse=True)
    changed = True
    while changed and tokens:
        changed = False
        for phrase in lead_phrases:
            n = len(phrase)
            if len(tokens) > n and tokens[:n] == phrase:
                tokens = tokens[n:]
                changed = True
                break
        for phrase in trail_phrases:
            n = len(phrase)
            if len(tokens) > n and tokens[-n:] == phrase:
                tokens = tokens[:-n]
                changed = True
                break
    return tokens


@dataclass(frozen=True)
class NormalizedName:
    norm_exact: str
    norm_stripped: str
    # Set only when a trailing/leading codename token (Black/Green/Red/NG/Mini)
    # was removable on top of norm_stripped; used as an extra *candidate* form.
    norm_codename_stripped: str | None = None


def normalize_entity_name(name: str, entity_type: str | None = None) -> NormalizedName:
    """Compute the hardened normal forms of an entity name.

    ``norm_exact`` (no descriptor/version stripping) is the hard-match key —
    it backs the DB ``normalized_name`` generated column and the alias index.
    ``norm_stripped`` additionally removes per-type descriptor words and
    trailing version tokens; a stripped-only match is a *candidate* (held for
    adjudication), never a hard match — Medusa≠MedusaLocker-class traps are
    why."""
    norm_exact = _fold(name)

    leading, trailing = _TYPE_DESCRIPTORS.get(entity_type or "", ((), ()))
    tokens = _strip_phrases(_tokens(name), leading, trailing)

    # Version-token strip (F8): trailing v-prefixed / dotted numbers, only
    # while the remaining stem stays ≥ 4 chars folded.
    while len(tokens) > 1 and _VERSION_TOKEN_RE.match(tokens[-1]) and len(_fold("".join(tokens[:-1]))) >= 4:
        tokens = tokens[:-1]

    norm_stripped = _fold(" ".join(tokens)) or norm_exact

    codename: str | None = None
    if len(tokens) > 1:
        if tokens[-1] in _CODENAME_TOKENS:
            stem = tokens[:-1]
        elif tokens[0] in _CODENAME_TOKENS:
            stem = tokens[1:]
        else:
            stem = None
        if stem:
            folded = _fold(" ".join(stem))
            if len(folded) >= 4:
                codename = folded

    return NormalizedName(norm_exact=norm_exact, norm_stripped=norm_stripped, norm_codename_stripped=codename)


# ---------------------------------------------------------------------------
# Generic-name gate patterns (Phase 2.1) — ported from the plan §2.1 / the
# tools-audit junk_reason() pattern set (scratchpad/build_tool_plan.py).
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.IGNORECASE)

# A CVE identifier names a vulnerability, and IntelFeed already has an entity
# type and an ingest pipeline for those. Minting a *second* row for the same id
# under another type is what breaks the autolinker: both rows enter the
# Aho-Corasick vocabulary, so every mention of the id links to the CVE and to
# the impostor, and the pair then correlates with itself forever. Malware may
# of course be *related* to a CVE — that belongs in entity_relationships.
#
# Anchored form catches "CVE-2026-55193" and "CVE-2026-55193 ransomware"; the
# unanchored form catches "Exploit for CVE-2026-55193". Both require digits
# after the prefix, so the real tools cve-search, cvemap and cve-bin-tool are
# unaffected.
_CVE_ID_RE = re.compile(r"^CVE-\d", re.IGNORECASE)
_CVE_IN_NAME_RE = re.compile(r"\bCVE[-_\s]?\d{4}-\d{3,}\b", re.IGNORECASE)


def cve_shaped_name(name: str) -> bool:
    """True when ``name`` is, or embeds, a CVE identifier.

    Shared by the generic-name gate, the always-enforced resolver block and the
    alias gate so the three can never drift apart.
    """
    stripped = (name or "").strip()
    return bool(_CVE_ID_RE.match(stripped) or _CVE_IN_NAME_RE.search(stripped))


_ACTOR_VAGUE_RE = re.compile(r"\b(unknown|unnamed|unidentified|unattributed|suspected|alleged)\b")
# Head noun with only nationality/qualifier adjectives before it.
_ACTOR_QUALIFIER = (
    r"(?:iranian|russian|chinese|north[- ]korean|dprk|israeli|ukrainian|indian|pakistani|turkish|"
    r"vietnamese|belarusian|pro[- ][a-z]+|state|nation[- ]state|government|foreign|multiple|various|"
    r"several|sophisticated|malicious|criminal|cyber|financially[- ]motivated|english[- ]speaking|"
    r"[a-z]+[- ](?:linked|aligned|affiliated|sponsored|backed|speaking|nexus))"
)
_ACTOR_HEAD_RE = re.compile(
    rf"^(?:{_ACTOR_QUALIFIER}[ -]+)*"
    r"(?:threat[ -]actors?|hackers?|attackers?|operators?|cyber[ -]?actors?|cyber[ -]?criminals?|"
    r"cybercriminals?|actors?|crews?|groups?|gangs?|adversar(?:y|ies)|hacktivists?|"
    r"ransomware[ -]groups?|apt[ -]groups?|insiders?)$"
)
_ACTOR_DESCRIPTOR_RE = re.compile(
    r"^(?:apt[ -]actors?|security[ -]researchers?|john[ -]doe|hackers?[- ]for[- ]hire|script[ -]kiddies)$"
)
# "the threat actor", "an attacker": the article is not part of the name, so it
# is dropped before the head-noun check — otherwise the determiner alone let
# the phrase through the gate.
_LEADING_ARTICLES = frozenset({"the", "a", "an", "this", "these", "those", "that"})

# Continents, regions and blocs. An article that says "targets North America"
# names a place, never an adversary, a family or a tool. Countries are gated
# separately against the country catalogue (``_country_named``), which knows
# every demonym and alias; this list covers what no country row holds.
_REGION_NAMES = frozenset(
    "north america|south america|central america|latin america|latam|the americas|americas|"
    "europe|western europe|eastern europe|central europe|northern europe|southern europe|european union|eu|"
    "asia|east asia|south asia|southeast asia|south east asia|central asia|west asia|asia pacific|apac|"
    "africa|north africa|west africa|east africa|southern africa|sub saharan africa|"
    "middle east|mena|gulf region|gulf|persian gulf|levant|"
    "oceania|australasia|pacific|pacific islands|caribbean|balkans|caucasus|nordics|scandinavia|benelux|"
    "baltics|emea|global|worldwide|international|nato|five eyes|g7|g20|brics|asean|arctic|antarctica".split("|")
)


def is_region_name(name: str) -> bool:
    """True when ``name`` is a continent, region or bloc rather than an entity."""
    toks = _tokens(name)
    while toks and toks[0] in _LEADING_ARTICLES:
        toks = toks[1:]
    return " ".join(toks) in _REGION_NAMES


_LANG_TOKENS = frozenset(
    "rust go golang python js javascript typescript java powershell ruby php perl lua swift "
    "dotnet net c cpp csharp vbs vbscript bash shell node assembly autoit delphi".split()
)
_MALWARE_GENERIC_TOKENS = (
    frozenset(
        "ransomware ransom stealer infostealer info malware wiper botnet bot trojan backdoor rat "
        "loader virus worm spyware rootkit bootkit miner coinminer cryptominer crypto implant "
        "dropper downloader keylogger webshell payload payloads exploit exploits kit package "
        "packages remote access banking mobile generic malicious lnk iso variant family sample "
        "samples threat based npm pypi vscode extension script scripts shellcode code stager "
        "agent framework toolkit tool tools attack campaign zero day windows linux macos android ios".split()
    )
    | _LANG_TOKENS
)

_FILENAME_RE = re.compile(
    r"\.(exe|dll|sys|app|bin|scr|ocx|js|ps1|vbs|php|aspx|asp|jsp|lua|txt|msi|pkg|py|bat|cmd|jar|"
    r"apk|dmg|hta|iso|img|vhd|lnk|docm?|xlsm?|zip|rar|7z|sh|elf|deb|rpm)$",
    re.IGNORECASE,
)
_AV_PREFIX_RE = re.compile(
    r"^(win32|win64|w32|w64|w97m|x97m|msil|js|vbs|html|hta|linux|osx|macos|android|elf|ransom|"
    r"trojan|troj|worm|backdoor|adware|riskware|hacktool|heur|pua|pup|mal|generic|gen)[./!:]",
    re.IGNORECASE,
)
_AV_TAXONOMY_RE = re.compile(r"^\S+[./!]\S+[./!]\S+$")  # ≥2 dotted segments, no spaces
_SANDBOX_ID_RE = re.compile(r"\.sbx(\.|$)", re.IGNORECASE)

# Tools-audit pattern set (F13) — ported verbatim from the audit script.
_CLI_FLAG_RE = re.compile(r"^--?\S")
_FUNC_CALL_RE = re.compile(r"[A-Za-z0-9_\]]\([^)]*\)")
_ACRONYM_PARENS_RE = re.compile(r"\s\([A-Z0-9/]{1,6}\)")
_SNAKE_CASE_RE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
_TECHNIQUE_PHRASES = frozenset(
    {
        "dll sideloading",
        "dll side-loading",
        "dll side loading",
        "prompt injection",
        "ntlm relay",
        "indicator removal on host",
        "indicator removal",
        "steganography",
        "evil twin attack",
        "clickfix",
        "process hollowing",
        "credential stuffing",
        "sim swapping",
    }
)
_PHYSICAL_OBJECT_RE = re.compile(
    r"\b(howitzer|missile|missiles|drone|drones|munition|munitions|artillery|rocket|uav|warhead|"
    r"loitering)\b|carrier board|variable frequency drive",
    re.IGNORECASE,
)

# --- Tool semantic gates (2026-09) -----------------------------------------
# The F13 pattern set above only rejects code-artifact *shapes*. It let eleven
# weeks of dependency names, vulnerable packages and API symbols through — see
# planning/tool-extraction-cleanup.md. A tool is software WIELDED during an
# intrusion; a library that is merely imported, shipped or exploited is not.
#
# These run after the resolver's exact/normalized matchers, so a known tool
# quoted with a version ("Cobalt Strike 4.9") has already resolved and never
# reaches them.

# Dependency / package coordinates: @scope/name, golang.org/x/..., biz44/id99-client.
# Requires a slash with no surrounding whitespace so product names that merely
# contain " / " ("Trend Micro Cloud One / Vision One") are untouched.
_PACKAGE_PATH_RE = re.compile(r"^@[\w.-]+/|^[\w.-]+(/[\w.@+-]+)+$")
# Single lowercase token starting lib* — libzypp, libde265, libvncclient.
_LIB_PREFIX_RE = re.compile(r"^lib[a-z0-9_+-]{2,}$")
# Ecosystem-prefixed distro/package names — python-jwcrypto, perl-XML-LibXML.
# 'go-' is deliberately absent: go-windapsearch and friends are real tools.
_ECOSYSTEM_PKG_RE = re.compile(r"^(python|perl|node|nodejs|ruby|php|npm|pypi|rubygem|golang)[-_][\w.+-]+$", re.I)
# Lowercase single token ending -client: nbd-client, id79-client.
_PKG_CLIENT_RE = re.compile(r"^[a-z0-9][a-z0-9.+_-]*-client$")
# Reverse-DNS Java/Android coordinates — org.apache.tomcat.dbcp...
_REVERSE_DNS_RE = re.compile(r"^(org|com|net|io|edu)\.[\w.]+$", re.IGNORECASE)
# C++/Rust scope operator — LogRule::matches.
_SCOPE_OP_RE = re.compile(r"\w::\w")
# Dotted API paths. Three-or-more segments (mlflow.pyfunc.load_model) or an
# all-lowercase pair (path.resolve, ipaddress.is_global). Filename extensions
# are excluded first by the caller, so certutil.exe never lands here.
_DOTTED_SYMBOL_RE = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*){2,}$")
_DOTTED_PAIR_RE = re.compile(r"^[a-z_]\w*\.[a-z_]\w*$")
# A whitespace-delimited version/build token: ".NET 9.0", "Info-ZIP Zip 3.0",
# "TOTOLINK T6 4.1.5cu.748_B20211015". A release string is a product, not a tool.
_VERSION_IN_NAME_RE = re.compile(r"(?:^|\s)v?\d+\.\d+[\w.]*(?:\s|$)")
# Source/script extensions that are always a file reference, never a tool
# identity. Binary extensions (.exe/.dll/.sys) are handled by the LOLBAS
# allowlist instead — the prompt explicitly permits abused signed binaries.
# `.js` is deliberately absent: too many real project names end in it
# (Node.js, Next.js, Vue.js). The evidence gate catches junk .js filenames.
_SCRIPT_FILE_RE = re.compile(r"\.(ps1|py|sh|go|rb|php|jsp|aspx?|bin|class|jar|pl|lua|vbs|bat|cmd|hta)$", re.I)
_BINARY_FILE_RE = re.compile(r"\.(exe|dll|sys|ocx|scr)$", re.IGNORECASE)

# Signed Windows binaries the prompt's LOLBAS carve-out is meant to admit.
# Anything else with a binary extension is a sideload target or crash artefact.
_LOLBAS_ALLOWLIST = frozenset(
    """
    at.exe atbroker.exe bash.exe bitsadmin.exe bginfo.exe cdb.exe certoc.exe certreq.exe certutil.exe
    charmap.exe cipher.exe cmd.exe cmdkey.exe cmstp.exe colorcpl.exe conhost.exe control.exe csc.exe
    cscript.exe datasvcutil.exe dfsvc.exe diantz.exe diskshadow.exe dnscmd.exe esentutl.exe eventvwr.exe
    expand.exe explorer.exe extexport.exe extrac32.exe findstr.exe finger.exe forfiles.exe ftp.exe
    gpscript.exe hh.exe ie4uinit.exe ieexec.exe iexpress.exe infdefaultinstall.exe installutil.exe
    jsc.exe makecab.exe mavinject.exe mmc.exe mofcomp.exe msbuild.exe msconfig.exe msdt.exe mshta.exe
    msiexec.exe msxsl.exe netsh.exe ntdsutil.exe odbcconf.exe pcalua.exe pcwrun.exe pnputil.exe
    presentationhost.exe print.exe psr.exe rasautou.exe reg.exe regasm.exe regedit.exe regini.exe
    regsvcs.exe regsvr32.exe replace.exe rpcping.exe rundll32.exe runonce.exe runscripthelper.exe
    sc.exe schtasks.exe scriptrunner.exe setres.exe sftp.exe ssh.exe syncappvpublishingserver.exe
    tar.exe ttdinject.exe tttracer.exe unregmp2.exe verclsid.exe wab.exe werfault.exe werfaultsecure.exe
    wmic.exe wscript.exe wsl.exe wsreset.exe wuauclt.exe xwizard.exe
    comsvcs.dll shell32.dll url.dll ieadvpack.dll advpack.dll pcwutl.dll setupapi.dll zipfldr.dll
    pubprn.vbs syncappvpublishingserver.vbs
    """.split()
)

# Script-named tools that really are the tool's identity. Impacket ships its
# suite as example scripts, and articles name them exactly this way — the
# controlled vocab comment cites "secretsdump" as the credential_access
# exemplar, so the file-artifact rule must not swallow them.
_SCRIPT_TOOL_ALLOWLIST = frozenset(
    """
    secretsdump.py psexec.py smbexec.py wmiexec.py atexec.py dcomexec.py smbclient.py mssqlclient.py
    ntlmrelayx.py getst.py getuserspns.py getnpusers.py gettgt.py goldenpac.py raisechild.py ticketer.py
    lookupsid.py rpcdump.py samrdump.py services.py addcomputer.py dpapi.py finddelegation.py
    secretsdump.exe mimikatz.py responder.py kerbrute.py certipy.py
    linpeas.sh winpeas.exe winpeas.bat linenum.sh pspy.sh lse.sh les.sh
    linux-exploit-suggester.sh linux-exploit-suggester-2.pl unix-privesc-check.sh mimipenguin.sh
    panix.sh lazyc2.py
    powerview.ps1 powerup.ps1 invoke-mimikatz.ps1 sharphound.ps1 nishang.ps1
    """.split()
)


# Concepts the model hands back as "tools": hash algorithms, vulnerability
# classes, protocols and generic words. None names software anyone wields,
# and once one is a tool row the autolinker tags it on every article that
# uses the word (SHA-256 and "Payload" sat on thousands of advisory entries).
# Never a tool for an automated source; the manual UI warns and can override.
TOOL_CONCEPT_NAMES = (
    # hashes, ciphers, encodings
    "SHA-1",
    "SHA-256",
    "SHA-512",
    "MD5",
    "AES",
    "Base64",
    # vulnerability and attack classes
    "SQL injection",
    "SQLi",
    "XSS",
    "Cross-site scripting",
    "CSRF",
    "SSRF",
    "RCE",
    "Remote code execution",
    "Command injection",
    "Buffer overflow",
    "Path traversal",
    "Directory traversal",
    "Use-after-free",
    "Deserialization",
    "Privilege escalation",
    # protocols, formats, interfaces
    "WebSocket",
    "HTTP",
    "HTTPS",
    "JSON",
    "XML",
    "API",
    "SPI",
    "DNS",
    "TLS",
    "SSL",
    # generic words
    "debug",
    "debugger",
    "payload",
    "payloads",
    "exploit",
    "shellcode",
    "backdoor",
    "script",
)
_TOOL_CONCEPT_NORMS = frozenset(normalize_entity_name(n, "tool").norm_exact for n in TOOL_CONCEPT_NAMES)

# Software that is legitimately both a product and a tool an intruder wields
# (remote-access, tunnelling and archive utilities). The product/vendor-name
# guard below lets these become tools; everything else already on file as a
# product or vendor stays one. Lowercased compare.
DUAL_USE_TOOL_NAMES = frozenset(
    {
        "metasploit",
        "anydesk",
        "autoit",
        "winrar",
        "wireguard",
        "openvpn",
        "fortigate",
        "forest druid",
        "ansible",
        "ngrok",
        "rclone",
        "tailscale",
        "netsupport manager",
    }
)


def is_tool_concept_name(name: str) -> bool:
    """True when ``name`` is a concept word that must never be a tool."""
    return normalize_entity_name(name or "", "tool").norm_exact in _TOOL_CONCEPT_NORMS


def _shared_junk_reason(name: str, norm: NormalizedName) -> str | None:
    if len(norm.norm_exact) < 3:
        return "too_short"
    if _UUID_RE.match(name.strip()) or _HASH_RE.match(name.strip()):
        return "uuid_or_hash"
    if name.strip().startswith("{{") or name.strip().endswith(("...", "…")) or "[.]" in name:
        return "placeholder_artifact"
    if cve_shaped_name(name):
        return "cve_id"
    return None


def _actor_junk_reason(name: str) -> str | None:
    toks = _tokens(name)
    while len(toks) > 1 and toks[0] in _LEADING_ARTICLES:
        toks = toks[1:]
    lowered = " ".join(toks)
    if _ACTOR_VAGUE_RE.search(lowered):
        return "vague_qualifier"
    if _ACTOR_HEAD_RE.match(lowered):
        return "generic_head_noun"
    if _ACTOR_DESCRIPTOR_RE.match(lowered):
        return "pure_descriptor"
    if _FILENAME_RE.search(name.strip()):
        return "filename"
    return None


def _malware_junk_reason(name: str) -> str | None:
    stripped = name.strip()
    if "/" in stripped or "\\" in stripped:
        if _AV_PREFIX_RE.match(stripped) or _FILENAME_RE.search(stripped):
            return "av_detection_string" if _AV_PREFIX_RE.match(stripped) else "filename"
        return "path_shape"
    if _FILENAME_RE.search(stripped):
        return "filename"
    if _AV_PREFIX_RE.match(stripped):
        return "av_detection_string"
    if " " not in stripped and (_AV_TAXONOMY_RE.match(stripped) or _SANDBOX_ID_RE.search(stripped)):
        return "av_detection_string"
    toks = _tokens(name)
    if toks and all(t in _MALWARE_GENERIC_TOKENS for t in toks):
        return "generic_type_phrase"
    return None


def _tool_junk_reason(name: str) -> str | None:
    stripped = name.strip()
    if _CLI_FLAG_RE.match(stripped):
        return "cli_flag"
    if _FUNC_CALL_RE.search(stripped) and not _ACRONYM_PARENS_RE.search(stripped):
        return "code_function_call"
    if _SNAKE_CASE_RE.match(stripped) and len(stripped) > 4:
        return "code_symbol"
    if _TECHNIQUE_ID_RE.match(stripped) or " ".join(_tokens(name)) in _TECHNIQUE_PHRASES:
        return "mitre_technique"
    if _PHYSICAL_OBJECT_RE.search(stripped):
        return "physical_object"
    if is_tool_concept_name(stripped):
        return "concept_term"

    # --- Semantic gates (2026-09). File shapes first: the extension checks
    # must win before the dotted-symbol rules, which would otherwise claim
    # "certutil.exe" as an API path.
    lowered = stripped.lower()
    if lowered in _LOLBAS_ALLOWLIST or lowered in _SCRIPT_TOOL_ALLOWLIST:
        return None
    if _BINARY_FILE_RE.search(stripped) or _SCRIPT_FILE_RE.search(stripped):
        return "file_artifact"
    if _PACKAGE_PATH_RE.search(stripped) or _REVERSE_DNS_RE.match(stripped):
        return "package_path"
    if _SCOPE_OP_RE.search(stripped) or _DOTTED_SYMBOL_RE.match(stripped) or _DOTTED_PAIR_RE.match(stripped):
        return "code_symbol"
    if _LIB_PREFIX_RE.match(stripped) or _ECOSYSTEM_PKG_RE.match(stripped) or _PKG_CLIENT_RE.match(stripped):
        return "package_name"
    if _VERSION_IN_NAME_RE.search(stripped):
        return "versioned_release"
    return None


_TYPE_JUNK_CHECKS = {
    "threat_actor": _actor_junk_reason,
    "malware": _malware_junk_reason,
    "tool": _tool_junk_reason,
}


def generic_name_reason(entity_type: str, name: str, norm: NormalizedName | None = None) -> str | None:
    """Return a junk-reason slug if ``name`` must never become an entity of
    ``entity_type``, else None. Pure function — DB denylist is checked
    separately by the resolver."""
    norm = norm or normalize_entity_name(name, entity_type)
    reason = _shared_junk_reason(name, norm)
    if reason:
        return reason
    if entity_type != "country" and is_region_name(name):
        return "region_name"
    check = _TYPE_JUNK_CHECKS.get(entity_type)
    return check(name) if check else None


async def _country_named(db: AsyncSession, name: str) -> str | None:
    """The catalogue country whose name or alias ``name`` is, else None. Used
    to keep "Iran" / "North Korea" / "Chinese" out of the actor, malware and
    tool catalogues: an article attributes to a country, it does not name one
    as the adversary."""
    from app.models.country import Country

    cleaned = (name or "").strip()
    if not cleaned:
        return None
    toks = _tokens(cleaned)
    while len(toks) > 1 and toks[0] in _LEADING_ARTICLES:
        toks = toks[1:]
    stripped = " ".join(toks)
    forms = {cleaned.lower(), stripped}
    # Aliases are stored as written ("Chinese", "PRC"); try the common casings.
    variants = {
        cleaned,
        cleaned.lower(),
        cleaned.upper(),
        cleaned.title(),
        stripped,
        stripped.title(),
        stripped.upper(),
    }
    return (
        await db.execute(
            select(Country.name)
            .where(or_(func.lower(Country.name).in_(sorted(forms)), Country.aliases.overlap(sorted(variants))))
            .limit(1)
        )
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Controlled type vocabularies (Phase 2.4, F12)
# ---------------------------------------------------------------------------

# Ordered coercion rules: first regex hit wins. Raw value is preserved by the
# caller in metadata_ when it doesn't round-trip.
_TOOL_TYPE_RULES: tuple[tuple[re.Pattern, str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), slug)
    for p, slug in (
        (r"\bc2\b|command.{0,6}control|post.?exploitation", "c2_framework"),
        (r"credential|password|secret|token theft|dump", "credential_access"),
        (r"lateral", "lateral_movement"),
        (r"recon|scan|enum|discovery|osint|fingerprint", "reconnaissance"),
        (r"exploit|vulnerab|fuzz|sql.?inject", "exploitation"),
        (r"persist", "persistence"),
        (r"edr.?(kill|bypass|evasion)|evasion|packer|crypter|obfusc|anti.?(av|detect)", "defense_evasion"),
        (r"lolb|living.?off", "lolbas"),
        (r"phish|smish|quish|aitm|adversary.?in.?the.?middle|2fa bypass", "phishing_kit"),
        (r"tunnel|proxy|vpn|socks|dns.?exfil", "tunneling"),
        (r"remote.?(access|management|monitoring|desktop)|rmm|\brat\b", "remote_access"),
        (r"llm|language model|\bai\b|artificial intelligence|chatbot|genai|generative|model|agent", "ai_model"),
        (
            r"antivirus|anti-virus|edr|xdr|siem|soar|firewall|defen[cs]|detection|dfir|forensic|honeypot|sandbox",
            "defensive",
        ),
        (r"monitor|observab|logging|telemetry|network analy", "observability"),
        (r"cloud|saas|kubernetes|container|docker|s3|azure|aws|gcp", "cloud"),
        (r"identity|sso|iam|mfa|authenticat|directory", "identity"),
        (r"framework|toolkit|suite", "framework"),
        (r"develop|compiler|ide\b|runtime|library|sdk|package manager|version control|repository|cli\b", "dev_tool"),
        (r"service|platform|marketplace|hosting|as.?a.?service", "service"),
        (
            r"software|application|app\b|utility|tool|program|browser|client|protocol|operating system|os\b|messenger",
            "software",
        ),
    )
)

_MALWARE_TYPE_RULES: tuple[tuple[re.Pattern, str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), slug)
    for p, slug in (
        (r"ransom|extortion|locker", "ransomware"),
        (r"steal|clipper|grabber", "stealer"),
        (r"banking|banker", "banking_trojan"),
        (r"loader", "loader"),
        (r"\brat\b|remote access", "rat"),
        (r"backdoor", "backdoor"),
        (r"botnet|\bbot\b|ddos", "botnet"),
        (r"worm|self.?propagat", "worm"),
        (r"wiper|destruct", "wiper"),
        (r"spyware|surveillance|stalkerware", "spyware"),
        (r"rootkit|bootkit", "rootkit"),
        (r"dropper", "dropper"),
        (r"downloader", "downloader"),
        (r"miner|mining|cryptojack", "miner"),
        (r"keylog", "keylogger"),
        (r"web.?shell", "webshell"),
        (r"exploit", "exploit_kit"),
        (r"phish", "phishing_kit"),
        (r"implant|beacon", "implant"),
        (r"adware|scareware|pup\b|pua\b", "adware"),
        (r"trojan", "trojan"),
    )
)


def _coerce_type(
    raw: str | None, vocab: list[str], rules: tuple[tuple[re.Pattern, str], ...]
) -> tuple[str | None, str | None]:
    """Coerce a free-text type to the controlled vocabulary.

    Returns (slug, raw_if_coerced): raw_if_coerced is None when the input was
    already a valid slug (or empty), otherwise the original string the caller
    should stash in metadata_ for audit."""
    if not raw or not raw.strip():
        return None, None
    cleaned = raw.strip()
    slugged = re.sub(r"[^a-z0-9]+", "_", cleaned.lower()).strip("_")
    if slugged in vocab:
        return slugged, None if slugged == cleaned else cleaned
    for pattern, slug in rules:
        if pattern.search(cleaned):
            return slug, cleaned
    return "other", cleaned


def coerce_tool_type(raw: str | None) -> tuple[str | None, str | None]:
    return _coerce_type(raw, TOOL_TYPES, _TOOL_TYPE_RULES)


def coerce_malware_type(raw: str | None) -> tuple[str | None, str | None]:
    return _coerce_type(raw, MALWARE_TYPES, _MALWARE_TYPE_RULES)


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------


def normalized_match_enabled() -> bool:
    val = settings.get("entity_resolution_normalized_match")
    return True if val is None else bool(val)


def gates_mode() -> str:
    """'off' | 'shadow' | 'on' (default shadow)."""
    val = str(settings.get("entity_creation_gates") or "shadow").lower()
    return val if val in {"off", "shadow", "on"} else "shadow"


# ---------------------------------------------------------------------------
# Decision + logging
# ---------------------------------------------------------------------------


@dataclass
class ResolutionDecision:
    """Outcome of a creation attempt.

    action:
      matched   — an existing entity resolved; ``entity`` is set. Link to it.
      tombstone — name was folded cross-type; ``tombstone`` carries the target.
      blocked   — a gate fired and is enforced. Do not create.
      held      — candidate match / cross-type hit, enforced. Do not create;
                  a maintenance-log advisory was written (Phase 3 turns these
                  into pending_entities rows). When the hold was an unambiguous
                  cross-type hit, ``link_target`` names the surviving entity of
                  the other type — callers holding an entry_id should link to it
                  (same handling as ``tombstone``) so suppressing the duplicate
                  profile doesn't also drop the mention.
      create    — no match, gates passed (or shadow-mode downgraded them).
                  Caller creates the entity.
    """

    action: str
    entity: object | None = None
    tombstone: object | None = None
    reason: str | None = None
    match_kind: str | None = None
    # held + cross_type_hit: (entity_type, entity_id) of the survivor to link to.
    link_target: tuple[str, uuid.UUID] | None = None
    # Shadow mode: the gate that *would* have fired (action stays 'create').
    shadow_reason: str | None = None
    detail: dict = field(default_factory=dict)


def _log(
    db: AsyncSession,
    *,
    entity_type: str,
    action: str,
    mode: str,
    applied: bool,
    entity_id: uuid.UUID | None = None,
    before: dict | None = None,
    after: dict | None = None,
    reasoning: str | None = None,
) -> None:
    db.add(
        EntityMaintenanceLog(
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            mode=mode,
            before=before,
            after=after,
            reasoning=reasoning,
            applied=applied,
        )
    )


def _decision_context(name: str, aliases: list[str] | None, source: str, entry_id: uuid.UUID | None) -> dict:
    return {
        "name": name,
        "aliases": aliases or [],
        "source": source,
        "entry_id": str(entry_id) if entry_id else None,
    }


async def _normalized_lookup(db: AsyncSession, entity_type: str, normalized: str) -> list[uuid.UUID]:
    if not normalized:
        return []
    rows = await db.execute(
        select(EntityAliasIndex.entity_id)
        .where(EntityAliasIndex.entity_type == entity_type, EntityAliasIndex.normalized == normalized)
        .distinct()
    )
    return list(rows.scalars().all())


_trgm_available: bool | None = None


async def _trgm_candidates(db: AsyncSession, entity_type: str, norm_exact: str, threshold: float = 0.85) -> list[dict]:
    """pg_trgm advisory candidates over the alias index.

    Returns [] when the extension is missing (checked once per process) so a
    failed similarity() call can't poison the caller's transaction."""
    global _trgm_available
    if len(norm_exact) < 6:
        return []
    if _trgm_available is None:
        _trgm_available = bool(
            (await db.execute(sa_text("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'"))).scalar()
        )
    if not _trgm_available:
        return []
    rows = await db.execute(
        sa_text(
            "SELECT DISTINCT entity_id, surface, similarity(normalized, :n) AS sim "
            "FROM entity_alias_index WHERE entity_type = :t AND similarity(normalized, :n) >= :th "
            "ORDER BY sim DESC LIMIT 3"
        ).bindparams(n=norm_exact, t=entity_type, th=threshold)
    )
    return [{"entity_id": str(r.entity_id), "surface": r.surface, "similarity": float(r.sim)} for r in rows]


async def upsert_known_aliases(db: AsyncSession, source: str, items: list[tuple[str, list[str]]]) -> int:
    """Full-replace refresh of the known_alias_map for one reference source.

    ``items`` is [(canonical_name, [synonyms...])]. The canonical name is also
    stored as its own alias row so lookups only need the alias column."""
    from sqlalchemy import delete as sa_delete

    await db.execute(sa_delete(KnownAliasMap).where(KnownAliasMap.source == source))
    seen: set[tuple[str, str]] = set()
    count = 0
    for canonical, aliases in items:
        nc = normalize_entity_name(canonical, "threat_actor").norm_exact
        if not nc:
            continue
        for alias in {canonical, *aliases}:
            na = normalize_entity_name(alias, "threat_actor").norm_exact
            if not na or (nc, na) in seen:
                continue
            seen.add((nc, na))
            db.add(
                KnownAliasMap(
                    canonical_name=canonical,
                    alias=alias,
                    normalized_canonical=nc,
                    normalized_alias=na,
                    source=source,
                )
            )
            count += 1
    await db.flush()
    return count


async def _known_alias_resolve(db: AsyncSession, entity_type: str, forms: set[str]):
    """Resolve via the reference alias knowledge (Phase 4).

    Expands the incoming forms to their full synonym cluster and looks the
    cluster up in the entity alias index. Returns the entity only on an
    unambiguous single hit; never writes anything."""
    forms = {f for f in forms if f}
    if not forms:
        return None
    rows = await db.execute(
        select(KnownAliasMap.normalized_canonical).where(KnownAliasMap.normalized_alias.in_(forms)).distinct()
    )
    canonicals = set(rows.scalars().all())
    # A name appearing in more than one synonym cluster is ambiguous by
    # definition (e.g. a codename two vendors reuse) — never hard-match it.
    if len(canonicals) != 1:
        return None
    rows = await db.execute(
        select(KnownAliasMap.normalized_alias).where(KnownAliasMap.normalized_canonical.in_(canonicals)).distinct()
    )
    cluster = set(rows.scalars().all()) | canonicals
    ids = await db.execute(
        select(EntityAliasIndex.entity_id)
        .where(EntityAliasIndex.entity_type == entity_type, EntityAliasIndex.normalized.in_(cluster))
        .distinct()
    )
    entity_ids = list(ids.scalars().all())
    if len(entity_ids) != 1:
        return None
    model = RESOLVED_MODELS[entity_type]
    return (await db.execute(select(model).where(model.id == entity_ids[0]))).scalar_one_or_none()


# Denylist rows an analyst wrote at runtime — by deleting an entity with "don't
# re-create it" ticked, or by adding a name to the list in Engine → Extract.
# Unlike the migration-seeded cleanup rows they are an explicit decision, so
# they are enforced regardless of the creation-gate mode.
DO_NOT_RECREATE_SOURCE = "do_not_recreate"

# Sentinel entity_type for a row that bans a name for every type at once —
# "not scoped to a particular entity type".
ANY_ENTITY_TYPE = "any"


async def is_name_denied(db: AsyncSession, entity_type: str, name: str) -> EntityNameDenylist | None:
    """Return the do-not-recreate row banning ``name`` for this type, if any.

    Rows stored under ``ANY_ENTITY_TYPE`` ban the name for every type at once.

    Used by the extraction paths that mint entities without going through
    ``resolve_entity_creation`` (CVEs, TTPs) so a deleted name stays deleted
    there too.
    """
    norm = normalize_entity_name(name, entity_type)
    forms = {norm.norm_exact, norm.norm_stripped}
    forms.discard("")
    if not forms:
        return None
    row = await db.execute(
        select(EntityNameDenylist).where(
            EntityNameDenylist.entity_type.in_((entity_type, ANY_ENTITY_TYPE)),
            EntityNameDenylist.active.is_(True),
            EntityNameDenylist.source == DO_NOT_RECREATE_SOURCE,
            EntityNameDenylist.normalized_name.in_(forms),
        )
    )
    return row.scalars().first()


# Entity types where the do-not-recreate list is actually enforced: the three
# that route through resolve_entity_creation, plus the two whose store paths
# check is_name_denied() directly. Denying a country or a vendor would write a
# row nothing consults, so the UI must not offer it.
DENIABLE_TYPES = ("threat_actor", "malware", "tool", "cve", "ttp")

# The column each type would be re-minted under (aliases are added on top for
# the name-keyed types).
_DENY_KEY = {"threat_actor": "name", "malware": "name", "tool": "name", "cve": "cve_id", "ttp": "technique_id"}


def deniable_names(entity_type: str, entity) -> list[str]:
    """Surface forms to ban for an entity being deleted — the key the pipeline
    would re-create it under, plus its aliases so it can't return under one."""
    names = [getattr(entity, _DENY_KEY.get(entity_type, "name"), None)]
    if entity_type in ("threat_actor", "malware", "tool"):
        names.extend(getattr(entity, "aliases", None) or [])
    return [n.strip() for n in names if isinstance(n, str) and n.strip()]


async def sync_name_list_setting(
    db: AsyncSession, key: str, *, add: list[str] | None = None, remove: list[str] | None = None
) -> bool:
    """Add/remove surface forms in a comma-separated name-list setting.

    Backs both autolink name lists: the curated ``autolinker_false_positive_names``
    vocabulary and the analyst-written ``autolinker_blocked_surface_forms`` block
    list. Returns whether the setting changed; the caller rebuilds the vocabulary
    after committing."""
    from app.services.system_settings import get_setting, update_settings

    current = str(await get_setting(key, db) or "")
    existing = {n.strip().lower() for n in current.split(",") if n.strip()}
    updated = (existing | {n.strip().lower() for n in add or [] if n.strip()}) - {
        n.strip().lower() for n in remove or []
    }
    if updated == existing:
        return False
    await update_settings(db, {key: ",".join(sorted(updated))})
    # update_settings() invalidates the process-local settings cache but doesn't
    # repopulate it — force that here or a rebuild would read the stale default.
    await get_setting(key, db)
    return True


async def sync_fp_names(db: AsyncSession, *, add: list[str] | None = None, remove: list[str] | None = None) -> bool:
    """Add/remove surface forms in ``autolinker_false_positive_names`` — the
    "False Positive Names" field in Engine → Autolink. Blocking creation isn't
    enough on its own: the name must also drop out of the autolinker vocabulary,
    and analysts expect to see (and be able to edit) it there."""
    return await sync_name_list_setting(db, "autolinker_false_positive_names", add=add, remove=remove)


async def deny_entity_names(db: AsyncSession, entity_type: str, names: list[str], *, reason: str) -> int:
    """Upsert do-not-recreate rows and mirror the names into the autolinker's
    false-positive list. Returns how many forms were written."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    written = 0
    for name in names:
        normalized = normalize_entity_name(name, entity_type).norm_exact
        if not normalized:
            continue
        stmt = pg_insert(EntityNameDenylist).values(
            entity_type=entity_type,
            normalized_name=normalized,
            display_name=name,
            reason=reason,
            source=DO_NOT_RECREATE_SOURCE,
            active=True,
        )
        await db.execute(
            stmt.on_conflict_do_update(
                constraint="uq_entity_name_denylist",
                set_={
                    "display_name": stmt.excluded.display_name,
                    "reason": stmt.excluded.reason,
                    "source": stmt.excluded.source,
                    "active": True,
                },
            )
        )
        written += 1
    if written:
        await sync_fp_names(db, add=names)
    return written


async def _denylist_hit(db: AsyncSession, entity_type: str, norm: NormalizedName) -> EntityNameDenylist | None:
    forms = {norm.norm_exact, norm.norm_stripped}
    forms.discard("")
    if not forms:
        return None
    row = await db.execute(
        select(EntityNameDenylist).where(
            EntityNameDenylist.entity_type.in_((entity_type, ANY_ENTITY_TYPE)),
            EntityNameDenylist.active.is_(True),
            EntityNameDenylist.normalized_name.in_(forms),
        )
    )
    return row.scalars().first()


async def _cross_type_hits(db: AsyncSession, entity_type: str, forms: set[str]) -> list[dict]:
    forms = {f for f in forms if f}
    if not forms:
        return []
    rows = await db.execute(
        select(EntityAliasIndex.entity_type, EntityAliasIndex.entity_id, EntityAliasIndex.surface)
        .where(EntityAliasIndex.entity_type != entity_type, EntityAliasIndex.normalized.in_(forms))
        .limit(5)
    )
    return [{"entity_type": r.entity_type, "entity_id": str(r.entity_id), "surface": r.surface} for r in rows]


async def resolve_entity_creation(
    db: AsyncSession,
    entity_type: str,
    name: str,
    incoming_aliases: list[str] | None = None,
    *,
    source: str = "ai",
    entry_id: uuid.UUID | None = None,
    override: bool = False,
    link_only: bool = False,
) -> ResolutionDecision:
    """Resolve an incoming entity name before creation. See ResolutionDecision.

    ``override=True`` is reserved for the manual UI's logged "create anyway" —
    it bypasses enforced gates (never the matchers) and writes a
    ``creation_override`` log row. Automated sources must not pass it.

    ``link_only=True`` runs every matcher (exact, normalized, known alias,
    tombstone, cross-type survivor) but never answers ``create``: where the
    name would have minted a new entity the decision is ``blocked`` with
    reason ``creation_disabled``. Used by a feed whose "create records for
    new tools" switch is off — existing tools still link.
    """
    model = RESOLVED_MODELS.get(entity_type)
    if model is None:
        return ResolutionDecision(action="create")

    name = (name or "").strip()
    if not name:
        return ResolutionDecision(action="blocked", reason="empty_name")

    ctx = _decision_context(name, incoming_aliases, source, entry_id)
    norm = normalize_entity_name(name, entity_type)

    # --- 1. Exact name/alias match (pre-existing behavior, cheapest) -------
    entity = await find_entity_by_name_or_alias(db, model, name, incoming_aliases)
    if entity is not None:
        _log(
            db,
            entity_type=entity_type,
            action="resolution_matched",
            mode="apply",
            applied=True,
            entity_id=entity.id,
            before=ctx,
            after={"match_kind": "exact", "matched_name": entity.name},
            reasoning=f"'{name}' resolved to existing {entity_type} '{entity.name}' (exact name/alias match)",
        )
        return ResolutionDecision(action="matched", entity=entity, match_kind="exact")

    # --- 2. Normalized hard match (Phase 1) --------------------------------
    if normalized_match_enabled():
        # Name first; incoming aliases only as fallback so a hallucinated
        # alias cannot shadow a strong name match (same rule as entity_dedup).
        matched_ids: list[uuid.UUID] = []
        matched_via = name
        matched_ids = await _normalized_lookup(db, entity_type, norm.norm_exact)
        if not matched_ids:
            for alias in incoming_aliases or []:
                alias_norm = normalize_entity_name(alias, entity_type).norm_exact
                matched_ids = await _normalized_lookup(db, entity_type, alias_norm)
                if matched_ids:
                    matched_via = alias
                    break
        if len(matched_ids) == 1:
            entity = (await db.execute(select(model).where(model.id == matched_ids[0]))).scalar_one_or_none()
            if entity is not None:
                _log(
                    db,
                    entity_type=entity_type,
                    action="resolution_matched",
                    mode="apply",
                    applied=True,
                    entity_id=entity.id,
                    before=ctx,
                    after={"match_kind": "normalized", "matched_name": entity.name, "via": matched_via},
                    reasoning=(
                        f"'{name}' resolved to existing {entity_type} '{entity.name}' "
                        f"(normalized match on '{matched_via}')"
                    ),
                )
                return ResolutionDecision(action="matched", entity=entity, match_kind="normalized")
        elif len(matched_ids) > 1:
            # .NET vs Net class: one normalized form, several legit entities.
            # Never guess — treat as a candidate situation below.
            ctx["ambiguous_ids"] = [str(i) for i in matched_ids]

    # --- 2b. Reference alias knowledge (Phase 4) ---------------------------
    # MISP Galaxy / ATT&CK synonym clusters: "Secret Blizzard" resolves to the
    # stored Turla profile even with zero string overlap. Unambiguous single
    # hits only; never writes aliases. Actor knowledge only for now.
    if normalized_match_enabled() and entity_type == "threat_actor" and "ambiguous_ids" not in ctx:
        forms = {norm.norm_exact} | {normalize_entity_name(a, entity_type).norm_exact for a in incoming_aliases or []}
        entity = await _known_alias_resolve(db, entity_type, forms)
        if entity is not None:
            _log(
                db,
                entity_type=entity_type,
                action="resolution_matched",
                mode="apply",
                applied=True,
                entity_id=entity.id,
                before=ctx,
                after={"match_kind": "known_alias", "matched_name": entity.name},
                reasoning=(
                    f"'{name}' resolved to existing {entity_type} '{entity.name}' "
                    f"(known synonym cluster from reference alias map)"
                ),
            )
            return ResolutionDecision(action="matched", entity=entity, match_kind="known_alias")

    # --- 3. Cross-type tombstone (pre-existing guard) ----------------------
    tombstone = await find_reclassify_tombstone(db, entity_type, name, incoming_aliases)
    if tombstone is not None:
        _log(
            db,
            entity_type=entity_type,
            action="resolution_tombstone",
            mode="apply",
            applied=True,
            entity_id=tombstone.target_id,
            before=ctx,
            after={"target_type": tombstone.target_type, "target_id": str(tombstone.target_id)},
            reasoning=f"'{name}' was reclassified out of {entity_type}; linking to survivor",
        )
        return ResolutionDecision(action="tombstone", tombstone=tombstone)

    # --- 3b. Pre-existing junk guard — always enforced for automated sources
    # (predates the gate flags; shadow mode must not weaken it). Manual UI
    # never had this guard, so for it fp names flow through the gates below
    # (warn + logged override) instead of a hard block.
    if source != "manual" and entity_type in ("threat_actor", "malware"):
        from app.intelligence.autolinker import is_fp_entity_name

        if is_fp_entity_name(name):
            _log(
                db,
                entity_type=entity_type,
                action="resolution_blocked",
                mode="apply",
                applied=True,
                before=ctx,
                after={"reason": "fp_name"},
                reasoning=f"blocked creation of {entity_type} '{name}': fp_name (system-binary/FP name list)",
            )
            return ResolutionDecision(action="blocked", reason="fp_name")

    # --- 3c. Analyst do-not-recreate list ----------------------------------
    # An analyst deleting the entity is an explicit decision, so (like 3b) it
    # holds even with the heuristic gates off or in shadow. The manual UI still
    # routes through the gates below, where it can warn and override.
    if source != "manual":
        denied = await is_name_denied(db, entity_type, name)
        if denied is not None:
            _log(
                db,
                entity_type=entity_type,
                action="resolution_blocked",
                mode="apply",
                applied=True,
                before=ctx,
                after={"reason": "denylist_do_not_recreate", "denylist_name": denied.display_name},
                reasoning=(
                    f"blocked creation of {entity_type} '{name}': on the analyst "
                    f"do-not-recreate list (as '{denied.display_name}')"
                ),
            )
            return ResolutionDecision(action="blocked", reason="denylist_do_not_recreate")

    # --- 3d. CVE identifier as a name --------------------------------------
    # "CVE-2026-55193" is a vulnerability id. IntelFeed tracks those as CVE
    # entities with their own ingest pipeline, so a second row for the same id
    # under another type is never right — it duplicates the entity and puts the
    # id in the autolinker vocabulary twice. The extraction prompt already
    # forbids it ("DO NOT: extract CVE IDs as malware"), so a name in this shape
    # is a model mistake with no legitimate reading. Like 3b and 3c it is
    # therefore enforced even with the heuristic gates off or in shadow.
    #
    # Nothing is lost: the id still reaches the entry through the `cves`
    # extraction array and the autolinker's CVE pass, and a genuine malware↔CVE
    # connection belongs in entity_relationships. The manual UI still routes
    # through the gates below, where an analyst sees the warning and can
    # override.
    if source != "manual" and cve_shaped_name(name):
        _log(
            db,
            entity_type=entity_type,
            action="resolution_blocked",
            mode="apply",
            applied=True,
            before=ctx,
            after={"reason": "generic_name:cve_id"},
            reasoning=(
                f"blocked creation of {entity_type} '{name}': the name is a CVE identifier, "
                f"which belongs to the CVE entity type"
            ),
        )
        return ResolutionDecision(action="blocked", reason="generic_name:cve_id")

    # --- 3e. Tool names that belong to another catalog --------------------
    # A concept word (SHA-256, SQL injection, payload) is never a tool, and a
    # name already on file as a product or vendor (Linux, Chrome, Kubernetes)
    # is that product or vendor: advisory text names it as affected software,
    # and a tool row holding the same string makes the autolinker tag it twice
    # on every article. Enforced for automated sources whatever the gate mode;
    # the manual UI goes through the gates below (concept_term /
    # cross_type_hit), where an analyst can override.
    if source != "manual" and entity_type == "tool":
        if is_tool_concept_name(name):
            _log(
                db,
                entity_type=entity_type,
                action="resolution_blocked",
                mode="apply",
                applied=True,
                before=ctx,
                after={"reason": "generic_name:concept_term"},
                reasoning=f"blocked creation of tool '{name}': a concept, not software anyone wields",
            )
            return ResolutionDecision(action="blocked", reason="generic_name:concept_term")
        if name.lower() not in DUAL_USE_TOOL_NAMES and len(norm.norm_exact) >= 3:
            owners = (
                await db.execute(
                    select(EntityAliasIndex.entity_type, EntityAliasIndex.entity_id)
                    .where(
                        EntityAliasIndex.entity_type.in_(("product", "vendor")),
                        EntityAliasIndex.normalized == norm.norm_exact,
                    )
                    .distinct()
                )
            ).all()
            if owners:
                # Products first: "Chrome" as both a product and a vendor alias
                # is the product.
                owners.sort(key=lambda o: o.entity_type != "product")
                survivor = (owners[0].entity_type, owners[0].entity_id)
                _log(
                    db,
                    entity_type=entity_type,
                    action="resolution_held",
                    mode="apply",
                    applied=True,
                    before=ctx,
                    after={
                        "reason": "product_or_vendor_name",
                        "owners": [{"entity_type": o.entity_type, "entity_id": str(o.entity_id)} for o in owners],
                    },
                    reasoning=(
                        f"held creation of tool '{name}': already on file as a {survivor[0]}; linking to it instead"
                    ),
                )
                return ResolutionDecision(action="held", reason="product_or_vendor_name", link_target=survivor)

    # --- 4. Creation gates (Phase 2) ---------------------------------------
    mode = gates_mode()
    gate_reason: str | None = None
    gate_detail: dict = {}
    gate_action = "blocked"
    link_target: tuple[str, uuid.UUID] | None = None

    if mode != "off":
        deny = await _denylist_hit(db, entity_type, norm)
        if deny is not None:
            gate_reason = "denylist"
            gate_detail = {"denylist_name": deny.display_name, "denylist_reason": deny.reason}
        if gate_reason is None:
            junk = generic_name_reason(entity_type, name, norm)
            if junk:
                gate_reason = f"generic_name:{junk}"
        if gate_reason is None and entity_type in ("threat_actor", "malware"):
            from app.intelligence.autolinker import is_fp_entity_name

            if is_fp_entity_name(name):
                gate_reason = "fp_name"
        if gate_reason is None and entity_type in ("threat_actor", "malware", "tool"):
            country = await _country_named(db, name)
            if country:
                gate_reason = "country_name"
                gate_detail = {"country": country}
        if gate_reason is None:
            hits = await _cross_type_hits(
                db,
                entity_type,
                {norm.norm_exact} | {normalize_entity_name(a, entity_type).norm_exact for a in incoming_aliases or []},
            )
            if hits:
                gate_reason = "cross_type_hit"
                gate_detail = {"cross_type_candidates": hits}
                gate_action = "held"
                # Suppressing the duplicate profile must not also drop the
                # mention: when every hit is the same entity, hand the caller a
                # survivor to link the entry to (mirrors the tombstone branch).
                targets = {(h["entity_type"], h["entity_id"]) for h in hits}
                if len(targets) == 1:
                    t_type, t_id = targets.pop()
                    link_target = (t_type, uuid.UUID(t_id))

    # --- 5. Candidate (stripped / fuzzy) matches — held, never hard --------
    if mode != "off" and gate_reason is None:
        candidates: list[dict] = []
        for kind, form in (
            ("stripped_match", norm.norm_stripped if norm.norm_stripped != norm.norm_exact else ""),
            ("stripped_match", norm.norm_codename_stripped or ""),
        ):
            for eid in await _normalized_lookup(db, entity_type, form):
                candidates.append({"entity_id": str(eid), "kind": kind, "via": form})
        if ctx.get("ambiguous_ids"):
            candidates.extend({"entity_id": i, "kind": "ambiguous_normalized"} for i in ctx["ambiguous_ids"])
        if not candidates:
            for c in await _trgm_candidates(db, entity_type, norm.norm_exact):
                candidates.append({**c, "kind": "fuzzy_match"})
        if candidates:
            gate_reason = candidates[0]["kind"]
            gate_detail = {"candidates": candidates}
            gate_action = "held"

    # --- 4b. Link-only callers stop here ----------------------------------
    # An enforced hold with a survivor still links; anything that would have
    # gone on to create (clear, or a shadow-mode gate) does not.
    if link_only and (gate_reason is None or mode == "shadow"):
        _log(
            db,
            entity_type=entity_type,
            action="resolution_blocked",
            mode="apply",
            applied=True,
            before=ctx,
            after={"reason": "creation_disabled"},
            reasoning=f"'{name}' matched no existing {entity_type}, and creating one is switched off for this source",
        )
        return ResolutionDecision(action="blocked", reason="creation_disabled")

    if gate_reason is not None:
        if override:
            _log(
                db,
                entity_type=entity_type,
                action="creation_override",
                mode="apply",
                applied=True,
                before=ctx,
                after={"reason": gate_reason, **gate_detail},
                reasoning=f"Manual 'create anyway' override for '{name}' (gate: {gate_reason})",
            )
            return ResolutionDecision(action="create", shadow_reason=gate_reason, detail=gate_detail)
        if mode == "shadow":
            _log(
                db,
                entity_type=entity_type,
                action=f"resolution_{gate_action}",
                mode="shadow",
                applied=False,
                before=ctx,
                after={"reason": gate_reason, **gate_detail},
                reasoning=f"[shadow] would {gate_action} creation of {entity_type} '{name}': {gate_reason}",
            )
            return ResolutionDecision(action="create", shadow_reason=gate_reason, detail=gate_detail)
        _log(
            db,
            entity_type=entity_type,
            action=f"resolution_{gate_action}",
            mode="apply",
            applied=True,
            before=ctx,
            after={"reason": gate_reason, **gate_detail},
            reasoning=f"{gate_action} creation of {entity_type} '{name}': {gate_reason}",
        )
        return ResolutionDecision(
            action=gate_action,
            reason=gate_reason,
            detail=gate_detail,
            link_target=link_target if gate_action == "held" else None,
        )

    # --- 6. Clear to create -------------------------------------------------
    _log(
        db,
        entity_type=entity_type,
        action="resolution_created",
        mode="apply",
        applied=True,
        before=ctx,
        after={"norm_exact": norm.norm_exact, "norm_stripped": norm.norm_stripped},
        reasoning=f"No existing {entity_type} matched '{name}'; creation allowed",
    )
    return ResolutionDecision(action="create")


# ---------------------------------------------------------------------------
# Alias quality gate (Phase 2.2)
# ---------------------------------------------------------------------------

_MAX_ALIAS_TOKENS = 6


async def _is_country_name(db: AsyncSession, normalized: str) -> bool:
    from app.models.country import Country

    row = await db.execute(
        select(Country.id).where(
            sa_text(
                "entity_norm(name) = :n OR EXISTS (SELECT 1 FROM unnest(aliases) a WHERE entity_norm(a) = :n)"
            ).bindparams(n=normalized)
        )
    )
    return row.scalars().first() is not None


async def _is_sector_name(db: AsyncSession, normalized: str) -> bool:
    """A sector name or alias ("Healthcare", "banks") is never a new actor or malware."""
    from app.models.sector import Sector

    row = await db.execute(
        select(Sector.id).where(
            sa_text(
                "entity_norm(name) = :n OR entity_norm(slug) = :n "
                "OR EXISTS (SELECT 1 FROM unnest(aliases) a WHERE entity_norm(a) = :n)"
            ).bindparams(n=normalized)
        )
    )
    return row.scalars().first() is not None


async def gate_aliases(
    db: AsyncSession,
    entity_type: str,
    canonical_name: str,
    aliases: list[str] | None,
    *,
    entity_id: uuid.UUID | None = None,
    source: str = "ai",
) -> list[str]:
    """Filter incoming aliases through the quality gate. Returns the survivors.

    Rejections are logged (``alias_rejected``); cross-entity collisions —
    an alias already owned by a *different* same-type entity — additionally
    write ``alias_conflict`` rows for the Hygiene tab (the Qilin↔ShinyHunters
    rule). In shadow mode rejections still log but aliases pass through, except
    collisions, which are always dropped: writing a contested alias is what
    caused the contamination this plan exists to stop.
    """
    from app.intelligence.autolinker import is_common_english_word, is_junk_alias

    if not aliases:
        return []

    mode = gates_mode()
    kept: list[str] = []
    for alias in aliases:
        form = (alias or "").strip()
        if not form:
            continue
        norm = normalize_entity_name(form, entity_type)
        reason: str | None = None

        # is_junk_alias is the pre-existing, always-enforced filter (min
        # length, FP name list, duplicate of own name) — dropping these does
        # not follow gate mode, or shadow would regress current behavior.
        if is_junk_alias(form, canonical_name):
            continue

        # A CVE id is never an alias either, and here shadow mode is actively
        # harmful: a passed-through alias enters the autolinker vocabulary, so
        # every mention of that id would link to this entity *as well as* to the
        # CVE. "Spring4Shell" really is CVE-2022-22965, but recording that as an
        # alias is what produces the duplicate link — the connection belongs in
        # entity_relationships. Dropped regardless of gate mode, like the
        # collision cases below.
        if cve_shaped_name(form):
            _log(
                db,
                entity_type=entity_type,
                action="alias_rejected",
                mode="apply",
                applied=True,
                entity_id=entity_id,
                before={"entity": canonical_name, "alias": form, "source": source},
                after={"reason": "cve_id"},
                reasoning=(
                    f"Alias '{form}' for {entity_type} '{canonical_name}' is a CVE identifier — "
                    f"not written (belongs in entity_relationships, not the alias list)"
                ),
            )
            continue

        if len(_tokens(form)) > _MAX_ALIAS_TOKENS:
            reason = "too_many_tokens"
        elif generic_name_reason(entity_type, form, norm):
            reason = f"generic:{generic_name_reason(entity_type, form, norm)}"
        elif " " not in form and is_common_english_word(form):
            reason = "dictionary_word"
        elif await _is_country_name(db, norm.norm_exact):
            reason = "country_name"
        elif await _is_sector_name(db, norm.norm_exact):
            reason = "sector_name"

        if reason is None:
            owners = await db.execute(
                select(EntityAliasIndex.entity_id, EntityAliasIndex.surface)
                .where(
                    EntityAliasIndex.entity_type == entity_type,
                    EntityAliasIndex.normalized == norm.norm_exact,
                )
                .limit(5)
            )
            conflicts = [r for r in owners if entity_id is None or r.entity_id != entity_id]
            already_own = entity_id is not None and any(r.entity_id == entity_id for r in owners)
            if conflicts:
                _log(
                    db,
                    entity_type=entity_type,
                    action="alias_conflict",
                    mode="apply",
                    applied=True,
                    entity_id=entity_id,
                    before={"entity": canonical_name, "alias": form, "source": source},
                    after={"owners": [{"entity_id": str(r.entity_id), "surface": r.surface} for r in conflicts]},
                    reasoning=(
                        f"Alias '{form}' for {entity_type} '{canonical_name}' already belongs to another "
                        f"entity — not written (cross-entity collision)"
                    ),
                )
                continue  # collisions are dropped even in shadow
            if already_own:
                continue  # duplicate of a form the entity already carries

            # Cross-type: an alias that is another type's *canonical* name is
            # how "Agrius" (the group) ended up on DEADWOOD (its wiper). The two
            # are genuinely different entities, so the autolinker then links
            # every mention to both and they correlate with themselves forever.
            # That relationship belongs in entity_relationships, not an alias.
            # Dropped regardless of gate mode, like same-type collisions.
            owner = (
                await db.execute(
                    select(EntityAliasIndex.entity_type, EntityAliasIndex.entity_id, EntityAliasIndex.surface)
                    .where(
                        EntityAliasIndex.entity_type != entity_type,
                        EntityAliasIndex.normalized == norm.norm_exact,
                        EntityAliasIndex.is_name.is_(True),
                    )
                    .limit(1)
                )
            ).first()
            if owner is not None:
                _log(
                    db,
                    entity_type=entity_type,
                    action="alias_conflict",
                    mode="apply",
                    applied=True,
                    entity_id=entity_id,
                    before={"entity": canonical_name, "alias": form, "source": source},
                    after={
                        "cross_type_owner": {
                            "entity_type": owner.entity_type,
                            "entity_id": str(owner.entity_id),
                            "surface": owner.surface,
                        }
                    },
                    reasoning=(
                        f"Alias '{form}' for {entity_type} '{canonical_name}' is the canonical name of "
                        f"{owner.entity_type} '{owner.surface}' — not written (cross-type collision)"
                    ),
                )
                continue

            kept.append(form)
            continue

        _log(
            db,
            entity_type=entity_type,
            action="alias_rejected",
            mode=mode if mode != "off" else "shadow",
            applied=mode == "on",
            entity_id=entity_id,
            before={"entity": canonical_name, "alias": form, "source": source},
            after={"reason": reason},
            reasoning=f"Alias '{form}' for '{canonical_name}' rejected: {reason}",
        )
        if mode != "on":
            kept.append(form)

    return kept


# ---------------------------------------------------------------------------
# Enrichment topical guard (Phase 2.5, F11)
# ---------------------------------------------------------------------------

_ENRICH_DISAMBIG_RE = re.compile(r"may (also )?refer to\b|most commonly refers to\b", re.IGNORECASE)
_ENRICH_YEAR_RE = re.compile(
    r"\b(was|is) a (common |leap )?year\b|^\W*(year\s+)?\d{1,4}\s*\((?:[A-Z]+\)|.{0,20}calendar)",
    re.IGNORECASE,
)
_ENRICH_GEO_RE = re.compile(
    r"\bis an? (city|town|village|municipality|commune|hamlet|river|lake|mountain|valley|region|"
    r"district|province|county|department|prefecture|island|archipelago|suburb)\b",
    re.IGNORECASE,
)
_ENRICH_BIO_RE = re.compile(r"\(born \d{4}\)|\(\d{4}\s*[–—-]\s*\d{4}\)", re.IGNORECASE)
_CYBER_CONTEXT_RE = re.compile(
    r"\b(cyber|hacker|hacking|malware|ransomware|security|threat|espionage|botnet|phishing|"
    r"vulnerabilit|exploit|breach|apt\b|infosec|penetration)\w*",
    re.IGNORECASE,
)


def enrichment_content_ok(entity_name: str, content: str | None) -> tuple[bool, str | None]:
    """Cheap relevance check before persisting external-lookup content onto an
    entity profile. Returns (ok, reject_reason).

    A wrong description is worse than none — it anchors every later AI
    resolution to the wrong identity (the actor-764 / Wikipedia-year-764
    problem)."""
    if not content or not content.strip():
        return False, "empty"
    first_para = next((c.strip() for c in content.split("\n\n") if c.strip() and not c.strip().startswith("#")), "")
    if _ENRICH_DISAMBIG_RE.search(first_para):
        return False, "disambiguation_page"
    if _ENRICH_YEAR_RE.search(first_para):
        return False, "calendar_year"
    if _ENRICH_GEO_RE.search(first_para) and not _CYBER_CONTEXT_RE.search(content):
        return False, "geography"
    if _ENRICH_BIO_RE.search(first_para) and not _CYBER_CONTEXT_RE.search(content):
        return False, "person_bio_no_cyber_context"
    return True, None


def log_enrichment_reject(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID | None,
    entity_name: str,
    reason: str,
    *,
    source: str = "wikipedia",
    detail: str | None = None,
) -> None:
    """Record a topical-guard rejection so a human can pick the right source."""
    _log(
        db,
        entity_type=entity_type,
        action="enrichment_rejected",
        mode="apply",
        applied=True,
        entity_id=entity_id,
        before={"entity": entity_name, "source": source},
        after={"reason": reason, "detail": detail},
        reasoning=f"{source} content for '{entity_name}' rejected by topical guard: {reason}",
    )
