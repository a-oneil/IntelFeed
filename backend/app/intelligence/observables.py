"""The observables engine: refang, candidate scan, classification, sightings.

The contract (see models/observable.py): **nothing in this module creates an
observable from a regex match.** ``scan_candidates`` writes entry-local
nominations only; rows are created by the judgment doors (analysis AI, curated
ioc_list feeds, rule bodies, TTP observables, analysts) through
``get_or_create_observable``. The one regex-adjacent write path is
``sight_known_values``, which exact-matches candidates against values a door
already created — sighting a known-bad string is precise; discovering strings
by regex is what killed IOC v1.

Candidate policy is precision-first by construction:

- hashes and public IPs are always candidates (unambiguous, octet-validated,
  reserved/benign ranges gated out);
- domains, URLs and emails become candidates only when the author defanged
  them (``evil[.]com``, ``hxxps://``) — an author who defangs is telling you
  it's an indicator, so ``microsoft.com`` in prose never nominates anything;
- host artifacts are never regex candidates at all — they arrive through the
  TTP observable door or an analyst.
"""

import hashlib
import ipaddress
import re
import uuid as uuid_mod
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from sqlalchemy import case, func, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.observable import (
    ALL_KINDS,
    DECAY_HALF_LIFE_DAYS,
    HASH_KINDS,
    ROLES,
    SCRIPT_KIND,
    STATUS_ACTIVE,
    STATUS_AGING,
    STATUS_EXPIRED,
    VIA_MANUAL,
    EntryObservable,
    Observable,
)

# ---------------------------------------------------------------------------
# Refanging
# ---------------------------------------------------------------------------

_REFANG_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bhxxp(s?)\b", re.IGNORECASE), r"http\1"),
    (re.compile(r"\bh..p(s?)://", re.IGNORECASE), r"http\1://"),
    # Markdown-escaped brackets ("evil\[.\]com") are how a CMS renders an
    # author's [.] — same meaning.
    (re.compile(r"\\?\[(\.|dot)\\?\]|\((\.|dot)\)|\{(\.|dot)\}", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\[://\]"), lambda m: ":" if m.group(0) == "[:]" else "://"),
    (re.compile(r"\[@\]|\(@\)| ?\bat\b ?(?=\S+\[\.\])", re.IGNORECASE), "@"),
]

#: Anything that marks a token as author-defanged.
_DEFANG_MARKER = re.compile(r"hxxp|\\?\[\.\\?\]|\(\.\)|\[dot\]|\(dot\)|\[:\]|\[@\]|\[://\]", re.IGNORECASE)


def refang(text: str) -> str:
    """Normalize defanged notation back to the real value."""
    out = text
    for pattern, repl in _REFANG_RULES:
        out = pattern.sub(repl, out)
    return out


def is_defanged(token: str) -> bool:
    return bool(_DEFANG_MARKER.search(token))


#: Kinds where defanging means anything; everything else shares verbatim.
_DEFANGABLE_KINDS = frozenset({"ipv4", "ipv6", "domain", "url", "email"})


def defang(kind: str, value: str) -> str:
    """Neuter a network value the way analysts share it (mirror of the
    frontend's utils/observables.ts). Non-network kinds — hashes, cmdlines,
    registry keys — pass through untouched."""
    if kind not in _DEFANGABLE_KINDS:
        return value
    v = re.sub(r"(?i)^http", "hxxp", value).replace(".", "[.]")
    if kind == "email":
        v = v.replace("@", "[@]")
    return v


# ---------------------------------------------------------------------------
# Classification (used by candidates, ioc_list parsing and manual create)
# ---------------------------------------------------------------------------

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\d.]){_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}(?![\d.])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]{0,8}(?![0-9a-fA-F:])")
HASH_RE = re.compile(r"(?<![a-fA-F0-9])(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![a-fA-F0-9])")
DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}(?![\w-])", re.IGNORECASE
)
URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]]+", re.IGNORECASE)
#: Full-token URL check (classify/validate): parens and brackets are legal in
#: real payload URLs ("/path(1).exe"); the stricter URL_RE stays for prose
#: scanning, where a trailing ")" usually closes the sentence, not the URL.
URL_FULL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(
    r"(?<![\w.-])[\w.+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])", re.IGNORECASE
)

#: Resolver/documentation/broadcast values nobody means as an indicator.
_BENIGN_IPS = frozenset(
    {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"}
)
#: Documentation/testing domains, plus schema-ish suffixes that regex-match a
#: domain but never name infrastructure.
_BENIGN_DOMAIN_SUFFIXES = ("example.com", "example.net", "example.org", "example", "localhost", "w3.org", "schema.org")
#: Placeholder names writers use for "some domain" — never infrastructure.
_PLACEHOLDER_DOMAINS = frozenset(
    {
        "third-party.com",
        "attacker.com",
        "evil.com",
        "malicious.com",
        "victim.com",
        "company.com",
        "yourcompany.com",
        "yourdomain.com",
        "domain.com",
        "test.com",
        "contoso.com",
        "fabrikam.com",
        "acme.com",
        "foo.com",
        "bar.com",
        "site.com",
        "website.com",
        "phishing.com",
        "legit.com",
        "badguy.com",
        "c2.com",
        "malware.com",
        "target.com",
        "internal.com",
        "corp.com",
        "mycompany.com",
        "vendor.com",
        "customer.com",
    }
)
#: A real TLD never starts with a common TLD followed by more letters — that
#: shape is two table cells glued together ("pobelstudio.comdomain",
#: "info@nuf.co.jpsender") by an HTML renderer that dropped the cell boundary.
_GLUED_TLD_RE = re.compile(
    r"^(?:com|net|org|info|biz|io|co|us|uk|ru|cn|de|fr|xyz|top|live|app|dev|cloud|site|online|store|tech|club"
    r"|shop|edu|gov|mil|int|me|tv|cc|ws|pw|su|in|br|jp|kr|au|ca|eu|nl|se|ch|it|es|pl|ir|tr|vn|id|mx|ar|za|ng)"
    r"[a-z0-9]{2,}$"
)
#: Reference and shared-service hosts an article links *about* an indicator
#: (sandbox reports, catalogs, vendor docs, social) or that malware merely
#: uses (IP-echo, messaging APIs). Candidate-tier veto for bare domains and
#: URLs; the AI door and the analyst can still promote a real abuse.
_REFERENCE_HOSTS = frozenset(
    {
        "api.telegram.org",
        "api.ipify.org",
        "ipinfo.io",
        "ifconfig.me",
        "icanhazip.com",
        "checkip.amazonaws.com",
        "ip-api.com",
        "api.ip.sb",
        "whatismyipaddress.com",
        "dns.google",
        "virustotal.com",
        "www.virustotal.com",
        "urlscan.io",
        "any.run",
        "app.any.run",
        "hybrid-analysis.com",
        "www.hybrid-analysis.com",
        "bazaar.abuse.ch",
        "urlhaus.abuse.ch",
        "threatfox.abuse.ch",
        "otx.alienvault.com",
        "exchange.xforce.ibmcloud.com",
        "attack.mitre.org",
        "nvd.nist.gov",
        "cve.mitre.org",
        "cve.org",
        "www.cve.org",
        "github.com",
        "www.github.com",
        "gist.github.com",
        "raw.githubusercontent.com",
        "twitter.com",
        "x.com",
        "t.me",
        "linkedin.com",
        "www.linkedin.com",
        "reddit.com",
        "www.reddit.com",
        "medium.com",
        "youtube.com",
        "www.youtube.com",
        "google.com",
        "www.google.com",
        "microsoft.com",
        "www.microsoft.com",
        "learn.microsoft.com",
        "docs.microsoft.com",
        "apple.com",
        "support.apple.com",
        "wikipedia.org",
        "en.wikipedia.org",
        "shodan.io",
        "www.shodan.io",
        "censys.io",
        "greynoise.io",
        "viz.greynoise.io",
        "malpedia.caad.fkie.fraunhofer.de",
        "bleepingcomputer.com",
        "www.bleepingcomputer.com",
        "thehackernews.com",
        "therecord.media",
        "krebsonsecurity.com",
    }
)


def is_reference_host(value: str) -> bool:
    """A domain, or a URL's host, that names a reference/shared service."""
    v = value.lower()
    host = v.split("/")[2] if "://" in v else v.split("/")[0]
    host = host.split("@")[-1].split(":")[0]
    if host in _REFERENCE_HOSTS:
        return True
    # The apex of a shared-infrastructure suffix (github.io, amazonaws.com) is
    # the platform, never an indicator; a subdomain on it may be.
    return host in SHARED_INFRA_SUFFIXES


def _classify_hash(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def _valid_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast and value not in _BENIGN_IPS


def _plausible_domain(value: str) -> bool:
    v = value.lower().rstrip(".")
    if any(v == s or v.endswith("." + s) for s in _BENIGN_DOMAIN_SUFFIXES):
        return False
    if v in _PLACEHOLDER_DOMAINS or v.startswith("www.") and v[4:] in _PLACEHOLDER_DOMAINS:
        return False
    tld = v.rsplit(".", 1)[-1]
    if _GLUED_TLD_RE.match(tld):
        return False
    # Version-ish and filename-ish tails regex-match a domain; a real TLD is
    # never all digits and this list covers the common file-suffix collisions.
    if tld.isdigit() or tld in {
        "exe",
        "dll",
        "bat",
        "ps1",
        "vbs",
        "js",
        "ts",
        "py",
        "rb",
        "go",
        "rs",
        "css",
        "htm",
        "html",
        "json",
        "yml",
        "yaml",
        "xml",
        "txt",
        "csv",
        "md",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "ico",
        "webp",
        "mp3",
        "mp4",
        "avi",
        "iso",
        "img",
        "bin",
        "dat",
        "log",
        "ini",
        "cfg",
        "conf",
        "tmp",
        "bak",
        "lnk",
        "msi",
        "jar",
        "war",
        "class",
        "so",
        "dylib",
        "sys",
        "reg",
        "db",
        "sqlite",
        "gz",
        "tar",
        "rar",
        "7z",
    }:
        return False
    return "." in v and len(v) <= 253


def classify_value(raw: str) -> tuple[str, str] | None:
    """Best-effort (kind, canonical_value) for one bare token, or None.

    Used where the *context* supplies the judgment (ioc_list bodies, analyst
    input) — never to sweep prose.
    """
    token = refang(raw.strip().strip(",;")).strip()
    if not token or len(token) > 2048:
        return None
    if HASH_RE.fullmatch(token):
        return _classify_hash(token), token.lower()
    if IPV4_RE.fullmatch(token) and _valid_public_ip(token):
        return "ipv4", token
    if ":" in token and IPV6_CANDIDATE_RE.fullmatch(token) and _valid_public_ip(token):
        return "ipv6", token.lower()
    if URL_FULL_RE.fullmatch(token):
        return "url", token
    if EMAIL_RE.fullmatch(token) and _plausible_domain(token.rsplit("@", 1)[-1]):
        return "email", token.lower()
    if DOMAIN_RE.fullmatch(token) and _plausible_domain(token):
        return "domain", token.lower()
    return None


def normalize_value(kind: str, value: str) -> str:
    """Canonical storage form per kind. Identity depends on this being stable."""
    v = refang(value).strip()
    lowered = {
        "domain",
        "email",
        "ja3",
        "ja4",
        "cert_fingerprint",
        "registry",
        "service_name",
        "scheduled_task",
        "mutex",
        "named_pipe",
        "http_header",
    }
    if kind in lowered | HASH_KINDS:
        return v.lower()
    if kind == "cmdline":
        return re.sub(r"\s+", " ", v)
    if kind == "url":
        m = re.match(r"(?i)^(https?)(://[^/]+)(.*)$", v)
        if m:
            return m.group(1).lower() + m.group(2).lower() + m.group(3)
    return v


def script_identity(snippet: str) -> tuple[str, str]:
    """(sha256_value, normalized_snippet) for kind="script" rows."""
    normalized = "\n".join(line.rstrip() for line in snippet.replace("\r\n", "\n").strip().splitlines())
    return hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest(), normalized


# ---------------------------------------------------------------------------
# Candidate scan (Tier 0 — entry-local, never entities)
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    kind: str
    value: str
    surface_form: str
    was_defanged: bool
    paragraph_index: int


def _paragraph_index(text: str, offset: int) -> int:
    return text.count("\n\n", 0, offset)


#: Words that say a dotted quad or a hex string is an *indicator* rather than
#: a version or a commit — they lift the context vetoes below.
_IOC_CONTEXT_RE = re.compile(
    r"(?i)\b(?:ip|ips|c2|c&c|command[- ]and[- ]control|beacon\w*|server|host\w*|address\w*|infrastructure"
    r"|callback|scann\w*|attacker\w*|malicious|connect\w*|download\w*|resolv\w*|listen\w*|port|payload"
    r"|sample\w*|hash\w*|sha\d*|md5|dropper|loader|binar\w*|file\w*|ioc\w*|indicator\w*)\b"
)
_VERSION_CONTEXT_RE = re.compile(
    r"(?i)\b(?:version[s]?|ver\.?|release[sd]?|build[s]?|firmware|fixed in|patched in|prior to|earlier than"
    r"|later than|up to|through|affect\w*|vulnerable|upgrade\w*|update\w*|between|and (?:earlier|later)"
    r"|v\d)\b[^\n]{0,40}$"
)
_RANGE_SUFFIX_RE = re.compile(
    r"^\s*(?:to|through|and|or|-|–|—|,)\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", re.IGNORECASE
)
_RANGE_PREFIX_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*(?:to|through|and|or|-|–|—|,)\s*$", re.IGNORECASE)
_COMMIT_CONTEXT_RE = re.compile(
    r"(?i)(?:commit|merge|pull request|\bgit\b|revision|changeset|\btag\b|up to|prior to|before|fixed|patch\w*"
    r"|version|affected|identified in)[^\n]{0,40}$"
)


def scan_candidates(
    text: str, *, max_candidates: int = 200, plain_hashes: bool = True, plain_ips: bool = True
) -> list[Candidate]:
    """Nominate observable candidates from entry text. Precision-first:
    hashes + public IPs always; domains/URLs/emails only when defanged.

    ``plain_hashes`` / ``plain_ips`` switch off the un-defanged hash and IP
    sweeps for sources where those tokens are almost never indicators
    (advisory bulletins and NVD: package checksums, commit ids, version
    quads; rule and catalog repositories: the rule's own metadata). Defanged
    tokens always nominate — the author marked them."""
    seen: set[tuple[str, str]] = set()
    out: list[Candidate] = []

    def add(kind: str, value: str, surface: str, defanged: bool, offset: int) -> None:
        if kind == "url":
            # An HTML entity glued to the URL by a flattened renderer.
            value = value.split("&nbsp;", 1)[0].split("&amp;nbsp;", 1)[0].rstrip(".,;:)")
        if kind in ("url", "domain") and is_reference_host(value):
            return
        canonical = normalize_value(kind, value)
        key = (kind, canonical)
        if not canonical or key in seen or len(out) >= max_candidates:
            return
        seen.add(key)
        out.append(Candidate(kind, canonical, surface, defanged, _paragraph_index(text, offset)))

    # Defanged tokens: the author marked these as indicators.
    for m in re.finditer(r"\S+", text):
        token = m.group(0).strip(".,;:!?\"'()")
        if not is_defanged(token):
            continue
        classified = classify_value(token)
        if classified:
            add(classified[0], classified[1], token, True, m.start())

    # Hashes: unambiguous at 32/40/64 hex — but hex strings also live in
    # package checksums (RHSA advisories), git commits, tracking/gravatar URLs.
    # Context vetoes keep those out of the nominations.
    for m in HASH_RE.finditer(text) if plain_hashes else ():
        prefix = text[max(0, m.start() - 90) : m.start()]
        suffix = text[m.end() : m.end() + 60]
        # Inside any URL-ish token (query strings, permalinks, gravatar).
        token_start = prefix.rsplit(None, 1)[-1] if prefix.split() else ""
        if "/" in token_start or "=" in token_start or "?" in token_start:
            continue
        # Part of a larger token — a bucket id inside a hostname
        # ("pub-9ee1bf…a.r2.dev"), a path segment, an identifier — is not a hash.
        if token_start.endswith(("-", "_", ".")) or re.match(r"[.\-_][A-Za-z0-9]", suffix):
            continue
        # Package/checksum context: advisory manifests, not indicators.
        if re.search(
            r"(?i)(checksum|sha\d*sum|md5sum|digest|\.rpm|\.deb|\.tar|\.iso|package[s]?:?\s*$|commit)", prefix
        ):
            continue
        if re.search(r"(?i)^\s*\.(rpm|deb|tar|iso)\b", suffix):
            continue
        # "fixed in commit 5dadec…", "up to 5dadec…" (NVD names versions by
        # commit): a hex id in version/commit context, with nothing nearby
        # calling it a sample or a hash, is not an indicator.
        near = prefix[-60:] + suffix[:40]
        if _COMMIT_CONTEXT_RE.search(prefix[-60:]) and not _IOC_CONTEXT_RE.search(near):
            continue
        add(_classify_hash(m.group(0)), m.group(0).lower(), m.group(0), False, m.start())

    # Public IPv4s, octet-validated and reserved-range gated. A four-part
    # version number ("Version 2.4.1.100", "through 1.1.10.8") is a
    # syntactically valid global IP, so both context directions get a veto.
    for m in IPV4_RE.finditer(text) if plain_ips else ():
        prefix = text[max(0, m.start() - 60) : m.start()]
        suffix = text[m.end() : m.end() + 40]
        if re.search(
            r"(?i)(version[s]?|ver\.?|build|v|through|prior to|upgrade[d]? to|update[d]? to|release[sd]?)\s*$", prefix
        ):
            continue
        if re.search(r"(?i)^\s*(and|or)\s+(earlier|later|prior|below|above|newer|older)", suffix):
            continue
        # Version ranges ("9.4.0.0 - 9.4.0.25", "from 20.15.6.1 to 20.18.4.1")
        # and version talk earlier in the sentence with nothing calling the
        # quad an address.
        if _RANGE_SUFFIX_RE.match(suffix) or _RANGE_PREFIX_RE.search(prefix):
            continue
        if _VERSION_CONTEXT_RE.search(prefix) and not _IOC_CONTEXT_RE.search(prefix + suffix):
            continue
        # A fixed-release table row: "20.15 | 20.15.6.1" — a shorter dotted
        # number on the same line that prefixes the quad names a release train.
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line = text[line_start : len(text) if line_end == -1 else line_end]
        quad = m.group(0)
        if any(
            quad.startswith(t + ".") and t != quad
            for t in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){1,2}(?![\d.])", line)
        ):
            continue
        if _valid_public_ip(quad):
            add("ipv4", quad, quad, False, m.start())

    return out


def candidates_as_json(candidates: list[Candidate]) -> list[dict]:
    return [{**asdict(c), "origin": "scan"} for c in candidates]


def scan_sighting_probes(text: str, *, max_probes: int = 500) -> list[Candidate]:
    """Sighting-only probes: every domain/URL/email-shaped token, fanged or not.

    ``scan_candidates`` deliberately nominates domains/URLs/emails only when
    the author defanged them — but a known C2 domain printed plainly in a new
    article must still count as a sighting, or the ledger under-counts and
    decays values that are actively being reported. Probes exist solely for
    ``sight_known_values``'s exact match against rows a judgment door already
    created; they are never stored on the entry and can never create a row.
    """
    seen: set[tuple[str, str]] = set()
    out: list[Candidate] = []

    def add(kind: str, value: str, surface: str, offset: int) -> None:
        canonical = normalize_value(kind, value)
        key = (kind, canonical)
        if key in seen or len(out) >= max_probes:
            return
        seen.add(key)
        out.append(Candidate(kind, canonical, surface, is_defanged(surface), _paragraph_index(text, offset)))

    for m in URL_RE.finditer(text):
        add("url", m.group(0), m.group(0), m.start())
    for m in EMAIL_RE.finditer(text):
        add("email", m.group(0), m.group(0), m.start())
    for m in DOMAIN_RE.finditer(text):
        if _plausible_domain(m.group(0)):
            add("domain", m.group(0), m.group(0), m.start())
    return out


# ---------------------------------------------------------------------------
# ioc_list bodies (curated indicator feeds — the whole body is indicators)
# ---------------------------------------------------------------------------


#: Path fragments that mark an indicator-list file as NOT ingestable at all:
#: known-good inventories, anything the publisher itself files under
#: "unverified", and aggregate files whose per-list provenance is lost.
#: (NOTE: no "filter" fragment — drb-ra's best files are literally named
#: "*-filter-abused.csv", shared/abused infrastructure filtered OUT.)
IOC_LIST_PATH_DENY = (
    "whitelist",
    "allowlist",
    "benign",
    "unverified",
    # C2-Tracker's aggregate of every list, junk included — the per-tool
    # files carry the real provenance.
    "all.txt",
)

#: Path fragments that mark a file as DUAL-USE INFRASTRUCTURE rather than
#: malicious indicators: VPN/proxy/TOR exits, RMM/KVM endpoints, scanner and
#: phish-sim servers. These files ARE ingested — an attack sourced from a
#: NordVPN exit or a Burp Collaborator callback is context worth keeping —
#: but their rows carry the tag, and tagged rows never publish. First match
#: wins, so filename-specific fragments come before "vpn" (files like
#: ResidentialProxy.csv live inside a vpn/ directory).
IOC_LIST_PATH_TAGS: tuple[tuple[str, str], ...] = (
    ("gophish", "phish_sim"),
    ("nessus", "scanner"),
    ("burp", "scanner"),
    ("acunetix", "scanner"),
    ("sniper", "scanner"),
    ("scanner", "scanner"),
    ("proxy", "proxy"),
    ("rmm", "rmm"),
    ("kvm", "kvm"),
    # "tor" is token-matched in ioc_list_path_tag — as a substring it would
    # tag every "history"/"director"/"monitor" file.
    ("tor", "tor"),
    ("vpn", "vpn"),
)

INFRA_TAGS = frozenset(tag for _, tag in IOC_LIST_PATH_TAGS)

#: Fragments too short/common for substring matching — they must appear as a
#: whole path token (split on separators) to count.
_TOKEN_ONLY_TAG_FRAGMENTS = frozenset({"tor"})

#: Shared-infrastructure suffixes: real indicators sometimes front through
#: these, but publishing one to a blocklist blocks a CDN edge for everyone.
#: Captured rows keep them; the publish boundary excludes them.
SHARED_INFRA_SUFFIXES = (
    "cloudfront.net",
    "azureedge.net",
    "azurefd.net",
    "akamaized.net",
    "fastly.net",
    "workers.dev",
    "pages.dev",
    "r2.dev",
    "trycloudflare.com",
    "ngrok.io",
    "ngrok-free.app",
    "azurewebsites.net",
    "blob.core.windows.net",
    "web.app",
    "firebaseapp.com",
    "vercel.app",
    "netlify.app",
    "glitch.me",
    "repl.co",
    "onrender.com",
    "fly.dev",
    "icp0.io",
    "github.io",
    "amazonaws.com",
    "googleapis.com",
    "herokuapp.com",
)


def is_shared_infra(value: str) -> bool:
    v = value.lower()
    host = v.split("/")[2] if "://" in v else v
    return any(host == s or host.endswith("." + s) for s in SHARED_INFRA_SUFFIXES)


def ioc_list_path_allowed(file_path: str | None) -> bool:
    """Whether a curated-feed file's path clears the deny fragments."""
    if not file_path:
        return True
    lowered = file_path.lower()
    return not any(fragment in lowered for fragment in IOC_LIST_PATH_DENY)


def ioc_list_path_tag(file_path: str | None) -> str | None:
    """The infra tag a curated-feed file's path implies, or None for a true
    indicator list."""
    if not file_path:
        return None
    lowered = file_path.lower()
    tokens = set(re.split(r"[/_\-. ]+", lowered))
    for fragment, tag in IOC_LIST_PATH_TAGS:
        if fragment in _TOKEN_ONLY_TAG_FRAGMENTS:
            if fragment in tokens:
                return tag
        elif fragment in lowered:
            return tag
    return None


#: Path tokens that mark a curated list as command-and-control infrastructure
#: (drb-ra's ``domainC2s`` / ``IPC2s`` / ``C2_configs``, C2-Tracker's per-tool
#: ``<Tool> C2 IPs`` / ``<RAT> Trojan IPs`` / ``<Bot> Botnet IPs`` files).
_C2_PATH_TOKENS = ("c2", "c2s", "botnet", "rat", "trojan", "implant", "beacon", "stealer", "loader")
_INFRA_TAG_ROLES = {"scanner": "scanning", "phish_sim": "phishing"}


def ioc_list_path_role(file_path: str | None, infra_tag: str | None = None) -> str | None:
    """The network role a curated-feed file's path implies, or None.

    Dual-use infrastructure files (VPN/proxy/TOR/RMM/KVM) carry no role —
    the tag says what the host is, not what it did. Scanner and phish-sim
    files map to their roles; everything else with a C2-ish token is ``c2``.
    """
    if infra_tag in _INFRA_TAG_ROLES:
        return _INFRA_TAG_ROLES[infra_tag]
    if infra_tag is not None:
        return None
    if not file_path:
        return None
    tokens = set(re.split(r"[/_\-. ]+", file_path.lower()))
    # "domainC2swithURL" / "IPPortC2s-90day": the token holds C2 inside it.
    if any(t in tokens for t in _C2_PATH_TOKENS) or any("c2" in t for t in tokens):
        return "c2"
    return None


def parse_ioc_list_body(text: str, *, max_values: int = 5000) -> list[tuple[str, str]]:
    """(kind, value) pairs from a raw indicator-list body (one per line/cell)."""
    results: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        # "//" is a comment only at line start or after whitespace — never the
        # "//" inside https:// (which this split used to destroy).
        line = re.split(r"(?:^|\s)//", line)[0].strip()
        if not line:
            continue
        # csv-ish rows: try each cell, keep the first classifiable one.
        for cell in re.split(r"[,;\t]", line):
            classified = classify_value(cell)
            if classified and classified not in seen:
                seen.add(classified)
                results.append(classified)
                break
        if len(results) >= max_values:
            break
    return results


# ---------------------------------------------------------------------------
# Confidence & lifecycle
# ---------------------------------------------------------------------------

#: Base confidence per creation door.
BASE_CONFIDENCE = {"manual": 1.0, "publisher_ioc": 0.9, "ioc_list": 0.85, "ttp_observable": 0.85, "ai_extraction": 0.8}
DEFANG_BONUS = 0.1
_AGING_BELOW = 0.5
_EXPIRED_BELOW = 0.15


def compute_confidence(base: float, kind: str, last_seen_at: datetime, now: datetime | None = None) -> float:
    half_life = DECAY_HALF_LIFE_DAYS.get(kind)
    if half_life is None:
        return base
    now = now or datetime.now(UTC)
    last = last_seen_at if last_seen_at.tzinfo else last_seen_at.replace(tzinfo=UTC)
    days = max(0.0, (now - last).total_seconds() / 86400)
    return round(base * 0.5 ** (days / half_life), 4)


def status_for(confidence: float) -> str:
    if confidence < _EXPIRED_BELOW:
        return STATUS_EXPIRED
    if confidence < _AGING_BELOW:
        return STATUS_AGING
    return STATUS_ACTIVE


# ---------------------------------------------------------------------------
# Writes (the doors call these)
# ---------------------------------------------------------------------------


#: Kinds and doors that queue lookups on creation, at every enabled source
#: with trigger_mode=auto that takes the kind (Shodan InternetDB, Team Cymru
#: and RDAP are keyless; VirusTotal once its key is configured).
AUTO_ENRICH_KINDS = frozenset({"ipv4", "ipv6", "domain", "sha256", "md5", "sha1"})
AUTO_ENRICH_DOORS = frozenset({"ai_extraction", "manual", "publisher_ioc"})
#: A publisher's indicator file can carry hundreds of fresh rows for one
#: article; only this many of them queue a reputation lookup (the rest stay
#: available to the manual enrich button). Shodan InternetDB allows ~30/min.
AUTO_ENRICH_PER_ENTRY_CAP = 25
_auto_enrich_queued: dict[str, int] = {}


async def _enqueue_auto_enrich(session: AsyncSession, obs: Observable) -> None:
    from app.enrichment.queue import enqueue

    await enqueue(
        session,
        "observable",
        obs.id,
        obs.value,
        entity_base_confidence=float(obs.base_confidence or 0.8),
    )


async def get_or_create_observable(
    session: AsyncSession,
    kind: str,
    value: str,
    *,
    via: str,
    entry_id=None,
    role: str | None = None,
    evidence: str | None = None,
    label: str | None = None,
    content: str | None = None,
    language: str | None = None,
    was_defanged: bool = False,
    infra_tag: str | None = None,
) -> Observable | None:
    """Create (or fetch) a ledger row. Returns None for denied/invalid input.

    ``via`` must be a judgment door — this function is the chokepoint where
    the no-regex rule is enforced, so it refuses unknown kinds outright.
    """
    if kind not in ALL_KINDS:
        return None
    if role is not None and role not in ROLES:
        role = None
    canonical = normalize_value(kind, value)
    if not canonical or len(canonical) > 8192:
        return None

    base = min(1.0, BASE_CONFIDENCE.get(via, BASE_CONFIDENCE[VIA_MANUAL]) + (DEFANG_BONUS if was_defanged else 0.0))
    # Insert-or-ignore first: two doors creating the same (kind, value)
    # concurrently must not raise — an IntegrityError would abort the caller's
    # whole transaction (in the analysis fan-out that loses the entire payload).
    inserted = await session.execute(
        pg_insert(Observable)
        .values(
            id=uuid_mod.uuid4(),
            kind=kind,
            value=canonical,
            label=label,
            content=content,
            language=language,
            role=role,
            evidence=evidence,
            base_confidence=base,
            current_confidence=base,
            created_via=via,
            created_from_entry_id=entry_id,
            infra_tag=infra_tag,
            # AI-created rows carry the review flag so a capture-mode audit can
            # filter to them. The TTP door is the same model's output riding a
            # different array, so it carries the flag too; feed/analyst doors
            # are curator judgment already.
            needs_review=via in ("ai_extraction", "ttp_observable"),
        )
        .on_conflict_do_nothing(index_elements=["kind", "value"])
    )
    obs = (
        await session.execute(select(Observable).where(Observable.kind == kind, Observable.value == canonical))
    ).scalar_one_or_none()
    if obs is None or obs.is_denied:
        return None
    if inserted.rowcount and kind in AUTO_ENRICH_KINDS and via in AUTO_ENRICH_DOORS:
        # Reputation lookups for freshly judged infrastructure — never for the
        # bulk feed door (16k rows of blocklist would burn every budget), and
        # at most AUTO_ENRICH_PER_ENTRY_CAP per capturing entry so a publisher
        # file's 400 hashes don't queue 400 lookups.
        key = str(entry_id) if entry_id else ""
        n = _auto_enrich_queued.get(key, 0)
        if not key or n < AUTO_ENRICH_PER_ENTRY_CAP:
            if key:
                if len(_auto_enrich_queued) > 2048:
                    _auto_enrich_queued.clear()
                _auto_enrich_queued[key] = n + 1
            await _enqueue_auto_enrich(session, obs)
    # A later door can enrich what an earlier one left blank. infra_tag is
    # fill-only too: "this IP is a VPN exit" stays true even after an AI door
    # later confirms it as C2 — the dual signal is the point.
    obs.role = obs.role or role
    obs.evidence = obs.evidence or evidence
    obs.label = obs.label or label
    obs.infra_tag = obs.infra_tag or infra_tag
    return obs


async def record_sighting(
    session: AsyncSession,
    entry_id,
    observable: Observable,
    *,
    source: str,
    confidence: str | None = None,
    surface_form: str | None = None,
    was_defanged: bool = False,
    paragraph_indices: list[int] | None = None,
    ttp_id=None,
    seen_at: datetime | None = None,
) -> bool:
    """Upsert one junction row and refresh the ledger row's clock.

    Returns True when this (entry, observable) pair is new — decided by the
    insert itself, so concurrent writers (the ingest stage racing the
    retro-sighting job) can't double-increment the counters.

    ``seen_at`` is when the sighting happened in the world (the entry's
    publish date). A retro-sighted 2023 article must not stamp the row fresh:
    ``last_seen_at`` only moves forward, and the decay clock resets only for
    sightings from the recent past.
    """
    insert_stmt = (
        pg_insert(EntryObservable)
        .values(
            entry_id=entry_id,
            observable_id=observable.id,
            source=source,
            confidence=confidence,
            surface_form=surface_form,
            was_defanged=was_defanged,
            paragraph_indices=paragraph_indices,
            ttp_id=ttp_id,
        )
        .on_conflict_do_nothing(index_elements=["entry_id", "observable_id"])
    )
    result = await session.execute(insert_stmt)
    is_new = bool(result.rowcount)

    if not is_new and source != "sighting":
        # A judgment door outranks a passive sighting on the same pair: upgrade
        # the provenance fields the passive scan couldn't know.
        await session.execute(
            update(EntryObservable)
            .where(
                EntryObservable.entry_id == entry_id,
                EntryObservable.observable_id == observable.id,
                EntryObservable.source == "sighting",
            )
            .values(
                source=source,
                confidence=func.coalesce(confidence, EntryObservable.confidence),
                surface_form=func.coalesce(surface_form, EntryObservable.surface_form),
                ttp_id=func.coalesce(ttp_id, EntryObservable.ttp_id),
            )
        )

    if is_new:
        effective = seen_at if seen_at is not None else datetime.now(UTC)
        if effective.tzinfo is None:
            effective = effective.replace(tzinfo=UTC)
        recent = (datetime.now(UTC) - effective).days <= 7
        values: dict = {
            # Increment, not recount — this runs per sighting and the backfill
            # does it ~100k times. Unlink recomputes when rows leave.
            "sighting_count": Observable.sighting_count + 1,
            "article_count": func.coalesce(Observable.article_count, 0) + 1,
            # Reports are the corroboration count: every door but the
            # indicator-feed one is an article/advisory/rule file saying so.
            "report_count": Observable.report_count + (0 if source == "feed" else 1),
            # The row's FIRST sighting owns the clock outright — a freshly
            # created row carries now() column defaults, and greatest() would
            # keep them, stamping a backfilled 2023 article as seen today.
            # After that, last_seen only ever moves forward.
            "first_seen_at": func.least(Observable.first_seen_at, effective),
            "last_seen_at": case(
                (Observable.sighting_count == 0, effective),
                else_=func.greatest(Observable.last_seen_at, effective),
            ),
        }
        if recent:
            values["current_confidence"] = Observable.base_confidence
            values["status"] = STATUS_ACTIVE
        await session.execute(update(Observable).where(Observable.id == observable.id).values(**values))
    return is_new


def corroboration_counts_subquery():
    """Per-observable ground truth for the four counters, from the junction.

    ``report_count`` = distinct entries that are not indicator-list files;
    ``feed_source_count`` = distinct feeds among indicator-list entries.
    """
    from app.models.entry import Entry

    is_list = func.coalesce(Entry.metadata_["content_type"].astext, "") == "ioc_list"
    return (
        select(
            EntryObservable.observable_id.label("observable_id"),
            func.count().label("cnt"),
            func.count(func.distinct(EntryObservable.entry_id)).filter(~is_list).label("reports"),
            func.count(func.distinct(Entry.feed_id)).filter(is_list).label("feeds"),
        )
        .join(Entry, Entry.id == EntryObservable.entry_id)
        .group_by(EntryObservable.observable_id)
        .subquery()
    )


async def recount_observable(session: AsyncSession, observable_id) -> None:
    """Recompute every counter for one row from the junction (after an unlink)."""
    agg = corroboration_counts_subquery()
    row = (
        await session.execute(select(agg.c.cnt, agg.c.reports, agg.c.feeds).where(agg.c.observable_id == observable_id))
    ).first()
    cnt, reports, feeds = (row.cnt, row.reports, row.feeds) if row else (0, 0, 0)
    await session.execute(
        update(Observable)
        .where(Observable.id == observable_id)
        .values(sighting_count=cnt, article_count=cnt, report_count=reports, feed_source_count=feeds)
    )


async def sight_known_values(session: AsyncSession, entry_id, candidates: list[Candidate]) -> int:
    """Exact-match candidates against the ledger and record sightings.

    This is the only regex-adjacent write path, and it can only touch rows a
    judgment door already created. Denied rows never re-sight.
    """
    if not candidates:
        return 0
    pairs = {(c.kind, c.value) for c in candidates}
    rows = await session.execute(
        select(Observable).where(
            tuple_(Observable.kind, Observable.value).in_(list(pairs)),
            Observable.is_denied.is_(False),
        )
    )
    by_key = {(o.kind, o.value): o for o in rows.scalars()}
    sighted = 0
    for c in candidates:
        obs = by_key.get((c.kind, c.value))
        if obs is None:
            continue
        await record_sighting(
            session,
            entry_id,
            obs,
            source="sighting",
            surface_form=c.surface_form,
            was_defanged=c.was_defanged,
            paragraph_indices=[c.paragraph_index],
        )
        sighted += 1
    return sighted


#: Redaction and template tokens: a value carrying one is a pattern, not an
#: exact-match atom.
_PLACEHOLDER_RE = re.compile(
    r"(?i)redacted|anonymi[sz]ed|<[^>\s]{1,40}>|\{[a-z_][\w\s]{0,40}\}|\[(?:redacted|victim|target|user)[^\]]*\]"
)

#: Discovery / admin commands every incident report quotes and no ledger
#: wants: they carry nothing attacker-chosen, so an exact match in telemetry
#: means nothing. Matched against the whitespace-normalised, lowercased line.
GENERIC_COMMANDS_RE = re.compile(
    r"(?i)^(?:"
    r"whoami(?:\s+/\w+)*|systeminfo|hostname|ipconfig(?:\s+/\w+)*|ifconfig(?:\s+-?\w+)*|uname(?:\s+-\w+)?|id|pwd|w|who|last|"
    r"quser|qwinsta|query\s+user|set|env|printenv|history|netstat(?:\s+-\w+)*|arp\s+-a|route\s+print|nltest(?:\s+/\S+)*|"
    r"net\s+(?:view|user|group|localgroup|accounts|share|session|start|config|time)(?:\s+(?:\"[^\"]*\"|[^/\s]+))*(?:\s+/domain)?|"
    r"tasklist(?:\s+/\S+(?:\s+\"[^\"]*\")?)*|dir(?:\s+\S+)?|ls(?:\s+-\w+)*|ps(?:\s+-?\w+)*|sc\s+query(?:\s+\S+)?|"
    r"wmic\s+\w+\s+get(?:\s+[\w,]+)?|"
    r"get-(?:process|service|adcomputer|aduser|adgroup|netipconfiguration|hotfix|wmiobject\s+win32_\w+)(?:\s+-\w+(?:\s+\S+)?)*|"
    r"invoke-sharefinder(?:\s+-\w+)*|export-dnsserverzone(?:\s+-\w+\s+\S+)*|nslookup(?:\s+\S+)?|ping(?:\s+-\w+\s*\d*)*\s*\S*|"
    r"klist|whoami\.exe|cmd(?:\.exe)?|powershell(?:\.exe)?|sudo\s+su|su\s+-"
    r")$"
)
#: Something only the attacker could have chosen: a path with two segments, a
#: host/URL/IP, a quoted string, an encoded blob, a dropped file name, or a
#: flag that changes state.
_ATTACKER_LITERAL_RE = re.compile(
    r"(?i)(?:[\\/][\w.$~%-]+[\\/]|https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|"
    r"\b[a-z0-9-]{2,}\.(?:com|net|org|io|top|xyz|ru|cn|cc|info|biz|site|online|shop|club|dev|app|cloud|lat|sbs|cfd|click|lol|pro|ws|me|to|su|li|ee|sh|zip)\b|"
    r"\"[^\"]{4,}\"|'[^']{4,}'|[A-Za-z0-9+/=]{24,}|"
    r"\b[\w-]+\.(?:exe|dll|ps1|bat|cmd|vbs|vbe|js|jse|hta|sh|py|pl|msi|zip|rar|7z|jar|iso|img|lnk|scr|pif|dat|bin|txt|log|cfg|ini|xml|json|yml)\b|"
    r"\s/(?:add|create|change|delete|tn|tr|ru|sc|mo|v|d|f|q|c|k|urlcache|split|decode|encode|transfer|download)\b|"
    r"\s-(?:enc|e|ec|encodedcommand|nop|noprofile|w|windowstyle|ep|executionpolicy|c|command|u|p|H|M|R|L)\b)"
)
#: Windows binaries whose system path says nothing about an intrusion: the
#: LOLBins and core processes a write-up names as the technique's *target*.
#: Only these basenames are vetoed — a planted ``phoneinfo.dll`` under
#: System32 is exactly the kind of artifact the ledger wants.
_OS_BINARY_NAMES = (
    "cmd|powershell|pwsh|cscript|wscript|mshta|rundll32|regsvr32|regsvcs|regasm|certutil|bitsadmin|msiexec|schtasks|"
    "sc|reg|net|net1|wmic|msbuild|installutil|cmstp|forfiles|pcalua|odbcconf|control|svchost|explorer|lsass|winlogon|"
    "services|csrss|conhost|dllhost|taskhostw|taskhost|spoolsv|msdtc|wmiprvse|consent|notepad|calc|taskmgr|wbadmin|"
    "vssadmin|bcdedit|wevtutil|ntdsutil|comsvcs|ntdll|kernel32|kernelbase|user32|advapi32|msvcrt|amsi|sdiagnhost|"
    "sdiageng|werfault|smss|wininit|runtimebroker|sihost|dwm|ctfmon|searchindexer|searchhost|msedge|iexplore|"
    "appcmd|w3wp|inetinfo|mmc|tasklist|whoami|systeminfo|ipconfig|nslookup|netsh|ping|find|findstr|xcopy|robocopy|"
    "attrib|icacls|takeown|cacls|at|schtasks|wscript|cmdkey|curl|tar|expand|extrac32|makecab|esentutl|print"
)
_SYSTEM_BINARY_PATH_RE = re.compile(
    r"(?i)^(?:[a-z]:)?\\(?:windows|winnt)\\(?:system32|syswow64|winsxs|microsoft\.net|systemapps)\\"
    r"(?:[\w.-]+\\)*(?:" + _OS_BINARY_NAMES + r")\.(?:exe|dll|sys|ocx|cpl|msc|mui)$"
)
_BARE_SYSTEM_DIR_RE = re.compile(
    r"(?i)^(?:[a-z]:)?\\(?:windows(?:\\(?:system32|syswow64|temp))?|programdata|users(?:\\public)?"
    r"|program files(?: \(x86\))?)\\?$"
    r"|^%(?:temp|tmp|appdata|localappdata|programdata|userprofile|windir|systemroot|public)%\\?$"
    r"|^/(?:usr(?:/local)?/s?bin|s?bin)/[a-z0-9_.-]+$"
)
#: Well-known registry keys an author names as the *location* of persistence;
#: the IOC is the value name under them, never the bare key.
_BARE_UNIX_LOCATION_RE = re.compile(
    r"(?i)^/(?:dev/(?:shm|null|tcp|vd[a-z]|sd[a-z]|nvme\d\w*)|var/(?:tmp|log|lib|spool(?:/cron(?:/crontabs)?)?|run|www(?:/html)?)"
    r"|etc/(?:hosts|passwd|shadow|group|sudoers|crontab|cron\.d|cron\.daily|cron\.hourly|rc\.local|profile|bashrc"
    r"|ld\.so\.preload|ssh|ssh/sshd_config|resolv\.conf|fstab|hostname|motd|environment|init\.d|systemd(?:/system)?"
    r"|network(?:/interfaces)?|nginx|apache2|httpd|pam\.d|security|selinux)"
    r"|proc(?:/self)?|sys|boot|root(?:/\.ssh)?|home(?:/[a-z0-9_-]+(?:/\.ssh)?)?|usr/(?:lib|lib64|share|local|include|src)"
    r"|opt|srv|mnt|media|run|lib|lib64|tmp|bin|sbin|usr/s?bin|usr/local/s?bin|private/tmp|private/var/tmp"
    r"|library/launchagents|library/launchdaemons|applications|users(?:/[a-z0-9_-]+)?)$"
)
_BARE_WELLKNOWN_KEY_RE = re.compile(
    r"(?i)^hk(?:lm|cu|u|cr|cc|ey_[a-z_]+)\\(?:(?:software|system)\\)?(?:wow6432node\\)?(?:"
    r"microsoft\\windows(?: nt)?\\currentversion(?:\\(?:run|runonce|runservices|explorer|policies|policies\\explorer"
    r"|policies\\explorer\\run|winlogon|image file execution options))?|"
    r"currentcontrolset(?:\\services|\\control)?|microsoft\\cryptography"
    r"|microsoft\\windows defender(?:\\exclusions(?:\\paths)?)?|"
    r"classes|microsoft|software|system|environment"
    r")\\?$"
)
_BENIGN_URI_PATHS = frozenset(
    {
        "/",
        "/index.html",
        "/index.php",
        "/index.htm",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/wp-login.php",
        "/wp-admin",
        "/wp-admin/",
        "/login",
        "/login/",
        "/admin",
        "/admin/",
        "/api",
        "/api/",
        "/api/v1",
        "/api/v1/",
        "/health",
        "/status",
        "/.env",
        "/.git/config",
    }
)
_STANDARD_HEADERS = frozenset(
    {
        "accept", "accept-encoding", "accept-language", "authorization", "cache-control", "connection",
        "content-length", "content-type", "cookie", "date", "etag", "host", "if-modified-since", "location",
        "origin", "pragma", "range", "referer", "server", "set-cookie", "transfer-encoding", "upgrade",
        "user-agent", "vary", "via", "www-authenticate", "x-forwarded-for", "x-forwarded-proto", "x-real-ip",
        "x-requested-with", "x-frame-options", "x-xss-protection", "x-content-type-options",
        "strict-transport-security", "content-security-policy", "access-control-allow-origin", "x-powered-by",
        "x-api-key", "x-csrf-token", "x-auth-token", "accept-ranges", "content-disposition", "expires",
        "last-modified", "keep-alive", "te", "trailer", "dnt", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest",
    }
)  # fmt: skip
#: Service / task names Windows ships with — a report naming one describes the
#: target of the technique, not the attacker's artifact.
_OS_DEFAULT_NAMES = frozenset(
    {
        "schedule", "spooler", "wuauserv", "bits", "winlogon", "lanmanserver", "lanmanworkstation", "eventlog",
        "dnscache", "dhcp", "w32time", "termservice", "rpcss", "lsass", "samss", "netlogon", "winmgmt", "wscsvc",
        "windefend", "mpssvc", "sense", "trustedinstaller", "cryptsvc", "appidsvc", "msiserver", "vss", "svchost",
        "explorer", "cron", "sshd", "systemd", "init", "rsyslog", "networkmanager",
    }
)  # fmt: skip
_DETECTION_QUERY_START_RE = re.compile(
    r"(?i)^(?:process\.|event\.|file\.|registry\.|network\.|host\.|user\.|winlog\.|index\s*=|source\s*=|sourcetype\s*=|@|\||"
    r"selection|condition|not\s|and\s|or\s|where\s|from\s|select\s|title:|detection:|logsource:)"
)

#: Known UA product prefixes for strings without a version token.
_UA_PREFIXES = ("mozilla/", "curl/", "wget/", "python-requests/", "python-urllib", "okhttp", "go-http-client", "java/")


def _plausible_cmdline(value: str) -> bool:
    """A command line, not a sentence about one and not detection logic.

    Prose ("disable Microsoft's Antimalware Scan Interface") is words all the
    way down; a real command's arguments carry flags, paths, separators or
    digits. ``OR``/``AND`` chains and field-prefixed expressions are rule
    material. Generic discovery/admin commands (``whoami /priv``,
    ``net group "Domain Admins" /domain``) are vetoed outright, and whatever
    remains must carry something the attacker chose — a path, a host, a
    quoted string, an encoded blob, a dropped file, a state-changing flag."""
    if re.search(r"\s(?:OR|AND)\s", value):
        return False
    if _DETECTION_QUERY_START_RE.match(value.strip()):
        return False
    tokens = value.split()
    # A command has arguments; a lone "mimikatz.exe" is a filename, not a cmdline.
    if len(tokens) < 2:
        return False
    # Quotes excluded from the "command-ish" set: possessives ("Microsoft's")
    # would let prose through.
    if len(tokens) >= 4 and not any(re.search(r"[\\/=:.\-|&$%<>_@\d]", tok) for tok in tokens[1:]):
        return False
    normalized = re.sub(r"\s+", " ", value.strip()).lower().strip("\"'`")
    if GENERIC_COMMANDS_RE.match(normalized):
        return False
    return bool(_ATTACKER_LITERAL_RE.search(value))


def _plausible_path_atom(value: str) -> bool:
    """An exact file path: no wildcard/placeholder patterns, no prose tails,
    and not a bare well-known directory that would sight half the corpus."""
    if any(ch in value for ch in "*<>{}"):
        return False
    # Prose tails and enumerations, not space-counting — Windows paths carry
    # spaces legitimately ("\Program Files (x86)\Adobe\Acrobat Reader DC").
    if ", " in value:
        return False
    bare_words = [tok for tok in value.split() if len(tok) >= 3 and not re.search(r"[\\/.%~]", tok)]
    if len(bare_words) >= 3:
        return False
    if re.fullmatch(r"/(?:tmp|etc|var|usr|opt|home|dev|bin|sbin|lib|root|ui|api)/?", value, re.IGNORECASE):
        return False
    # A single top-level segment ("/PSEMHUB/") is a URI path or a name, not a
    # file-system location anyone chose; bare well-known locations
    # ("/dev/shm", "/var/tmp", "/etc/hosts") would sight half the corpus.
    if re.fullmatch(r"/[^/\\]+/?", value):
        return False
    if _BARE_UNIX_LOCATION_RE.match(value.rstrip("/") or value):
        return False
    if _PLACEHOLDER_RE.search(value):
        return False
    # The technique's *target* — a signed OS binary under System32, a bare
    # well-known directory — is never the attacker's artifact.
    if _SYSTEM_BINARY_PATH_RE.match(value) or _BARE_SYSTEM_DIR_RE.match(value.rstrip("\\/") or value):
        return False
    if re.search(r"(?i)\\users\\(?:lab|admin|user|test\w*|analyst|sandbox|anonymi[sz]ed\w*)\\", value):
        return False
    if re.search(r"(?i)\\device\\harddiskvolume\D", value):
        return False
    return "/" in value or "\\" in value


def _plausible_user_agent(value: str) -> bool:
    """A real User-Agent carries product/version syntax ("Mozilla/5.0 ...",
    "curl/8.1.2"). The TTP extraction's client_id field is a grab-bag of
    account names, service labels and prose ("administrator", "ScreenConnect",
    "session cookies") — none of which belong in a user_agent row."""
    v = value.strip().lower()
    if len(v) < 5 or len(v) > 512:
        return False
    return v.startswith(_UA_PREFIXES) or bool(re.search(r"[a-z][\w.-]*/\d", v))


def validate_kind_value(kind: str, raw: str) -> str | None:
    """Canonical value when (kind, raw) is a plausible atom, else None.

    Applied to every door's input — the AI included. A "malicious IP" in
    RFC1918 space or a domain with a file-extension TLD is a misread, whoever
    reported it.
    """
    canonical = normalize_value(kind, raw)
    if not canonical:
        return None
    if kind in ("ipv4", "ipv6"):
        return canonical if _valid_public_ip(canonical) else None
    if kind == "domain":
        return canonical if DOMAIN_RE.fullmatch(canonical) and _plausible_domain(canonical) else None
    if kind in HASH_KINDS:
        return canonical if HASH_RE.fullmatch(canonical) and _classify_hash(canonical) == kind else None
    if kind == "url":
        return canonical if URL_FULL_RE.fullmatch(canonical) else None
    if kind == "email":
        return canonical if EMAIL_RE.fullmatch(canonical) else None
    if kind == "uri_path":
        if not canonical.startswith("/") or len(canonical) < 3 or canonical.lower() in _BENIGN_URI_PATHS:
            return None
        return None if _PLACEHOLDER_RE.search(canonical) or "*" in canonical else canonical
    if kind == "registry":
        bare = canonical.rstrip("\\")
        if not re.match(r"hk(?:lm|cu|u|cr|cc|ey_)", bare) or _PLACEHOLDER_RE.search(bare) or "\\\\" in bare:
            return None
        return None if _BARE_WELLKNOWN_KEY_RE.match(bare) or "*" in bare else bare
    if kind == "http_header":
        name = canonical.split(":", 1)[0].strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", name) or name in _STANDARD_HEADERS:
            return None
        return canonical if len(canonical) <= 320 else None
    if kind in ("scheduled_task", "service_name", "mutex", "named_pipe"):
        if not (3 <= len(canonical) <= 128) or len(canonical.split()) > 5 or _PLACEHOLDER_RE.search(canonical):
            return None
        if canonical.rsplit("\\", 1)[-1] in _OS_DEFAULT_NAMES:
            return None
        return canonical
    if kind == "ja3":
        return canonical if re.fullmatch(r"[a-f0-9]{32}", canonical) else None
    if kind == "ja4":
        return canonical if re.fullmatch(r"[\w._-]{10,64}", canonical) else None
    if kind == "cert_fingerprint":
        bare = canonical.replace(":", "")
        return bare if re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", bare) else None
    if kind == "cmdline":
        return canonical if len(canonical) >= 6 and _plausible_cmdline(canonical) else None
    if kind == "path":
        return canonical if 4 <= len(canonical) <= 4096 and _plausible_path_atom(canonical) else None
    if kind == "user_agent":
        return canonical if _plausible_user_agent(canonical) else None
    if kind == SCRIPT_KIND:
        return canonical if re.fullmatch(r"[a-f0-9]{64}", canonical) else None
    # Remaining host kinds: length sanity only. Floor of 4 — a 2-char
    # mutex/service name would underline every occurrence of a short word
    # across its linked articles.
    return canonical if 4 <= len(canonical) <= 4096 else None


#: A 64-hex string the author calls a key, token or secret is not a file hash
#: (AES keys and API tokens share SHA256's shape).
_NOT_A_HASH_EVIDENCE_RE = re.compile(r"(?i)\b(?:aes|xor|rc4|chacha)?\s*(?:key|token|secret|nonce|iv|seed|salt)s?\b")


async def _ttp_id_for(session: AsyncSession, technique_id: str | None):
    if not technique_id:
        return None
    from app.models.ttp import TTP

    tid = technique_id.strip().upper()
    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid):
        return None
    return (await session.execute(select(TTP.id).where(TTP.technique_id == tid))).scalar_one_or_none()


async def store_observables(session: AsyncSession, entry_id, iocs: list[dict]) -> int:
    """The AI door: persist entry_analysis's confirmed indicators (network,
    hash and host kinds alike — every one through ``validate_kind_value``)."""
    stored = 0
    for item in iocs or []:
        kind = (item.get("kind") or "").strip()
        raw = (item.get("value") or "").strip()
        if not raw or kind not in ALL_KINDS:
            continue
        canonical = validate_kind_value(kind, raw)
        if canonical is None:
            continue
        evidence = (item.get("evidence") or "").strip() or None
        if (
            kind in HASH_KINDS
            and evidence
            and _NOT_A_HASH_EVIDENCE_RE.search(evidence)
            and "hash" not in evidence.lower()
        ):
            continue
        defanged = bool(item.get("defanged")) or is_defanged(raw)
        obs = await get_or_create_observable(
            session,
            kind,
            canonical,
            via="ai_extraction",
            entry_id=entry_id,
            role=(item.get("role") or "").strip() or None,
            evidence=evidence,
            was_defanged=defanged,
        )
        if obs is None:
            continue
        await record_sighting(
            session,
            entry_id,
            obs,
            source="ai",
            confidence=(item.get("confidence") or "").strip() or None,
            surface_form=raw,
            was_defanged=defanged,
            ttp_id=await _ttp_id_for(session, item.get("technique_id")),
        )
        stored += 1
    return stored


async def shadow_observables(
    session: AsyncSession, entry_id, iocs: list[dict], scripts: list[dict] | None = None
) -> int:
    """Shadow mode for the AI door: validated confirmations land on the entry's
    candidate list instead of the ledger — same one-click promote, zero rows —
    so the model's judgment can be eyeballed for a while before capture is
    switched on. The v1 lesson, applied to our own new judge."""
    from app.models.entry import Entry

    entry = (await session.execute(select(Entry).where(Entry.id == entry_id))).scalar_one_or_none()
    if entry is None:
        return 0
    existing = list(entry.observable_candidates or [])
    seen = {(c.get("kind"), c.get("value")) for c in existing}
    staged = 0
    _SHADOW_CAP = 40  # a hallucination-sized array must not grow the entry unbounded
    for item in iocs or []:
        if staged >= _SHADOW_CAP:
            break
        kind = (item.get("kind") or "").strip()
        raw = (item.get("value") or "").strip()
        if not raw or kind not in ALL_KINDS:
            continue
        canonical = validate_kind_value(kind, raw)
        if canonical is None or (kind, canonical) in seen:
            continue
        seen.add((kind, canonical))
        role = (item.get("role") or "").strip()
        existing.append(
            {
                "kind": kind,
                "value": canonical,
                "surface_form": raw,
                "was_defanged": bool(item.get("defanged")) or is_defanged(raw),
                "paragraph_index": 0,
                "origin": "ai",
                # The judgment travels with the nomination so a later promote
                # (or a capture-mode replay) creates the row the AI meant,
                # not a bare manual row.
                "role": role if role in ROLES else None,
                "evidence": ((item.get("evidence") or "").strip() or None),
                "confidence": ((item.get("confidence") or "").strip() or None),
                "technique_id": ((item.get("technique_id") or "").strip() or None),
            }
        )
        staged += 1
    for item in scripts or []:
        if staged >= _SHADOW_CAP:
            break
        code = (item.get("code") or "").strip()
        if len(code) < 40:
            continue
        sha, _ = script_identity(code)
        if (SCRIPT_KIND, sha) in seen:
            continue
        seen.add((SCRIPT_KIND, sha))
        label = (item.get("label") or "").strip()[:80]
        existing.append(
            {
                "kind": SCRIPT_KIND,
                "value": sha,
                "surface_form": label or sha[:16],
                "was_defanged": False,
                "paragraph_index": 0,
                "origin": "ai",
            }
        )
        staged += 1
    entry.observable_candidates = existing
    return staged


async def store_scripts(session: AsyncSession, entry_id, scripts: list[dict]) -> int:
    """The script half of the AI door: attacker code becomes a hash-keyed row.

    Identity is the sha256 of the normalized snippet (the model can't hash, so
    we do), the snippet lives in ``content``, and a reposted loader folds into
    one row with sightings across write-ups.
    """
    stored = 0
    for item in scripts or []:
        code = (item.get("code") or "").strip()
        if len(code) < 40:  # a one-liner is a cmdline, not a script
            continue
        sha, normalized = script_identity(code)
        obs = await get_or_create_observable(
            session,
            SCRIPT_KIND,
            sha,
            via="ai_extraction",
            entry_id=entry_id,
            label=(item.get("label") or "").strip()[:200] or None,
            content=normalized[:20000],
            language=(item.get("language") or "").strip() or None,
        )
        if obs is None:
            continue
        await record_sighting(
            session,
            entry_id,
            obs,
            source="ai",
            confidence=(item.get("confidence") or "").strip() or None,
        )
        stored += 1
    return stored


async def sync_observables_from_entry_ttps(
    session: AsyncSession, entry_id=None, *, kinds: set[str] | None = None
) -> int:
    """The TTP door: upsert host artifacts the technique extraction captured.

    With ``entry_id`` this runs per-entry at ingest; without it, it is the
    retroactive backfill over every populated EntryTTP.observable_value row.
    ``kinds`` restricts the door to the per-kind capture list.
    """
    from app.models.entry import Entry
    from app.models.ttp import EntryTTP

    q = (
        select(
            EntryTTP.entry_id,
            EntryTTP.ttp_id,
            EntryTTP.observable_type,
            EntryTTP.observable_value,
            EntryTTP.confidence,
            Entry.published_at,
        )
        .join(Entry, Entry.id == EntryTTP.entry_id)
        .where(EntryTTP.observable_value.isnot(None))
    )
    if entry_id is not None:
        q = q.where(EntryTTP.entry_id == entry_id)
    rows = (await session.execute(q)).all()
    stored = 0
    for row in rows:
        kind = kind_for_ttp_observable(row.observable_type, row.observable_value)
        if kind is None or (kinds is not None and kind not in kinds):
            continue
        canonical = validate_kind_value(kind, row.observable_value)
        if canonical is None:
            continue
        obs = await get_or_create_observable(session, kind, canonical, via="ttp_observable", entry_id=row.entry_id)
        if obs is None:
            continue
        await record_sighting(
            session,
            row.entry_id,
            obs,
            source="ttp",
            confidence=row.confidence,
            surface_form=row.observable_value.strip(),
            ttp_id=row.ttp_id,
            seen_at=row.published_at,
        )
        stored += 1
    return stored


async def store_ioc_list_observables(
    session: AsyncSession, entry_id, body: str, *, file_path: str | None = None, seen_at: datetime | None = None
) -> int:
    """The curated-feed door: an ioc_list body is indicators by definition —
    but only for files that are actually indicator lists. Known-good and
    unverified inventories never enter (``ioc_list_path_allowed``); dual-use
    infrastructure files (VPN/proxy/RMM/scanner) enter TAGGED
    (``ioc_list_path_tag``) so the rows read as what they are and the publish
    boundary can exclude them."""
    # Tag first: a tagged file is already quarantined (labeled context, never
    # published), so the publisher filing it under "unverified" doesn't deny
    # it. An UNTAGGED unverified/whitelist/aggregate file stays denied — those
    # rows would claim to be real indicators.
    infra_tag = ioc_list_path_tag(file_path)
    if infra_tag is None and not ioc_list_path_allowed(file_path):
        return 0
    pairs = parse_ioc_list_body(body)
    if not pairs:
        return 0
    role = ioc_list_path_role(file_path, infra_tag)

    # Bulk, not per-value record_sighting: a big C2 list is thousands of values
    # and the per-row path (4 statements each) blows the stage's time limit.
    # Semantics match record_sighting exactly because each observable appears
    # at most once per entry (parse dedupes), so every genuinely new junction
    # row means exactly one new sighting.
    base = BASE_CONFIDENCE["ioc_list"]
    effective = seen_at if seen_at is not None else datetime.now(UTC)
    if effective.tzinfo is None:
        effective = effective.replace(tzinfo=UTC)
    # Chunked: a 5000-row multi-VALUES insert (~10 params/row) would blow
    # asyncpg's 32k bind-parameter ceiling in one statement.
    _CHUNK = 1000
    for i in range(0, len(pairs), _CHUNK):
        await session.execute(
            pg_insert(Observable)
            .values(
                [
                    {
                        "id": uuid_mod.uuid4(),
                        "kind": kind,
                        "value": value,
                        "base_confidence": base,
                        "current_confidence": base,
                        "created_via": "ioc_list",
                        "created_from_entry_id": entry_id,
                        "infra_tag": infra_tag,
                        "role": role,
                        "feed_source_count": 1,
                        # Explicit clocks: a backfilled historical list must not
                        # mint rows stamped "seen today" by the column defaults.
                        "first_seen_at": effective,
                        "last_seen_at": effective,
                    }
                    for kind, value in pairs[i : i + _CHUNK]
                ]
            )
            .on_conflict_do_nothing(index_elements=["kind", "value"])
        )
    rows = (
        await session.execute(
            select(Observable.id, Observable.value).where(
                tuple_(Observable.kind, Observable.value).in_(pairs), Observable.is_denied.is_(False)
            )
        )
    ).all()
    if not rows:
        return 0
    ids = [r.id for r in rows]
    if infra_tag:
        # Fill-only, like get_or_create_observable: tag pre-existing untagged rows.
        await session.execute(
            update(Observable).where(Observable.id.in_(ids), Observable.infra_tag.is_(None)).values(infra_tag=infra_tag)
        )
    if role:
        # Fill-only too: a C2 list naming a row the AI already judged keeps the AI's role.
        await session.execute(
            update(Observable).where(Observable.id.in_(ids), Observable.role.is_(None)).values(role=role)
        )
    new_ids = []
    for i in range(0, len(rows), _CHUNK):
        result = await session.execute(
            pg_insert(EntryObservable)
            .values(
                [
                    {"entry_id": entry_id, "observable_id": r.id, "source": "feed", "surface_form": r.value}
                    for r in rows[i : i + _CHUNK]
                ]
            )
            .on_conflict_do_nothing(index_elements=["entry_id", "observable_id"])
            .returning(EntryObservable.observable_id)
        )
        new_ids.extend(result.scalars())
    # The feed door outranks a passive sighting that already covered this pair.
    await session.execute(
        update(EntryObservable)
        .where(
            EntryObservable.entry_id == entry_id,
            EntryObservable.observable_id.in_(ids),
            EntryObservable.source == "sighting",
        )
        .values(source="feed")
    )
    if new_ids:
        values: dict = {
            "sighting_count": Observable.sighting_count + 1,
            "article_count": func.coalesce(Observable.article_count, 0) + 1,
            # A list file is one source however many variants it ships; the
            # nightly reconcile counts distinct feeds exactly, this keeps a
            # pre-existing row from reading "0 feeds" until then.
            "feed_source_count": func.greatest(Observable.feed_source_count, 1),
            "first_seen_at": func.least(Observable.first_seen_at, effective),
            "last_seen_at": case(
                (Observable.sighting_count == 0, effective),
                else_=func.greatest(Observable.last_seen_at, effective),
            ),
        }
        if (datetime.now(UTC) - effective).days <= 7:
            values["current_confidence"] = Observable.base_confidence
            values["status"] = STATUS_ACTIVE
        await session.execute(update(Observable).where(Observable.id.in_(new_ids)).values(**values))
    return len(ids)


#: EntryTTP.observable_type -> observable kind. "header" and "other" are
#: deliberately unmapped: they're pattern-shaped, and patterns stay on the
#: technique (see the atoms-vs-rule-material boundary in the design doc).
TTP_OBSERVABLE_KIND_MAP = {
    "domain_pattern": "domain",
    "path": "path",
    "cmdline": "cmdline",
    "registry": "registry",
    "client_id": "user_agent",
    "hash": None,  # classified by length below
}


def kind_for_ttp_observable(observable_type: str | None, observable_value: str | None) -> str | None:
    """Map a TTP observable onto a ledger kind, or None when it's a pattern."""
    if not observable_type or not observable_value:
        return None
    value = observable_value.strip()
    if observable_type == "hash":
        return _classify_hash(value) if HASH_RE.fullmatch(refang(value)) else None
    kind = TTP_OBSERVABLE_KIND_MAP.get(observable_type)
    if kind == "domain":
        # A domain_pattern with wildcards or spaces is a pattern, not an atom.
        if re.search(r"[\s*]", value) or not _plausible_domain(refang(value)):
            return None
    if kind == "cmdline":
        # The extraction sometimes fills observable_value with a *description*
        # ("arbitrary operating system commands", "Python code"). A real
        # command line carries syntax — flags, paths, quotes, digits — prose
        # carries only letters and spaces.
        if len(value) < 6 or not re.search(r"[\\/\-=:.\"'|&$%<>_(){}\[\],;]|\d", value):
            return None
    if kind == "path":
        # A path without a separator is a filename at best, prose at worst.
        if "/" not in value and "\\" not in value:
            return None
    if kind == "registry" and not re.match(r"(?i)\s*hk", value):
        return None
    if kind == "user_agent" and not _plausible_user_agent(value):
        # client_id is where the extraction parks every identity-ish artifact
        # (account names, service labels, "admin tokens") — only actual
        # product/version UA strings map to the ledger.
        return None
    return kind


# ---------------------------------------------------------------------------
# Code-block candidates: a command inside a <pre> block is where authors
# actually put attacker tradecraft — nominations only, same candidate tier.
# ---------------------------------------------------------------------------


_CODE_BLOCK_RE = re.compile(r"<(?:pre|code)[^>]*>(.*?)</(?:pre|code)>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_WIN_PATH_RE = re.compile(r"^(?:[a-zA-Z]:\\|\\\\)[^<>\n]{3,}$")
_NIX_PATH_RE = re.compile(r"^/(?:etc|tmp|var|usr|opt|home|dev|bin|sbin|lib)/[\w./-]{2,}$")

#: A code-block line nominates as a command only when it starts the way a
#: command does. The old rule ("a word followed by a space, with one digit or
#: punctuation mark somewhere") let every preformatted bulletin line through —
#: "Operating System: Red Hat", "Patch Instructions:" — and AusCERT alone
#: staged 12k of them. Either the line opens with a shell prompt, or its
#: first token is a known executor / script host / transfer tool, or it names
#: an executable or script file.
_PROMPT_RE = re.compile(r"^(?:PS [A-Z]:\\[^>]*>|[a-z0-9_.\-]+@[a-z0-9_.\-]+:[~/][^$#]*[$#]|[$#>])\s+")
_EXECUTORS = (
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "cscript",
    "wscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "regsvcs",
    "regasm",
    "certutil",
    "bitsadmin",
    "msiexec",
    "schtasks",
    "sc",
    "reg",
    "net",
    "net1",
    "wmic",
    "msbuild",
    "installutil",
    "cmstp",
    "forfiles",
    "pcalua",
    "odbcconf",
    "control",
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr",
    "irm",
    "invoke-expression",
    "iex",
    "start-process",
    "bash",
    "sh",
    "zsh",
    "dash",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "php",
    "java",
    "nc",
    "ncat",
    "socat",
    "chmod",
    "chattr",
    "chown",
    "crontab",
    "nohup",
    "setsid",
    "base64",
    "echo",
    "sudo",
    "su",
    "ssh",
    "scp",
    "sftp",
    "rclone",
    "nxc",
    "crackmapexec",
    "psexec",
    "mimikatz",
    "procdump",
    "ntdsutil",
    "vssadmin",
    "wbadmin",
    "bcdedit",
    "wevtutil",
    "taskkill",
    "tasklist",
    "whoami",
    "nltest",
    "dsquery",
    "adfind",
    "systeminfo",
    "ipconfig",
    "netsh",
    "arp",
    "route",
    "attrib",
    "icacls",
    "takeown",
    "cacls",
    "xcopy",
    "robocopy",
    "copy",
    "move",
    "del",
    "ren",
    "mkdir",
    "rmdir",
    "type",
    "findstr",
    "find",
    "ping",
    "nslookup",
    "dig",
    "tar",
    "unzip",
    "7z",
    "rar",
    "zip",
    "gzip",
    "openssl",
    "gpg",
    "docker",
    "kubectl",
    "aws",
    "az",
    "gcloud",
    "wmiexec.py",
    "smbclient",
    "impacket-",
    "add-mppreference",
    "set-mppreference",
    "new-itemproperty",
    "set-itemproperty",
    "new-scheduledtask",
    "register-scheduledtask",
    "new-service",
    "invoke-command",
    "invoke-wmimethod",
    "invoke-mimikatz",
    "set-executionpolicy",
)
_EXEC_SUFFIXES = (
    ".exe",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".hta",
    ".sh",
    ".py",
    ".pl",
    ".jar",
    ".msi",
    ".dll",
    ".scr",
    ".pif",
)  # no ".com": a bare domain on its own line would read as a COM executable
_PROSE_START_RE = re.compile(
    r"(?i)^(the|this|that|these|those|it|we|you|note|output|example|figure|table|affected|operating|security|patch|cve|cvss|epss|announcement|an|a|in|on|for|if|when|several|multiple|please|see|refer|more|cvssv?\d|published|updated|product|vendor|summary|description|impact|resolution|references?|revision)\b"
)
#: Lines in a code block that look like a command — used to veto blocks that
#: are mostly prose (bulletin text, log excerpts, config dumps).
_COMMANDISH_RE = re.compile(r"[\\/=:.\-|&$%<>_@]|\d")


def _looks_like_command(line: str) -> bool:
    if _PROMPT_RE.match(line):
        return True
    first = line.split(None, 1)[0].lower().strip("\"'`") if line.split() else ""
    if not first:
        return False
    if first.startswith("./") or first.startswith("\\") or first.startswith("~/"):
        return True
    base = first.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if base in _EXECUTORS or any(base.startswith(e) for e in _EXECUTORS if e.endswith("-")):
        return True
    return base.endswith(_EXEC_SUFFIXES)


def scan_code_block_candidates(content_html: str | None, *, max_candidates: int = 20) -> list[Candidate]:
    """Host-kind candidates from the article's <pre>/<code> blocks — where
    authors put commands — instead of prose regex. Nominations only: same
    entry-local candidate tier, same one-click promote, never entities.

    Precision rules: a block that is mostly prose (fewer than half its
    non-trivial lines carry command syntax) nominates nothing; a cmdline
    nomination needs a prompt marker or a known executor as its first token;
    placeholder tokens (``REDACTED``, ``<GUID>``, ``{session_id}``) stay out of
    path/registry nominations.
    """
    if not content_html:
        return []
    out: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    import html as html_mod

    def add(kind: str, value: str) -> None:
        canonical = normalize_value(kind, value)
        if not canonical or (kind, canonical) in seen or len(out) >= max_candidates:
            return
        if validate_kind_value(kind, canonical) is None:
            return
        seen.add((kind, canonical))
        out.append(Candidate(kind, canonical, value.strip()[:300], False, 0))

    for block_idx, m in enumerate(_CODE_BLOCK_RE.finditer(content_html)):
        if block_idx > 30:
            break
        block = html_mod.unescape(_TAG_RE.sub("", m.group(1)))
        lines = [ln.strip() for ln in block.splitlines() if 6 <= len(ln.strip()) <= 400]
        if not lines:
            continue
        # Majority-prose veto: preformatted bulletins and log excerpts.
        commandish = sum(1 for ln in lines if _COMMANDISH_RE.search(ln) and not _PROSE_START_RE.match(ln))
        if commandish * 2 < len(lines):
            continue
        for line in lines:
            had_prompt = bool(_PROMPT_RE.match(line))
            body = _PROMPT_RE.sub("", line, count=1).strip() if had_prompt else line.lstrip("$#> ").strip()
            if not (6 <= len(body) <= 400):
                continue
            # Structural / comment lines never nominate; a bare "/" can open a
            # real unix path, so only comment markers skip.
            if body[:1] in "{<[\"'-*=" or body.startswith(("//", "/*", "rem ", "REM ")):
                continue
            if _PROSE_START_RE.match(body):
                continue
            if re.match(r"(?i)^hk(?:lm|cu|cr|u|cc)\b", body):
                if not _PLACEHOLDER_RE.search(body) and "\\\\" not in body:
                    add("registry", body)
            elif _WIN_PATH_RE.match(body) or _NIX_PATH_RE.match(body):
                if not _PLACEHOLDER_RE.search(body):
                    add("path", body)
            elif (had_prompt or _looks_like_command(body)) and kind_for_ttp_observable("cmdline", body) == "cmdline":
                add("cmdline", body)
    return out


async def retro_sight_observable(session: AsyncSession, obs: Observable, *, max_entries: int = 20) -> int:
    """Retro-sight one confirmed value across the existing corpus.

    Exact-string search via Meilisearch (phrase query) verified against the
    entry text — searching for a known-bad value is precise; discovering
    values by regex was the trap. Safe by construction: only rows a judgment
    door already created ever reach here."""
    from app.models.entry import Entry
    from app.services.meilisearch_client import search_entries
    from app.services.sanitizer import entry_text_with_translation

    if obs.is_denied or len(obs.value) < 6:
        return 0
    try:
        hits = search_entries(f'"{obs.value}"', limit=max_entries, show_matches=False)
    except Exception:
        return 0
    entry_ids = []
    for hit in hits.get("hits", []):
        try:
            entry_ids.append(uuid_mod.UUID(str(hit.get("id"))))
        except (ValueError, TypeError):
            continue
    if not entry_ids:
        return 0
    rows = (await session.execute(select(Entry).where(Entry.id.in_(entry_ids)))).scalars().all()
    sighted = 0
    needle = obs.value.lower()
    for entry in rows:
        title, text = entry_text_with_translation(entry)
        haystack = f"{title}\n{text}".lower()
        if needle not in haystack and needle not in refang(haystack):
            continue
        if await record_sighting(
            session, entry.id, obs, source="sighting", surface_form=obs.value, seen_at=entry.published_at
        ):
            sighted += 1
    return sighted
