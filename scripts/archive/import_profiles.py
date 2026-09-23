"""Import legacy markdown intelligence profiles into IntelFeed entities.

Parses the ~3,390 markdown files in ``profiles/`` (YAML frontmatter + prose body,
Obsidian ``[[wikilinks]]``) and folds them into the existing entity tables
(ThreatActor / MalwareFamily / Tool / Country). The prose body lands in
each entity's ``description`` column, which the workbench profile page already
renders as entity-linked GFM markdown, so imported content is usable immediately
with zero frontend work.

Safety-first design (nothing is written unless ``--apply`` is passed):

* **Alias-aware matching** — reuses ``find_entity_by_name_or_alias`` semantics via
  an in-memory index so a profile for "8base" enriches the existing "8base"
  instead of creating a duplicate.
* **Type-conflict quarantine** — if a profile's name/alias matches an entity of a
  *different* type, it is quarantined (not written) for human review.
* **Alias-collision guarding** — a candidate alias is added only if it does not
  already belong to a *different* entity of any type. This is what prevents the
  autolinker from mislabeling unrelated articles.
* **Non-destructive** — existing descriptions are appended-to under a marker (never
  overwritten); structured columns are filled only when currently empty; the
  ``metadata_`` JSONB gets a provenance record without clobbering other keys.
* **Idempotent** — a per-file marker comment in the description means re-running
  ``--apply`` is a no-op for already-imported files.

Run (dry-run analysis, writes a JSON report, touches nothing):
    docker compose -f docker-compose.dev.yml cp ./profiles api:/tmp/profiles
    docker compose -f docker-compose.dev.yml exec api \
        python scripts/archive/import_profiles.py --profiles-dir /tmp/profiles \
        --report /tmp/profiles_report.json

Then, after reviewing the report, apply:
    docker compose -f docker-compose.dev.yml exec api \
        python scripts/archive/import_profiles.py --profiles-dir /tmp/profiles --apply

Full AI-managed import (deterministic import + AI-authored descriptions for the
frontmatter'd files, then AI triage of the ~70% of files whose frontmatter is
missing/broken — the AI picks type/name/aliases and authors a merged description,
routed through the same collision safety rails):
    python scripts/archive/import_profiles.py --profiles-dir /tmp/profiles \
        --apply --ai --ai-classify --backlink

All AI-managed text uses plain entity names — Obsidian ``[[wikilinks]]`` and local
``[x](y.md)`` links are stripped both deterministically and via prompt instruction.
"""

import argparse
import asyncio
import difflib
import json
import re
import shutil
import sys
from collections import defaultdict
from datetime import UTC, date, datetime
from pathlib import Path

sys.path.insert(0, "/app")
sys.path.insert(0, "backend")

import yaml  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.database import async_session  # noqa: E402
from app.models.country import Country  # noqa: E402
from app.models.malware_family import MalwareFamily  # noqa: E402
from app.models.product import Product  # noqa: E402
from app.models.threat_actor import ThreatActor  # noqa: E402
from app.models.tool import Tool  # noqa: E402
from app.models.vendor import Vendor  # noqa: E402

# ─── Type mapping ───────────────────────────────────────────────────────────

# Entity types this importer writes to, mapped to their ORM model.
TYPE_MODEL = {
    "threat_actor": ThreatActor,
    "malware": MalwareFamily,
    "tool": Tool,
    "country": Country,
}
# Additional alias-bearing models included ONLY for collision / cross-type
# conflict detection (not written to in this pass).
COLLISION_MODELS = {**TYPE_MODEL, "vendor": Vendor, "product": Product}

# Specific profiles the source data mis-filed as "Security Tool" that are really
# products/companies. Rerouted to the correct table (per user direction). Only
# these named vendor/product creations are written; generic company-classified
# profiles remain deferred.
FORCE_TYPE = {
    "accellion": "vendor",
    "activemq": "product",
    "arcserve": "vendor",
    "atera": "vendor",
    "coalfire": "vendor",
    "datadog": "vendor",
}
# Entity types this pass actually writes to.
WRITE_MODELS = {**TYPE_MODEL, "vendor": Vendor, "product": Product}

# Malware sub-type keywords (checked before tool, since "remote access tool" is
# malware but "security tool" is an offensive tool).
_MALWARE_KW = [
    "malware",
    "backdoor",
    "trojan",
    "remote access",
    "rat ",
    "loader",
    "stealer",
    "botnet",
    "worm",
    "wiper",
    "rootkit",
    "spyware",
    "dropper",
    "downloader",
    "webshell",
    "web shell",
    "implant",
    "ransomware",
    "keylogger",
    "infostealer",
    "banking trojan",
    "cryptominer",
    "miner",
    "bootkit",
    "adware",
]
_ACTOR_KW = [
    "threat actor",
    "apt",
    "advanced persistent",
    "intrusion set",
    "espionage group",
    "hacktivist",
    "cybercriminal",
    "cyber criminal",
    "adversary",
    "hacking group",
    "crime group",
    "ransomware group",
    "ransomware gang",
    "state sponsored",
]
_TOOL_KW = [
    "security tool",
    "offensive tool",
    "hacking tool",
    "pentest",
    "penetration test",
    "framework",
    "post-exploitation",
    "post exploitation",
    "c2 ",
    "command and control",
    "scanner",
    "utility",
    "red team",
]


def _norm_kw(s: str) -> str:
    """Lowercase and collapse _/-/whitespace so 'threat_actor' == 'threat actor'."""
    return re.sub(r"[\s_\-]+", " ", str(s or "").strip().lower().strip("\\"))


def classify(fm: dict) -> tuple[str | None, str]:
    """Return (entity_type, reason) from frontmatter. type=None means skip.

    Returned type may be one of the writable TYPE_MODEL keys, or 'campaign' /
    'vendor' which the caller routes to the deferred (skip_unsupported_type) bucket.
    """
    stix_type = _norm_kw(fm.get("type"))
    if stix_type in ("threat actor", "intrusion set"):
        return "threat_actor", f"stix type={stix_type}"
    if stix_type == "malware":
        return "malware", "stix type=malware"
    if stix_type == "tool":
        return "tool", "stix type=tool"
    if stix_type == "campaign":
        return "campaign", "stix type=campaign"

    classification = _norm_kw(fm.get("classification"))
    tags = _norm_kw(" ".join(str(t) for t in (fm.get("tags") or [])))
    hay = f"{classification} {tags}"

    if "campaign" in classification or "operation" in classification:
        return "campaign", f"classification={classification!r}"
    if any(k in classification for k in ("company", "corporation", "vendor")):
        return "vendor", f"classification={classification!r}"
    # Group-flavoured ransomware ("Ransomware Group", ransomware + threat-actor tag)
    # is an actor; bare "ransomware" is malware — actor check runs first.
    if any(k in classification for k in _ACTOR_KW):
        return "threat_actor", f"classification={classification!r}"
    ransomware_group = "ransomware" in classification and (
        "group" in hay or "gang" in hay or "threat actor" in tags or " actor" in f" {tags}"
    )
    if ransomware_group:
        return "threat_actor", f"classification={classification!r} + group tag"
    if any(k in classification for k in ("country", "nation", "geographic", "territory")):
        return "country", f"classification={classification!r}"
    malware_tags = any(k in tags for k in ("malware", "backdoor", "trojan", "ransomware", "rat"))
    if any(k in classification for k in _MALWARE_KW) or malware_tags:
        return "malware", f"classification={classification!r}"
    if classification == "tool" or any(k in classification for k in _TOOL_KW):
        return "tool", f"classification={classification!r}"

    return None, f"unmapped classification={classification!r} tags={tags[:60]!r}"


# ─── Parsing ────────────────────────────────────────────────────────────────

_FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)
_HEX_STEM = re.compile(r"^[0-9a-f]{5,}$")
_ALIAS_STOP = {"apt", "rat", "malware", "tool", "group", "the", "aka", "n/a", "unknown"}


def parse_file(path: Path) -> dict | None:
    """Parse one markdown profile into a normalized dict, or None if unusable."""
    raw = path.read_text(encoding="utf-8", errors="replace").lstrip("﻿ \t\r\n")
    m = _FM_RE.match(raw)
    fm: dict = {}
    body = raw
    if m:
        try:
            loaded = yaml.safe_load(m.group(1))
            if isinstance(loaded, dict):
                fm = loaded
        except yaml.YAMLError:
            fm = {}
        body = m.group(2)

    stem = path.stem.strip()
    fm_aliases = [str(a).strip() for a in (fm.get("aliases") or []) if str(a).strip()]

    # Canonical name: filename stem, unless it's a junk hash — then first alias.
    name = stem
    if _HEX_STEM.match(stem.lower()) and fm_aliases:
        name = fm_aliases[0]

    # Aliases = frontmatter aliases minus the canonical name (case-insensitive).
    aliases = [a for a in fm_aliases if a.lower() != name.lower()]

    return {
        "file": path.name,
        "name": name,
        "aliases": aliases,
        "frontmatter": fm,
        "has_frontmatter": bool(fm),
        "body": body.strip(),
    }


def clean_alias_candidates(aliases: list[str], name: str) -> list[str]:
    """Drop junk aliases (too short, all-digits, stopwords, == name)."""
    out, seen = [], set()
    for a in aliases:
        low = a.strip().lower()
        if not low or low == name.lower() or low in seen:
            continue
        if len(low) < 3 or low.isdigit() or low in _ALIAS_STOP:
            continue
        seen.add(low)
        out.append(a.strip())
    return out


# ─── In-memory entity index ─────────────────────────────────────────────────


def _squash(s: str) -> str:
    """Lowercase and drop all non-alphanumerics: 'APT-29' == 'apt 29' == 'APT29'."""
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


class Index:
    """Case-insensitive term -> [(type, id, name)] across all alias-bearing entities.

    Matching is two-tier: exact lowercase term first, then a punctuation/space-
    squashed form so name variants ('Black Basta' / 'BlackBasta', 'APT 29' /
    'APT29') resolve to the same entity instead of creating duplicates."""

    def __init__(self) -> None:
        self.terms: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        self.squashed: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        # per-type name/alias -> instance id, for same-type resolution
        self.by_type_term: dict[str, dict[str, str]] = defaultdict(dict)
        self.by_type_squashed: dict[str, dict[str, str]] = defaultdict(dict)

    def add(self, etype: str, ident, name: str, aliases: list[str]) -> None:
        sid = str(ident)
        for term in [name, *(aliases or [])]:
            if not term or not str(term).strip():
                continue
            low = str(term).strip().lower()
            self.terms[low].append((etype, sid, name))
            self.by_type_term[etype].setdefault(low, sid)
            sq = _squash(low)
            if sq:
                self.squashed[sq].append((etype, sid, name))
                self.by_type_squashed[etype].setdefault(sq, sid)

    def resolve_same_type(self, etype: str, name: str, aliases: list[str]) -> str | None:
        """Name preferred, then aliases; exact term first, squashed fallback."""
        tt = self.by_type_term.get(etype, {})
        ts = self.by_type_squashed.get(etype, {})
        for term in [name, *(aliases or [])]:
            if not term:
                continue
            hit = tt.get(term.lower()) or ts.get(_squash(term))
            if hit:
                return hit
        return None

    def other_type_hit(self, etype: str, terms: list[str]) -> tuple[str, str, str] | None:
        """First entity of a DIFFERENT type matching any term (for conflict/collision)."""
        for t in terms:
            if not t:
                continue
            for owner in self.terms.get(t.lower(), []) + self.squashed.get(_squash(t), []):
                if owner[0] != etype:
                    return owner
        return None

    def alias_collision(self, self_id: str | None, alias: str) -> tuple[str, str, str] | None:
        """Return an entity that already owns `alias` and isn't `self_id`, else None."""
        for owner in self.terms.get(alias.lower(), []) + self.squashed.get(_squash(alias), []):
            if owner[1] != (self_id or ""):
                return owner
        return None

    def lookup_owners(self, terms: list[str]) -> list[tuple[str, str, str]]:
        """Ordered, deduped owners matching any term exactly or squashed (any type)."""
        out, seen = [], set()
        for t in terms:
            if not t:
                continue
            for owner in self.terms.get(t.lower(), []) + self.squashed.get(_squash(t), []):
                if (owner[0], owner[1]) not in seen:
                    seen.add((owner[0], owner[1]))
                    out.append(owner)
        return out

    def similar(self, terms: list[str], limit: int = 3) -> list[tuple[str, str, str]]:
        """Fuzzy shortlist for near-miss duplicates: squashed substring containment
        ('lockbit' ~ 'lockbit30') plus difflib close matches ('blackbasta' ~
        'blackbastagroup'). Advisory only — results are offered to the AI as merge
        candidates, never auto-merged."""
        out: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()

        def push(owner):
            if (owner[0], owner[1]) not in seen:
                seen.add((owner[0], owner[1]))
                out.append(owner)

        for t in terms:
            sq = _squash(t)
            if len(sq) < 5:
                continue
            for key, owners in self.squashed.items():
                if key != sq and len(key) >= 5 and (sq in key or key in sq):
                    for o in owners:
                        push(o)
            for key in difflib.get_close_matches(sq, self.squashed.keys(), n=limit, cutoff=0.86):
                for o in self.squashed.get(key, []):
                    push(o)
        return out[:limit]


async def build_index(db) -> Index:
    idx = Index()
    for etype, model in COLLISION_MODELS.items():
        rows = (await db.execute(select(model.id, model.name, model.aliases))).all()
        for rid, name, aliases in rows:
            idx.add(etype, rid, name, aliases or [])
    return idx


# ─── Field extraction ───────────────────────────────────────────────────────

_MALWARE_TYPE_MAP = {
    "backdoor": "backdoor",
    "banking trojan": "banking_trojan",
    "trojan": "trojan",
    "remote access": "rat",
    "rat": "rat",
    "ransomware": "ransomware",
    "loader": "loader",
    "stealer": "stealer",
    "infostealer": "stealer",
    "botnet": "botnet",
    "worm": "worm",
    "wiper": "wiper",
    "rootkit": "rootkit",
    "downloader": "downloader",
    "dropper": "dropper",
    "webshell": "webshell",
}


def malware_type_from(fm: dict) -> str | None:
    c = str(fm.get("classification") or "").lower()
    for k, v in _MALWARE_TYPE_MAP.items():
        if k in c:
            return v
    return None


def sectors_from(fm: dict) -> list[str]:
    vals = fm.get("target_sectors") or fm.get("primary_targets") or fm.get("target_regions") or []
    return [str(s).strip() for s in vals if str(s).strip()][:20]


def _json_safe(v):
    """Recursively coerce YAML values (dates, etc.) into JSON-serializable form."""
    if isinstance(v, dict):
        return {k: _json_safe(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_json_safe(x) for x in v]
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)


def provenance(p: dict) -> dict:
    fm = p["frontmatter"]
    keys = (
        "data_source",
        "stix_id",
        "mitre_id",
        "references",
        "tags",
        "classification",
        "attribution",
        "first_seen",
        "status",
    )
    rec = {k: _json_safe(fm.get(k)) for k in keys if fm.get(k)}
    rec["source_file"] = p["file"]
    return rec


# Idempotency record: which source files have been folded into an entity. Lives
# in metadata_.imported_profile.source_files — NOT in the description (HTML
# comment markers used to live there, but the workbench renders them visibly).
def imported_files(obj) -> set[str]:
    ip = (obj.metadata_ or {}).get("imported_profile") or {}
    return {str(f) for f in (ip.get("source_files") or [])}


def record_import(ip: dict, file: str) -> None:
    """Add `file` to the imported_profile source_files list (idempotent)."""
    ip["source_files"] = sorted({*(str(f) for f in (ip.get("source_files") or [])), file})


def stash_pre_import(meta_ip: dict, current_desc: str | None) -> None:
    """Record the entity's pre-import description ONCE (survives reruns) so any
    bad AI merge can be reverted per-entity without a full DB restore."""
    if "pre_import_description" not in meta_ip:
        meta_ip["pre_import_description"] = current_desc or ""


def dispatch_backlinks_staggered(to_backlink, stagger_seconds: int) -> tuple[int, int]:
    """Queue backlink tasks spread out over time. Each task rescans ALL entries
    for one entity; dispatching hundreds at once would monopolize the Celery
    worker for hours and starve feed processing."""
    from app.workers.intel_feed_tasks import link_new_entity_to_entries

    ok = failed = 0
    for i, (etype, obj) in enumerate(to_backlink):
        try:
            link_new_entity_to_entries.apply_async(
                kwargs={"entity_type": etype, "entity_id": str(obj.id)},
                countdown=5 + i * stagger_seconds,
            )
            ok += 1
        except Exception:  # noqa: BLE001
            failed += 1
    return ok, failed


async def bump_autolinker_vocab() -> bool:
    """Force every worker to rebuild the autolinker vocabulary from the DB.

    The script writes entities directly (bypassing the API), so nothing else
    bumps the Redis vocab version — without this, new entities/aliases stay
    invisible to the autolinker for future articles."""
    try:
        from app.intelligence.autolinker import VOCAB_VERSION_KEY
        from app.services.redis_client import get_redis

        r = await get_redis()
        await r.set(VOCAB_VERSION_KEY, f"import-{datetime.now(UTC).isoformat()}")
        return True
    except Exception:  # noqa: BLE001
        return False


# Obsidian [[Name]] / [[Target|Display]] wikilinks and local [Label](File.md) links.
# Imported/AI-managed descriptions keep plain names only — the platform auto-links
# known entities itself, and the bracket syntax renders as literal noise.
_WIKILINK_RE = re.compile(r"\[\[([^\]|]+?)(?:\|([^\]]+?))?\]\]")
_LOCAL_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((?:\./)?[^)\s]+\.md\)")
# After bracket-stripping, an Obsidian image embed ![[x.png]] degrades to "!x.png".
_IMG_LEFTOVER_RE = re.compile(r"!\s*[\w./ -]+\.(?:png|jpe?g|gif|webp|svg)", re.IGNORECASE)


def strip_wikilinks(text: str) -> str:
    """Replace [[wikilinks]] and local .md links with their plain display text.

    Wikilinks in the corpus can be NESTED ("![[[[Bahrain]].png]]",
    "[[ [[T1006]] ]]"), so substitution iterates to a fixpoint. Image embeds are
    removed outright — their attachments don't exist in the platform."""
    for _ in range(6):
        new = _WIKILINK_RE.sub(lambda m: (m.group(2) or m.group(1)).strip(), text)
        if new == text:
            break
        text = new
    text = _IMG_LEFTOVER_RE.sub("", text)
    return _LOCAL_MD_LINK_RE.sub(r"\1", text)


# Whole sections dropped during rework — provenance / reference echo, not substance.
# Atomic-IOC dumps (IPs, domains, hashes) are dropped too; IOA / behavioral
# indicator sections are intelligence and are kept ("indicator of attack",
# "behavioral indicators" etc. match none of these keywords).
_DROP_SECTIONS = (
    "external reference",
    "reference",
    "source information",
    "mitre att&ck data",
    "external link",
    "citation",
    "further reading",
    "stix",
    "raw data",
    "created by",
    "data source",
    "full json",
    "kill chain phase",
    "related profile",
    "related note",
    "ioc",
    "indicator of compromise",
    "indicators of compromise",
    "network indicator",
    "host-based indicator",
    "host based indicator",
    "file indicator",
    "file system indicator",
    "infrastructure indicator",
)
# Exact-title drops — substring matching on short/common words would swallow
# legitimate sections (or, with level-aware dropping, entire files: 'platform'
# used to match the H1 'APT27 ... Multi-Platform Espionage Group' and drop
# everything under it). Kept exact: echo/boilerplate sections only.
_DROP_EXACT = (
    "literature",
    "license",
    "license information",
    "license and attribution",
    "platform",
    "platforms",
    "label",
    "labels",
    "json",
    "metadata",
    "sources",
)
# Leading "**Label:**" lines that merely echo structured columns we already store.
_DROP_BOLD = (
    "also known as",
    "aka",
    "classification",
    "mitre id",
    "mitre attack id",
    "first seen",
    "active since",
    "status",
    "stix",
)
_STUB_LEN = 200  # existing descriptions shorter than this are treated as stubs.


def rework_body(body: str) -> str:
    """Deduplicate a raw profile body: drop the H1 title, boilerplate header echo,
    provenance/reference sections, atomic-IOC dumps, and Related Notes. Keeps the
    substantive narrative (overview, TTPs, operations, indicators of ATTACK).

    Dropping is level-aware: a dropped section swallows its own subsections
    (e.g. '### Network Indicators' under '## IOC - Indicator of Compromise')
    until a heading at the same or higher level ends it."""
    out: list[str] = []
    drop_level: int | None = None
    in_fence = False
    for line in body.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            if drop_level is None:
                out.append(line)
            continue
        h = None if in_fence else re.match(r"^(#{1,6})\s+(.*)$", line)
        if h:
            level = len(h.group(1))
            if drop_level is not None and level > drop_level:
                continue  # subsection of a dropped section
            title = h.group(2).strip().lower()
            if title in _DROP_EXACT or any(k in title for k in _DROP_SECTIONS):
                drop_level = level
                continue
            drop_level = None
            if level == 1:
                continue  # drop the top-level title echo
            out.append(line)
            continue
        if drop_level is not None:
            continue
        m = re.match(r"^\*\*([^:*]+):\*\*", line.strip())
        if m and any(k in m.group(1).strip().lower() for k in _DROP_BOLD):
            continue
        out.append(line)
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()
    return strip_wikilinks(text)


def build_description(existing: str | None, p: dict, already_imported: bool) -> tuple[str | None, str]:
    """Return (new_description or None-if-unchanged, action). Non-destructive and
    idempotent; content is reworked (not copied 1:1) to avoid duplication."""
    body = rework_body(p["body"])
    if not body:
        return None, "no-body"
    if already_imported:
        return None, "already-imported"
    cur = (existing or "").strip()
    # Empty or thin stub → replace with the reworked profile (no duplication).
    if len(cur) < _STUB_LEN:
        return body, "set"
    # Substantial existing text → append reworked profile under a heading.
    return f"{existing.rstrip()}\n\n## Imported profile\n\n{body}", "appended"


# ─── Evaluation ─────────────────────────────────────────────────────────────


async def evaluate(db, profiles: list[dict], idx: Index, include_vendors: bool) -> dict:
    """Classify every profile into buckets. Read-only."""
    buckets: dict[str, list] = defaultdict(list)
    seen_in_batch: dict[tuple[str, str], str] = {}  # (type, matched_id or name) -> file

    for p in profiles:
        fm = p["frontmatter"]
        if not p["has_frontmatter"]:
            buckets["skip_no_frontmatter"].append({"file": p["file"], "name": p["name"]})
            continue

        etype, reason = classify(fm)
        forced = FORCE_TYPE.get(p["name"].strip().lower())
        if forced:
            etype, reason = forced, f"forced reroute → {forced} (source mis-filed as tool)"
        if etype is None:
            buckets["skip_no_type"].append({"file": p["file"], "name": p["name"], "reason": reason})
            continue
        # Writable = a core type, or one of the explicitly forced vendor/product names.
        if etype not in TYPE_MODEL and not forced:
            buckets["skip_unsupported_type"].append({"file": p["file"], "name": p["name"], "type": etype})
            continue

        name, aliases = p["name"], p["aliases"]

        # Junk hash-only name with no real alias to fall back on → skip.
        if _HEX_STEM.match(name.lower()) and any(c.isdigit() for c in name) and not aliases:
            buckets["skip_junk_name"].append({"file": p["file"], "name": name, "type": etype})
            continue

        terms = [name, *aliases]
        match_id = idx.resolve_same_type(etype, name, aliases)

        # Cross-type conflict: name/alias owned by a different entity type.
        # Skipped for forced reroutes — the user directed those explicitly.
        if match_id is None and not forced:
            other = idx.other_type_hit(etype, terms)
            if other is not None:
                buckets["conflict_cross_type"].append(
                    {
                        "file": p["file"],
                        "name": name,
                        "intended_type": etype,
                        "conflicts_with": {"type": other[0], "name": other[2], "id": other[1]},
                        "reason": reason,
                    }
                )
                continue

        # Within-batch dedupe (squashed, so "Black Basta.md" + "BlackBasta.md" collide).
        batch_key = (etype, match_id or _squash(name))
        if batch_key in seen_in_batch:
            buckets["conflict_duplicate_in_batch"].append(
                {
                    "file": p["file"],
                    "name": name,
                    "type": etype,
                    "duplicate_of_file": seen_in_batch[batch_key],
                }
            )
            continue
        seen_in_batch[batch_key] = p["file"]

        # Alias safety: keep only non-colliding, non-junk aliases.
        candidates = clean_alias_candidates(aliases, name)
        safe_aliases, dropped = [], []
        for a in candidates:
            coll = idx.alias_collision(match_id, a)
            if coll is not None:
                dropped.append({"alias": a, "owned_by": {"type": coll[0], "name": coll[2]}})
            else:
                safe_aliases.append(a)

        rec = {
            "file": p["file"],
            "name": name,
            "type": etype,
            "reason": reason,
            "match_id": match_id,
            "safe_aliases": safe_aliases,
            "dropped_aliases": dropped,
            "body_chars": len(p["body"]),
            "mitre_id": fm.get("mitre_id"),
            "sectors": sectors_from(fm),
            "malware_type": malware_type_from(fm) if etype == "malware" else None,
            "platforms": [str(x) for x in (fm.get("platform") or [])] if etype == "tool" else None,
        }
        buckets["enrich" if match_id else "create"].append(rec)

    return buckets


# ─── Apply ──────────────────────────────────────────────────────────────────


async def apply_bucket(db, buckets: dict, profiles_by_file: dict, backlink: bool, stagger: int = 15) -> dict:
    stats = defaultdict(int)
    now = datetime.now(UTC)
    to_backlink: list[tuple[str, object]] = []  # (entity_type, obj) — resolved to id post-commit

    async def _write(rec: dict, create: bool):
        model = WRITE_MODELS[rec["type"]]
        p = profiles_by_file[rec["file"]]
        if create:
            obj = model(name=rec["name"], aliases=[])
            db.add(obj)
        else:
            obj = await db.get(model, rec["match_id"])
            if obj is None:
                stats["missing_on_apply"] += 1
                return

        # description (non-destructive / idempotent via metadata source_files)
        new_desc, action = build_description(
            obj.description, p, already_imported=not create and p["file"] in imported_files(obj)
        )
        if new_desc is not None:
            obj.description = new_desc
            stats[f"desc_{action}"] += 1

        # aliases (union with safe candidates)
        existing = {a.lower() for a in (obj.aliases or [])}
        merged = list(obj.aliases or [])
        added_aliases = 0
        for a in rec["safe_aliases"]:
            if a.lower() not in existing:
                merged.append(a)
                existing.add(a.lower())
                stats["aliases_added"] += 1
                added_aliases += 1
        obj.aliases = merged

        # structured fills (only when empty)
        if rec.get("mitre_id") and hasattr(obj, "mitre_id") and not obj.mitre_id:
            obj.mitre_id = str(rec["mitre_id"])[:20]
        if rec["type"] == "malware" and rec.get("malware_type") and not obj.malware_type:
            obj.malware_type = rec["malware_type"]
        if rec["type"] == "tool" and rec.get("platforms") and not (obj.platforms or []):
            obj.platforms = rec["platforms"]
        if rec.get("sectors") and hasattr(obj, "targeted_sectors") and not (obj.targeted_sectors or []):
            obj.targeted_sectors = rec["sectors"]

        # provenance metadata (merge, don't clobber — a rerun must not wipe
        # ai_reworked_at / pre_import_description written by the AI pass)
        meta = dict(obj.metadata_ or {})
        ip = dict(meta.get("imported_profile") or {})
        ip.update({**provenance(p), "imported_at": now.isoformat()})
        record_import(ip, p["file"])
        meta["imported_profile"] = ip
        obj.metadata_ = meta

        # Backlink newly created entities, and enrichments that actually gained
        # new aliases (new names to match against existing articles).
        if create or added_aliases:
            to_backlink.append((rec["type"], obj))

        stats["created" if create else "enriched"] += 1

    for rec in buckets.get("create", []):
        await _write(rec, create=True)
    for rec in buckets.get("enrich", []):
        await _write(rec, create=False)

    await db.commit()

    if backlink and to_backlink:
        ok, failed = dispatch_backlinks_staggered(to_backlink, stagger)
        stats["backlink_dispatched"] += ok
        stats["backlink_failed"] += failed

    return dict(stats)


# ─── AI rework via IntelFeed's configured provider ──────────────────────────
#
# The script calls the platform's own AI provider (Settings → AI) so it is
# self-contained on prod: descriptions/aliases are AI-authored at import time,
# never raw dumps. Junk / wrong-type entities are quarantined (source file moved
# aside + entity flagged), never deleted.

DEFAULT_MODEL = "claude-haiku-4-5-20251001"
QUARANTINE_META_KEY = "quarantine"
_AI_CHUNK = 100  # AI calls per commit batch — bounds transaction time and crash loss

REWORK_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "action": {"type": "string", "enum": ["rewrite", "junk", "wrong_type"]},
        "description": {"type": "string"},
        "aliases": {"type": "array", "items": {"type": "string"}},
        "analyst_note": {"type": "string"},
        "suggested_type": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["action", "description", "aliases", "analyst_note", "suggested_type", "confidence"],
}

REWORK_SYSTEM = """You are a senior threat-intelligence analyst curating entity profiles for a \
threat-intelligence platform (TIP). You receive a legacy Markdown profile for a single entity of a \
stated type (threat_actor, malware, tool, country, vendor, product). These were scraped from mixed \
sources and are often outdated, heavily duplicated, or occasionally junk / misclassified.

Return a JSON object per the schema:

- action:
  - "rewrite": a legitimate entity of the stated type. Provide a clean description.
  - "wrong_type": a real entity but the WRONG type (e.g. a product stored as a tool, an actor stored \
as malware). Set suggested_type to the correct one.
  - "junk": not a real intelligence entity (bulk IP/infrastructure dump, empty/garbage file, generic term).

- description: a concise, de-duplicated, analyst-grade profile in Markdown.
  * Invent NOTHING. Use only facts present in the source. If the source is thin, keep it short.
  * Strip all boilerplate: header/alias echo lines, reference/citation lists, raw JSON/STIX blobs.
  * Write entity names as PLAIN TEXT — never Obsidian [[wikilink]] brackets or
    local .md links. If the source has [[APT29]] or [[x|Display]], output just the
    name; the platform auto-links known entities itself.
  * If an EXISTING PLATFORM DESCRIPTION is provided, MERGE it with the source into
    one coherent profile: keep every unique fact from both, drop duplicated ground,
    prefer the more specific/recent claim on conflicts. Never discard existing
    intelligence just because the source omits it.
  * Keep concrete intelligence: attribution, dates, MITRE/STIX IDs, key TTPs,
    targeted sectors/regions, notable campaigns, capabilities.
  * DROP atomic IOCs — IP addresses, domains, URLs, file hashes, email addresses,
    filenames-as-indicators, and 'IOC / Indicators of Compromise' lists. KEEP
    indicators of ATTACK (IOA): behavioral TTPs, tooling, persistence and
    lateral-movement techniques, and other detection-relevant behaviors.
  * 120-320 words for a rich entity; fewer if sparse. End with one
    '**Analyst note:**' line assessing source freshness/reliability.
  * For junk / wrong_type, still give a 1-2 sentence description of what it actually is.

- aliases: the clean, de-duplicated canonical alias set (names only, no descriptions). Exclude the \
canonical name, generic words, and anything that is actually a different entity. Empty array if none.
- analyst_note: one sentence summarizing your assessment.
- suggested_type: the correct type if action=wrong_type, otherwise repeat the stated type.
- confidence: high / medium / low in the action classification.

Output ONLY the JSON object."""


def _same_type(suggested: str | None, etype: str) -> bool:
    """True if an AI-suggested type is really the same as the current entity type."""
    s = _norm_kw(suggested).replace(" ", "_")
    synonyms = {"malware_family": "malware", "tool": "tool", "attack_technique": "ttp"}
    s = synonyms.get(s, s)
    return s in ("", etype)


async def load_ai_provider(db):
    """Return (provider_instance, provider_model) for the active configured AI provider."""
    from app.ai.engine import _get_provider_instance
    from app.models.ai_provider import AIProvider as AIProviderModel

    rows = (
        (
            await db.execute(select(AIProviderModel).where(AIProviderModel.is_active == True))  # noqa: E712
        )
        .scalars()
        .all()
    )
    # Prefer an API-key provider (batch-friendly) over the interactive CLI provider.
    chosen = next((r for r in rows if r.provider_type == "claude" and r.api_key_encrypted), None)
    chosen = chosen or next((r for r in rows if r.api_key_encrypted), None) or (rows[0] if rows else None)
    if chosen is None:
        raise RuntimeError("No active AI provider configured (Settings → AI)")
    return _get_provider_instance(chosen), chosen


async def ai_rework_one(provider, model, etype, name, aliases, raw_md, existing_desc=""):
    """Call the provider to rework one profile; returns the parsed JSON dict."""
    # Bound token cost on pathologically large files (head + tail keep the useful parts).
    if len(raw_md) > 24000:
        raw_md = raw_md[:16000] + "\n\n...[source truncated]...\n\n" + raw_md[-6000:]
    if len(existing_desc) > 12000:
        existing_desc = existing_desc[:12000] + "\n\n...[truncated]..."
    existing_block = (
        f"EXISTING PLATFORM DESCRIPTION (merge with the source; keep unique facts):\n---\n{existing_desc}\n---\n\n"
        if existing_desc
        else ""
    )
    prompt = (
        f"ENTITY TYPE (as currently stored): {etype}\n"
        f"CANONICAL NAME: {name}\n"
        f"EXISTING ALIASES: {', '.join(aliases) or '(none)'}\n\n"
        f"{existing_block}"
        f"SOURCE PROFILE MARKDOWN:\n---\n{raw_md}\n---"
    )
    resp = await provider.complete(
        prompt=prompt,
        system=REWORK_SYSTEM,
        model=model,
        temperature=0.0,
        max_tokens=1800,
        response_format=REWORK_SCHEMA,
        timeout_seconds=150,
    )
    return json.loads(resp.content)


async def ai_rework_entities(db, profiles_dir, quarantine_dir, model, concurrency, limit, report_path):
    """Re-author descriptions/aliases for already-imported entities via AI.

    Used to repair a raw import (dev) and reused inside the prod fresh-import flow
    so prod descriptions are AI-authored, never raw dumps.
    """
    provider, pm = await load_ai_provider(db)
    print(f"AI provider: {pm.name} ({pm.provider_type})  model={model}  concurrency={concurrency}", flush=True)

    targets = []
    for etype, mc in WRITE_MODELS.items():
        rows = (await db.execute(select(mc).where(mc.metadata_.has_key("imported_profile")))).scalars().all()  # noqa: W601
        for obj in rows:
            sf = (obj.metadata_ or {}).get("imported_profile", {}).get("source_file")
            # Skip ones already AI-reworked (idempotent) unless re-forced.
            already = (obj.metadata_ or {}).get("imported_profile", {}).get("ai_reworked_at")
            if sf and not already:
                targets.append({"etype": etype, "obj": obj, "source_file": sf})
    if limit:
        targets = targets[:limit]
    print(f"AI-reworking {len(targets)} imported entities...", flush=True)
    if not targets:
        return {"rewritten": [], "quarantined": [], "errors": []}

    idx = await build_index(db)
    pdir = Path(profiles_dir)
    qdir = Path(quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(concurrency)
    now = datetime.now(UTC)
    report = {"rewritten": [], "quarantined": [], "errors": []}
    done = 0

    def pre_import_desc(obj, sf: str) -> str:
        """The entity's description as it stood before this file's import touched it.

        The metadata stash is authoritative when present — after an AI rewrite the
        live description no longer contains the original text, so a re-rework
        without the stash would merge against nothing."""
        stashed = ((obj.metadata_ or {}).get("imported_profile") or {}).get("pre_import_description")
        if stashed:
            return stashed
        cur = obj.description or ""
        if "\n## Imported profile\n" in cur:
            return cur.split("\n## Imported profile\n", 1)[0].strip()
        if sf in imported_files(obj):
            return ""  # description was set from the import itself; source covers it
        return cur.strip()

    async def call_ai(t):
        nonlocal done
        async with sem:
            src = pdir / t["source_file"]
            if not src.exists():
                return t, None, "source-missing"
            raw = src.read_text(encoding="utf-8", errors="replace")
            try:
                data = await ai_rework_one(
                    provider,
                    model,
                    t["etype"],
                    t["obj"].name,
                    t["obj"].aliases or [],
                    raw,
                    existing_desc=pre_import_desc(t["obj"], t["source_file"]),
                )
                return t, data, None
            except Exception as e:  # noqa: BLE001
                return t, None, f"{type(e).__name__}: {e}"[:200]
            finally:
                done += 1
                if done % 25 == 0:
                    print(f"  ...{done}/{len(targets)}", flush=True)

    def route(t, data, err) -> None:
        obj, etype, sf = t["obj"], t["etype"], t["source_file"]
        if err or not data:
            report["errors"].append({"name": obj.name, "type": etype, "file": sf, "error": err})
            return
        action = data.get("action", "rewrite")
        # "wrong_type" only counts if the suggested type actually DIFFERS from the
        # current one — otherwise the model contradicted itself; treat as a rewrite.
        if action == "wrong_type" and _same_type(data.get("suggested_type"), etype):
            action = "rewrite"
        if action in ("junk", "wrong_type"):
            try:
                if (pdir / sf).exists():
                    shutil.move(str(pdir / sf), str(qdir / sf))
            except OSError:
                pass
            meta = dict(obj.metadata_ or {})
            meta[QUARANTINE_META_KEY] = {
                "reason": action,
                "suggested_type": data.get("suggested_type"),
                "note": data.get("analyst_note"),
                "confidence": data.get("confidence"),
                "at": now.isoformat(),
            }
            obj.metadata_ = meta
            report["quarantined"].append(
                {
                    "name": obj.name,
                    "type": etype,
                    "file": sf,
                    "reason": action,
                    "suggested_type": data.get("suggested_type"),
                    "note": data.get("analyst_note"),
                }
            )
            return
        # rewrite
        desc = strip_wikilinks((data.get("description") or "").strip())
        if not desc:
            report["errors"].append({"name": obj.name, "type": etype, "file": sf, "error": "empty-description"})
            return
        pre_import = pre_import_desc(obj, sf)
        obj.description = desc
        ai_aliases = clean_alias_candidates([str(a) for a in (data.get("aliases") or [])], obj.name)
        merged = list(obj.aliases or [])
        existing = {a.lower() for a in merged}
        added = 0
        for a in ai_aliases:
            if a.lower() in existing or idx.alias_collision(str(obj.id), a) is not None:
                continue
            merged.append(a)
            existing.add(a.lower())
            added += 1
        obj.aliases = merged
        meta = dict(obj.metadata_ or {})
        meta.pop(QUARANTINE_META_KEY, None)  # clear any stale quarantine flag
        ip = dict(meta.get("imported_profile") or {})
        stash_pre_import(ip, pre_import)
        ip["ai_reworked_at"] = now.isoformat()
        meta["imported_profile"] = ip
        obj.metadata_ = meta
        report["rewritten"].append(
            {
                "name": obj.name,
                "type": etype,
                "aliases_added": added,
                "desc_len": len(desc),
                "confidence": data.get("confidence"),
            }
        )

    # Chunked AI -> write -> commit: progress survives a crash (idempotent reruns
    # skip completed entities), and no transaction stays open for the whole run.
    await db.commit()  # close the target-prefetch read transaction
    for start in range(0, len(targets), _AI_CHUNK):
        chunk = targets[start : start + _AI_CHUNK]
        results = await asyncio.gather(*(call_ai(t) for t in chunk))
        for t, data, err in results:
            route(t, data, err)
        await db.commit()
    Path(report_path).write_text(json.dumps(report, indent=2, default=str))
    print(
        f"\nrewritten={len(report['rewritten'])} "
        f"quarantined={len(report['quarantined'])} errors={len(report['errors'])}"
    )
    print(f"AI report -> {report_path}")
    return report


# ─── AI classification of files the deterministic pass could not route ──────
#
# ~70% of the corpus has missing or mangled frontmatter (no ``type`` /
# ``classification`` to key on), so classify() can never bucket it. This pass
# hands each such file to the AI: it decides the entity type, canonical name,
# aliases, and authors the description — then the result flows through the same
# collision / cross-type safety rails as the deterministic import.

CLASSIFY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "action": {"type": "string", "enum": ["create", "merge", "skip"]},
        "entity_type": {
            "type": "string",
            "enum": ["threat_actor", "malware", "tool", "country", "vendor", "product", "campaign", "other"],
        },
        "canonical_name": {"type": "string"},
        "merge_target": {"type": "string"},
        "aliases": {"type": "array", "items": {"type": "string"}},
        "description": {"type": "string"},
        "analyst_note": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": [
        "action",
        "entity_type",
        "canonical_name",
        "merge_target",
        "aliases",
        "description",
        "analyst_note",
        "confidence",
    ],
}

CLASSIFY_SYSTEM = """You are a senior threat-intelligence analyst triaging legacy Markdown profile \
files with missing or broken metadata for import into a threat-intelligence platform (TIP).

You receive one source file (filename + content) and a list of EXISTING PLATFORM ENTITIES that \
may correspond to it (found by exact name/alias lookup, normalized variants, and fuzzy similarity \
across the entire entity workbench).

DUPLICATE DISCIPLINE — the platform must never gain a duplicate profile. The file's subject may \
be the same entity under a different spelling, or merely an ALIAS of an existing entity (e.g. a \
file 'Grim Spider.md' when the platform tracks it as 'Wizard Spider'). Check every candidate \
before choosing "create". If identity is plausible but you cannot be confident, choose "skip" \
and explain — those files go to human review; a wrong "create" pollutes the workbench.

Return a JSON object per the schema:

- action:
  - "merge": the file describes the SAME real-world entity as one of the listed candidates. Set \
merge_target to that candidate's exact name.
  - "create": a legitimate intelligence entity matching NONE of the candidates.
  - "skip": not an importable entity — junk, a bulk IOC/infrastructure dump, a generic concept, \
a person, an empty/boilerplate-only file — or a suspected-but-unconfirmed duplicate.
- entity_type: what the file actually describes: threat_actor, malware, tool (offensive/security \
tool), country, vendor (company), product, campaign, or other.
- canonical_name: the entity's proper name (from the content, never a filename hash).
- merge_target: exact name of the chosen candidate when action=merge, otherwise "".
- aliases: clean canonical alias set, excluding the canonical name and generic words. Empty if none.
- description: a concise, de-duplicated, analyst-grade profile in Markdown.
  * Invent NOTHING. Use only facts present in the inputs. If the source is thin, keep it short.
  * When action=merge, MERGE the merge target's existing description with the source: keep every \
unique fact from both, drop duplicated ground, prefer the more specific/recent claim on conflicts.
  * Write entity names as PLAIN TEXT — never Obsidian [[wikilink]] brackets or local .md links.
  * Strip boilerplate: header/alias echoes, reference/citation lists, raw JSON/STIX, link dumps.
  * Keep concrete intelligence: attribution, dates, MITRE/STIX IDs, key TTPs, targeted \
sectors/regions, notable campaigns, capabilities.
  * DROP atomic IOCs — IP addresses, domains, URLs, file hashes, email addresses, and 'IOC / \
Indicators of Compromise' lists. KEEP indicators of ATTACK (IOA): behavioral TTPs, tooling, \
persistence and lateral-movement techniques, and other detection-relevant behaviors.
  * 120-320 words for a rich entity; fewer if sparse. End with one '**Analyst note:**' line.
  * For skip, 1-2 sentences on what the file actually is.
- analyst_note: one sentence summarizing your assessment.
- confidence: high / medium / low in the action + type classification.

Output ONLY the JSON object."""

_ET_SYNONYMS = {"malware_family": "malware", "tool": "tool", "apt_group": "threat_actor"}


def _fill_structured(obj, et: str, fm: dict) -> None:
    """Fill structured columns from frontmatter, only where currently empty
    (mirrors the deterministic apply path)."""
    if fm.get("mitre_id") and hasattr(obj, "mitre_id") and not obj.mitre_id:
        obj.mitre_id = str(fm["mitre_id"])[:20]
    if et == "malware" and not obj.malware_type:
        mt = malware_type_from(fm)
        if mt:
            obj.malware_type = mt
    if et == "tool" and not (obj.platforms or []):
        platforms = [str(x) for x in (fm.get("platform") or [])]
        if platforms:
            obj.platforms = platforms
    if hasattr(obj, "targeted_sectors") and not (obj.targeted_sectors or []):
        sectors = sectors_from(fm)
        if sectors:
            obj.targeted_sectors = sectors


async def ai_classify_files(
    db, profiles_by_file, buckets, profiles_dir, model, concurrency, limit, apply, report_path, backlink, stagger=15
):
    """AI-triage files the deterministic pass skipped; create/enrich entities from them."""
    provider, pm = await load_ai_provider(db)
    pdir = Path(profiles_dir)
    idx = await build_index(db)

    files = [
        r["file"]
        for r in buckets.get("skip_no_frontmatter", [])
        + buckets.get("skip_no_type", [])
        + buckets.get("ai_create_review", [])
        # company/campaign-classified frontmatter: the AI decides — vendors and
        # products are creatable (user-approved), campaigns still get skipped.
        + buckets.get("skip_unsupported_type", [])
    ]
    report = {"created": [], "merged": [], "skipped": [], "conflicts": [], "deferred": [], "errors": []}

    # Candidate discovery (exact + squashed + fuzzy over the whole workbench) and
    # already-imported pre-skip (no AI cost for idempotent reruns).
    targets = []
    obj_cache: dict[tuple[str, str], object] = {}
    for f in files:
        p = profiles_by_file.get(f)
        if p is None or not (pdir / f).exists():
            continue
        terms = [p["name"], *p["aliases"]]
        owners = idx.lookup_owners(terms)
        owner_keys = {(o[0], o[1]) for o in owners}
        owners += [o for o in idx.similar(terms) if (o[0], o[1]) not in owner_keys]
        cands, already = [], False
        for etype, oid, _name in owners[:4]:
            if oid.startswith("new:"):  # created earlier in this run's bookkeeping
                continue
            key = (etype, oid)
            if key not in obj_cache:
                obj_cache[key] = await db.get(COLLISION_MODELS[etype], oid)
            obj = obj_cache[key]
            if obj is None:
                continue
            if f in imported_files(obj):
                report["skipped"].append({"file": f, "name": p["name"], "reason": "already-imported"})
                already = True
                break
            cands.append({"etype": etype, "obj": obj})
        if already:
            continue
        targets.append((p, cands))
    if limit:
        targets = targets[:limit]
    print(
        f"AI provider: {pm.name} ({pm.provider_type})  model={model}  concurrency={concurrency}\n"
        f"AI-classifying {len(targets)} unclassified files (apply={apply})...",
        flush=True,
    )
    if not targets:
        Path(report_path).write_text(json.dumps(report, indent=2, default=str))
        return report

    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def call_ai(p, cands):
        nonlocal done
        async with sem:
            raw = (pdir / p["file"]).read_text(encoding="utf-8", errors="replace")
            if len(raw) > 24000:
                raw = raw[:16000] + "\n\n...[source truncated]...\n\n" + raw[-6000:]
            cand_block = ""
            if cands:
                parts = ["EXISTING PLATFORM ENTITIES THAT MAY MATCH (check each before creating anything new):"]
                for i, c in enumerate(cands, 1):
                    obj = c["obj"]
                    desc = (obj.description or "").strip()
                    cap = 8000 if i == 1 else 3000
                    if len(desc) > cap:
                        desc = desc[:cap] + "\n...[truncated]..."
                    parts.append(
                        f"[candidate {i}] type={c['etype']}  name={obj.name}\n"
                        f"aliases: {', '.join(obj.aliases or []) or '(none)'}\n"
                        f"current description:\n{desc or '(empty)'}"
                    )
                cand_block = "\n\n".join(parts) + "\n\n"
            prompt = f"FILENAME: {p['file']}\n\n{cand_block}SOURCE FILE CONTENT:\n---\n{raw}\n---"
            try:
                resp = await provider.complete(
                    prompt=prompt,
                    system=CLASSIFY_SYSTEM,
                    model=model,
                    temperature=0.0,
                    max_tokens=1800,
                    response_format=CLASSIFY_SCHEMA,
                    timeout_seconds=150,
                )
                return p, cands, json.loads(resp.content), None
            except Exception as e:  # noqa: BLE001
                return p, cands, None, f"{type(e).__name__}: {e}"[:200]
            finally:
                done += 1
                if done % 25 == 0:
                    print(f"  ...{done}/{len(targets)}", flush=True)

    now = datetime.now(UTC)
    to_backlink: list[tuple[str, object]] = []

    def route(p, cands, data, err) -> None:
        f = p["file"]
        if err or not data:
            report["errors"].append({"file": f, "name": p["name"], "error": err})
            return
        action = data.get("action")
        et = _ET_SYNONYMS.get(
            _norm_kw(data.get("entity_type")).replace(" ", "_"), _norm_kw(data.get("entity_type")).replace(" ", "_")
        )
        name = (data.get("canonical_name") or "").strip() or p["name"]
        desc = strip_wikilinks((data.get("description") or "").strip())
        note = data.get("analyst_note")
        base = {"file": f, "name": name, "type": et, "note": note, "confidence": data.get("confidence")}

        if action == "skip" or et in ("campaign", "other"):
            report["skipped"].append({**base, "reason": action if action == "skip" else f"type={et}"})
            return
        if not desc:
            report["errors"].append({"file": f, "name": name, "error": "empty-description"})
            return

        # Resolve the AI's merge_target against the candidates it was actually shown.
        # Vendor/product creation and merging are user-approved; countries stay
        # merge-only (seeded, ISO-coded table).
        cand = None
        if action == "merge":
            tgt = (data.get("merge_target") or "").strip()
            cand = next(
                (
                    c
                    for c in cands
                    if c["etype"] == et
                    and (c["obj"].name.lower() == tgt.lower() or _squash(c["obj"].name) == _squash(tgt))
                ),
                None,
            )
        if cand is None and et not in WRITE_MODELS:
            report["deferred"].append(base)
            return

        aliases = clean_alias_candidates([str(a) for a in (data.get("aliases") or [])], name)

        if action == "merge":
            if cand is None:
                report["conflicts"].append(
                    {
                        **base,
                        "reason": "merge-target-mismatch",
                        "merge_target": data.get("merge_target"),
                        "candidates": [{"type": c["etype"], "name": c["obj"].name} for c in cands],
                    }
                )
                return
            obj = cand["obj"]
            if not apply:
                report["merged"].append({**base, "into": obj.name, "desc_len": len(desc), "description": desc})
                return
            pre_import = obj.description
            obj.description = desc
            merged, existing = list(obj.aliases or []), {a.lower() for a in (obj.aliases or [])}
            added = 0
            for a in aliases:
                if a.lower() in existing or idx.alias_collision(str(obj.id), a) is not None:
                    continue
                merged.append(a)
                existing.add(a.lower())
                added += 1
            obj.aliases = merged
            _fill_structured(obj, et, p["frontmatter"])
            meta = dict(obj.metadata_ or {})
            ip = dict(meta.get("imported_profile") or {})
            stash_pre_import(ip, pre_import)
            ip.update(
                {
                    **provenance(p),
                    "imported_at": now.isoformat(),
                    "ai_reworked_at": now.isoformat(),
                    "ai_classified": True,
                }
            )
            record_import(ip, f)
            meta["imported_profile"] = ip
            obj.metadata_ = meta
            if added:
                to_backlink.append((et, obj))
            report["merged"].append({**base, "into": obj.name, "aliases_added": added, "desc_len": len(desc)})
            return

        # create — guard against same-type and cross-type name ownership.
        if et == "country":
            # Countries are a seeded, ISO-coded table — never auto-create new rows
            # (territories/regions the seeder skipped need a human decision).
            report["deferred"].append({**base, "reason": "country-create-needs-review"})
            return
        if idx.resolve_same_type(et, name, aliases):
            report["conflicts"].append({**base, "reason": "create-but-same-type-name-exists"})
            return
        other = idx.other_type_hit(et, [name, *aliases])
        if other is not None:
            report["conflicts"].append(
                {
                    **base,
                    "reason": "cross-type-collision",
                    "conflicts_with": {"type": other[0], "name": other[2]},
                }
            )
            return
        if not apply:
            report["created"].append({**base, "desc_len": len(desc), "description": desc})
            idx.add(et, f"new:{f}", name, aliases)  # within-batch dedupe
            return
        safe = [a for a in aliases if idx.alias_collision(None, a) is None]
        obj = WRITE_MODELS[et](name=name, aliases=safe)
        obj.description = desc
        _fill_structured(obj, et, p["frontmatter"])
        obj.metadata_ = {
            "imported_profile": {
                **provenance(p),
                "imported_at": now.isoformat(),
                "ai_reworked_at": now.isoformat(),
                "ai_classified": True,
                "source_files": [f],
            }
        }
        db.add(obj)
        idx.add(et, f"new:{f}", name, safe)
        to_backlink.append((et, obj))
        report["created"].append({**base, "aliases": safe, "desc_len": len(desc)})

    # Chunked AI -> write -> commit: progress survives a crash (idempotent reruns
    # skip completed files), and no transaction stays open for the whole run.
    await db.commit()  # close the candidate-prefetch read transaction
    for start in range(0, len(targets), _AI_CHUNK):
        chunk = targets[start : start + _AI_CHUNK]
        results = await asyncio.gather(*(call_ai(p, cands) for p, cands in chunk))
        for p, cands, data, err in results:
            route(p, cands, data, err)
        if apply:
            await db.commit()

    if apply and backlink and to_backlink:
        ok, failed = dispatch_backlinks_staggered(to_backlink, stagger)
        report["backlink_dispatched"] = ok
        if failed:
            report["backlink_failed"] = failed

    Path(report_path).write_text(json.dumps(report, indent=2, default=str))
    print(
        f"\nclassify: created={len(report['created'])} merged={len(report['merged'])} "
        f"skipped={len(report['skipped'])} conflicts={len(report['conflicts'])} "
        f"deferred={len(report['deferred'])} errors={len(report['errors'])}"
        + ("" if apply else "  [dry-run: nothing written]")
    )
    print(f"Classify report -> {report_path}")
    return report


# ─── AI relationship extraction from imported descriptions ──────────────────
#
# Imported profiles state concrete relationships ("used Phobos", "targeted
# Turkey", "attributed to the FSB") that the platform's relationship graph
# never sees — co-occurrence edges only come from entries. This pass extracts
# explicitly-stated relationships from each imported entity's description,
# resolves targets against the workbench (plus CVE/TTP id lookups), and writes
# EntityRelationship rows with source="auto_extracted".

REL_TYPES = (
    "uses",
    "exploits",
    "targets",
    "attributed_to",
    "variant_of",
    "communicates_with",
    "delivers",
    "drops",
    "hosts",
    "related_to",
)
# (source_type, target_type) pairs allowed per relationship verb, after the
# pair is oriented by the AI's direction field. None = any cross-entity pair.
_REL_ALLOWED: dict[str, set | None] = {
    "uses": {
        ("threat_actor", "malware"),
        ("threat_actor", "tool"),
        ("threat_actor", "ttp"),
        ("threat_actor", "product"),
        ("malware", "ttp"),
        ("malware", "tool"),
    },
    "exploits": {("threat_actor", "cve"), ("malware", "cve"), ("tool", "cve")},
    "targets": {
        ("threat_actor", "country"),
        ("malware", "country"),
        ("threat_actor", "vendor"),
        ("threat_actor", "product"),
        ("malware", "vendor"),
        ("malware", "product"),
    },
    "attributed_to": {("threat_actor", "country"), ("malware", "threat_actor"), ("tool", "threat_actor")},
    "variant_of": {("malware", "malware"), ("tool", "tool")},
    "delivers": {("malware", "malware"), ("threat_actor", "malware"), ("tool", "malware")},
    "drops": {("malware", "malware"), ("threat_actor", "malware"), ("tool", "malware")},
    "communicates_with": {("malware", "malware")},
    "hosts": set(),  # infrastructure semantics — nothing we track qualifies
    "related_to": None,
}
_MAX_RELS_PER_ENTITY = 15

REL_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "relationships": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "target_name": {"type": "string"},
                    "target_type": {
                        "type": "string",
                        "enum": ["threat_actor", "malware", "tool", "country", "vendor", "product", "cve", "ttp"],
                    },
                    "relationship_type": {"type": "string", "enum": list(REL_TYPES)},
                    "direction": {"type": "string", "enum": ["outgoing", "incoming"]},
                    "statement": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": [
                    "target_name",
                    "target_type",
                    "relationship_type",
                    "direction",
                    "statement",
                    "confidence",
                ],
            },
        },
    },
    "required": ["relationships"],
}

REL_SYSTEM = """You are a threat-intelligence analyst extracting STRUCTURED RELATIONSHIPS from an \
entity profile for a TIP relationship graph.

You receive one entity (its type and name) and its profile description. Extract every relationship \
the text EXPLICITLY states between this entity and OTHER named entities.

Rules:
- Extract only what the text states. No inference beyond plain reading, no outside knowledge.
- target_name: the other entity's canonical name exactly as written (no brackets/markup).
- target_type: threat_actor, malware, tool, country, vendor, product, cve (CVE-YYYY-NNNN ids), \
ttp (MITRE ATT&CK Txxxx / Txxxx.yyy ids).
- relationship_type, read as "subject VERB object": uses (actor uses malware/tool/technique), \
exploits (exploits a CVE), targets (targets a country/vendor/product), attributed_to (actor \
attributed to a country/state; malware or tool attributed to an actor), variant_of (malware \
variant of another family), delivers / drops (delivers or drops a payload), communicates_with, \
related_to (clearly associated, no more specific verb fits).
- direction: "outgoing" when the profiled entity is the subject; "incoming" when it is the object \
(a malware profile saying "used by APT29" -> uses, incoming, target_name=APT29).
- statement: the short supporting phrase from the text.
- confidence: high for direct factual claims, medium for hedged ("likely", "believed"), low for \
speculation.
- Regions and continents ("Europe", "Southeast Asia") are NOT countries — skip them. Sectors \
("healthcare") are not entities — skip. Skip relationships to entities that are only mentioned \
as part of a list of unrelated examples.

Return {"relationships": []} if none. Output ONLY the JSON object."""

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_TTP_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


async def ai_extract_relationships(db, model, concurrency, limit, apply, report_path):
    """Extract typed relationships from imported entity descriptions."""
    from app.models.cve import CVE
    from app.models.entity_relationship import EntityRelationship
    from app.models.ttp import TTP

    provider, pm = await load_ai_provider(db)
    idx = await build_index(db)
    cve_map = {c.upper(): str(i) for i, c in (await db.execute(select(CVE.id, CVE.cve_id))).all() if c}
    ttp_map = {t.upper(): str(i) for i, t in (await db.execute(select(TTP.id, TTP.technique_id))).all() if t}

    targets = []
    for etype, mc in WRITE_MODELS.items():
        rows = (await db.execute(select(mc).where(mc.metadata_.has_key("imported_profile")))).scalars().all()  # noqa: W601
        for obj in rows:
            meta = obj.metadata_ or {}
            ip = meta.get("imported_profile") or {}
            if ip.get("relationships_extracted_at") or QUARANTINE_META_KEY in meta:
                continue
            if not (obj.description or "").strip():
                continue
            targets.append({"etype": etype, "obj": obj})
    if limit:
        targets = targets[:limit]
    print(
        f"AI provider: {pm.name} ({pm.provider_type})  model={model}  concurrency={concurrency}\n"
        f"Extracting relationships from {len(targets)} imported entities (apply={apply})...",
        flush=True,
    )
    report = {"created": [], "unresolved": [], "invalid": [], "existing": 0, "errors": []}
    if not targets:
        Path(report_path).write_text(json.dumps(report, indent=2, default=str))
        return report

    sem = asyncio.Semaphore(concurrency)
    done = 0

    async def call_ai(t):
        nonlocal done
        async with sem:
            desc = (t["obj"].description or "").strip()
            if len(desc) > 12000:
                desc = desc[:12000] + "\n...[truncated]..."
            prompt = (
                f"ENTITY TYPE: {t['etype']}\nENTITY NAME: {t['obj'].name}\n\nPROFILE DESCRIPTION:\n---\n{desc}\n---"
            )
            try:
                resp = await provider.complete(
                    prompt=prompt,
                    system=REL_SYSTEM,
                    model=model,
                    temperature=0.0,
                    max_tokens=1500,
                    response_format=REL_SCHEMA,
                    timeout_seconds=150,
                )
                return t, json.loads(resp.content), None
            except Exception as e:  # noqa: BLE001
                return t, None, f"{type(e).__name__}: {e}"[:200]
            finally:
                done += 1
                if done % 50 == 0:
                    print(f"  ...{done}/{len(targets)}", flush=True)

    def resolve(tt: str, name: str) -> str | None:
        if tt == "cve":
            m = _CVE_RE.search(name)
            return cve_map.get(m.group(0).upper()) if m else None
        if tt == "ttp":
            m = _TTP_RE.search(name.upper())
            return ttp_map.get(m.group(0)) if m else None
        return idx.resolve_same_type(tt, name.strip(), [])

    now = datetime.now(UTC)
    seen_keys: set[tuple] = set()
    to_invalidate: set[tuple[str, str]] = set()

    async def route(t, data, err):
        obj, etype = t["obj"], t["etype"]
        if err or data is None:
            report["errors"].append({"name": obj.name, "type": etype, "error": err})
            return
        for rel in (data.get("relationships") or [])[:_MAX_RELS_PER_ENTITY]:
            rtype = rel.get("relationship_type")
            tt = rel.get("target_type")
            tname = (rel.get("target_name") or "").strip()
            if rtype not in _REL_ALLOWED or not tname:
                continue
            # Orient: profiled entity is subject (outgoing) or object (incoming).
            if rel.get("direction") == "incoming":
                pair_src_type, pair_tgt_type = tt, etype
            else:
                pair_src_type, pair_tgt_type = etype, tt
            allowed = _REL_ALLOWED[rtype]
            if allowed is not None and (pair_src_type, pair_tgt_type) not in allowed:
                report["invalid"].append(
                    {
                        "entity": obj.name,
                        "rel": rtype,
                        "target": tname,
                        "pair": f"{pair_src_type}->{pair_tgt_type}",
                    }
                )
                continue
            tid = resolve(tt, tname)
            if tid is None or tid.startswith("new:"):
                report["unresolved"].append(
                    {
                        "entity": obj.name,
                        "rel": rtype,
                        "target": tname,
                        "target_type": tt,
                    }
                )
                continue
            if rel.get("direction") == "incoming":
                src_type, src_id, tgt_type, tgt_id = tt, tid, etype, str(obj.id)
            else:
                src_type, src_id, tgt_type, tgt_id = etype, str(obj.id), tt, tid
            if (src_type, src_id) == (tgt_type, tgt_id):
                continue
            key = (src_type, src_id, tgt_type, tgt_id, rtype)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            existing = (
                await db.execute(
                    select(EntityRelationship).where(
                        EntityRelationship.source_type == src_type,
                        EntityRelationship.source_id == src_id,
                        EntityRelationship.target_type == tgt_type,
                        EntityRelationship.target_id == tgt_id,
                        EntityRelationship.relationship_type == rtype,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                report["existing"] += 1
                continue
            statement = (rel.get("statement") or "").strip()[:500]
            entry = {
                "source": f"{src_type}:{obj.name if src_id == str(obj.id) else tname}",
                "rel": rtype,
                "target": f"{tgt_type}:{tname if tgt_id == tid else obj.name}",
                "confidence": "probable" if rel.get("confidence") == "high" else "possible",
                "statement": statement,
            }
            if apply:
                db.add(
                    EntityRelationship(
                        source_type=src_type,
                        source_id=src_id,
                        target_type=tgt_type,
                        target_id=tgt_id,
                        relationship_type=rtype,
                        confidence=entry["confidence"],
                        source="auto_extracted",
                        description=f"From imported profile: {statement}" if statement else "From imported profile",
                    )
                )
                to_invalidate.add((src_type, src_id))
                to_invalidate.add((tgt_type, tgt_id))
            report["created"].append(entry)
        if apply:
            meta = dict(obj.metadata_ or {})
            ip = dict(meta.get("imported_profile") or {})
            ip["relationships_extracted_at"] = now.isoformat()
            meta["imported_profile"] = ip
            obj.metadata_ = meta

    await db.commit()  # close the target-prefetch read transaction
    for start in range(0, len(targets), _AI_CHUNK):
        chunk = targets[start : start + _AI_CHUNK]
        results = await asyncio.gather(*(call_ai(t) for t in chunk))
        for t, data, err in results:
            await route(t, data, err)
        if apply:
            await db.commit()

    # New edges change correlation payloads — drop the per-entity caches.
    if apply and to_invalidate:
        try:
            from app.intelligence.correlation_cache import invalidate_entity_cache

            for et, eid in to_invalidate:
                await invalidate_entity_cache(et, eid)
        except Exception:  # noqa: BLE001
            print("WARNING: correlation cache invalidation failed", flush=True)

    Path(report_path).write_text(json.dumps(report, indent=2, default=str))
    print(
        f"\nrelationships: created={len(report['created'])} existing={report['existing']} "
        f"unresolved={len(report['unresolved'])} invalid={len(report['invalid'])} "
        f"errors={len(report['errors'])}" + ("" if apply else "  [dry-run: nothing written]")
    )
    print(f"Relationship report -> {report_path}")
    return report


# ─── Main ───────────────────────────────────────────────────────────────────


def summarize(buckets: dict) -> dict:
    counts = {k: len(v) for k, v in buckets.items()}
    dropped = sum(len(r.get("dropped_aliases", [])) for r in buckets.get("enrich", []) + buckets.get("create", []))
    added = sum(len(r.get("safe_aliases", [])) for r in buckets.get("enrich", []) + buckets.get("create", []))
    by_type = defaultdict(lambda: defaultdict(int))
    for b in ("create", "enrich"):
        for r in buckets.get(b, []):
            by_type[r["type"]][b] += 1
    return {
        "counts": counts,
        "aliases_to_add": added,
        "aliases_dropped_collision": dropped,
        "by_type": {k: dict(v) for k, v in by_type.items()},
    }


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profiles-dir", default="/tmp/profiles")
    ap.add_argument("--report", default="/tmp/profiles_report.json")
    ap.add_argument("--apply", action="store_true", help="perform writes (default: dry-run)")
    ap.add_argument("--include-vendors", action="store_true", help="(reserved) import Company-classified as vendors")
    ap.add_argument("--backlink", action="store_true", help="dispatch article-backlink tasks after write")
    ap.add_argument("--limit", type=int, default=0, help="limit files/entities (testing)")
    # AI rework
    ap.add_argument("--ai", action="store_true", help="AI-author descriptions/aliases (after --apply, or standalone)")
    ap.add_argument("--rerework-existing", action="store_true", help="run AI pass over already-imported entities")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="model id for the AI rework")
    ap.add_argument("--concurrency", type=int, default=8, help="concurrent AI calls")
    ap.add_argument("--quarantine-dir", default=None, help="folder to move junk/wrong-type source files into")
    ap.add_argument("--ai-report", default="/tmp/profiles_ai_report.json")
    ap.add_argument(
        "--ai-classify",
        action="store_true",
        help="AI-triage files the deterministic pass skipped (no/broken frontmatter); writes with --apply",
    )
    ap.add_argument("--classify-report", default="/tmp/profiles_classify_report.json")
    ap.add_argument("--classify-limit", type=int, default=0, help="limit AI-classify targets (testing)")
    ap.add_argument(
        "--backlink-stagger",
        type=int,
        default=15,
        help="seconds between queued backlink tasks (each rescans all entries; don't flood the worker)",
    )
    ap.add_argument(
        "--extract-relationships",
        action="store_true",
        help="standalone: AI-extract typed relationships from imported descriptions (writes with --apply)",
    )
    ap.add_argument("--rel-report", default="/tmp/profiles_rel_report.json")
    args = ap.parse_args()

    pdir = Path(args.profiles_dir)
    qdir = args.quarantine_dir or f"{str(pdir).rstrip('/')}_quarantine"

    # Standalone AI pass over already-imported entities (repairs a raw import).
    if args.rerework_existing:
        async with async_session() as db:
            await ai_rework_entities(db, pdir, qdir, args.model, args.concurrency, args.limit, args.ai_report)
        return

    # Standalone relationship extraction over imported entities.
    if args.extract_relationships:
        async with async_session() as db:
            await ai_extract_relationships(db, args.model, args.concurrency, args.limit, args.apply, args.rel_report)
        return

    files = sorted(pdir.glob("*.md"))
    if args.limit:
        files = files[: args.limit]
    print(f"Scanning {len(files)} files in {pdir} ...", flush=True)

    profiles = [p for p in (parse_file(f) for f in files) if p]
    profiles_by_file = {p["file"]: p for p in profiles}

    async with async_session() as db:
        idx = await build_index(db)
        print(f"Index: {sum(len(v) for v in idx.terms.values())} terms across existing entities", flush=True)
        buckets = await evaluate(db, profiles, idx, args.include_vendors)

        summary = summarize(buckets)
        report = {
            "generated_at": datetime.now(UTC).isoformat(),
            "profiles_dir": str(pdir),
            "files_scanned": len(files),
            "summary": summary,
            "samples": {k: v[:20] for k, v in buckets.items()},
            "buckets": buckets,
        }
        Path(args.report).write_text(json.dumps(report, indent=2, default=str))
        print("\n=== SUMMARY ===")
        print(json.dumps(summary, indent=2))
        print(f"\nFull report -> {args.report}")

        if args.ai_classify:
            # Nothing gets CREATED without the AI reviewing fuzzy workbench
            # candidates: reroute deterministic creates through the classify pass
            # (enrichments of confirmed matches stay deterministic).
            buckets["ai_create_review"] = buckets.pop("create", [])
            print(
                f"Rerouting {len(buckets['ai_create_review'])} deterministic creates "
                "through the AI identity check (--ai-classify).",
                flush=True,
            )

        if args.apply:
            print("\n=== APPLYING ===", flush=True)
            stats = await apply_bucket(db, buckets, profiles_by_file, args.backlink, args.backlink_stagger)
            print(json.dumps(stats, indent=2))
            # Prod-safe: author descriptions/aliases with AI in the SAME run, so raw
            # dumps never persist. Runs after apply on the just-imported entities.
            if args.ai:
                print("\n=== AI REWORK ===", flush=True)
                await ai_rework_entities(db, pdir, qdir, args.model, args.concurrency, 0, args.ai_report)
        else:
            print("\nDry-run only. Re-run with --apply to write.")

        if args.ai_classify:
            print("\n=== AI CLASSIFY (files the deterministic pass skipped) ===", flush=True)
            await ai_classify_files(
                db,
                profiles_by_file,
                buckets,
                pdir,
                args.model,
                args.concurrency,
                args.classify_limit or args.limit,
                args.apply,
                args.classify_report,
                args.backlink,
                args.backlink_stagger,
            )

        if args.apply:
            bumped = await bump_autolinker_vocab()
            print(
                "Autolinker vocab version bumped — workers will rebuild from DB."
                if bumped
                else "WARNING: could not bump autolinker vocab version; new entities/aliases "
                "stay invisible to the autolinker until a vocabulary refresh happens.",
                flush=True,
            )


if __name__ == "__main__":
    asyncio.run(main())
