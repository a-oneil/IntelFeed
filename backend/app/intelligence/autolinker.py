"""Entity auto-linker: dictionary-based entity recognition using Aho-Corasick.

Scans article text against all known entity names (threat actors, malware families)
and structured identifiers (CVEs, TTPs) to create entry-entity junction records.
This is Layer 0 — free, instant correlation that runs on every entry.
"""

import asyncio
import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import ahocorasick
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.country import Country, EntryCountry
from app.models.cve import CVE, EntryCVE
from app.models.cwe import CWE, EntryCWE
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import EntryMitigation, Mitigation
from app.models.pending_autolink import PendingAutolinkMatch
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.vendor import EntryVendor, Vendor
from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)

VOCAB_VERSION_KEY = "intelfeed:autolinker:vocab_version"

# Matches a single word of purely alphabetic characters (no digits, spaces, or punctuation).
# Used to detect names that overlap heavily with common English vocabulary.
_ALPHA_WORD_RE = re.compile(r"^[a-zA-Z]+$")


def _get_min_name_length() -> int:
    return settings.get("autolinker_min_name_length") or settings.autolinker_min_name_length


def _get_fp_names() -> frozenset[str]:
    raw = settings.get("autolinker_false_positive_names") or settings.autolinker_false_positive_names
    return frozenset(n.strip().lower() for n in raw.split(",") if n.strip())


def _get_blocked_forms() -> frozenset[str]:
    """Analyst hard blocks — surface forms that must not match for ANY entity type.

    Separate from :func:`_get_fp_names` because that list is a curated vocabulary
    of ambiguous codenames and brand words (``windows``, ``chrome``, ``microsoft``)
    that vendor/product/tool/mitigation intentionally bypass — those words are
    those entities' real names. This list is written only when an analyst
    explicitly reports "never match this word", so it binds everywhere.
    """
    raw = settings.get("autolinker_blocked_surface_forms") or settings.autolinker_blocked_surface_forms
    return frozenset(n.strip().lower() for n in raw.split(",") if n.strip())


# Module-level aliases kept for backwards compatibility with tests / external callers.
@property  # type: ignore[misc]
def _FALSE_POSITIVE_NAMES_prop() -> frozenset[str]:  # noqa: N802
    return _get_fp_names()


def _get_false_positive_names() -> frozenset[str]:
    return _get_fp_names()


def is_junk_alias(alias: str, canonical_name: str = "") -> bool:
    """Return True if an alias should not be stored or matched as a synonym.

    Rejects empty/whitespace forms, aliases below the minimum match length,
    exact duplicates of the entity's own name, and known false-positive surface
    forms (common words / brand names in ``autolinker_false_positive_names``).

    This is the same word set the autolinker uses to skip matches, exposed so
    ingestion paths (Malpedia sync, AI extraction) can drop junk aliases at
    import time instead of letting them pollute the aliases array and later
    generate false-positive links. Intended for actor/malware aliases; vendor
    and product names deliberately bypass the FP list.
    """
    form = (alias or "").strip()
    if len(form) < _get_min_name_length():
        return True
    if canonical_name and form.lower() == canonical_name.strip().lower():
        return True
    return form.lower() in _get_fp_names() or form.lower() in _get_blocked_forms()


_BINARY_NAME_RE = re.compile(r"\.(exe|dll|sys|app|bin|scr|ocx)$", re.IGNORECASE)


def is_fp_entity_name(name: str) -> bool:
    """Return True if ``name`` should never be created as a new actor/malware entity.

    Guards the automated creation paths (AI extraction, external feed sync) against
    spawning junk profiles. Rejects the configurable false-positive name set (shared
    with :func:`is_junk_alias`) plus bare system-binary / LOLBin filenames
    (``svchost.exe``, ``python310.dll``, ``*.sys`` …) — those are file references,
    not malware families, and get re-extracted from article text constantly. Does
    not gate manual creation (a human deliberately adding an entity is trusted).
    """
    form = (name or "").strip()
    if not form:
        return True
    if form.lower() in _get_fp_names() or form.lower() in _get_blocked_forms():
        return True
    return bool(_BINARY_NAME_RE.search(form))


def filter_aliases(aliases: list[str], canonical_name: str = "") -> list[str]:
    """Drop junk aliases, de-duplicate case-insensitively, preserve order."""
    cleaned: list[str] = []
    seen: set[str] = set()
    for alias in aliases or []:
        form = (alias or "").strip()
        key = form.lower()
        if key in seen or is_junk_alias(form, canonical_name):
            continue
        seen.add(key)
        cleaned.append(form)
    return cleaned


# Lazy module-level proxies so that `from app.intelligence.autolinker import FALSE_POSITIVE_NAMES`
# still works and reflects the current settings value at call time.
class _LazyFPSet:
    """Proxy that delegates set-like membership tests to the live settings value."""

    def __contains__(self, item: object) -> bool:
        return item in _get_fp_names()

    def __iter__(self):
        return iter(_get_fp_names())

    def __len__(self) -> int:
        return len(_get_fp_names())


FALSE_POSITIVE_NAMES: frozenset[str] = _LazyFPSet()  # type: ignore[assignment]
MIN_NAME_LENGTH: int = 4  # sentinel; real value comes from settings at runtime


# Entity types whose dictionary-word matches go to the pending tier instead of
# linking immediately. Limited to types the one-pass AI analysis extracts and can
# therefore confirm or reject; vendor/product have no AI payload to reconcile
# against and keep instant linking.
PENDING_TIER_TYPES = frozenset({"threat_actor", "malware", "tool", "country"})

_COMMON_WORDS_PATH = Path(__file__).parent / "data" / "common_english_words.txt"
_common_words: frozenset[str] | None = None


def _get_common_words() -> frozenset[str]:
    global _common_words
    if _common_words is None:
        try:
            with open(_COMMON_WORDS_PATH, encoding="utf-8") as f:
                _common_words = frozenset(w.strip() for w in f if w.strip() and not w.startswith("#"))
        except OSError:
            logger.warning("Common-words list missing at %s; pending tier disabled", _COMMON_WORDS_PATH)
            _common_words = frozenset()
    return _common_words


def is_common_english_word(form: str) -> bool:
    """True for single-token alpha-only surface forms that are common English words.

    These are the forms where capitalization alone cannot disambiguate an entity
    mention from ordinary proper-noun usage ("Royal Navy", "N2K Networks, Inc."),
    so their matches are held for AI confirmation instead of linking instantly.
    """
    form = (form or "").strip().lower()
    return bool(_ALPHA_WORD_RE.match(form)) and form in _get_common_words()


# Country names that are also ordinary words. The common-words list is built
# from subtitle frequencies, so it carries proper nouns too ("canada",
# "germany", "australia") — holding those held most country links for no
# reason. A country match is provisional only when its surface form is here.
AMBIGUOUS_COUNTRY_WORDS = frozenset(
    {"chad", "china", "georgia", "guinea", "jersey", "jordan", "niger", "panama", "turkey", "chile", "cuba"}
)


def is_provisional_form(entity_type: str, form: str) -> bool:
    """True when a match on ``form`` is held for AI confirmation instead of linking."""
    if entity_type not in PENDING_TIER_TYPES:
        return False
    if entity_type == "country":
        return (form or "").strip().lower() in AMBIGUOUS_COUNTRY_WORDS
    return is_common_english_word(form)


def pending_tier_enabled() -> bool:
    """Pending tier requires its own flag AND the one-pass AI analysis.

    The AI reconciler is the only promotion path — with `ai_one_pass_enabled`
    off, holding dictionary-word matches would mean those entities never link
    at all, so the tier auto-disables and matching falls back to the legacy
    instant-link behavior (capitalization guard only).
    """
    return bool(settings.get("autolink_pending_tier_enabled")) and bool(settings.get("ai_one_pass_enabled"))


# The FP list was built to filter ambiguous actor/malware codenames ("Storm",
# "Agent") and common-OS/brand words that overlapped with malware aliases. Those
# same words ARE the canonical names of vendor/product entities (Microsoft,
# Windows, Chrome, …), so these types bypass it. The is_ambiguous +
# uppercase-first check at match time still prevents lowercase prose matches.
_FP_LIST_EXEMPT_TYPES = frozenset({"vendor", "product", "tool", "mitigation"})


def _surface_form_filtered(entity_type: str, form: str) -> bool:
    """True when the FP list or an analyst hard block rules ``form`` out as a match.

    Shared by the vocabulary build (ingest autolink) and the retroactive
    backlink, so a form that never links at ingest never links after the fact.
    """
    key = form.lower()
    if entity_type not in _FP_LIST_EXEMPT_TYPES and key in _get_fp_names():
        return True
    # Analyst hard blocks bind for every type — including the FP-exempt ones.
    return key in _get_blocked_forms()


def reliability_to_weight(rating: str | None) -> float:
    """Map a feed's A-F reliability rating to an autolink confidence multiplier."""
    weights = {"A": 1.0, "B": 0.85, "C": 0.7, "D": 0.5, "E": 0.3, "F": 0.15}
    return weights.get(rating, 0.5)  # Unrated defaults to 0.5


# Daily Redis counters of dictionary-word matches dropped because the entry's
# feed never gets AI analysis (so nothing would ever confirm them). Kept a
# little past the 30-day window the Engine view sums.
_DROPPED_AI_OFF_KEY = "autolink:pending_dropped_ai_off:{day}"
_DROPPED_AI_OFF_TTL = 35 * 86400


async def _count_dropped_ai_off(n: int) -> None:
    if n <= 0:
        return
    try:
        r = await get_redis()
        key = _DROPPED_AI_OFF_KEY.format(day=datetime.now(UTC).strftime("%Y%m%d"))
        await r.incrby(key, n)
        await r.expire(key, _DROPPED_AI_OFF_TTL)
    except Exception:
        logger.debug("pending-tier drop counter update failed", exc_info=True)


async def dropped_ai_off_count(days: int = 30) -> int:
    """Dictionary-word matches dropped on AI-off feeds over the last ``days`` days."""
    today = datetime.now(UTC)
    keys = [_DROPPED_AI_OFF_KEY.format(day=(today - timedelta(days=i)).strftime("%Y%m%d")) for i in range(days)]
    try:
        r = await get_redis()
        return sum(int(v or 0) for v in await r.mget(keys))
    except Exception:
        logger.debug("pending-tier drop counter read failed", exc_info=True)
        return 0


def _is_ambiguous_surface_form(form: str) -> bool:
    """Return True for single short alpha-only tokens that could be common English words.

    These require the original-text character at the match position to be uppercase
    (i.e., used as a proper noun) before they are accepted as entity mentions.
    Multi-word forms, names with digits/hyphens/underscores, and names longer than the
    configured threshold are NOT considered ambiguous — they are specific enough on their own.
    """
    max_len = settings.get("autolinker_ambiguous_name_max_length") or settings.autolinker_ambiguous_name_max_length
    return (
        len(form) <= max_len
        and " " not in form
        and "-" not in form
        and "_" not in form
        and _ALPHA_WORD_RE.match(form) is not None
    )


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
# Weakness ids run CWE-1 .. CWE-1425. Unlike CVE and TTP no stub is ever created
# from a match: the catalog is seeded whole, so an id that isn't in it is a typo
# or a MITRE release we haven't pulled — inventing a row would be worse than
# dropping the link.
CWE_PATTERN = re.compile(r"\bCWE-\d{1,4}\b")
# Valid ATT&CK sub-techniques are .001+; ".000" is invalid, so a lookahead rejects
# it and the match falls back to the parent technique (e.g. "T1059.000" -> "T1059").
TTP_PATTERN = re.compile(r"\bT\d{4}(?:\.(?!000\b)\d{3})?\b")

_PARAGRAPH_SPLIT_RE = re.compile(r"\n\s*\n")


def split_into_paragraphs(title: str, summary: str, content_text: str) -> list[tuple[int, str]]:
    """Split entry text into (paragraph_index, text) pairs.

    Title = paragraph 0, summary = paragraph 1, content split on double newlines = paragraph 2+.
    """
    paragraphs: list[tuple[int, str]] = []
    idx = 0
    if title and title.strip():
        paragraphs.append((idx, title.strip()))
        idx += 1
    if summary and summary.strip():
        paragraphs.append((idx, summary.strip()))
        idx += 1
    if content_text and content_text.strip():
        for chunk in _PARAGRAPH_SPLIT_RE.split(content_text):
            chunk = chunk.strip()
            if chunk:
                paragraphs.append((idx, chunk))
                idx += 1
    return paragraphs


@dataclass
class VocabEntry:
    entity_type: str  # threat_actor, malware, country, vendor, product, tool, mitigation
    entity_id: uuid.UUID
    canonical_name: str
    surface_form: str  # The text being matched (name or alias)
    is_alias: bool
    is_ambiguous: bool = False  # Requires uppercase-first match in original text
    is_provisional: bool = False  # Common English word — match held for AI confirmation


@dataclass
class EntityVocabulary:
    automaton: ahocorasick.Automaton = field(default_factory=ahocorasick.Automaton)
    entry_count: int = 0
    version: str = ""
    built: bool = False
    # Per-surface-form fingerprints, hashed into `version` once the build ends.
    _fingerprints: list[str] = field(default_factory=list, repr=False)

    def build_from_entities(
        self,
        actors: list[ThreatActor],
        malware_families: list[MalwareFamily],
        countries: list[Country] | None = None,
        vendors: list[Vendor] | None = None,
        products: list[Product] | None = None,
        tools: list[Tool] | None = None,
        mitigations: list[Mitigation] | None = None,
    ) -> int:
        """Build Aho-Corasick automaton from entity names and aliases."""
        self.automaton = ahocorasick.Automaton()
        self._fingerprints = []
        count = 0

        for actor in actors:
            count += self._add_entity("threat_actor", actor.id, actor.name, actor.aliases or [])

        for malware in malware_families:
            count += self._add_entity("malware", malware.id, malware.name, malware.aliases or [])

        for country in countries or []:
            count += self._add_entity("country", country.id, country.name, country.aliases or [])

        for vendor in vendors or []:
            count += self._add_entity("vendor", vendor.id, vendor.name, vendor.aliases or [])

        for product in products or []:
            count += self._add_entity("product", product.id, product.name, product.aliases or [])

        for tool in tools or []:
            count += self._add_entity("tool", tool.id, tool.name, tool.aliases or [])

        # Mitigations have no aliases column; match on the canonical name only.
        for mitigation in mitigations or []:
            count += self._add_entity("mitigation", mitigation.id, mitigation.name, [])

        if count > 0:
            self.automaton.make_automaton()

        self.entry_count = count
        self.built = True
        self.version = self._content_version()
        logger.info("Built auto-linker vocabulary: %d surface forms (version %s)", count, self.version[:12])
        return count

    def _content_version(self) -> str:
        """Hash of everything this vocabulary matches on.

        Must be derived from content, never from a clock. `_ensure_vocabulary`
        decides freshness by comparing a worker's local version against the one
        in Redis, and every gunicorn/Celery process keeps its own copy. A
        timestamp version is unique per build, so no two processes could ever
        agree: each rebuild published a version the others didn't have, which
        made them rebuild and publish again — a self-sustaining loop that put a
        full 7-table load plus automaton build in front of essentially every
        autolink call (~27s on prod). Hashing the content means identical input
        yields an identical version, so the workers converge after one build and
        a real entity change still invalidates them all.

        Sorted because the source queries carry no ORDER BY — two workers can
        load the same rows in different orders and must still agree.
        """
        digest = hashlib.sha256()
        for part in sorted(self._fingerprints):
            digest.update(part.encode("utf-8"))
            digest.update(b"\n")
        return digest.hexdigest()

    def _add_entity(
        self,
        entity_type: str,
        entity_id: uuid.UUID,
        name: str,
        aliases: list[str],
    ) -> int:
        """Add an entity's name and aliases to the automaton."""
        count = 0
        all_forms = [(name, False)] + [(alias, True) for alias in aliases]

        # Post-merge entities often carry aliases that duplicate their own
        # canonical name (case variants folded in by merge). Each surface form
        # only needs to map to this entity's canonical id once — skip repeats
        # so the automaton payload doesn't accumulate duplicate VocabEntry rows.
        seen_forms: set[str] = set()

        for surface_form, is_alias in all_forms:
            if not surface_form or len(surface_form) < _get_min_name_length():
                continue
            if _surface_form_filtered(entity_type, surface_form):
                continue

            key = surface_form.lower()
            if key in seen_forms:
                continue
            seen_forms.add(key)
            entry = VocabEntry(
                entity_type=entity_type,
                entity_id=entity_id,
                canonical_name=name,
                surface_form=surface_form,
                is_alias=is_alias,
                is_ambiguous=_is_ambiguous_surface_form(surface_form),
                is_provisional=is_provisional_form(entity_type, surface_form),
            )

            # Multiple entities can share a surface form
            existing = self.automaton.get(key, None)
            if existing is not None:
                existing.append(entry)
            else:
                self.automaton.add_word(key, [entry])
            count += 1
            # Everything that changes what this form matches or how it renders,
            # so a rename, a new alias, or a change to the FP/block lists all
            # move the version.
            self._fingerprints.append(
                f"{key}|{entity_type}|{entity_id}|{name}|{int(is_alias)}"
                f"|{int(entry.is_ambiguous)}|{int(entry.is_provisional)}"
            )

        return count


# Module-level singleton vocabulary
_vocabulary: EntityVocabulary | None = None
_vocab_version: str = ""


def _is_word_boundary(text: str, start: int, end: int) -> bool:
    """Check that match has word boundaries on both sides. An underscore is part
    of the word: "RTM" in RTM_NEWLINK is a code identifier, not a mention."""
    if start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        return False
    if end < len(text) and (text[end].isalnum() or text[end] == "_"):
        return False
    return True


def _case_fits(form: str, seen: str) -> bool:
    """Case test for a short one-word form (see _is_ambiguous_surface_form).
    An acronym must appear in capitals ("TRAP", not a kernel "trap"; "MMC",
    not "mmc:"), a mixed-case brand exactly as written ("iOS", not Cisco
    "IOS"). Other forms need a capital first letter, as a proper noun does."""
    if form.isupper():
        return seen.isupper()
    if any(c.isupper() for c in form[1:]):
        return seen == form
    return seen[:1].isupper()


def _starts_dotted_identifier(text: str, start: int, end: int) -> bool:
    """True for an all-lowercase match that opens a dotted package or bundle id:
    "the com" in "the com.apple.screensharing", "com" in "com.ahsay.c". A name
    written as a name has capitals; a lowercase run followed by two more dotted
    segments is code. One segment ("google.com", "certutil.exe") still matches."""
    if text[start:end] != text[start:end].lower():
        return False
    rest = text[end:]
    return rest.startswith(".") and _DOTTED_TAIL_RE.match(rest) is not None


_DOTTED_TAIL_RE = re.compile(r"\.[a-z0-9_]+\.[a-z0-9_]")


def scan_text(text_or_paragraphs: str | list[tuple[int, str]]) -> list[dict]:
    """Scan text for entity mentions using Aho-Corasick + regex patterns.

    Args:
        text_or_paragraphs: Either a plain string (backward compat — treated as
            paragraph 0) or a list of (paragraph_index, text) tuples from
            split_into_paragraphs().

    Returns list of match dicts with keys:
        entity_type, entity_id, canonical_name, surface_form, confidence, source,
        paragraph_indices
    """
    if not _vocabulary or not _vocabulary.built:
        return []

    # Backward compat: bare string → single paragraph
    if isinstance(text_or_paragraphs, str):
        if not text_or_paragraphs:
            return []
        paragraphs: list[tuple[int, str]] = [(0, text_or_paragraphs)]
    else:
        paragraphs = text_or_paragraphs
        if not paragraphs:
            return []

    # For ambiguous-name frequency check, build combined text
    combined_lower = " ".join(t for _, t in paragraphs).lower()
    max_occurrences = (
        settings.get("autolinker_ambiguous_max_occurrences") or settings.autolinker_ambiguous_max_occurrences
    )
    pending_tier = pending_tier_enabled()

    # Accumulate matches: (entity_type, entity_id_str) → match_dict with paragraph_indices
    seen: dict[tuple[str, str], dict] = {}

    for para_idx, para_text in paragraphs:
        if not para_text:
            continue
        para_lower = para_text.lower()

        # Phase 1: Aho-Corasick scan for threat actors, malware, countries.
        # Collect the paragraph's accepted matches first, then drop any that
        # sit inside a longer one ("Korea" in "North Korea").
        candidates: list[tuple[int, int, VocabEntry]] = []
        for end_idx, entries in _vocabulary.automaton.iter(para_lower) if _vocabulary.entry_count > 0 else []:
            for vocab_entry in entries:
                match_len = len(vocab_entry.surface_form)
                start_idx = end_idx - match_len + 1

                if not _is_word_boundary(para_lower, start_idx, end_idx + 1):
                    continue
                if _starts_dotted_identifier(para_text, start_idx, end_idx + 1):
                    continue

                if vocab_entry.is_ambiguous:
                    if not _case_fits(vocab_entry.surface_form, para_text[start_idx : end_idx + 1]):
                        continue
                    # Frequency gate only applies to actor/malware-style codenames
                    # (e.g. "Storm", "Agent") — for vendor/product/tool proper
                    # nouns, high frequency means the article is about that entity.
                    # Mitigations stay gated: a generic word like "Audit" repeated
                    # in prose is noise, not a mention of the MITRE mitigation.
                    if vocab_entry.entity_type not in ("vendor", "product", "tool"):
                        term_lower = vocab_entry.surface_form.lower()
                        if combined_lower.count(term_lower) > max_occurrences:
                            continue
                candidates.append((start_idx, end_idx + 1, vocab_entry))

        for start_idx, end, vocab_entry in candidates:
            if any(s <= start_idx and end <= e and (e - s) > (end - start_idx) for s, e, _ in candidates):
                continue
            key = (vocab_entry.entity_type, str(vocab_entry.entity_id))
            if key in seen:
                # Entity already matched — record this paragraph + surface form
                if para_idx not in seen[key]["paragraph_indices"]:
                    seen[key]["paragraph_indices"].append(para_idx)
                if vocab_entry.surface_form not in seen[key]["surface_forms"]:
                    seen[key]["surface_forms"].append(vocab_entry.surface_form)
                # A single non-provisional form (multi-word, coined name)
                # rescues the whole match from the pending tier.
                if not vocab_entry.is_provisional:
                    seen[key]["provisional"] = False
                continue

            seen[key] = {
                "entity_type": vocab_entry.entity_type,
                "entity_id": str(vocab_entry.entity_id),
                "canonical_name": vocab_entry.canonical_name,
                "surface_form": vocab_entry.surface_form,
                "surface_forms": [vocab_entry.surface_form],
                "confidence": "medium" if vocab_entry.is_alias else "high",
                "source": "auto_link",
                "paragraph_indices": [para_idx],
                "provisional": pending_tier and vocab_entry.is_provisional,
            }

        # Phase 2: Regex scan for structured identifiers
        for m in CVE_PATTERN.finditer(para_text):
            cve_id = m.group()
            key = ("cve", cve_id)
            if key in seen:
                if para_idx not in seen[key]["paragraph_indices"]:
                    seen[key]["paragraph_indices"].append(para_idx)
                continue
            seen[key] = {
                "entity_type": "cve",
                "entity_id": None,
                "canonical_name": cve_id,
                "surface_form": cve_id,
                "confidence": "high",
                "source": "auto_link",
                "lookup_key": cve_id,
                "paragraph_indices": [para_idx],
            }

        for m in CWE_PATTERN.finditer(para_text):
            cwe_id = m.group()
            key = ("cwe", cwe_id)
            if key in seen:
                if para_idx not in seen[key]["paragraph_indices"]:
                    seen[key]["paragraph_indices"].append(para_idx)
                continue
            seen[key] = {
                "entity_type": "cwe",
                "entity_id": None,
                "canonical_name": cwe_id,
                "surface_form": cwe_id,
                "confidence": "high",
                "source": "auto_link",
                "lookup_key": cwe_id,
                "paragraph_indices": [para_idx],
            }

        for m in TTP_PATTERN.finditer(para_text):
            technique_id = m.group()
            key = ("ttp", technique_id)
            if key in seen:
                if para_idx not in seen[key]["paragraph_indices"]:
                    seen[key]["paragraph_indices"].append(para_idx)
                continue
            seen[key] = {
                "entity_type": "ttp",
                "entity_id": None,
                "canonical_name": technique_id,
                "surface_form": technique_id,
                "confidence": "high",
                "source": "auto_link",
                "lookup_key": technique_id,
                "paragraph_indices": [para_idx],
            }

    return list(seen.values())


def _weighted_confidence(raw: str, weight: float) -> str:
    """Downgrade confidence string based on source reliability weight."""
    scores = {"high": 0.9, "medium": 0.5, "low": 0.3}
    numeric = scores.get(raw, 0.5) * weight
    if numeric >= 0.7:
        return "high"
    elif numeric >= 0.4:
        return "medium"
    return "low"


async def _filter_ttp_matches(
    db: AsyncSession,
    entry_id: uuid.UUID,
    matches: list[dict],
    context_text: str | None,
) -> list[dict]:
    """Validate TTP regex matches against the hydrated ATT&CK catalog.

    Unknown technique IDs are dropped, revoked ones are remapped to their
    replacement, and ICS-matrix techniques are dropped unless the entry
    context looks ICS/OT related.
    """
    from app.intelligence.attack_catalog import resolve_technique_ids

    ttp_keys = [m["lookup_key"] for m in matches if m["entity_type"] == "ttp" and m.get("lookup_key")]
    if not ttp_keys:
        return matches

    if context_text is None:
        from app.models.entry import Entry

        result = await db.execute(select(Entry.title, Entry.summary, Entry.content_text).where(Entry.id == entry_id))
        row = result.one_or_none()
        context_text = " ".join(part for part in row if part) if row else ""

    resolution = await resolve_technique_ids(db, ttp_keys, context_text)
    filtered: list[dict] = []
    seen_resolved: set[str] = set()
    for match in matches:
        if match["entity_type"] != "ttp":
            filtered.append(match)
            continue
        resolved = resolution.get(match.get("lookup_key") or "")
        if not resolved or resolved in seen_resolved:
            continue  # unknown/gated id, or duplicate after revoked-remap
        seen_resolved.add(resolved)
        if resolved != match["lookup_key"]:
            match = {**match, "lookup_key": resolved, "canonical_name": resolved}
        filtered.append(match)
    return filtered


async def _bump_entity_stats(db: AsyncSession, model, entity_id: uuid.UUID) -> None:
    """Atomically bump ``article_count`` / ``last_seen_at`` for one entity row.

    Emitted as a single UPDATE rather than a load-mutate-flush so the row lock is
    taken here — in the caller's deterministic order — instead of at commit time
    in whatever order SQLAlchemy happens to flush its dirty set. Also makes the
    increment atomic: the old read-modify-write could drop counts when two
    entries linked the same entity concurrently.
    """
    await db.execute(
        update(model)
        .where(model.id == entity_id)
        .values(
            article_count=func.coalesce(model.article_count, 0) + 1,
            last_seen_at=datetime.now(UTC),
        )
    )


async def store_autolink_matches(
    db: AsyncSession,
    entry_id: uuid.UUID,
    matches: list[dict],
    source_confidence_weight: float = 1.0,
    context_text: str | None = None,
    allow_provisional: bool = False,
) -> list[dict]:
    """Store auto-link matches as junction records. Returns list of stored matches.

    Matches flagged ``provisional`` (dictionary-word surface forms) are diverted
    to ``pending_autolink_matches`` instead of becoming junction rows — the AI
    reconciler promotes or rejects them later. ``allow_provisional=True`` is the
    reconciler's promotion path: it commits provisional matches directly.

    On an entry the AI will never read (its feed's AI is off, or its mode is
    "none") nothing would confirm a held match, so provisional matches are
    dropped and counted instead of held.
    """
    matches = await _filter_ttp_matches(db, entry_id, matches, context_text)

    if not allow_provisional:
        provisional = [m for m in matches if m.get("provisional")]
        matches = [m for m in matches if not m.get("provisional")]
        if provisional:
            from app.services.ai_eligibility import entry_will_get_ai_analysis

            if not await entry_will_get_ai_analysis(db, entry_id):
                logger.info(
                    "Dropped %d provisional autolink match(es) for entry %s; its feed gets no AI analysis: %s",
                    len(provisional),
                    entry_id,
                    [m.get("canonical_name") for m in provisional],
                )
                await _count_dropped_ai_off(len(provisional))
                provisional = []
        for match in provisional:
            try:
                await db.execute(
                    pg_insert(PendingAutolinkMatch)
                    .values(
                        entry_id=entry_id,
                        entity_type=match["entity_type"],
                        entity_id=uuid.UUID(match["entity_id"]),
                        canonical_name=match["canonical_name"],
                        matched_names=match.get("surface_forms")
                        or ([match["surface_form"]] if match.get("surface_form") else None),
                        paragraph_indices=match.get("paragraph_indices"),
                        confidence=match["confidence"],
                        source_weight=source_confidence_weight,
                    )
                    .on_conflict_do_nothing(constraint="uq_pending_autolink_entry_entity")
                )
            except Exception:
                logger.warning(
                    "Failed to hold pending autolink %s for entry %s",
                    match.get("canonical_name"),
                    entry_id,
                    exc_info=True,
                )
        if provisional:
            logger.info(
                "Held %d provisional autolink match(es) for entry %s pending AI confirmation: %s",
                len(provisional),
                entry_id,
                [m.get("canonical_name") for m in provisional],
            )

    stored = []

    # Lock ordering. Concurrent autolink transactions bump article_count on the
    # same entity rows, and two workers touching e.g. Cisco and Microsoft in
    # opposite orders deadlock: each holds one row and waits on the other.
    # Postgres kills one of them, and because autolink_entry_task is a chord
    # header that failure skips entry_post_processing entirely — the entry
    # silently loses co-occurrence, correlation, requirements and scoring, with
    # no retry. Touching rows in one globally consistent order (type, then id)
    # makes the wait-for cycle impossible to form.
    matches = sorted(matches, key=lambda m: (str(m.get("entity_type")), str(m.get("entity_id"))))

    for match in matches:
        entity_type = match["entity_type"]
        try:
            para_indices = match.get("paragraph_indices")

            if entity_type == "threat_actor":
                actor_id = uuid.UUID(match["entity_id"])
                result = await db.execute(
                    pg_insert(EntryThreatActor)
                    .values(
                        entry_id=entry_id,
                        threat_actor_id=actor_id,
                        confidence=_weighted_confidence(match["confidence"], source_confidence_weight),
                        source="auto_link",
                        matched_names=match.get("surface_forms")
                        or ([match["surface_form"]] if match.get("surface_form") else None),
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryThreatActor.entry_id)
                )
                if not result.scalar_one_or_none():
                    continue  # Already linked
                # Update entity stats
                await _bump_entity_stats(db, ThreatActor, actor_id)
                stored.append(match)

            elif entity_type == "malware":
                malware_id = uuid.UUID(match["entity_id"])
                result = await db.execute(
                    pg_insert(EntryMalware)
                    .values(
                        entry_id=entry_id,
                        malware_family_id=malware_id,
                        confidence=_weighted_confidence(match["confidence"], source_confidence_weight),
                        source="auto_link",
                        matched_names=match.get("surface_forms")
                        or ([match["surface_form"]] if match.get("surface_form") else None),
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryMalware.entry_id)
                )
                if not result.scalar_one_or_none():
                    continue  # Already linked
                await _bump_entity_stats(db, MalwareFamily, malware_id)
                stored.append(match)

            elif entity_type == "country":
                country_id = uuid.UUID(match["entity_id"])
                result = await db.execute(
                    pg_insert(EntryCountry)
                    .values(
                        entry_id=entry_id,
                        country_id=country_id,
                        confidence=_weighted_confidence(match["confidence"], source_confidence_weight),
                        source="auto_link",
                        role="mentioned",
                        matched_names=match.get("surface_forms")
                        or ([match["surface_form"]] if match.get("surface_form") else None),
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryCountry.entry_id)
                )
                if not result.scalar_one_or_none():
                    continue  # Already linked
                await _bump_entity_stats(db, Country, country_id)
                stored.append(match)

            elif entity_type == "vendor":
                vendor_id = uuid.UUID(match["entity_id"])
                result = await db.execute(
                    pg_insert(EntryVendor)
                    .values(
                        entry_id=entry_id,
                        vendor_id=vendor_id,
                        confidence=_weighted_confidence(match["confidence"], source_confidence_weight),
                        source="auto_link",
                        matched_names=match.get("surface_forms")
                        or ([match["surface_form"]] if match.get("surface_form") else None),
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryVendor.entry_id)
                )
                if not result.scalar_one_or_none():
                    continue
                await _bump_entity_stats(db, Vendor, vendor_id)
                stored.append(match)

            elif entity_type == "product":
                product_id = uuid.UUID(match["entity_id"])
                result = await db.execute(
                    pg_insert(EntryProduct)
                    .values(
                        entry_id=entry_id,
                        product_id=product_id,
                        confidence=_weighted_confidence(match["confidence"], source_confidence_weight),
                        source="auto_link",
                        matched_names=match.get("surface_forms")
                        or ([match["surface_form"]] if match.get("surface_form") else None),
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryProduct.entry_id)
                )
                if not result.scalar_one_or_none():
                    continue
                await _bump_entity_stats(db, Product, product_id)
                stored.append(match)

            elif entity_type == "tool":
                tool_id = uuid.UUID(match["entity_id"])
                result = await db.execute(
                    pg_insert(EntryTool)
                    .values(
                        entry_id=entry_id,
                        tool_id=tool_id,
                        confidence=_weighted_confidence(match["confidence"], source_confidence_weight),
                        source="auto_link",
                        matched_names=match.get("surface_forms")
                        or ([match["surface_form"]] if match.get("surface_form") else None),
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryTool.entry_id)
                )
                if not result.scalar_one_or_none():
                    continue
                await _bump_entity_stats(db, Tool, tool_id)
                stored.append(match)

            elif entity_type == "mitigation":
                # EntryMitigation has no matched_names column — surface forms are
                # carried in the returned match for the description/summary linkers.
                mitigation_id = uuid.UUID(match["entity_id"])
                result = await db.execute(
                    pg_insert(EntryMitigation)
                    .values(
                        entry_id=entry_id,
                        mitigation_id=mitigation_id,
                        confidence=_weighted_confidence(match["confidence"], source_confidence_weight),
                        source="auto_link",
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryMitigation.entry_id)
                )
                if not result.scalar_one_or_none():
                    continue
                await _bump_entity_stats(db, Mitigation, mitigation_id)
                stored.append(match)

            elif entity_type == "cve":
                lookup_key = match.get("lookup_key")
                if not lookup_key:
                    continue
                cve_uuid = (await db.execute(select(CVE.id).where(CVE.cve_id == lookup_key))).scalar_one_or_none()
                is_new_stub = False
                if cve_uuid is None:
                    # The one entity autolink creates rather than only links: a
                    # CVE id is specific enough to stand on its own. It honours
                    # the same do-not-recreate list as the extract path, and
                    # created_via marks the stub so curation can find it.
                    from app.intelligence.entity_resolution import is_name_denied

                    if await is_name_denied(db, "cve", lookup_key):
                        continue
                    # Upsert — concurrent workers may race on the same id, and a
                    # raw INSERT would IntegrityError and poison the txn.
                    upsert_result = await db.execute(
                        pg_insert(CVE)
                        .values(cve_id=lookup_key, created_via="auto_link", created_from_entry_id=entry_id)
                        .on_conflict_do_nothing(index_elements=["cve_id"])
                        .returning(CVE.id)
                    )
                    cve_uuid = upsert_result.scalar_one_or_none()
                    is_new_stub = cve_uuid is not None
                    if cve_uuid is None:
                        existing = await db.execute(select(CVE.id).where(CVE.cve_id == lookup_key))
                        cve_uuid = existing.scalar_one()
                await db.execute(
                    pg_insert(EntryCVE)
                    .values(entry_id=entry_id, cve_id=cve_uuid, paragraph_indices=para_indices)
                    .on_conflict_do_nothing()
                )
                stored.append({**match, "entity_id": str(cve_uuid), "is_new_stub": is_new_stub})

            elif entity_type == "cwe":
                lookup_key = match.get("lookup_key")
                if not lookup_key:
                    continue
                # Catalog lookup, never an upsert — see CWE_PATTERN.
                cwe_row = await db.execute(select(CWE.id).where(CWE.cwe_id == lookup_key))
                cwe_uuid = cwe_row.scalar_one_or_none()
                if cwe_uuid is None:
                    continue
                link_result = await db.execute(
                    pg_insert(EntryCWE)
                    .values(
                        entry_id=entry_id,
                        cwe_id=cwe_uuid,
                        confidence=_weighted_confidence("high", source_confidence_weight),
                        source="auto_link",
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryCWE.entry_id)
                )
                if not link_result.scalar_one_or_none():
                    continue
                await _bump_entity_stats(db, CWE, cwe_uuid)
                stored.append({**match, "entity_id": str(cwe_uuid)})

            elif entity_type == "ttp":
                lookup_key = match.get("lookup_key")
                if not lookup_key:
                    continue
                upsert_result = await db.execute(
                    pg_insert(TTP)
                    .values(
                        technique_id=lookup_key,
                        technique_name=lookup_key,
                        is_subtechnique="." in lookup_key,
                    )
                    .on_conflict_do_nothing(index_elements=["technique_id"])
                    .returning(TTP.id)
                )
                ttp_uuid = upsert_result.scalar_one_or_none()
                is_new_stub = ttp_uuid is not None
                if ttp_uuid is None:
                    existing = await db.execute(select(TTP.id).where(TTP.technique_id == lookup_key))
                    ttp_uuid = existing.scalar_one()
                link_result = await db.execute(
                    pg_insert(EntryTTP)
                    .values(
                        entry_id=entry_id,
                        ttp_id=ttp_uuid,
                        confidence=_weighted_confidence("high", source_confidence_weight),
                        source_text=f"auto_link:{lookup_key}",
                        paragraph_indices=para_indices,
                    )
                    .on_conflict_do_nothing()
                    .returning(EntryTTP.entry_id)
                )
                if not link_result.scalar_one_or_none():
                    continue  # Already linked
                await _bump_entity_stats(db, TTP, ttp_uuid)
                stored.append({**match, "entity_id": str(ttp_uuid), "is_new_stub": is_new_stub})

        except Exception:
            logger.exception("Error storing auto-link match: %s", match)

    if stored:
        await db.flush()
    return stored


async def autolink_entry(
    db: AsyncSession,
    entry_id: uuid.UUID,
    content_text: str,
    title: str,
    summary: str,
    source_confidence_weight: float = 1.0,
) -> list[dict]:
    """Auto-link entities for a single entry. High-level entry point."""
    global _vocabulary, _vocab_version

    # Check vocabulary freshness
    await _ensure_vocabulary(db)

    # Split into paragraphs for proximity tracking
    paragraphs = split_into_paragraphs(title, summary, content_text)
    if not paragraphs:
        return []

    # Off the event loop: the scan is pure CPU with nothing to await, and this
    # path is reachable from POST /entries/{id}/autolink, where running it
    # inline froze every other request on the same gunicorn worker. In a Celery
    # worker the thread hop costs nothing.
    matches = await asyncio.to_thread(scan_text, paragraphs)
    if not matches:
        return []

    stored = await store_autolink_matches(
        db,
        entry_id,
        matches,
        source_confidence_weight,
        context_text=" ".join(t for _, t in paragraphs),
    )

    # Invalidate correlation caches for affected entities
    if stored:
        from app.intelligence.correlation_cache import invalidate_entity_cache

        for match in stored:
            if match.get("entity_id"):
                await invalidate_entity_cache(match["entity_type"], match["entity_id"])

    await _enqueue_stub_enrichment(db, stored)
    return stored


async def _enqueue_stub_enrichment(db: AsyncSession, stored: list[dict]) -> None:
    """Queue enrichment for CVE/TTP stubs this autolink pass created.

    A stub is just an id; enrichment fills in the rest (MITRE name/tactic for a
    TTP, NVD/EPSS/KEV for a CVE), the same as the extract path does for the
    stubs it mints.
    """
    from app.enrichment.queue import enqueue

    for m in stored:
        if m.get("entity_type") in ("ttp", "cve") and m.get("is_new_stub"):
            await enqueue(db, m["entity_type"], m["entity_id"], m["lookup_key"])


async def autolink_batch(
    db: AsyncSession,
    entry_ids: list[uuid.UUID],
    delete_first: bool = False,
) -> dict:
    """Batch auto-link for multiple entries. Commits every 100 entries.

    When delete_first=True, deletes existing auto_link junction records
    per entry before re-inserting — ensures paragraph_indices are populated
    and stale links are removed.
    """
    from sqlalchemy import delete

    from app.models.entry import Entry

    await _ensure_vocabulary(db)

    # Junction tables that have a `source` column (auto_link records)
    source_junctions = [
        (EntryThreatActor, EntryThreatActor.source),
        (EntryMalware, EntryMalware.source),
        (EntryCountry, EntryCountry.source),
        (EntryVendor, EntryVendor.source),
        (EntryProduct, EntryProduct.source),
        # Tool/Mitigation are now auto-linked too; deleting only source="auto_link"
        # rows preserves any AI-extracted links.
        (EntryTool, EntryTool.source),
        (EntryMitigation, EntryMitigation.source),
    ]
    # Junction tables without a `source` column — always delete auto-linked records
    # (CVE/TTP are always auto_link from the autolinker)
    nosource_junctions = [
        EntryCVE,
        EntryTTP,
    ]

    stats = {"scanned": 0, "linked": 0, "deleted": 0}

    for i, entry_id in enumerate(entry_ids):
        result = await db.execute(
            select(Entry.id, Entry.title, Entry.summary, Entry.content_text).where(Entry.id == entry_id)
        )
        row = result.one_or_none()
        if not row:
            continue

        paragraphs = split_into_paragraphs(row.title or "", row.summary or "", row.content_text or "")
        if not paragraphs:
            stats["scanned"] += 1
            continue

        # Delete existing auto_link records before reinserting
        if delete_first:
            for junc_model, source_col in source_junctions:
                del_result = await db.execute(
                    delete(junc_model).where(
                        junc_model.entry_id == row.id,
                        source_col == "auto_link",
                    )
                )
                stats["deleted"] += del_result.rowcount
            for junc_model in nosource_junctions:
                del_result = await db.execute(delete(junc_model).where(junc_model.entry_id == row.id))
                stats["deleted"] += del_result.rowcount

        matches = scan_text(paragraphs)
        if matches:
            stored = await store_autolink_matches(db, row.id, matches, context_text=" ".join(t for _, t in paragraphs))
            stats["linked"] += len(stored)
            await _enqueue_stub_enrichment(db, stored)

        stats["scanned"] += 1

        # Commit in batches
        if (i + 1) % 100 == 0:
            await db.commit()
            logger.info("Auto-link batch progress: %d/%d entries", i + 1, len(entry_ids))

    await db.commit()
    return stats


async def _ensure_vocabulary(db: AsyncSession) -> None:
    """Ensure vocabulary is loaded and fresh."""
    global _vocabulary, _vocab_version

    if _vocabulary and _vocabulary.built:
        # Check Redis version for cross-worker freshness
        try:
            r = await get_redis()
            redis_version = await r.get(VOCAB_VERSION_KEY) or ""
            if redis_version == _vocab_version:
                return  # Already up to date
        except Exception:
            return  # Redis unavailable, use cached version

    await refresh_vocabulary(db)


async def refresh_vocabulary(db: AsyncSession) -> int:
    """Rebuild vocabulary from database and update Redis version.

    Always from the whole instance: a visitor's request can trigger this, and
    a vocabulary built under the visitor filter would drop every entity known
    only from a hidden feed, for every worker that loads it.
    """
    from app.core.public_access import instance_view, viewer_is_anonymous

    for_visitor = viewer_is_anonymous()
    with instance_view():
        count, loaded = await _rebuild_vocabulary(db)
    if for_visitor:
        # Those rows were read without the visitor filter; left in the
        # session's identity map, a later session.get() in this request would
        # hand one to the visitor.
        for obj in loaded:
            if obj in db:
                db.expunge(obj)
    return count


async def _rebuild_vocabulary(db: AsyncSession) -> tuple[int, list]:
    global _vocabulary, _vocab_version

    # Warm the process-local settings cache first. The build filters read
    # settings.get(), which falls back to the env default when the cache is cold
    # — and the analyst block list defaults to empty, so a worker rebuilding with
    # a cold cache would publish a vocabulary that ignores every block.
    try:
        from app.services.system_settings import get_setting

        await get_setting("autolinker_blocked_surface_forms", db)
    except Exception:
        logger.debug("Could not warm settings cache before vocabulary rebuild")

    actors_result = await db.execute(select(ThreatActor))
    actors = actors_result.scalars().all()

    malware_result = await db.execute(select(MalwareFamily))
    malware_families = malware_result.scalars().all()

    countries_result = await db.execute(select(Country))
    countries = countries_result.scalars().all()

    vendors_result = await db.execute(select(Vendor))
    vendors = vendors_result.scalars().all()

    products_result = await db.execute(select(Product))
    products = products_result.scalars().all()

    tools_result = await db.execute(select(Tool))
    tools = tools_result.scalars().all()

    mitigations_result = await db.execute(select(Mitigation))
    mitigations = mitigations_result.scalars().all()

    vocab = EntityVocabulary()
    count = vocab.build_from_entities(actors, malware_families, countries, vendors, products, tools, mitigations)
    loaded = [*actors, *malware_families, *countries, *vendors, *products, *tools, *mitigations]

    _vocabulary = vocab
    _vocab_version = vocab.version

    # Publish version to Redis so other workers can check freshness
    try:
        r = await get_redis()
        await r.set(VOCAB_VERSION_KEY, vocab.version)
    except Exception:
        logger.debug("Failed to publish vocabulary version to Redis")

    return count, loaded


async def backfill_paragraph_indices(db: AsyncSession) -> dict:
    """Backfill paragraph_indices for existing junction records that have NULL.

    Lighter than a full rescan — preserves existing confidence/source metadata
    and just adds paragraph position data by re-scanning entry text.
    """
    from app.models.entry import Entry

    await _ensure_vocabulary(db)

    # Junction table configs: (model, entity_fk_col_name, entity_type)
    junction_configs = [
        (EntryThreatActor, "threat_actor_id", "threat_actor"),
        (EntryMalware, "malware_family_id", "malware"),
        (EntryCountry, "country_id", "country"),
        (EntryCVE, "cve_id", "cve"),
        (EntryTTP, "ttp_id", "ttp"),
        (EntryTool, "tool_id", "tool"),
        (EntryMitigation, "mitigation_id", "mitigation"),
        (EntryVendor, "vendor_id", "vendor"),
        (EntryProduct, "product_id", "product"),
    ]

    # Collect entry IDs that have NULL paragraph_indices in any junction
    entry_ids_set: set[uuid.UUID] = set()
    for junc_model, _, _ in junction_configs:
        result = await db.execute(select(junc_model.entry_id).where(junc_model.paragraph_indices.is_(None)).distinct())
        entry_ids_set.update(row[0] for row in result.all())

    if not entry_ids_set:
        return {"entries": 0, "updated": 0}

    entry_ids = list(entry_ids_set)
    stats = {"entries": len(entry_ids), "updated": 0}

    for i, eid in enumerate(entry_ids):
        result = await db.execute(
            select(Entry.id, Entry.title, Entry.summary, Entry.content_text).where(Entry.id == eid)
        )
        row = result.one_or_none()
        if not row:
            continue

        paragraphs = split_into_paragraphs(row.title or "", row.summary or "", row.content_text or "")
        if not paragraphs:
            continue

        matches = scan_text(paragraphs)
        # Build lookup: (entity_type, entity_id_str) → paragraph_indices
        match_map: dict[tuple[str, str], list[int]] = {}
        for m in matches:
            key = (m["entity_type"], str(m.get("entity_id") or m.get("lookup_key", "")))
            match_map[key] = m.get("paragraph_indices", [])

        # Update each junction table
        for junc_model, fk_col_name, entity_type in junction_configs:
            junc_result = await db.execute(
                select(junc_model).where(junc_model.entry_id == eid).where(junc_model.paragraph_indices.is_(None))
            )
            for junc_row in junc_result.scalars().all():
                entity_id_str = str(getattr(junc_row, fk_col_name))
                para = match_map.get((entity_type, entity_id_str))
                if para:
                    junc_row.paragraph_indices = para
                    stats["updated"] += 1

        if (i + 1) % 100 == 0:
            await db.commit()
            logger.info("Backfill progress: %d/%d entries", i + 1, len(entry_ids))

    await db.commit()
    return stats


# Feed modes that switch ingest autolink off; the retroactive backlink skips
# their entries too.
_NO_AUTOLINK_MODES = ("manual", "none")


def _accepted_mention(term: str, pattern: re.Pattern, text: str) -> bool:
    """Word-boundary match of ``term`` in ``text``, with ingest's capital-letter rule.

    An ambiguous form (a short single word like "Play" or "Hive") only counts
    where the text spells it the way scan_text requires (see _case_fits).
    """
    if not _is_ambiguous_surface_form(term):
        return pattern.search(text) is not None
    return any(_case_fits(term, m.group()) for m in pattern.finditer(text))


async def link_entity_to_existing_entries(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    batch_size: int = 500,
) -> dict:
    """Search existing entries for mentions of a specific entity and create links.

    Called after a new entity is manually created so it gets retroactively linked
    to entries that already mention it. Applies ingest autolink's rules: entries
    from feeds set to manual or none are skipped, the FP list / hard blocks and
    the capital-letter check apply, and confidence scales by feed reliability.

    Supports all entity types:
    - threat_actor, malware, country: name + aliases text search
    - cve: CVE ID pattern search
    - cwe: weakness ID pattern search
    - ttp: technique ID pattern search
    - tool, mitigation: name + aliases text search
    """
    stats = {"scanned": 0, "linked": 0, "entity_type": entity_type}

    # Acquire a per-entity lock to prevent duplicate work from concurrent calls
    import redis as _redis

    from app.config import settings as _settings

    lock_key = f"autolink_entity:{entity_type}:{entity_id}"
    r = _redis.from_url(_settings.redis_url)
    try:
        if not r.set(lock_key, "1", nx=True, ex=600):
            logger.info("Skipping link_entity_to_existing_entries — already running for %s:%s", entity_type, entity_id)
            return {**stats, "skipped": "already_running"}
    finally:
        r.close()

    try:
        return await _link_entity_to_existing_entries_inner(db, entity_type, entity_id, batch_size, stats)
    finally:
        r = _redis.from_url(_settings.redis_url)
        try:
            r.delete(lock_key)
        finally:
            r.close()


async def _link_entity_to_existing_entries_inner(
    db: AsyncSession,
    entity_type: str,
    entity_id: uuid.UUID,
    batch_size: int,
    stats: dict,
) -> dict:
    from sqlalchemy import or_

    from app.models.entry import Entry
    from app.models.feed import Feed

    # ── Load entity and build search terms ──────────────────────────
    search_terms: list[str] = []

    if entity_type == "threat_actor":
        entity = (await db.execute(select(ThreatActor).where(ThreatActor.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.name] + (entity.aliases or [])
    elif entity_type == "malware":
        entity = (await db.execute(select(MalwareFamily).where(MalwareFamily.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.name] + (entity.aliases or [])
    elif entity_type == "country":
        entity = (await db.execute(select(Country).where(Country.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.name] + (entity.aliases or [])
    elif entity_type == "tool":
        entity = (await db.execute(select(Tool).where(Tool.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.name] + (entity.aliases or [])
    elif entity_type == "vendor":
        entity = (await db.execute(select(Vendor).where(Vendor.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.name] + (entity.aliases or [])
    elif entity_type == "product":
        entity = (await db.execute(select(Product).where(Product.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.name] + (entity.aliases or [])
    elif entity_type == "mitigation":
        entity = (await db.execute(select(Mitigation).where(Mitigation.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.name]
        if entity.mitre_id:
            search_terms.append(entity.mitre_id)
    elif entity_type == "cve":
        entity = (await db.execute(select(CVE).where(CVE.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.cve_id]
    elif entity_type == "cwe":
        entity = (await db.execute(select(CWE).where(CWE.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        # Id only. The catalog's alternate terms ("UAF", "Dangling pointer") are
        # exactly the dictionary-word aliases that produced the 2026-07 false
        # positive epidemic, so they stay out of the search terms.
        search_terms = [entity.cwe_id]
    elif entity_type == "ttp":
        entity = (await db.execute(select(TTP).where(TTP.id == entity_id))).scalar_one_or_none()
        if not entity:
            return {**stats, "error": "entity_not_found"}
        search_terms = [entity.technique_id]
    else:
        return {**stats, "error": f"unsupported_entity_type: {entity_type}"}

    # Same surface-form rules as the ingest vocabulary: drop short terms, the
    # FP list (for the types it covers) and analyst hard blocks.
    canonical_term = search_terms[0] if search_terms else None
    min_len = _get_min_name_length()
    search_terms = [t for t in search_terms if t and len(t) >= min_len and not _surface_form_filtered(entity_type, t)]
    if not search_terms:
        return stats
    term_patterns = [(t, re.compile(r"(?<!\w)" + re.escape(t) + r"(?!\w)", re.IGNORECASE)) for t in search_terms]

    # ── Find entries mentioning any search term ─────────────────────
    text_conditions = []
    for term in search_terms:
        escaped = term.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        text_conditions.append(Entry.title.ilike(pattern))
        text_conditions.append(Entry.summary.ilike(pattern))
        text_conditions.append(Entry.content_text.ilike(pattern))

    # Paginate through matching entries. Feeds set to manual or none get no
    # autolinks at ingest, so they get none after the fact either.
    offset = 0
    while True:
        result = await db.execute(
            select(Entry.id, Entry.title, Entry.summary, Entry.content_text, Feed.reliability_rating)
            .join(Feed, Feed.id == Entry.feed_id)
            .where(or_(*text_conditions), Feed.intel_extraction_mode.notin_(_NO_AUTOLINK_MODES))
            .order_by(Entry.id)
            .offset(offset)
            .limit(batch_size)
        )
        rows = result.all()
        if not rows:
            break

        for entry_row in rows:
            stats["scanned"] += 1
            eid = entry_row.id

            # Build combined text and verify word-boundary match
            combined = " ".join(filter(None, [entry_row.title, entry_row.summary, entry_row.content_text]))
            if not combined:
                continue

            # Collect every term that has an accepted match in the combined text
            matched_terms = [t for t, pat in term_patterns if _accepted_mention(t, pat, combined)]
            if not matched_terms:
                continue
            matched_term = matched_terms[0]
            # Canonical name "high", alias-only "medium", then scaled by the
            # feed's reliability — the same confidence ingest autolink writes.
            raw_confidence = "high" if canonical_term in matched_terms else "medium"
            confidence = _weighted_confidence(raw_confidence, reliability_to_weight(entry_row.reliability_rating))

            # Find paragraph indices for the match
            paragraphs = split_into_paragraphs(
                entry_row.title or "", entry_row.summary or "", entry_row.content_text or ""
            )
            para_indices = [
                para_idx
                for para_idx, para_text in paragraphs
                if any(_accepted_mention(t, pat, para_text) for t, pat in term_patterns)
            ]

            # ── Insert junction record ──────────────────────────────
            try:
                inserted = False
                if entity_type == "threat_actor":
                    r = await db.execute(
                        pg_insert(EntryThreatActor)
                        .values(
                            entry_id=eid,
                            threat_actor_id=entity_id,
                            confidence=confidence,
                            source="auto_link",
                            matched_names=matched_terms or None,
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryThreatActor.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "malware":
                    r = await db.execute(
                        pg_insert(EntryMalware)
                        .values(
                            entry_id=eid,
                            malware_family_id=entity_id,
                            confidence=confidence,
                            source="auto_link",
                            matched_names=matched_terms or None,
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryMalware.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "country":
                    r = await db.execute(
                        pg_insert(EntryCountry)
                        .values(
                            entry_id=eid,
                            country_id=entity_id,
                            confidence=confidence,
                            source="auto_link",
                            role="mentioned",
                            matched_names=matched_terms or None,
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryCountry.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "cve":
                    r = await db.execute(
                        pg_insert(EntryCVE)
                        .values(
                            entry_id=eid,
                            cve_id=entity_id,
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryCVE.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "cwe":
                    r = await db.execute(
                        pg_insert(EntryCWE)
                        .values(
                            entry_id=eid,
                            cwe_id=entity_id,
                            confidence=confidence,
                            source="auto_link",
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryCWE.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "ttp":
                    r = await db.execute(
                        pg_insert(EntryTTP)
                        .values(
                            entry_id=eid,
                            ttp_id=entity_id,
                            confidence=confidence,
                            source_text=f"auto_link:{matched_term}",
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryTTP.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "tool":
                    r = await db.execute(
                        pg_insert(EntryTool)
                        .values(
                            entry_id=eid,
                            tool_id=entity_id,
                            confidence=confidence,
                            source="auto_link",
                            matched_names=matched_terms or None,
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryTool.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "vendor":
                    r = await db.execute(
                        pg_insert(EntryVendor)
                        .values(
                            entry_id=eid,
                            vendor_id=entity_id,
                            confidence=confidence,
                            source="auto_link",
                            matched_names=matched_terms or None,
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryVendor.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "product":
                    r = await db.execute(
                        pg_insert(EntryProduct)
                        .values(
                            entry_id=eid,
                            product_id=entity_id,
                            confidence=confidence,
                            source="auto_link",
                            matched_names=matched_terms or None,
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryProduct.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None
                elif entity_type == "mitigation":
                    r = await db.execute(
                        pg_insert(EntryMitigation)
                        .values(
                            entry_id=eid,
                            mitigation_id=entity_id,
                            confidence=confidence,
                            source="auto_link",
                            paragraph_indices=para_indices or None,
                        )
                        .on_conflict_do_nothing()
                        .returning(EntryMitigation.entry_id)
                    )
                    inserted = r.scalar_one_or_none() is not None

                if inserted:
                    stats["linked"] += 1

            except Exception:
                logger.exception("Error linking entity %s/%s to entry %s", entity_type, entity_id, eid)

        # Commit batch
        await db.commit()
        if len(rows) < batch_size:
            break
        offset += batch_size

    # Update entity article_count if we linked anything
    if stats["linked"] > 0 and hasattr(entity, "article_count"):
        entity = (await db.execute(select(type(entity)).where(type(entity).id == entity_id))).scalar_one_or_none()
        if entity:
            entity.article_count = (entity.article_count or 0) + stats["linked"]
            from datetime import UTC

            entity.last_seen_at = datetime.now(UTC)
            await db.commit()

        # Invalidate correlation cache
        from app.intelligence.correlation_cache import invalidate_entity_cache

        await invalidate_entity_cache(entity_type, str(entity_id))

    logger.info(
        "Entity backlink complete: type=%s id=%s scanned=%d linked=%d",
        entity_type,
        entity_id,
        stats["scanned"],
        stats["linked"],
    )
    return stats
