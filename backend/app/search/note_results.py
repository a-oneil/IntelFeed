"""Shared machinery for returning analyst notes as search results.

Notes live in two tables — `notes` (attached to an entry, or standalone) and
`entity_notes` (attached to an actor, CVE, campaign, ...) — but search returns
them as one `note` type, because the person looking for something they wrote
does not remember which table it landed in.

Both the plain-text sweep (`search_all_entities`) and the `note:` query-language
field build their own WHERE clauses and hand them here, so the two paths cannot
drift in what a note result looks like.
"""

import html
import re

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.campaign import Campaign
from app.models.cve import CVE
from app.models.entity_note import EntityNote
from app.models.entry import Entry
from app.models.malware_family import MalwareFamily
from app.models.note import Note
from app.models.product import Product
from app.models.threat_actor import ThreatActor
from app.models.ttp import TTP
from app.models.vendor import Vendor
from app.services.entity_names import resolve_entity_names
from app.services.sanitizer import html_to_text

# The entity kinds a note can hang off, for resolving "a note about what?" in
# one query per type. Mirrors the map the entity-notes API enforces on write, so
# a note can never name a subject search cannot resolve.
NOTE_SUBJECT_MODELS: dict[str, tuple] = {
    "threat_actor": (ThreatActor, ThreatActor.name),
    "malware": (MalwareFamily, MalwareFamily.name),
    "cve": (CVE, CVE.cve_id),
    "ttp": (TTP, TTP.technique_name),
    "campaign": (Campaign, Campaign.name),
    "vendor": (Vendor, Vendor.name),
    "product": (Product, Product.name),
}

# Block-level tags become line breaks before the rest of the markup is stripped.
# Without this, `report.</p><p>---` collapses to `report.---` and every
# line-anchored markdown rule below has a single line to work on.
_HTML_BLOCK_RE = re.compile(
    r"</?(?:p|div|br|li|ul|ol|h[1-6]|tr|table|thead|tbody|blockquote|section|article|pre|hr)\b[^>]*>",
    re.IGNORECASE,
)
_MD_LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_MD_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s*", re.MULTILINE)
_MD_RULE_RE = re.compile(r"^\s{0,3}([-*_])\1{2,}\s*$", re.MULTILINE)
_MD_QUOTE_RE = re.compile(r"^\s*>+\s?", re.MULTILINE)
# Emphasis, code and strikethrough markers only — a bare underscore is left
# alone so snake_case survives.
_MD_EMPHASIS_RE = re.compile(r"\*\*|__|\*|`|~~")


def note_prose(text: str) -> str:
    """Flatten a note body to one line of readable prose.

    A note holds whatever its author put there: markdown, HTML pasted out of a
    vendor report, or both in the same paragraph. Neither renders in a search
    row, so a raw slice of it shows `</p><p>` where the sentence should be.
    """
    body = html.unescape(html_to_text(_HTML_BLOCK_RE.sub("\n", text)))
    body = _MD_LINK_RE.sub(r"\1", body)
    body = _MD_HEADING_RE.sub("", body)
    body = _MD_RULE_RE.sub(" ", body)
    body = _MD_QUOTE_RE.sub("", body)
    body = _MD_EMPHASIS_RE.sub("", body)
    return " ".join(body.split())


def note_snippet(text: str | None, query_lower: str, width: int = 190) -> str | None:
    """A window of a note's body centred on the match.

    Every other entity leads with a description whose first line says what it
    is, so a head-of-string truncation reads fine. A note is somebody's prose:
    the sentence that matched is usually nowhere near the top, and showing the
    first 190 characters explains nothing about why the row is on screen.
    """
    if not text:
        return None
    body = note_prose(text)
    if not body:
        return None
    if len(body) <= width:
        return body
    idx = body.lower().find(query_lower) if query_lower else -1
    if idx < 0:
        return body[:width].rstrip() + "…"
    start = max(0, idx - width // 3)
    end = min(len(body), start + width)
    lead = "…" if start > 0 else ""
    trail = "…" if end < len(body) else ""
    return lead + body[start:end].strip() + trail


def _match_field(title: str | None, body: str | None, query_lower: str) -> str:
    """Which part of the note the query hit, for the row's match tag.

    Defaults to the body rather than the tags: a `note:` field query carries no
    text to locate, and "in body" is the honest answer for a note that matched
    on something other than its title.
    """
    if query_lower and query_lower in (title or "").lower():
        return "title"
    if not query_lower or query_lower in (body or "").lower():
        return "content"
    return "tags"


def serialize_note(note: Note, entry_title: str | None, query_lower: str = "") -> dict:
    return {
        "id": str(note.id),
        "type": "note",
        "title": note.title,
        "description": note_snippet(note.content_markdown, query_lower),
        "note_source": "note",
        "entry_id": str(note.entry_id) if note.entry_id else None,
        "entry_title": entry_title,
        "is_pinned": note.is_pinned,
        "tags": note.tags or [],
        "match_field": _match_field(note.title, note.content_markdown, query_lower),
    }


def serialize_entity_note(note: EntityNote, subject: str | None, query_lower: str = "") -> dict:
    return {
        "id": str(note.id),
        "type": "note",
        # An entity note's title is optional; without one, what it is about is
        # the only name the row has.
        "title": note.title or (f"Note on {subject}" if subject else "Entity note"),
        "description": note_snippet(note.content, query_lower),
        "note_source": "entity_note",
        "note_type": note.note_type,
        "entity_type": note.entity_type,
        "entity_id": str(note.entity_id),
        "entity_name": subject,
        "tags": note.tags or [],
        "match_field": _match_field(note.title, note.content, query_lower),
    }


async def fetch_notes(
    db: AsyncSession,
    note_conditions: list,
    entity_note_conditions: list,
    limit: int,
    query_lower: str = "",
) -> tuple[list[dict], set[str]]:
    """Run both note queries and return (serialized results, linked entry IDs).

    An empty condition list means "this table cannot match" rather than "match
    everything" — an unconstrained note query would return the whole notebook.
    """
    results: list[dict] = []
    entry_ids: set[str] = set()

    if note_conditions:
        rows = (
            await db.execute(
                select(Note, Entry.title)
                .outerjoin(Entry, Entry.id == Note.entry_id)
                .where(*note_conditions)
                .order_by(Note.is_pinned.desc(), Note.updated_at.desc())
                .limit(limit)
            )
        ).all()
        for note, entry_title in rows:
            results.append(serialize_note(note, entry_title, query_lower))
            if note.entry_id:
                entry_ids.add(str(note.entry_id))

    if entity_note_conditions:
        entity_notes = (
            (
                await db.execute(
                    select(EntityNote)
                    .where(*entity_note_conditions)
                    .order_by(EntityNote.updated_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        subjects = await resolve_entity_names(db, entity_notes, NOTE_SUBJECT_MODELS)
        for note in entity_notes:
            results.append(serialize_entity_note(note, subjects.get((note.entity_type, note.entity_id)), query_lower))

    return results, entry_ids


def text_conditions(query: str) -> tuple[list, list]:
    """The WHERE clauses for "this text appears anywhere in a note"."""
    like = f"%{query}%"
    return (
        [
            or_(
                Note.title.ilike(like),
                Note.content_markdown.ilike(like),
                func.array_to_string(Note.tags, ",").ilike(like),
            )
        ],
        [
            or_(
                EntityNote.title.ilike(like),
                EntityNote.content.ilike(like),
                func.array_to_string(EntityNote.tags, ",").ilike(like),
            )
        ],
    )
