import csv
import io
import json
import re
import uuid
import zipfile
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Path
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError
from app.core.security import get_current_user
from app.database import get_db
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.note import Note
from app.models.tag import EntryTag, Tag
from app.models.user import User
from app.services.entity_markdown import (
    ENTITY_TYPE_LABELS,
    build_entity_profile_markdown,
)
from app.services.markdown import (
    entry_to_markdown,
    note_to_markdown,
)

router = APIRouter()

# entity_type -> attribute holding the entity's display name/identifier
_ENTITY_NAME_ATTR = {
    "threat_actor": "name",
    "malware": "name",
    "cve": "cve_id",
    "cwe": "cwe_id",
    "ttp": "technique_id",
    "country": "name",
    "mitigation": "name",
    "tool": "name",
    "vendor": "name",
    "product": "name",
    "observable": "value",
}


async def _build_research_bundle_zip(db: AsyncSession, entry_ids: list[uuid.UUID], bundle_name: str) -> bytes:
    """Build a research bundle ZIP: per-entry markdown + entities.md + iocs.csv + attack_layer.json.

    Shared by the multi-select entry bundle export and the campaign bundle export.
    """
    from app.intelligence.correlation import ENTITY_CONFIG
    from app.intelligence.ttp import generate_navigator_layer

    entries: list[Entry] = []
    for eid in entry_ids:
        entry = await db.get(Entry, eid)
        if entry:
            entries.append(entry)
    if not entries:
        raise AppError(code="no_entries", message="No entries found to export", status_code=400)

    feed_titles = dict(
        (await db.execute(select(Feed.id, Feed.title).where(Feed.id.in_({e.feed_id for e in entries})))).all()
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        used_names: set[str] = set()
        ioc_rows: list[tuple[str, str, str]] = []  # (type, value, source entry title)

        for entry in entries:
            pub = entry.published_at.strftime("%Y-%m-%d") if entry.published_at else None
            md = entry_to_markdown(
                title=entry.title,
                feed_title=feed_titles.get(entry.feed_id),
                author=entry.author,
                published_at=pub,
                url=entry.url,
                tags=None,
                content_text=entry.content_text,
                content_html=entry.content_html,
            )
            safe = (entry.title or str(entry.id))[:50].replace("/", "-").replace("\\", "-")
            name, n = safe, 2
            while name in used_names:
                name = f"{safe}-{n}"
                n += 1
            used_names.add(name)
            zf.writestr(f"entries/{name}.md", md)

            for extracted in entry.extracted_urls or []:
                # extracted_urls holds {"url": ..., "context": ...} dicts, not bare strings.
                url = extracted.get("url") if isinstance(extracted, dict) else extracted
                if url:
                    ioc_rows.append(("referenced_url", url, entry.title or str(entry.id)))

        # iocs.csv reads the observables ledger — judged rows with dedup and
        # lifecycle — not a throwaway regex sweep of the prose (the v1 mistake:
        # that sweep exported private IPs and version strings as indicators).
        from app.models.observable import EntryObservable, Observable

        title_by_id = {e.id: (e.title or str(e.id)) for e in entries}
        obs_result = await db.execute(
            select(Observable.kind, Observable.value, EntryObservable.entry_id)
            .join(EntryObservable, EntryObservable.observable_id == Observable.id)
            .where(
                EntryObservable.entry_id.in_(list(title_by_id)),
                Observable.is_denied.is_(False),
            )
        )
        for kind, value, obs_entry_id in obs_result.all():
            ioc_rows.append((kind, value, title_by_id.get(obs_entry_id, "")))

        # --- entities.md: every entity linked to any entry in the bundle, grouped by type ---
        entity_lines = [f"# Entities referenced ({len(entries)} article(s))\n"]
        ttp_rows: list[dict] = []
        for entity_type, (model, junction, fk_col) in ENTITY_CONFIG.items():
            name_attr = _ENTITY_NAME_ATTR[entity_type]
            name_col = getattr(model, name_attr)
            result = await db.execute(
                select(model.id, name_col, func.count(func.distinct(junction.entry_id)))
                .join(junction, fk_col == model.id)
                .where(junction.entry_id.in_([e.id for e in entries]))
                .group_by(model.id, name_col)
                .order_by(func.count(func.distinct(junction.entry_id)).desc())
            )
            rows = result.all()
            if not rows:
                continue
            entity_lines.append(f"## {ENTITY_TYPE_LABELS.get(entity_type, entity_type)} ({len(rows)})\n")
            for _id, name, count in rows:
                entity_lines.append(f"- {name} ({count} article{'s' if count != 1 else ''})")
            entity_lines.append("")

            if entity_type == "ttp":
                for _id, technique_id, _count in rows:
                    ttp_rows.append({"technique_id": technique_id})

        zf.writestr("entities.md", "\n".join(entity_lines) + "\n")

        # --- iocs.csv ---
        csv_buf = io.StringIO()
        writer = csv.writer(csv_buf)
        writer.writerow(["type", "value", "source_entry"])
        writer.writerows(sorted(set(ioc_rows)))
        zf.writestr("iocs.csv", csv_buf.getvalue())

        # --- attack_layer.json ---
        layer = generate_navigator_layer(ttp_rows, title=bundle_name)
        zf.writestr("attack_layer.json", json.dumps(layer, indent=2))

        manifest = [
            f"IntelFeed research bundle — {bundle_name}",
            f"Entries: {len(entries)}",
            f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        ]
        zf.writestr("_manifest.txt", "\n".join(manifest) + "\n")

    buf.seek(0)
    return buf.read()


# Cap bulk profile exports so a "select all CVEs" can't spawn thousands of
# heavy pivot queries in a single synchronous request.
MAX_BULK_ENTITIES = 500


@router.get("/entries/{entry_id}")
async def export_entry(
    entry_id: uuid.UUID = Path(..., description="ID of the entry to export"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export a single entry as a downloadable markdown file, including its feed title, tags,
    and any notes attached to the entry."""
    # Get entry
    result = await db.execute(select(Entry).where(Entry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise AppError(
            code="not_found",
            message="Entry not found",
            status_code=404,
        )

    # Get feed title
    feed_result = await db.execute(select(Feed.title).where(Feed.id == entry.feed_id))
    feed_title = feed_result.scalar_one_or_none()

    # Get tags
    tag_result = await db.execute(
        select(Tag.name)
        .join(EntryTag, EntryTag.tag_id == Tag.id)
        .where(
            EntryTag.entry_id == entry_id,
        )
    )
    tags = [r[0] for r in tag_result.all()]

    # Get notes
    notes_result = await db.execute(
        select(Note).where(
            Note.entry_id == entry_id,
        )
    )
    notes = [
        {
            "title": n.title,
            "content_markdown": n.content_markdown,
            "created_at": n.created_at.strftime("%Y-%m-%d"),
        }
        for n in notes_result.scalars().all()
    ]

    pub = None
    if entry.published_at:
        pub = entry.published_at.strftime("%Y-%m-%d")

    md = entry_to_markdown(
        title=entry.title,
        feed_title=feed_title,
        author=entry.author,
        published_at=pub,
        url=entry.url,
        tags=tags or None,
        content_text=entry.content_text,
        content_html=entry.content_html,
        notes=notes or None,
    )

    safe_title = entry.title[:50].replace("/", "-").replace("\\", "-")
    filename = f"{safe_title}.md"

    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": (f'attachment; filename="{filename}"')},
    )


@router.get("/notes/{note_id}")
async def export_note(
    note_id: uuid.UUID = Path(..., description="ID of the note to export"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export a single note as a downloadable markdown file."""
    result = await db.execute(
        select(Note).where(
            Note.id == note_id,
        )
    )
    note = result.scalar_one_or_none()
    if not note:
        raise AppError(
            code="not_found",
            message="Note not found",
            status_code=404,
        )

    md = note_to_markdown(
        title=note.title,
        content_markdown=note.content_markdown,
        created_at=note.created_at.strftime("%Y-%m-%d"),
    )

    safe_title = note.title[:50].replace("/", "-").replace("\\", "-")
    filename = f"{safe_title}.md"

    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": (f'attachment; filename="{filename}"')},
    )


class BulkExportBody(BaseModel):
    entry_ids: list[uuid.UUID] = []
    note_ids: list[uuid.UUID] = []

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_ids": [
                    "d5b2f1c8-7a3e-4b9d-8c2f-1e6a9b4d7c3e",
                    "a1f4e7b2-9c5d-4e8a-b3f6-2d7c8e9a1b4f",
                ],
                "note_ids": ["c3e6a9d2-1b4f-4c7e-8a5b-9d2f3e6c1a8b"],
            }
        }
    )


@router.post("/bulk")
async def bulk_export(
    body: BulkExportBody,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export multiple entries and/or notes as a ZIP archive of markdown files
    (under entries/ and notes/ folders). IDs that do not resolve are silently skipped."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Export entries
        for eid in body.entry_ids:
            result = await db.execute(select(Entry).where(Entry.id == eid))
            entry = result.scalar_one_or_none()
            if not entry:
                continue

            feed_result = await db.execute(select(Feed.title).where(Feed.id == entry.feed_id))
            feed_title = feed_result.scalar_one_or_none()

            pub = None
            if entry.published_at:
                pub = entry.published_at.strftime("%Y-%m-%d")

            md = entry_to_markdown(
                title=entry.title,
                feed_title=feed_title,
                author=entry.author,
                published_at=pub,
                url=entry.url,
                tags=None,
                content_text=entry.content_text,
                content_html=entry.content_html,
            )
            safe = entry.title[:50].replace("/", "-").replace("\\", "-")
            zf.writestr(f"entries/{safe}.md", md)

        # Export notes
        for nid in body.note_ids:
            result = await db.execute(
                select(Note).where(
                    Note.id == nid,
                )
            )
            note = result.scalar_one_or_none()
            if not note:
                continue

            md = note_to_markdown(
                title=note.title,
                content_markdown=note.content_markdown,
                created_at=note.created_at.strftime("%Y-%m-%d"),
            )
            safe = note.title[:50].replace("/", "-").replace("\\", "-")
            zf.writestr(f"notes/{safe}.md", md)

    buf.seek(0)
    return Response(
        content=buf.read(),
        media_type="application/zip",
        headers={"Content-Disposition": ('attachment; filename="intelfeed-export.zip"')},
    )


@router.get("/entities/{entity_type}/{entity_id}")
async def export_entity_profile(
    entity_type: str = Path(
        ..., description="Entity type, e.g. 'threat_actor', 'malware', 'cve', 'ttp', 'tool', 'vendor', 'product'"
    ),
    entity_id: uuid.UUID = Path(..., description="ID of the entity to export"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export a single entity profile as a markdown document."""
    from app.intelligence.correlation import VALID_ENTITY_TYPES

    if entity_type not in VALID_ENTITY_TYPES:
        raise AppError(
            code="invalid_entity_type",
            message=f"Unknown entity type: {entity_type}",
            status_code=400,
        )

    result = await build_entity_profile_markdown(db, entity_type, entity_id)
    if not result:
        raise AppError(
            code="not_found",
            message="Entity not found",
            status_code=404,
        )

    filename_base, md = result
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": (f'attachment; filename="{filename_base}.md"')},
    )


class BulkEntityExportBody(BaseModel):
    entity_type: str
    entity_ids: list[uuid.UUID] = []
    all: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_type": "threat_actor",
                "entity_ids": [
                    "d5b2f1c8-7a3e-4b9d-8c2f-1e6a9b4d7c3e",
                    "a1f4e7b2-9c5d-4e8a-b3f6-2d7c8e9a1b4f",
                ],
                "all": False,
            }
        }
    )


@router.post("/entities/bulk")
async def bulk_export_entities(
    body: BulkEntityExportBody,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export many entity profiles of one type as a ZIP of markdown files.

    Pass explicit `entity_ids`, or `all: true` to export every entity of the
    type (capped at MAX_BULK_ENTITIES, most-referenced first).
    """
    from app.intelligence.correlation import ENTITY_CONFIG, VALID_ENTITY_TYPES

    if body.entity_type not in VALID_ENTITY_TYPES:
        raise AppError(
            code="invalid_entity_type",
            message=f"Unknown entity type: {body.entity_type}",
            status_code=400,
        )

    ids = list(body.entity_ids)
    truncated_total = 0
    if body.all:
        model = ENTITY_CONFIG[body.entity_type][0]
        order_col = getattr(model, "article_count", None)
        q = select(model.id)
        if order_col is not None:
            q = q.order_by(order_col.desc().nullslast())
        count_result = await db.execute(select(func.count()).select_from(model))
        truncated_total = count_result.scalar_one()
        q = q.limit(MAX_BULK_ENTITIES)
        id_result = await db.execute(q)
        ids = [row[0] for row in id_result.all()]
    else:
        if len(ids) > MAX_BULK_ENTITIES:
            truncated_total = len(ids)
            ids = ids[:MAX_BULK_ENTITIES]

    if not ids:
        raise AppError(
            code="no_entities",
            message="No entities selected for export",
            status_code=400,
        )

    type_label = ENTITY_TYPE_LABELS.get(body.entity_type, body.entity_type)
    folder = body.entity_type
    used_names: set[str] = set()
    exported = 0

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for eid in ids:
            try:
                result = await build_entity_profile_markdown(db, body.entity_type, eid, related_limit=25)
            except Exception:
                result = None
            if not result:
                continue
            filename_base, md = result
            # Disambiguate filename collisions within the archive.
            name = filename_base
            n = 2
            while name in used_names:
                name = f"{filename_base}-{n}"
                n += 1
            used_names.add(name)
            zf.writestr(f"{folder}/{name}.md", md)
            exported += 1

        manifest = [
            f"IntelFeed entity export — {type_label}",
            f"Exported: {exported} profile(s)",
        ]
        if truncated_total and truncated_total > len(ids):
            manifest.append(
                f"NOTE: truncated to the {len(ids)} most-referenced of {truncated_total} total {type_label} entities."
            )
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        manifest.append(f"Generated: {now}")
        zf.writestr("_manifest.txt", "\n".join(manifest) + "\n")

    buf.seek(0)
    return Response(
        content=buf.read(),
        media_type="application/zip",
        headers={"Content-Disposition": (f'attachment; filename="intelfeed-{folder}-profiles.zip"')},
    )


class ResearchBundleBody(BaseModel):
    entry_ids: list[uuid.UUID]
    name: str = "IntelFeed Export"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entry_ids": [
                    "d5b2f1c8-7a3e-4b9d-8c2f-1e6a9b4d7c3e",
                    "a1f4e7b2-9c5d-4e8a-b3f6-2d7c8e9a1b4f",
                ],
                "name": "LockBit Q3 Research",
            }
        }
    )


@router.post("/research-bundle")
async def export_research_bundle(
    body: ResearchBundleBody,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export a multi-select of entries as a research bundle ZIP.

    Contains per-entry markdown, an entities.md appendix (every linked
    entity across the selection, grouped by type), an iocs.csv (extracted
    URLs + a regex pass for IPv4/hashes), and an ATT&CK Navigator layer for
    the union of referenced techniques — an Obsidian/vault-ready hand-off.
    """
    if not body.entry_ids:
        raise AppError(code="no_entries", message="No entries selected", status_code=400)

    zip_bytes = await _build_research_bundle_zip(db, body.entry_ids, body.name)
    safe_name = re.sub(r"[^\w\- ]+", "", body.name)[:60] or "intelfeed-research-bundle"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": (f'attachment; filename="{safe_name}.zip"')},
    )


@router.get("/campaigns/{campaign_id}/bundle")
async def export_campaign_bundle(
    campaign_id: uuid.UUID = Path(..., description="ID of the campaign whose linked entries are bundled"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export every entry linked to a campaign as a research bundle ZIP (see /research-bundle)."""
    from app.models.campaign import Campaign, CampaignEntry

    campaign = await db.get(Campaign, campaign_id)
    if not campaign:
        raise AppError(code="not_found", message="Campaign not found", status_code=404)

    entry_ids_result = await db.execute(select(CampaignEntry.entry_id).where(CampaignEntry.campaign_id == campaign_id))
    entry_ids = [row[0] for row in entry_ids_result.all()]
    if not entry_ids:
        raise AppError(code="no_entries", message="Campaign has no linked entries", status_code=400)

    zip_bytes = await _build_research_bundle_zip(db, entry_ids, campaign.name)
    safe_name = re.sub(r"[^\w\- ]+", "", campaign.name)[:60] or "campaign"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": (f'attachment; filename="{safe_name}-bundle.zip"')},
    )
