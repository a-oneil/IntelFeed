"""Bulk ingest: parsers, the batch spine, per-item outcomes, the download route, eviction."""

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.config import settings
from app.models.entry import Entry
from app.models.feed import Feed
from app.models.ingest_batch import IngestFile
from app.services import ingest_batches as batches
from app.services import ingest_parsers as parsers
from app.services.manual_ingest import MANUAL_FEED_URL

# --- fixtures -------------------------------------------------------------------


@pytest.fixture
def ingest_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "ingest_files_dir", str(tmp_path), raising=False)
    return tmp_path


@pytest.fixture
def quiet_worker(monkeypatch):
    """No Celery, no pipeline, no Meilisearch: record what would have been dispatched."""
    dispatched: list[str] = []
    created: list[Entry] = []
    monkeypatch.setattr(batches, "dispatch_item", lambda item: dispatched.append(str(item.id)))
    monkeypatch.setattr(batches, "_after_entry_created", lambda entry: created.append(entry))
    return {"dispatched": dispatched, "created": created}


def _pdf_bytes(text: str | None) -> bytes:
    import fitz

    doc = fitz.open()
    page = doc.new_page()
    if text:
        page.insert_text((72, 72), text)
    data = doc.tobytes()
    doc.close()
    return data


def _docx_bytes(paragraphs: list[tuple[str, str | None]], title: str | None = None) -> bytes:
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = ""
    for text, style in paragraphs:
        ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
        body += f"<w:p>{ppr}<w:r><w:t>{text}</w:t></w:r></w:p>"
    document = f'<?xml version="1.0"?><w:document xmlns:w="{w}"><w:body>{body}</w:body></w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", document)
        if title:
            zf.writestr(
                "docProps/core.xml",
                '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                f'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>{title}</dc:title></cp:coreProperties>',
            )
    return buf.getvalue()


async def _upload(client: AsyncClient, headers: dict, batch_id: str, name: str, data: bytes, ctype: str, **form):
    return await client.post(
        f"/api/entries/ingest/batches/{batch_id}/files",
        headers=headers,
        files={"file": (name, data, ctype)},
        data={k: str(v) for k, v in form.items()},
    )


async def _new_batch(client: AsyncClient, headers: dict) -> str:
    res = await client.post("/api/entries/ingest/batches", headers=headers, json={"label": "test drop"})
    assert res.status_code == 201, res.text
    return res.json()["id"]


# --- parsers ------------------------------------------------------------------------


def test_detect_kind_prefers_extension_then_mime_then_magic():
    assert parsers.detect_kind("report.PDF", "application/octet-stream", b"%PDF-1.7") == parsers.KIND_PDF
    assert parsers.detect_kind("notes", "text/markdown", b"# hi") == parsers.KIND_MARKDOWN
    assert parsers.detect_kind("blob", "application/octet-stream", b"%PDF-1.4 ...") == parsers.KIND_PDF
    assert parsers.detect_kind("blob", None, b"<!DOCTYPE html><html>") == parsers.KIND_HTML
    assert parsers.detect_kind("blob", None, b"plain words\nmore words") == parsers.KIND_TEXT
    assert parsers.detect_kind("blob", "application/octet-stream", b"\x00\x01\x02\xff" * 20) is None


def test_text_markdown_code_parsers():
    text = parsers.parse_document(parsers.KIND_TEXT, b"LockBit hit three hospitals.\n\nSecond paragraph.")
    assert text.html.count("<p>") == 2 and "LockBit" in text.text

    md = parsers.parse_document(parsers.KIND_MARKDOWN, b"# Scattered Spider notes\n\nThey **vish** helpdesks.")
    assert md.title == "Scattered Spider notes"
    assert "<strong>vish</strong>" in md.html and "vish" in md.text

    code = parsers.parse_document(parsers.KIND_CODE, b'{"a": 1}', "x.json")
    assert code.html.startswith("<pre><code>")

    with pytest.raises(parsers.EmptyDocument):
        parsers.parse_document(parsers.KIND_TEXT, b"   \n  ")


def test_csv_parser_builds_table_and_pipe_text():
    doc = parsers.parse_document(parsers.KIND_CSV, b"indicator,type\n1.2.3.4,ip\nevil.example,domain\n", "iocs.csv")
    assert "<table>" in doc.html and "<th>indicator</th>" in doc.html
    assert doc.text.splitlines()[1] == "1.2.3.4 | ip"
    assert doc.meta["rows"] == 3


def test_email_parser_uses_subject_and_body():
    raw = (
        b"From: alice@example.com\r\nTo: soc@example.com\r\nSubject: Phish report\r\n"
        b"Date: Fri, 24 Oct 2026 09:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Caller claimed to be IT. Domain used: login-okta.example\r\n"
    )
    doc = parsers.parse_document(parsers.KIND_EMAIL, raw, "report.eml")
    assert doc.title == "Phish report"
    assert "login-okta.example" in doc.text
    assert "alice@example.com" in doc.html
    assert doc.meta["from"] == "alice@example.com"


def test_docx_parser_reads_paragraphs_headings_and_title():
    data = _docx_bytes([("Incident notes", "Heading1"), ("The helpdesk took three calls.", None)], title="Oct 22 notes")
    doc = parsers.parse_document(parsers.KIND_DOCX, data, "notes.docx")
    assert doc.title == "Oct 22 notes"
    assert "<h2>Incident notes</h2>" in doc.html
    assert "three calls" in doc.text

    with pytest.raises(parsers.UnsupportedFormat):
        parsers.parse_document(parsers.KIND_DOCX, b"not a zip", "x.docx")


def test_pdf_parser_text_and_scanned():
    doc = parsers.parse_document(parsers.KIND_PDF, _pdf_bytes("Qilin ransomware note"), "a.pdf")
    assert "Qilin" in doc.text
    with pytest.raises(parsers.EmptyDocument):
        parsers.parse_document(parsers.KIND_PDF, _pdf_bytes(None), "scan.pdf")
    with pytest.raises(parsers.UnsupportedFormat):
        parsers.parse_document(parsers.KIND_PDF, b"nope", "a.pdf")


def test_zip_members_skip_traversal_and_junk_and_enforce_cap():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docs/a.txt", "alpha")
        zf.writestr("../escape.txt", "nope")
        zf.writestr("__MACOSX/._a.txt", "junk")
        zf.writestr(".hidden", "junk")
        zf.writestr("docs/", "")
        zf.writestr("b.md", "# beta")
    data = buf.getvalue()
    names = [n for n, _ in parsers.iter_zip_members(data, max_members=10, max_member_bytes=1_000_000)]
    assert names == ["docs/a.txt", "b.md"]
    with pytest.raises(parsers.ZipLimitExceeded):
        list(parsers.iter_zip_members(data, max_members=1, max_member_bytes=1_000_000))
    with pytest.raises(parsers.UnsupportedFormat):
        list(parsers.iter_zip_members(b"not zip", max_members=10, max_member_bytes=10))


def test_parse_github_repo_url():
    assert batches.parse_github_repo_url("https://github.com/SigmaHQ/sigma") == {
        "owner": "SigmaHQ",
        "repo": "sigma",
        "branch": None,
        "path": None,
    }
    assert batches.parse_github_repo_url("https://github.com/drb-ra/C2IntelFeeds/tree/master/feeds/") == {
        "owner": "drb-ra",
        "repo": "C2IntelFeeds",
        "branch": "master",
        "path": "feeds",
    }
    assert batches.parse_github_repo_url("https://github.com/orgs/foo/repositories") is None
    assert batches.parse_github_repo_url("https://example.com/a/b") is None


# --- the batch spine through the API ---------------------------------------------------


@pytest.mark.asyncio
async def test_file_batch_creates_entry_and_keeps_original(
    client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker
):
    batch_id = await _new_batch(client, auth_headers)
    res = await _upload(client, auth_headers, batch_id, "notes.txt", b"LockBit note.\n\nTwo lines.", "text/plain")
    assert res.status_code == 201, res.text
    item = res.json()
    assert item["status"] == "queued" and item["file"]["retained"] is True
    assert quiet_worker["dispatched"] == [item["id"]]
    stored = ingest_dir / batch_id / f"{item['file']['id']}.txt"
    assert stored.read_bytes() == b"LockBit note.\n\nTwo lines."

    done = await batches.process_item(db_session, uuid.UUID(item["id"]))
    assert done.status == "created", done.error
    entry = (await db_session.execute(select(Entry).where(Entry.id == done.entry_id))).scalar_one()
    feed = (await db_session.execute(select(Feed).where(Feed.id == entry.feed_id))).scalar_one()
    assert feed.url == MANUAL_FEED_URL
    assert entry.title == "notes"
    meta = entry.metadata_
    assert meta["source"] == "file_upload"
    assert meta["batch_id"] == batch_id
    assert meta["filename"] == "notes.txt"
    assert meta["ingest_file_id"] == item["file"]["id"]
    assert meta["original_retained"] is True
    assert "content_type" not in meta  # not an indicator list
    assert [e.id for e in quiet_worker["created"]] == [entry.id]

    res = await client.get(f"/api/entries/ingest/batches/{batch_id}", headers=auth_headers)
    body = res.json()
    assert body["summary"]["status"] == "complete" and body["summary"]["created"] == 1
    assert body["items"][0]["phase"] == "analyzing"
    assert body["items"][0]["entry_title"] == "notes"
    assert body["items"][0]["file"]["download_url"] == f"/api/ingest-files/{item['file']['id']}"


@pytest.mark.asyncio
async def test_per_item_outcomes_never_fail_the_batch(
    client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker, monkeypatch
):
    batch_id = await _new_batch(client, auth_headers)
    good = (await _upload(client, auth_headers, batch_id, "a.txt", b"first copy", "text/plain")).json()
    twin = (await _upload(client, auth_headers, batch_id, "b.txt", b"first copy", "text/plain")).json()
    scanned = (await _upload(client, auth_headers, batch_id, "scan.pdf", _pdf_bytes(None), "application/pdf")).json()
    weird = (
        await _upload(client, auth_headers, batch_id, "blob.xyz", b"\x00\x01\x02\xff" * 50, "application/octet-stream")
    ).json()

    monkeypatch.setattr(batches.store, "max_file_bytes", lambda: 1024 * 1024)
    big = (await _upload(client, auth_headers, batch_id, "big.txt", b"x" * (1024 * 1024 + 1), "text/plain")).json()
    assert big["status"] == "too_large" and big["file"] is None

    for it in (good, twin, scanned, weird):
        await batches.process_item(db_session, uuid.UUID(it["id"]))

    res = await client.get(f"/api/entries/ingest/batches/{batch_id}", headers=auth_headers)
    by_name = {i["filename"]: i for i in res.json()["items"]}
    assert by_name["a.txt"]["status"] == "created"
    assert by_name["b.txt"]["status"] == "duplicate"
    assert by_name["b.txt"]["entry_id"] == by_name["a.txt"]["entry_id"]
    assert by_name["scan.pdf"]["status"] == "no_text" and "scanned" in by_name["scan.pdf"]["error"]
    assert by_name["blob.xyz"]["status"] == "unsupported"
    assert by_name["big.txt"]["status"] == "too_large"
    assert res.json()["summary"] == {
        "total": 5,
        "active": 0,
        "created": 1,
        "duplicate": 1,
        "failed": 3,
        "status": "complete",
        "by_status": {"created": 1, "duplicate": 1, "no_text": 1, "unsupported": 1, "too_large": 1},
    }
    # Only one entry came out of five items.
    assert len(quiet_worker["created"]) == 1


@pytest.mark.asyncio
async def test_paste_marked_as_indicator_list_takes_the_curated_door(
    client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker
):
    batch_id = await _new_batch(client, auth_headers)
    res = await client.post(
        f"/api/entries/ingest/batches/{batch_id}/text",
        headers=auth_headers,
        json={"text": "1.2.3.4\nevil.example\n", "title": "C2 export", "is_ioc_list": True},
    )
    assert res.status_code == 201, res.text
    item = res.json()
    assert item["kind"] == "text" and item["filename"] == "c2-export.txt" and item["is_ioc_list"] is True
    done = await batches.process_item(db_session, uuid.UUID(item["id"]))
    assert done.status == "created"
    entry = (await db_session.execute(select(Entry).where(Entry.id == done.entry_id))).scalar_one()
    assert entry.metadata_["content_type"] == "ioc_list"
    assert entry.metadata_["raw_content"].startswith("1.2.3.4")
    assert entry.metadata_["source"] == "text_paste"
    assert entry.title == "C2 export"


@pytest.mark.asyncio
async def test_url_items_bad_scheme_is_a_row_and_github_links_become_repo_items(
    client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker, monkeypatch
):
    batch_id = await _new_batch(client, auth_headers)
    res = await client.post(
        f"/api/entries/ingest/batches/{batch_id}/urls",
        headers=auth_headers,
        json={
            "urls": [
                "https://example.com/report",
                "ftp://example.com/nope",
                "https://github.com/drb-ra/C2IntelFeeds/tree/master/feeds",
                "https://example.com/report",
            ]
        },
    )
    assert res.status_code == 201, res.text
    items = res.json()
    assert [i["kind"] for i in items] == ["url", "url", "github_repo"]
    assert items[1]["status"] == "failed" and "http" in items[1]["error"]
    assert items[2]["filename"] == "drb-ra/C2IntelFeeds"
    # Only the two live items were queued.
    assert set(quiet_worker["dispatched"]) == {items[0]["id"], items[2]["id"]}

    async def fake_fetch(url):
        return parsers.ParsedDocument(
            text="Page body about APT29.", html="<p>Page body about APT29.</p>", title="Report"
        )

    monkeypatch.setattr(batches, "fetch_url_document", fake_fetch)
    done = await batches.process_item(db_session, uuid.UUID(items[0]["id"]))
    assert done.status == "created"
    entry = (await db_session.execute(select(Entry).where(Entry.id == done.entry_id))).scalar_one()
    assert entry.url == "https://example.com/report" and entry.metadata_["source"] == "url_ingest"
    assert entry.guid.startswith("manual:url:")


@pytest.mark.asyncio
async def test_github_repo_item_expands_through_the_adapter_without_a_feed(
    client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker, monkeypatch
):
    from datetime import datetime as _dt

    from app.adapters.base import ParsedEntry
    from app.adapters.github_repo import GitHubRepoAdapter

    calls: list[dict] = []

    async def fake_full_tree(self, config, existing_guids=None):
        calls.append(config)
        if config["branch"] != "master":
            return None, []
        return None, [
            ParsedEntry(
                guid="drb-ra/C2IntelFeeds/feeds/domainC2s.csv",
                url="https://github.com/drb-ra/C2IntelFeeds/blob/abc/feeds/domainC2s.csv",
                title="domainC2s.csv",
                content_html="<pre>evil.example,Cobalt Strike</pre>",
                published_at=_dt.now(UTC),
                metadata={
                    "source": "github_repo",
                    "file_path": "feeds/domainC2s.csv",
                    "raw_content": "evil.example,Cobalt Strike\n",
                    "content_type": "ioc_list",
                    "commit_sha": "abc",
                },
            )
        ]

    monkeypatch.setattr(GitHubRepoAdapter, "fetch_full_tree", fake_full_tree)
    batch_id = await _new_batch(client, auth_headers)
    res = await client.post(
        f"/api/entries/ingest/batches/{batch_id}/urls",
        headers=auth_headers,
        json={"urls": ["https://github.com/drb-ra/C2IntelFeeds/tree/master/feeds"]},
    )
    parent_id = res.json()[0]["id"]
    parent = await batches.process_item(db_session, uuid.UUID(parent_id))
    assert parent.status == "expanded" and parent.extra["children"] == 1
    assert calls[0]["paths"] == ["feeds/**"] and calls[0]["branch"] == "master"

    body = (await client.get(f"/api/entries/ingest/batches/{batch_id}", headers=auth_headers)).json()
    child = next(i for i in body["items"] if i["kind"] == "github_file")
    assert child["parent_item_id"] == parent_id and child["filename"] == "domainC2s.csv"
    assert child["id"] in quiet_worker["dispatched"]

    done = await batches.process_item(db_session, uuid.UUID(child["id"]))
    assert done.status == "created", done.error
    entry = (await db_session.execute(select(Entry).where(Entry.id == done.entry_id))).scalar_one()
    assert entry.guid == "manual:github:drb-ra/C2IntelFeeds/feeds/domainC2s.csv"
    assert entry.metadata_["source"] == "github_repo"
    assert entry.metadata_["content_type"] == "ioc_list"  # the adapter's own classification rides along
    assert entry.metadata_["file_path"] == "feeds/domainC2s.csv"
    # No feed was minted for the repo.
    feeds = (await db_session.execute(select(Feed).where(Feed.feed_type == "github_repo"))).scalars().all()
    assert feeds == []


@pytest.mark.asyncio
async def test_zip_expands_into_child_items(client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("reports/one.txt", "Report one body.")
        zf.writestr("reports/two.md", "# Two\n\nReport two body.")
        zf.writestr("../escape.txt", "never")
    batch_id = await _new_batch(client, auth_headers)
    res = await _upload(client, auth_headers, batch_id, "drop.zip", buf.getvalue(), "application/zip")
    parent = await batches.process_item(db_session, uuid.UUID(res.json()["id"]))
    assert parent.status == "expanded" and parent.extra["children"] == 2

    body = (await client.get(f"/api/entries/ingest/batches/{batch_id}", headers=auth_headers)).json()
    children = [i for i in body["items"] if i["parent_item_id"] == res.json()["id"]]
    assert sorted(c["filename"] for c in children) == ["one.txt", "two.md"]
    for c in children:
        assert (await batches.process_item(db_session, uuid.UUID(c["id"]))).status == "created"
    assert len(quiet_worker["created"]) == 2


@pytest.mark.asyncio
async def test_retry_and_delete_items(
    client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker, monkeypatch
):
    batch_id = await _new_batch(client, auth_headers)
    item = (await _upload(client, auth_headers, batch_id, "x.txt", b"body text here", "text/plain")).json()

    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(batches, "parse_document", boom)
    failed = await batches.process_item(db_session, uuid.UUID(item["id"]))
    assert failed.status == "failed" and "disk on fire" in failed.error
    monkeypatch.undo()
    monkeypatch.setattr(settings, "ingest_files_dir", str(ingest_dir), raising=False)
    monkeypatch.setattr(batches, "dispatch_item", lambda i: quiet_worker["dispatched"].append(str(i.id)))
    monkeypatch.setattr(batches, "_after_entry_created", lambda e: quiet_worker["created"].append(e))

    res = await client.post(f"/api/entries/ingest/batches/{batch_id}/items/{item['id']}/retry", headers=auth_headers)
    assert res.status_code == 200 and res.json()["status"] == "queued" and res.json()["attempts"] == 1
    assert (await batches.process_item(db_session, uuid.UUID(item["id"]))).status == "created"

    # A created item cannot be retried; a fresh queued one can be deleted, file and all.
    res = await client.post(f"/api/entries/ingest/batches/{batch_id}/items/{item['id']}/retry", headers=auth_headers)
    assert res.status_code == 409
    other = (await _upload(client, auth_headers, batch_id, "y.txt", b"gone soon", "text/plain")).json()
    path = ingest_dir / batch_id / f"{other['file']['id']}.txt"
    assert path.exists()
    res = await client.delete(f"/api/entries/ingest/batches/{batch_id}/items/{other['id']}", headers=auth_headers)
    assert res.status_code == 204
    assert not path.exists()
    body = (await client.get(f"/api/entries/ingest/batches/{batch_id}", headers=auth_headers)).json()
    assert [i["filename"] for i in body["items"]] == ["x.txt"]


@pytest.mark.asyncio
async def test_batch_belongs_to_its_creator(client: AsyncClient, auth_headers, admin_headers, db_session, ingest_dir):
    batch_id = await _new_batch(client, auth_headers)
    # Another (admin) user may add to it; a different non-admin may not.
    from app.core.security import create_access_token, hash_password
    from app.models.user import User

    stranger = User(username="stranger", password_hash=hash_password("x"), role="user")
    db_session.add(stranger)
    await db_session.flush()
    stranger_headers = {"Authorization": f"Bearer {create_access_token(stranger.id, 'user')}"}
    res = await client.post(
        f"/api/entries/ingest/batches/{batch_id}/text", headers=stranger_headers, json={"text": "hi there"}
    )
    assert res.status_code == 403
    res = await client.post(f"/api/entries/ingest/batches/{batch_id}/text", headers=admin_headers, json={"text": "hi"})
    assert res.status_code == 201


@pytest.mark.asyncio
async def test_list_batches_and_capabilities(client: AsyncClient, auth_headers, ingest_dir, quiet_worker):
    await _new_batch(client, auth_headers)
    res = await client.get("/api/entries/ingest/batches?mine=true", headers=auth_headers)
    assert res.status_code == 200 and res.json()[0]["label"] == "test drop"
    caps = (await client.get("/api/entries/ingest/capabilities", headers=auth_headers)).json()
    assert "pdf" in caps["extensions"] and "docx" in caps["extensions"] and caps["max_file_mb"] == 50


# --- the one-item PDF door now keeps the original --------------------------------------


@pytest.mark.asyncio
async def test_legacy_pdf_endpoint_keeps_contract_and_stores_original(
    client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker
):
    data = _pdf_bytes("Akira ransomware advisory")
    res = await client.post(
        "/api/entries/ingest/pdf",
        headers=auth_headers,
        files={"file": ("advisory.pdf", data, "application/pdf")},
        data={"title": "Akira advisory"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["title"] == "Akira advisory" and body["message"] == "Entry created"
    entry = (await db_session.execute(select(Entry).where(Entry.id == uuid.UUID(body["id"])))).scalar_one()
    assert entry.metadata_["source"] == "pdf_upload" and entry.metadata_["original_retained"] is True
    assert entry.guid.startswith("manual:pdf:")
    stored = (await db_session.execute(select(IngestFile).where(IngestFile.entry_id == entry.id))).scalar_one()
    assert (ingest_dir / stored.path).read_bytes() == data

    # Same bytes again: still the 409 the Android client expects.
    res = await client.post(
        "/api/entries/ingest/pdf", headers=auth_headers, files={"file": ("again.pdf", data, "application/pdf")}
    )
    assert res.status_code == 409
    res = await client.post(
        "/api/entries/ingest/pdf",
        headers=auth_headers,
        files={"file": ("scan.pdf", _pdf_bytes(None), "application/pdf")},
    )
    assert res.status_code == 422


# --- download route -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_route(client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker):
    batch_id = await _new_batch(client, auth_headers)
    item = (await _upload(client, auth_headers, batch_id, "réport.txt", b"download me", "text/plain")).json()
    url = item["file"]["download_url"]

    assert (await client.get(url)).status_code == 401
    res = await client.get(url, headers=auth_headers)
    assert res.status_code == 200 and res.content == b"download me"
    assert res.headers["content-type"].startswith("text/plain")
    assert (
        "attachment" in res.headers["content-disposition"] and "r%C3%A9port.txt" in res.headers["content-disposition"]
    )

    token = auth_headers["Authorization"].split(" ", 1)[1]
    res = await client.get(f"{url}?token={token}&inline=true")
    assert res.status_code == 200 and res.headers["content-disposition"].startswith("inline")

    assert (await client.get(f"/api/ingest-files/{uuid.uuid4()}", headers=auth_headers)).status_code == 404

    row = (
        await db_session.execute(select(IngestFile).where(IngestFile.id == uuid.UUID(item["file"]["id"])))
    ).scalar_one()
    row.evicted_at = datetime.now(UTC)
    await db_session.flush()
    res = await client.get(url, headers=auth_headers)
    assert res.status_code == 404 and res.json()["error"]["code"] == "ingest_file_evicted"


# --- eviction -------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_eviction_removes_file_keeps_entry(
    client: AsyncClient, auth_headers, db_session, ingest_dir, quiet_worker, monkeypatch
):
    from contextlib import asynccontextmanager

    from app.workers import maintenance

    batch_id = await _new_batch(client, auth_headers)
    old = (await _upload(client, auth_headers, batch_id, "old.txt", b"old upload", "text/plain")).json()
    fresh = (await _upload(client, auth_headers, batch_id, "fresh.txt", b"fresh upload", "text/plain")).json()
    for it in (old, fresh):
        assert (await batches.process_item(db_session, uuid.UUID(it["id"]))).status == "created"
    old_row = (
        await db_session.execute(select(IngestFile).where(IngestFile.id == uuid.UUID(old["file"]["id"])))
    ).scalar_one()
    old_row.created_at = datetime.now(UTC) - timedelta(days=400)
    await db_session.flush()

    @asynccontextmanager
    async def fake_session():
        yield db_session

    monkeypatch.setattr(maintenance, "_get_worker_session", fake_session)
    result = await maintenance._evict_old_ingest_files(180)
    assert result == {"evicted": 1}

    assert not (ingest_dir / old_row.path).exists()
    assert (ingest_dir / batch_id / f"{fresh['file']['id']}.txt").exists()
    await db_session.refresh(old_row)
    assert old_row.evicted_at is not None
    entry = (await db_session.execute(select(Entry).where(Entry.id == old_row.entry_id))).scalar_one()
    await db_session.refresh(entry)
    assert entry.metadata_["original_retained"] is False
    assert entry.content_text == "old upload"  # the entry survives
    body = (await client.get(f"/api/entries/ingest/batches/{batch_id}", headers=auth_headers)).json()
    by_name = {i["filename"]: i for i in body["items"]}
    assert by_name["old.txt"]["file"]["retained"] is False and by_name["fresh.txt"]["file"]["retained"] is True


# --- registry tools ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_tools(db_session, test_user, ingest_dir, quiet_worker):
    import base64

    from app.tools import execute_tool

    out = json.loads(
        await execute_tool("ingest_text", {"text": "Pasted via tool", "title": "Tool paste"}, db_session, test_user.id)
    )
    assert out["summary"]["total"] == 1 and out["items"][0]["kind"] == "text"
    out = json.loads(
        await execute_tool(
            "ingest_file",
            {"filename": "a.md", "content_base64": base64.b64encode(b"# Hello\n\nbody").decode()},
            db_session,
            test_user.id,
        )
    )
    assert out["items"][0]["filename"] == "a.md"
    out = json.loads(
        await execute_tool(
            "ingest_batch",
            {"urls": ["https://example.com/x", "https://github.com/a/b"], "texts": [{"text": "t1"}]},
            db_session,
            test_user.id,
        )
    )
    assert [i["kind"] for i in out["items"]] == ["url", "github_repo", "text"]
    status = json.loads(await execute_tool("get_ingest_batch", {"batch_id": out["batch_id"]}, db_session, test_user.id))
    assert status["summary"]["total"] == 3 and status["summary"]["status"] == "processing"
    assert "error" in json.loads(await execute_tool("get_ingest_batch", {"batch_id": "nope"}, db_session, test_user.id))
