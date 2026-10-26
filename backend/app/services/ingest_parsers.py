"""Format parsers for bulk ingest.

One function per file type, all returning the same ``ParsedDocument`` shape the
PDF extractor always returned (text + HTML), behind one registry keyed on a
normalized kind. Detection is extension first, then the client's content
type, then magic bytes — a browser frequently sends ``application/octet-stream``
for anything it does not recognise.

No new dependencies: PDF is PyMuPDF (already here), Markdown is the ``markdown``
package (already here), HTML goes through the entry sanitizer, CSV and e-mail
are the standard library, and .docx is a zip of XML read with defusedxml.
OCR for scanned PDFs is deliberately not here — that is a clean ``no text``
outcome, not a parser.
"""

import csv
import email
import email.policy
import html as html_mod
import io
import logging
import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field

import defusedxml.ElementTree as DefusedET

from app.services.sanitizer import ALLOWED_ATTRIBUTES, ALLOWED_TAGS, html_to_text, sanitize_html

logger = logging.getLogger(__name__)


class UnsupportedFormat(Exception):
    """No parser for this file."""


class EmptyDocument(Exception):
    """Parsed fine, but there is nothing to read (scanned PDF, blank file)."""


@dataclass
class ParsedDocument:
    text: str
    html: str
    title: str | None = None
    meta: dict = field(default_factory=dict)


# --- detection --------------------------------------------------------------

KIND_PDF = "pdf"
KIND_HTML = "html"
KIND_TEXT = "text"
KIND_CODE = "code"  # json / yaml / xml / log: shown verbatim in a code block
KIND_MARKDOWN = "markdown"
KIND_CSV = "csv"
KIND_EMAIL = "email"
KIND_DOCX = "docx"
KIND_ZIP = "zip"

EXTENSION_KINDS: dict[str, str] = {
    "pdf": KIND_PDF,
    "html": KIND_HTML,
    "htm": KIND_HTML,
    "xhtml": KIND_HTML,
    "txt": KIND_TEXT,
    "text": KIND_TEXT,
    "md": KIND_MARKDOWN,
    "markdown": KIND_MARKDOWN,
    "csv": KIND_CSV,
    "tsv": KIND_CSV,
    "eml": KIND_EMAIL,
    "docx": KIND_DOCX,
    "zip": KIND_ZIP,
    "json": KIND_CODE,
    "yml": KIND_CODE,
    "yaml": KIND_CODE,
    "xml": KIND_CODE,
    "log": KIND_CODE,
    "ioc": KIND_TEXT,
    "iocs": KIND_TEXT,
}

MIME_KINDS: dict[str, str] = {
    "application/pdf": KIND_PDF,
    "text/html": KIND_HTML,
    "application/xhtml+xml": KIND_HTML,
    "text/plain": KIND_TEXT,
    "text/markdown": KIND_MARKDOWN,
    "text/x-markdown": KIND_MARKDOWN,
    "text/csv": KIND_CSV,
    "text/tab-separated-values": KIND_CSV,
    "message/rfc822": KIND_EMAIL,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": KIND_DOCX,
    "application/zip": KIND_ZIP,
    "application/x-zip-compressed": KIND_ZIP,
    "application/json": KIND_CODE,
    "application/x-yaml": KIND_CODE,
    "text/yaml": KIND_CODE,
    "application/xml": KIND_CODE,
    "text/xml": KIND_CODE,
}

#: What the UI's file picker and the API advertise as accepted.
SUPPORTED_EXTENSIONS: tuple[str, ...] = tuple(sorted(EXTENSION_KINDS))

_EXT_RE = re.compile(r"\.([A-Za-z0-9]{1,8})$")


def detect_kind(filename: str | None, content_type: str | None, head: bytes) -> str | None:
    """Which parser a file gets, or None when nothing here reads it."""
    if filename:
        match = _EXT_RE.search(filename.strip())
        if match:
            kind = EXTENSION_KINDS.get(match.group(1).lower())
            if kind:
                return _refine_zip(kind, head)
    if content_type:
        mime = content_type.split(";", 1)[0].strip().lower()
        kind = MIME_KINDS.get(mime)
        if kind:
            return _refine_zip(kind, head)
    # Magic bytes: the browser said octet-stream, or the name had no extension.
    if head.startswith(b"%PDF-"):
        return KIND_PDF
    if head.startswith(b"PK\x03\x04"):
        return _refine_zip(KIND_ZIP, head)
    lowered = head[:512].lstrip().lower()
    if lowered.startswith((b"<!doctype html", b"<html")):
        return KIND_HTML
    if _looks_like_text(head):
        return KIND_TEXT
    return None


def _refine_zip(kind: str, head: bytes) -> str:
    """A .docx is a zip; a renamed zip may be a docx. The member list decides."""
    if kind not in (KIND_ZIP, KIND_DOCX):
        return kind
    if not head.startswith(b"PK\x03\x04"):
        # Named .zip/.docx but not a zip container at all.
        return kind
    return kind


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return False
    sample = head[:4096]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        return printable / len(sample) > 0.9


def decode_text(data: bytes) -> str:
    """Bytes to str: BOM-aware UTF-8, UTF-16 by BOM, then a lossless latin-1 fallback."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


# --- renderers shared by the text-like kinds ---------------------------------


def _paragraphs_html(text: str) -> str:
    chunks = [c.strip() for c in re.split(r"\n\s*\n", text) if c.strip()]
    return "".join(f"<p>{html_mod.escape(c).replace(chr(10), '<br>')}</p>" for c in chunks)


def _code_html(text: str) -> str:
    return f"<pre><code>{html_mod.escape(text)}</code></pre>"


def _require_text(text: str) -> str:
    if not text or not text.strip():
        raise EmptyDocument("nothing to read")
    return text


# --- parsers -----------------------------------------------------------------


def extract_pdf_content(content: bytes) -> tuple[str, str]:
    """Extract text and HTML (with embedded images) from PDF bytes.

    Returns (plain_text, html_with_images) tuple.
    """
    import fitz  # pymupdf

    text_pages = []
    html_pages = []
    with fitz.open(stream=content, filetype="pdf") as doc:
        for page in doc:
            text = page.get_text()
            if text.strip():
                text_pages.append(text.strip())
            # get_text("html") returns HTML with images as base64 data URIs
            page_html = page.get_text("html")
            if page_html.strip():
                html_pages.append(page_html)

    plain_text = "\n\n".join(text_pages)
    # If HTML extraction produced content with images, use it; otherwise fall back to
    # wrapping plain text in paragraphs
    if html_pages:
        combined_html = "\n".join(html_pages)
    else:
        paragraphs = plain_text.split("\n\n")
        combined_html = "".join(f"<p>{p.strip()}</p>" for p in paragraphs if p.strip())

    return plain_text, combined_html


def sanitize_pdf_html(raw_html: str) -> str:
    """Sanitize PDF-extracted HTML, allowing data: URIs for embedded images."""
    import nh3

    return nh3.clean(
        raw_html,
        tags=ALLOWED_TAGS | {"span", "div", "img"},
        attributes={
            **ALLOWED_ATTRIBUTES,
            "img": {"src", "alt", "width", "height", "loading", "style"},
            "span": {"style"},
            "div": {"style"},
            "p": {"style"},
        },
        link_rel="noopener noreferrer nofollow",
        url_schemes={"http", "https", "data"},
    )


def _parse_pdf(data: bytes, filename: str | None) -> ParsedDocument:
    if not data.startswith(b"%PDF-"):
        raise UnsupportedFormat("not a PDF")
    try:
        text, raw_html = extract_pdf_content(data)
    except Exception as exc:  # pymupdf raises a few different things for corrupt files
        raise UnsupportedFormat(f"PDF could not be opened: {exc}") from exc
    if not text.strip():
        raise EmptyDocument("Could not extract text from this PDF (it may be a scanned image)")
    title = None
    try:
        import fitz

        with fitz.open(stream=data, filetype="pdf") as doc:
            title = (doc.metadata or {}).get("title") or None
    except Exception:
        title = None
    return ParsedDocument(text=text, html=sanitize_pdf_html(raw_html), title=title)


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_H1_RE = re.compile(r"<h1[^>]*>(.*?)</h1>", re.IGNORECASE | re.DOTALL)


def _parse_html(data: bytes, filename: str | None) -> ParsedDocument:
    raw = decode_text(data)
    title = None
    match = _TITLE_RE.search(raw) or _H1_RE.search(raw)
    if match:
        title = html_to_text(match.group(1)).strip() or None
    sanitized = sanitize_html(raw)
    text = _require_text(html_to_text(sanitized))
    return ParsedDocument(text=text, html=sanitized, title=title)


def _parse_text(data: bytes, filename: str | None) -> ParsedDocument:
    text = _require_text(decode_text(data))
    return ParsedDocument(text=text, html=sanitize_html(_paragraphs_html(text)))


def _parse_code(data: bytes, filename: str | None) -> ParsedDocument:
    text = _require_text(decode_text(data))
    return ParsedDocument(text=text, html=sanitize_html(_code_html(text)))


_MD_H1_RE = re.compile(r"^\s*#\s+(.+?)\s*$", re.MULTILINE)


def _parse_markdown(data: bytes, filename: str | None) -> ParsedDocument:
    from app.services.markdown import render_markdown

    text_md = _require_text(decode_text(data))
    title_match = _MD_H1_RE.search(text_md)
    html = sanitize_html(render_markdown(text_md))
    text = _require_text(html_to_text(html)) if html.strip() else text_md
    return ParsedDocument(text=text, html=html, title=title_match.group(1).strip() if title_match else None)


_CSV_ROW_CAP = 2000


def _parse_csv(data: bytes, filename: str | None) -> ParsedDocument:
    raw = _require_text(decode_text(data))
    sample = raw[:4096]
    delimiter = "\t" if (filename or "").lower().endswith(".tsv") else ","
    try:
        delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        pass
    reader = csv.reader(io.StringIO(raw), delimiter=delimiter)
    rows: list[list[str]] = []
    truncated = False
    for row in reader:
        if not any(cell.strip() for cell in row):
            continue
        if len(rows) >= _CSV_ROW_CAP:
            truncated = True
            break
        rows.append([cell.strip() for cell in row])
    if not rows:
        raise EmptyDocument("empty table")
    # The analysis renderer keeps table rows as "cell | cell", so the text form
    # matches what the observables scan sees for HTML tables.
    text_lines = [" | ".join(r) for r in rows]
    head, *body = rows
    parts = ["<table><thead><tr>"]
    parts += [f"<th>{html_mod.escape(c)}</th>" for c in head]
    parts.append("</tr></thead><tbody>")
    for r in body:
        parts.append("<tr>" + "".join(f"<td>{html_mod.escape(c)}</td>" for c in r) + "</tr>")
    parts.append("</tbody></table>")
    if truncated:
        parts.append(f"<p><em>Showing the first {_CSV_ROW_CAP} rows.</em></p>")
    return ParsedDocument(
        text="\n".join(text_lines),
        html=sanitize_html("".join(parts)),
        meta={"rows": len(rows), "truncated": truncated, "delimiter": delimiter},
    )


def _parse_email(data: bytes, filename: str | None) -> ParsedDocument:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    subject = (msg.get("subject") or "").strip() or None
    meta = {
        "from": str(msg.get("from") or ""),
        "to": str(msg.get("to") or ""),
        "date": str(msg.get("date") or ""),
        "attachments": [],
    }
    body_html: str | None = None
    body_text: str | None = None
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment" or part.get_filename():
            meta["attachments"].append(part.get_filename() or "attachment")
            continue
        ctype = part.get_content_type()
        try:
            payload = part.get_content()
        except Exception:
            continue
        if not isinstance(payload, str):
            continue
        if ctype == "text/html" and body_html is None:
            body_html = payload
        elif ctype == "text/plain" and body_text is None:
            body_text = payload
    header_lines = [
        f"<strong>{html_mod.escape(k)}:</strong> {html_mod.escape(v)}"
        for k, v in meta.items()
        if isinstance(v, str) and v
    ]
    header_html = f"<p>{'<br>'.join(header_lines)}</p>" if header_lines else ""
    if body_html:
        html = sanitize_html(header_html + body_html)
        text = html_to_text(sanitize_html(body_html))
    elif body_text:
        html = sanitize_html(header_html + _paragraphs_html(body_text))
        text = body_text
    else:
        raise EmptyDocument("the message has no readable body")
    _require_text(text)
    return ParsedDocument(text=text, html=html, title=subject, meta=meta)


_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_DC_NS = "{http://purl.org/dc/elements/1.1/}"


def _docx_paragraph_text(p) -> str:
    out: list[str] = []
    for node in p.iter():
        if node.tag == f"{_W_NS}t" and node.text:
            out.append(node.text)
        elif node.tag in (f"{_W_NS}tab",):
            out.append("\t")
        elif node.tag in (f"{_W_NS}br", f"{_W_NS}cr"):
            out.append("\n")
    return "".join(out)


def _parse_docx(data: bytes, filename: str | None) -> ParsedDocument:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UnsupportedFormat("not a .docx file") from exc
    with archive:
        try:
            document_xml = archive.read("word/document.xml")
        except KeyError as exc:
            raise UnsupportedFormat("not a .docx file (no word/document.xml)") from exc
        core_title = None
        try:
            core = DefusedET.fromstring(archive.read("docProps/core.xml"))
            node = core.find(f"{_DC_NS}title")
            core_title = (node.text or "").strip() or None if node is not None else None
        except Exception:
            core_title = None
    root = DefusedET.fromstring(document_xml)
    body = root.find(f"{_W_NS}body")
    if body is None:
        raise EmptyDocument("the document has no body")
    html_parts: list[str] = []
    text_parts: list[str] = []
    first_heading: str | None = None
    for block in body:
        if block.tag == f"{_W_NS}p":
            text = _docx_paragraph_text(block).strip()
            if not text:
                continue
            style_node = block.find(f"{_W_NS}pPr/{_W_NS}pStyle")
            style = (style_node.get(f"{_W_NS}val") or "") if style_node is not None else ""
            level = re.match(r"(?i)heading\s*(\d)", style)
            if style.lower() == "title" or level:
                tag = "h2" if (style.lower() == "title" or level.group(1) == "1") else "h3"
                html_parts.append(f"<{tag}>{html_mod.escape(text)}</{tag}>")
                first_heading = first_heading or text
            else:
                html_parts.append(f"<p>{html_mod.escape(text).replace(chr(10), '<br>')}</p>")
            text_parts.append(text)
        elif block.tag == f"{_W_NS}tbl":
            rows: list[list[str]] = []
            for tr in block.iter(f"{_W_NS}tr"):
                cells = [" ".join(_docx_paragraph_text(p).split()) for tc in tr.findall(f"{_W_NS}tc") for p in [tc]]
                cells = [c.strip() for c in cells]
                if any(cells):
                    rows.append(cells)
            if rows:
                html_parts.append(
                    "<table><tbody>"
                    + "".join("<tr>" + "".join(f"<td>{html_mod.escape(c)}</td>" for c in r) + "</tr>" for r in rows)
                    + "</tbody></table>"
                )
                text_parts.extend(" | ".join(r) for r in rows)
    text = _require_text("\n\n".join(text_parts))
    return ParsedDocument(text=text, html=sanitize_html("".join(html_parts)), title=core_title or first_heading)


PARSERS = {
    KIND_PDF: _parse_pdf,
    KIND_HTML: _parse_html,
    KIND_TEXT: _parse_text,
    KIND_CODE: _parse_code,
    KIND_MARKDOWN: _parse_markdown,
    KIND_CSV: _parse_csv,
    KIND_EMAIL: _parse_email,
    KIND_DOCX: _parse_docx,
}


def parse_document(kind: str, data: bytes, filename: str | None = None) -> ParsedDocument:
    """Run the parser for ``kind``. Raises UnsupportedFormat / EmptyDocument."""
    parser = PARSERS.get(kind)
    if parser is None:
        raise UnsupportedFormat(f"no parser for {kind!r}")
    return parser(data, filename)


# --- zip expansion ---------------------------------------------------------------

#: Members nobody meant to ingest.
_ZIP_SKIP_PREFIXES = ("__MACOSX/",)
_ZIP_SKIP_NAMES = (".DS_Store", "Thumbs.db")


class ZipLimitExceeded(Exception):
    def __init__(self, members: int, cap: int):
        super().__init__(f"archive holds {members} files; the cap is {cap}")
        self.members = members
        self.cap = cap


def iter_zip_members(data: bytes, *, max_members: int, max_member_bytes: int) -> Iterator[tuple[str, bytes]]:
    """Yield ``(name, bytes)`` for the files in a zip, safely.

    Skips directories, macOS resource forks, dotfiles and anything whose name
    would escape a directory (``..`` or absolute). Nested archives come out as
    ordinary members; the caller decides whether to recurse (it does not).
    Raises ZipLimitExceeded before reading anything when there are too many
    files, and skips members over ``max_member_bytes`` by declared size, so a
    zip bomb costs a directory listing, not memory.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UnsupportedFormat("not a zip archive") from exc
    with archive:
        infos = [i for i in archive.infolist() if not i.is_dir() and _zip_member_allowed(i.filename)]
        if len(infos) > max_members:
            raise ZipLimitExceeded(len(infos), max_members)
        for info in infos:
            if info.file_size > max_member_bytes:
                logger.info("Skipping zip member %s (%d bytes over cap)", info.filename, info.file_size)
                continue
            try:
                yield info.filename, archive.read(info)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                # RuntimeError: encrypted member; NotImplementedError: compression we lack.
                logger.info("Skipping zip member %s: %s", info.filename, exc)
                continue


def _zip_member_allowed(name: str) -> bool:
    if not name or name.startswith(_ZIP_SKIP_PREFIXES):
        return False
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or ".." in normalized.split("/"):
        return False
    base = normalized.rsplit("/", 1)[-1]
    if base in _ZIP_SKIP_NAMES or base.startswith("."):
        return False
    return True
