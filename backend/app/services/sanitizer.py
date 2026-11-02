import html as html_module
import re
from urllib.parse import urlencode, urljoin

import nh3

ALLOWED_TAGS = {
    "p",
    "a",
    "img",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ul",
    "ol",
    "li",
    "pre",
    "code",
    "blockquote",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "em",
    "strong",
    "b",
    "i",
    "u",
    "s",
    "br",
    "hr",
    "figure",
    "figcaption",
    "span",
    "div",
    "dl",
    "dt",
    "dd",
    "sub",
    "sup",
    "abbr",
    "details",
    "summary",
    "mark",
    "del",
    "ins",
}

ALLOWED_ATTRIBUTES = {
    "*": {"class", "id", "lang", "dir", "title"},
    "a": {"href", "target"},
    "img": {"src", "alt", "width", "height", "loading"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan"},
    "code": {"class"},
    "blockquote": {"cite"},
}

IMG_SRC_RE = re.compile(r'(<img\s[^>]*?)src="([^"]+)"', re.IGNORECASE)


def rewrite_image_urls(html: str, proxy_base_url: str) -> str:
    """Rewrite <img src> URLs to proxy endpoint."""

    def replace_src(match: re.Match) -> str:
        prefix = match.group(1)
        original_url = match.group(2)
        if original_url.startswith(proxy_base_url):
            return match.group(0)
        # Telegram-downloaded media is served by our own auth-gated route — never proxy it.
        if original_url.startswith("/api/telegram-media/"):
            return match.group(0)
        # Undo HTML entity encoding from nh3 (e.g., &amp; → &)
        # Preserve existing percent-encoding so URLs with encoded paths
        # (e.g. Substack CDN embedding URLs in the path) round-trip correctly.
        clean_url = html_module.unescape(original_url)
        proxy_url = f"{proxy_base_url}?{urlencode({'url': clean_url})}"
        return f'{prefix}src="{proxy_url}"'

    return IMG_SRC_RE.sub(replace_src, html)


def sanitize_html(raw_html: str, proxy_base_url: str = "/api/proxy/image") -> str:
    """Sanitize HTML and rewrite image URLs to proxy."""
    clean = nh3.clean(
        raw_html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        link_rel="noopener noreferrer nofollow",
        url_schemes={"http", "https", "mailto"},
    )
    clean = rewrite_image_urls(clean, proxy_base_url)
    return clean


# Block-level tags break the line and table cells are kept apart by a tab.
# Without this nh3's strip glues neighbours together: list items of defanged
# IPs ran into one another (46.233.40.20 + 4… read as 46.233.40.204), a CVE
# column into its CVSS column (CVE-2026-103849 + 10), a caption into the next
# "Source:" line ("powerSource" matched POWERSOURCE).
_ATTRS = r"""(?:[^>"']|"[^"]*"|'[^']*')*"""
_PARA_BREAK_RE = re.compile(
    r"</?(?:p|div|ul|ol|table|thead|tbody|tfoot|blockquote|pre|figure|h[1-6]|dl|details|summary|"
    rf"section|article|header|footer|aside|nav|main|address)\b{_ATTRS}>|<hr\b{_ATTRS}>",
    re.IGNORECASE,
)
_LINE_BREAK_RE = re.compile(rf"</?(?:li|tr|dt|dd|figcaption|caption)\b{_ATTRS}>|<br\b{_ATTRS}>", re.IGNORECASE)
_CELL_BREAK_RE = re.compile(rf"</?t[dh]\b{_ATTRS}>", re.IGNORECASE)
# The tags are replaced by control-character marks before the strip (they
# would be dropped anyway, and an HTML parser moves text put between table
# rows out of the table). Each run of marks, with the source whitespace before
# and between them, then becomes one separator; where the source already had a
# newline (or, between cells, any whitespace) that whitespace is kept.
_PARA_MARK, _LINE_MARK, _CELL_MARK = "\x1e", "\x1d", "\x1f"
_MARKS = _PARA_MARK + _LINE_MARK + _CELL_MARK
_MARK_RUN_RE = re.compile(rf"[\s{_MARKS}]*[{_MARKS}]")


def _join_marks(m: re.Match) -> str:
    run = m.group(0)
    source_ws = "".join(ch for ch in run if ch not in _MARKS)
    at_edge = m.start() == 0 or m.end() == len(m.string)
    if _PARA_MARK in run or _LINE_MARK in run:
        if "\n" in source_ws or at_edge:
            return source_ws
        return "\n\n" if _PARA_MARK in run else "\n"
    return source_ws if source_ws or at_edge else "\t"


def html_to_text(html: str) -> str:
    """Strip HTML tags to get plain text.

    Text from neighbouring elements never runs together: paragraph-level
    elements are separated by a blank line, list items, table rows, captions
    and ``<br>`` by a newline, table cells by a tab — unless the source
    already had whitespace there, which is kept."""
    if not html:
        return ""
    for mark in _MARKS:
        html = html.replace(mark, "")
    spaced = _CELL_BREAK_RE.sub(_CELL_MARK, html)
    spaced = _LINE_BREAK_RE.sub(_LINE_MARK, spaced)
    spaced = _PARA_BREAK_RE.sub(_PARA_MARK, spaced)
    return _MARK_RUN_RE.sub(_join_marks, nh3.clean(spaced, tags=set()))


def entry_text_with_translation(entry) -> tuple[str, str]:
    """(title, content_text) for an entry with translated forms appended when present.

    Foreign-language entries carry entity mentions and keywords in non-Latin
    script that English-built matchers (autolink vocab, relevance keywords,
    regex extraction) won't catch — scanning original + translation together
    matches both forms. Duck-typed over Entry to keep this module model-free.
    """
    title = entry.title or ""
    content_text = entry.content_text or ""
    if getattr(entry, "translated_title", None):
        title = f"{title}\n{entry.translated_title}".strip()
    if getattr(entry, "translated_html", None):
        translated_text = html_to_text(entry.translated_html)
        if translated_text:
            content_text = f"{content_text}\n\n{translated_text}".strip()
    return title, content_text


_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_IMG_SRC_ATTR_RE = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
_IMG_DIM_RE = re.compile(r'\b(width|height)\s*=\s*["\']?(\d+)', re.IGNORECASE)
_OG_IMAGE_RE = re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
_OG_IMAGE_RE_ALT = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']', re.IGNORECASE)

# Tracking pixel / analytics beacon patterns that shouldn't be used as lead images.
_TRACKER_URL_PATTERNS = (
    "matomo.php",
    "/piwik",
    "wp-piwik",
    "/__track",
    "/pixel.gif",
    "/pixel.png",
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "/utm.gif",
    "feedburner.com/~ff",
    "feeds.feedburner.com",
)


def _normalize_relative(src: str) -> str:
    """Normalize CMS-style relative prefixes (e.g. .NET's ``~/``) to plain absolute paths."""
    if src.startswith("~/"):
        return src[1:]
    return src


def _is_tracking_pixel(img_tag: str, src: str) -> bool:
    """Return True if this <img> looks like a tracking beacon, not a real image."""
    src_lower = src.lower()
    for pat in _TRACKER_URL_PATTERNS:
        if pat in src_lower:
            return True
    for _, value in _IMG_DIM_RE.findall(img_tag):
        if value in ("0", "1"):
            return True
    return False


def extract_first_image(html: str, base_url: str | None = None) -> str | None:
    """Extract the first content-bearing <img> src URL from HTML.

    Skips tracking pixels (1x1, 0x0, analytics beacons). If base_url is given,
    relative srcs are resolved against it.
    """
    for img_tag in _IMG_TAG_RE.findall(html):
        m = _IMG_SRC_ATTR_RE.search(img_tag)
        if not m:
            continue
        src = _normalize_relative(html_module.unescape(m.group(1)))
        if _is_tracking_pixel(img_tag, src):
            continue
        if base_url:
            src = urljoin(base_url, src)
        return src
    return None


def extract_og_image(html: str, base_url: str | None = None) -> str | None:
    """Extract og:image from raw HTML page, resolving relative URLs against base_url."""
    m = _OG_IMAGE_RE.search(html) or _OG_IMAGE_RE_ALT.search(html)
    if not m:
        return None
    src = _normalize_relative(html_module.unescape(m.group(1)))
    if base_url:
        src = urljoin(base_url, src)
    return src
