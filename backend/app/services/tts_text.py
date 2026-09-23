"""Server-side port of the frontend read-aloud text preprocessing.

Mirrors frontend/src/utils/speechPreprocess.ts so Piper reads security articles
sanely: URLs/emails/hashes are collapsed to a word, CVE IDs are spelled out,
IPs/hostnames are dotted, and <pre> code blocks are stubbed instead of read
character by character. Kept behaviourally in sync with the TS version so the
browser (Web Speech) fallback and the Piper path pronounce content the same.
"""

import re

import markdown as _markdown
from lxml import html as lxml_html

_URL_RE = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE[-\s_]?(\d{4})[-\s_]?(\d+)\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-f0-9]{32,}\b", re.IGNORECASE)
_TLD_LIST = (
    "com|net|org|io|gov|edu|co|us|uk|ru|cn|de|fr|jp|info|biz|xyz|app|dev|tech|"
    "cloud|systems|security|tv|mil|me|ai|nl|au|ca|in|it|es|pl|br|kr|tw|hk|sg|nz|za"
)
_HOSTNAME_RE = re.compile(rf"\b(?:[a-z0-9][a-z0-9-]*\.)+(?:{_TLD_LIST})\b", re.IGNORECASE)
_FILE_PATH_RE = re.compile(r"\b[a-z]:\\[\w\\.\- ]+|/(?:[\w.\- ]+/)+[\w.\- ]+", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")

_BLOCK_TAGS = {"p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "blockquote", "td", "pre"}


def clean_for_speech(text: str) -> str:
    """Strip noise from a paragraph before sending it to the synthesizer."""
    text = _URL_RE.sub(" link ", text)
    text = _EMAIL_RE.sub(" email address ", text)
    text = _HASH_RE.sub(" hash ", text)
    text = _CVE_RE.sub(r"C V E \1 \2", text)
    text = _IPV4_RE.sub(lambda m: m.group(0).replace(".", " dot "), text)
    text = _HOSTNAME_RE.sub(lambda m: m.group(0).replace(".", " dot "), text)
    text = _FILE_PATH_RE.sub(" file path ", text)
    text = _WS_RE.sub(" ", text)
    return text.strip()


def extract_paragraphs(content_html: str | None, title: str | None = None) -> list[str]:
    """Pull readable paragraphs out of article HTML for read-aloud.

    Mirrors extractSpeechParagraphs(): title first, block-level text after, with
    nested blocks de-duplicated and <pre> replaced by a stub.
    """
    paragraphs: list[str] = []
    if title and title.strip():
        paragraphs.append(clean_for_speech(title))

    if not content_html or not content_html.strip():
        return paragraphs

    try:
        root = lxml_html.fromstring(content_html)
    except Exception:  # noqa: BLE001 — malformed HTML falls back to the text split below
        root = None

    pushed: list = []
    if root is not None:
        for block in root.iter(*_BLOCK_TAGS):
            # Skip blocks nested inside an already-emitted block (e.g. <p> in <li>).
            if any(anc in pushed for anc in block.iterancestors()):
                continue

            tag = block.tag.lower() if isinstance(block.tag, str) else ""
            if tag == "pre":
                paragraphs.append("Code block.")
                pushed.append(block)
                continue

            raw = (block.text_content() or "").strip()
            if not raw:
                continue
            cleaned = clean_for_speech(raw)
            if not cleaned:
                continue
            paragraphs.append(cleaned)
            pushed.append(block)

    # Fallback for content without recognizable blocks.
    if len(paragraphs) == (1 if title and title.strip() else 0):
        text = ""
        if root is not None:
            text = (root.text_content() or "").strip()
        if not text:
            text = content_html.strip()
        for chunk in re.split(r"\n\s*\n", text):
            cleaned = clean_for_speech(chunk)
            if cleaned:
                paragraphs.append(cleaned)

    return paragraphs


def paragraphs_to_speech_text(paragraphs: list[str]) -> str:
    """Join paragraphs into a single string for the synthesizer.

    Blank lines between paragraphs give Piper a prosodic pause.
    """
    return "\n\n".join(p for p in paragraphs if p.strip()).strip()


def text_from_html(content_html: str | None, title: str | None = None) -> str:
    """Convenience: HTML (+ optional title) → a single normalized speech string."""
    return paragraphs_to_speech_text(extract_paragraphs(content_html, title))


def text_from_markdown(markdown_text: str | None, title: str | None = None) -> str:
    """Markdown (e.g. the daily AI summary) → a single normalized speech string.

    Renders to HTML then reuses the HTML block extraction, so markdown syntax
    (headings, ``**bold**``, ``[text](url)`` links) is stripped to its readable
    text rather than spoken literally. Used server-side by both the daily-summary
    pre-generation and the on-click path so their cache keys match.
    """
    if not markdown_text or not markdown_text.strip():
        return text_from_html(None, title)
    html = _markdown.markdown(markdown_text, extensions=["extra"])
    return text_from_html(html, title)


def normalize_plain_text(text: str) -> str:
    """Normalize an already-plain string (e.g. a daily summary) for speech.

    Splits on blank lines, cleans each chunk, and rejoins — no HTML parsing.
    """
    chunks = [clean_for_speech(c) for c in re.split(r"\n\s*\n", text or "")]
    return paragraphs_to_speech_text(chunks)
