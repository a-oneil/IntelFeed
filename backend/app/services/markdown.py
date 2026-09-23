"""Markdown rendering service for notes and export."""

import html as html_mod
import re
from datetime import UTC
from urllib.parse import parse_qs, urlparse

import markdown
import nh3
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.tables import TableExtension
from markdown.extensions.toc import TocExtension


def _deproxy_url(proxy_url: str) -> str:
    """Extract original URL from a proxy image URL."""
    if "/api/proxy/image" not in proxy_url:
        return proxy_url
    parsed = urlparse(proxy_url)
    params = parse_qs(parsed.query)
    if "url" in params:
        return params["url"][0]
    return proxy_url


def _img_to_md(match: re.Match) -> str:
    """Convert an img tag to markdown image syntax."""
    tag = match.group(0)
    src_m = re.search(r'src="([^"]*)"', tag)
    alt_m = re.search(r'alt="([^"]*)"', tag)
    if not src_m:
        return ""
    url = _deproxy_url(src_m.group(1))
    alt = alt_m.group(1) if alt_m else ""
    return f"\n\n![{alt}]({url})\n\n"


def html_to_markdown_content(html: str) -> str:
    """Convert sanitized HTML to markdown, preserving images and links."""
    if not html:
        return ""

    text = html

    # Convert images to markdown (before stripping other tags)
    text = re.sub(r"<img\s[^>]*?>", _img_to_md, text)

    # Convert links
    text = re.sub(
        r'<a\s[^>]*?href="([^"]*)"[^>]*?>(.*?)</a>',
        r"[\2](\1)",
        text,
        flags=re.DOTALL,
    )

    # Convert headings
    for i in range(6, 0, -1):
        text = re.sub(
            rf"<h{i}[^>]*>(.*?)</h{i}>",
            lambda m, level=i: "\n\n" + "#" * level + " " + m.group(1).strip() + "\n\n",
            text,
            flags=re.DOTALL,
        )

    # Convert pre/code blocks
    text = re.sub(
        r"<pre[^>]*><code[^>]*>(.*?)</code></pre>",
        lambda m: "\n\n```\n" + m.group(1).strip() + "\n```\n\n",
        text,
        flags=re.DOTALL,
    )
    text = re.sub(r"<code>(.*?)</code>", r"`\1`", text, flags=re.DOTALL)

    # Convert formatting
    text = re.sub(r"<(?:strong|b)>(.*?)</(?:strong|b)>", r"**\1**", text, flags=re.DOTALL)
    text = re.sub(r"<(?:em|i)>(.*?)</(?:em|i)>", r"*\1*", text, flags=re.DOTALL)

    # Convert blockquotes
    def _blockquote_to_md(m: re.Match) -> str:
        inner = m.group(1).strip()
        lines = [line for line in inner.split("\n") if line.strip()]
        return "\n" + "\n".join("> " + line for line in lines) + "\n"

    text = re.sub(r"<blockquote[^>]*>(.*?)</blockquote>", _blockquote_to_md, text, flags=re.DOTALL)

    # Convert list items
    text = re.sub(r"<li[^>]*>(.*?)</li>", r"- \1\n", text, flags=re.DOTALL)

    # Convert line breaks and horizontal rules
    text = re.sub(r"<br\s*/?>", "\n", text)
    text = re.sub(r"<hr\s*/?>", "\n\n---\n\n", text)

    # Convert paragraph and div endings to spacing
    text = re.sub(r"</p>", "\n\n", text)
    text = re.sub(r"</div>", "\n", text)

    # Strip remaining tags
    text = re.sub(r"<[^>]+>", "", text)

    # Decode HTML entities
    text = html_mod.unescape(text)

    # Clean up whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" +", " ", text)
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = text.strip()

    return text


def render_markdown(text: str) -> str:
    """Convert markdown to sanitized HTML with GFM-like features."""
    md = markdown.Markdown(
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(css_class="highlight", guess_lang=False),
            TableExtension(),
            TocExtension(permalink=False),
            "markdown.extensions.nl2br",
            "markdown.extensions.sane_lists",
            "markdown.extensions.smarty",
        ]
    )
    html = md.convert(text)
    # Sanitize the output
    clean_html = nh3.clean(
        html,
        tags={
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "p",
            "br",
            "hr",
            "ul",
            "ol",
            "li",
            "strong",
            "em",
            "del",
            "s",
            "a",
            "code",
            "pre",
            "table",
            "thead",
            "tbody",
            "tr",
            "th",
            "td",
            "blockquote",
            "div",
            "span",
            "mark",
            "input",
            "img",
        },
        attributes={
            "*": {"class", "id"},
            "a": {"href", "title", "target"},
            "img": {"src", "alt", "title"},
            "input": {"type", "checked", "disabled"},
            "td": {"align"},
            "th": {"align"},
        },
        link_rel="noopener noreferrer",
    )
    return clean_html


def entry_to_markdown(
    title: str,
    feed_title: str | None,
    author: str | None,
    published_at: str | None,
    url: str | None,
    tags: list[str] | None,
    content_text: str | None,
    content_html: str | None = None,
    notes: list[dict] | None = None,
) -> str:
    """Export an entry as a markdown document."""
    lines = [f"# {title}", ""]

    if feed_title:
        lines.append(f"**Source**: {feed_title}")
    if author:
        lines.append(f"**Author**: {author}")
    if published_at:
        lines.append(f"**Published**: {published_at}")
    if url:
        lines.append(f"**URL**: {url}")
    if tags:
        lines.append(f"**Tags**: {', '.join(tags)}")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Content")
    lines.append("")
    # Prefer HTML-to-markdown (preserves images), fall back to plain text
    if content_html:
        lines.append(html_to_markdown_content(content_html))
    else:
        lines.append(content_text or "*No content available*")

    if notes:
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Notes")
        lines.append("")
        for note in notes:
            lines.append(f"### {note['title']}")
            lines.append(f"*Created: {note.get('created_at', 'Unknown')}*")
            lines.append("")
            lines.append(note.get("content_markdown", ""))
            lines.append("")

    lines.append("---")
    lines.append("")
    from datetime import datetime

    now = datetime.now(UTC).strftime("%Y-%m-%d")
    lines.append(f"*Exported from IntelFeed on {now}*")

    return "\n".join(lines)


def note_to_markdown(title: str, content_markdown: str, created_at: str | None = None) -> str:
    """Export a note as a markdown document."""
    lines = [f"# {title}", ""]
    if created_at:
        lines.append(f"*Created: {created_at}*")
        lines.append("")
    lines.append(content_markdown)
    lines.append("")
    lines.append("---")
    lines.append("")
    from datetime import datetime

    now = datetime.now(UTC).strftime("%Y-%m-%d")
    lines.append(f"*Exported from IntelFeed on {now}*")
    return "\n".join(lines)
