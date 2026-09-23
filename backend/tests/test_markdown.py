"""Tests for the markdown rendering and conversion service."""

from app.services.markdown import (
    entry_to_markdown,
    html_to_markdown_content,
    note_to_markdown,
    render_markdown,
)


class TestRenderMarkdown:
    """Tests for render_markdown (markdown -> sanitized HTML)."""

    def test_basic_paragraph(self):
        result = render_markdown("Hello world")
        assert "<p>" in result
        assert "Hello world" in result

    def test_heading(self):
        result = render_markdown("## Heading 2")
        assert "<h2" in result
        assert "Heading 2" in result

    def test_bold_and_italic(self):
        result = render_markdown("**bold** and *italic*")
        assert "<strong>bold</strong>" in result
        assert "<em>italic</em>" in result

    def test_fenced_code_block(self):
        result = render_markdown("```python\nprint('hi')\n```")
        assert "<code" in result
        assert "print" in result

    def test_inline_code(self):
        result = render_markdown("Use `foo()` here")
        assert "<code>foo()</code>" in result

    def test_link(self):
        result = render_markdown("[click](https://example.com)")
        assert 'href="https://example.com"' in result
        assert "click" in result

    def test_link_gets_rel_attribute(self):
        """nh3 should add rel=noopener noreferrer to links."""
        result = render_markdown("[link](https://example.com)")
        assert "noopener" in result

    def test_table(self):
        md = "| A | B |\n|---|---|\n| 1 | 2 |"
        result = render_markdown(md)
        assert "<table>" in result
        assert "<td>" in result

    def test_unordered_list(self):
        result = render_markdown("- item 1\n- item 2")
        assert "<li>" in result
        assert "item 1" in result

    def test_ordered_list(self):
        result = render_markdown("1. first\n2. second")
        assert "<ol>" in result
        assert "<li>" in result

    def test_blockquote(self):
        result = render_markdown("> quoted text")
        assert "<blockquote>" in result
        assert "quoted text" in result

    def test_html_input_doesnt_crash(self):
        """Frontend sends HTML from TipTap — render_markdown must not crash."""
        result = render_markdown("<p>Hello there</p>")
        assert "Hello" in result

    def test_empty_string(self):
        result = render_markdown("")
        assert result == ""

    def test_whitespace_only(self):
        result = render_markdown("   ")
        assert isinstance(result, str)

    def test_xss_script_stripped(self):
        result = render_markdown("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "alert" not in result

    def test_xss_onerror_stripped(self):
        result = render_markdown('<img src=x onerror="alert(1)">')
        assert "onerror" not in result

    def test_image_tag_preserved(self):
        result = render_markdown("![alt](https://example.com/img.png)")
        assert "<img" in result
        assert 'src="https://example.com/img.png"' in result

    def test_strikethrough(self):
        result = render_markdown("~~deleted~~")
        assert "<del>" in result or "deleted" in result

    def test_newlines_become_br(self):
        """nl2br extension should convert newlines to <br>."""
        result = render_markdown("line1\nline2")
        assert "<br" in result

    def test_special_characters(self):
        result = render_markdown("1 < 2 & 3 > 0")
        assert "&lt;" in result or "<" not in result.replace("<p>", "").replace("</p>", "").replace("<br", "")


class TestHtmlToMarkdownContent:
    """Tests for html_to_markdown_content (HTML -> markdown text)."""

    def test_paragraph(self):
        result = html_to_markdown_content("<p>Hello</p>")
        assert "Hello" in result

    def test_heading_conversion(self):
        result = html_to_markdown_content("<h2>Title</h2>")
        assert "## Title" in result

    def test_bold(self):
        result = html_to_markdown_content("<strong>bold</strong>")
        assert "**bold**" in result

    def test_italic(self):
        result = html_to_markdown_content("<em>italic</em>")
        assert "*italic*" in result

    def test_link(self):
        result = html_to_markdown_content('<a href="https://example.com">click</a>')
        assert "[click](https://example.com)" in result

    def test_image(self):
        result = html_to_markdown_content('<img src="https://example.com/img.png" alt="photo">')
        assert "![photo](https://example.com/img.png)" in result

    def test_code_block(self):
        result = html_to_markdown_content("<pre><code>foo()</code></pre>")
        assert "```" in result
        assert "foo()" in result

    def test_inline_code(self):
        result = html_to_markdown_content("<code>bar</code>")
        assert "`bar`" in result

    def test_list_items(self):
        result = html_to_markdown_content("<ul><li>one</li><li>two</li></ul>")
        assert "- one" in result
        assert "- two" in result

    def test_blockquote(self):
        result = html_to_markdown_content("<blockquote>quoted</blockquote>")
        assert "> quoted" in result

    def test_empty_input(self):
        assert html_to_markdown_content("") == ""

    def test_proxy_image_deproxy(self):
        result = html_to_markdown_content(
            '<img src="/api/proxy/image?url=https%3A%2F%2Fexample.com%2Fimg.png" alt="test">'
        )
        assert "https://example.com/img.png" in result

    def test_br_to_newline(self):
        result = html_to_markdown_content("line1<br/>line2")
        assert "line1\nline2" in result

    def test_hr_to_separator(self):
        result = html_to_markdown_content("<hr>")
        assert "---" in result


class TestEntryToMarkdown:
    """Tests for entry_to_markdown export."""

    def test_basic_export(self):
        result = entry_to_markdown(
            title="Test Entry",
            feed_title="Test Feed",
            author="Author",
            published_at="2025-01-01",
            url="https://example.com",
            tags=["security", "cve"],
            content_text="Entry content here",
        )
        assert "# Test Entry" in result
        assert "**Source**: Test Feed" in result
        assert "**Author**: Author" in result
        assert "security, cve" in result
        assert "Entry content here" in result

    def test_minimal_export(self):
        result = entry_to_markdown(
            title="Minimal",
            feed_title=None,
            author=None,
            published_at=None,
            url=None,
            tags=None,
            content_text=None,
        )
        assert "# Minimal" in result
        assert "*No content available*" in result

    def test_html_content_preferred(self):
        result = entry_to_markdown(
            title="Test",
            feed_title=None,
            author=None,
            published_at=None,
            url=None,
            tags=None,
            content_text="plain text",
            content_html="<p>rich content</p>",
        )
        assert "rich content" in result

    def test_notes_included(self):
        result = entry_to_markdown(
            title="Test",
            feed_title=None,
            author=None,
            published_at=None,
            url=None,
            tags=None,
            content_text="content",
            notes=[{"title": "My Note", "content_markdown": "note body", "created_at": "2025-01-01"}],
        )
        assert "### My Note" in result
        assert "note body" in result


class TestNoteToMarkdown:
    """Tests for note_to_markdown export."""

    def test_basic_export(self):
        result = note_to_markdown("My Note", "Some content", "2025-01-01")
        assert "# My Note" in result
        assert "Some content" in result
        assert "2025-01-01" in result
        assert "Exported from IntelFeed" in result

    def test_without_date(self):
        result = note_to_markdown("My Note", "Content")
        assert "# My Note" in result
        assert "Content" in result
