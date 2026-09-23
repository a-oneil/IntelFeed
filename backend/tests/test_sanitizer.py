from app.services.sanitizer import html_to_text, rewrite_image_urls, sanitize_html


def test_sanitize_removes_script_tags():
    dirty = '<p>Hello</p><script>alert("xss")</script><p>World</p>'
    result = sanitize_html(dirty)
    assert "<script>" not in result
    assert "alert" not in result
    assert "<p>Hello</p>" in result
    assert "<p>World</p>" in result


def test_sanitize_allows_safe_tags():
    html = (
        "<p>Paragraph</p>"
        '<a href="https://example.com">Link</a>'
        "<strong>Bold</strong>"
        "<em>Italic</em>"
        "<ul><li>Item</li></ul>"
        "<code>code</code>"
        "<blockquote>Quote</blockquote>"
        "<h2>Heading</h2>"
        "<table><tr><td>Cell</td></tr></table>"
    )
    result = sanitize_html(html)
    assert "<p>" in result
    assert "<a " in result
    assert "<strong>" in result
    assert "<em>" in result
    assert "<ul>" in result
    assert "<li>" in result
    assert "<code>" in result
    assert "<blockquote>" in result
    assert "<h2>" in result
    assert "<table>" in result


def test_sanitize_strips_event_handlers():
    html = '<div onclick="alert(1)">Click me</div><img src="x.png" onerror="alert(2)">'
    result = sanitize_html(html)
    assert "onclick" not in result
    assert "onerror" not in result
    assert "alert" not in result


def test_rewrite_image_urls():
    html = '<img src="https://example.com/image.png" alt="test">'
    result = rewrite_image_urls(html, "/api/proxy/image")
    assert result.startswith('<img src="/api/proxy/image?')
    assert "url=https" in result
    assert "example.com" in result
    assert 'alt="test"' in result


def test_rewrite_skips_already_proxied():
    html = '<img src="/api/proxy/image?url=https%3A%2F%2Fexample.com%2Fimg.png" alt="test">'
    result = rewrite_image_urls(html, "/api/proxy/image")
    # Should be unchanged since src already starts with proxy base URL
    assert result == html


def test_rewrite_url_with_ampersand_query_params():
    """URLs with & in query params must not be corrupted by nh3's &amp; encoding."""
    html = '<img src="https://example.com/img.jpg?w=100&amp;h=200" alt="">'
    result = rewrite_image_urls(html, "/api/proxy/image")
    # The decoded URL should have & not &amp;
    import re
    from urllib.parse import parse_qs, urlparse

    m = re.search(r'src="([^"]+)"', result)
    assert m
    parsed = urlparse(m.group(1))
    params = parse_qs(parsed.query)
    decoded_url = params["url"][0]
    assert decoded_url == "https://example.com/img.jpg?w=100&h=200"


def test_rewrite_already_percent_encoded_url():
    """Already percent-encoded URLs must preserve their encoding through the proxy."""
    html = '<img src="https://cdn.example.com/image.jpg?resize=640%2C480" alt="">'
    result = rewrite_image_urls(html, "/api/proxy/image")
    import re
    from urllib.parse import parse_qs, urlparse

    m = re.search(r'src="([^"]+)"', result)
    assert m
    parsed = urlparse(m.group(1))
    params = parse_qs(parsed.query)
    decoded_url = params["url"][0]
    # Percent-encoding is preserved so CDNs with encoded paths work correctly
    assert decoded_url == "https://cdn.example.com/image.jpg?resize=640%2C480"


def test_rewrite_url_with_embedded_url_in_path():
    """CDN URLs that embed another URL in the path (e.g. Substack) must preserve encoding."""
    embedded = "https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Ftest.png"
    html = f'<img src="https://substackcdn.com/image/fetch/f_auto/{embedded}" alt="">'
    result = rewrite_image_urls(html, "/api/proxy/image")
    import re
    from urllib.parse import parse_qs, urlparse

    m = re.search(r'src="([^"]+)"', result)
    assert m
    parsed = urlparse(m.group(1))
    params = parse_qs(parsed.query)
    decoded_url = params["url"][0]
    # The embedded URL must stay percent-encoded in the path
    assert "%3A%2F%2F" in decoded_url or "%3a%2f%2f" in decoded_url.lower()
    assert decoded_url.startswith("https://substackcdn.com/image/fetch/f_auto/https%3A%2F%2F")


def test_html_to_text():
    html = "<p>Hello <strong>World</strong></p><br><a href='http://x.com'>Link</a>"
    result = html_to_text(html)
    assert "<p>" not in result
    assert "<strong>" not in result
    assert "<br>" not in result
    assert "<a" not in result
    assert "Hello" in result
    assert "World" in result
    assert "Link" in result
