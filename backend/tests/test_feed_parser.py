"""Unit tests for feedparser parsing of RSS and Atom XML.

These are pure unit tests -- no database or network access required.
"""

import feedparser

SAMPLE_RSS_20 = """\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Security News</title>
    <link>https://example.com</link>
    <description>Latest security news</description>
    <item>
      <title>Critical CVE-2024-0001 Discovered</title>
      <link>https://example.com/cve-2024-0001</link>
      <guid>https://example.com/cve-2024-0001</guid>
      <description>A critical vulnerability was found in the widget library.</description>
      <pubDate>Mon, 01 Jan 2024 12:00:00 GMT</pubDate>
      <author>analyst@example.com</author>
    </item>
    <item>
      <title>New Threat Actor TTPs</title>
      <link>https://example.com/ttp-report</link>
      <guid>https://example.com/ttp-report</guid>
      <description>Detailed analysis of recent threat actor techniques.</description>
      <pubDate>Tue, 02 Jan 2024 08:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

SAMPLE_ATOM = """\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Threat Intel Blog</title>
  <link href="https://blog.example.com"/>
  <id>urn:uuid:blog-feed-001</id>
  <updated>2024-01-03T10:00:00Z</updated>
  <entry>
    <title>SIGMA Rule for Lateral Movement</title>
    <link href="https://blog.example.com/sigma-lateral"/>
    <id>urn:uuid:entry-001</id>
    <updated>2024-01-03T10:00:00Z</updated>
    <summary>New SIGMA detection rule for lateral movement via PsExec.</summary>
    <author><name>Detection Engineer</name></author>
  </entry>
</feed>
"""


class TestParseRssFeed:
    def test_parse_rss_feed(self):
        """feedparser correctly parses a minimal RSS 2.0 document."""
        parsed = feedparser.parse(SAMPLE_RSS_20)

        assert parsed.bozo == 0, f"feedparser reported an error: {parsed.bozo_exception}"
        assert parsed.feed.title == "Security News"
        assert parsed.feed.link == "https://example.com"
        assert parsed.feed.description == "Latest security news"

        assert len(parsed.entries) == 2

        first = parsed.entries[0]
        assert first.title == "Critical CVE-2024-0001 Discovered"
        assert first.link == "https://example.com/cve-2024-0001"
        assert first.id == "https://example.com/cve-2024-0001"
        assert "critical vulnerability" in first.description.lower()
        assert first.published_parsed is not None

        second = parsed.entries[1]
        assert second.title == "New Threat Actor TTPs"
        assert second.link == "https://example.com/ttp-report"

    def test_rss_entry_fields(self):
        """Verify that individual RSS entry fields are accessible."""
        parsed = feedparser.parse(SAMPLE_RSS_20)
        first = parsed.entries[0]

        # guid maps to feedparser's id field
        assert first.get("id") == "https://example.com/cve-2024-0001"
        assert first.get("link") == "https://example.com/cve-2024-0001"
        assert first.get("author") == "analyst@example.com"
        assert first.get("summary") is not None or first.get("description") is not None


class TestParseAtomFeed:
    def test_parse_atom_feed(self):
        """feedparser correctly parses a minimal Atom document."""
        parsed = feedparser.parse(SAMPLE_ATOM)

        assert parsed.bozo == 0, f"feedparser reported an error: {parsed.bozo_exception}"
        assert parsed.feed.title == "Threat Intel Blog"

        assert len(parsed.entries) == 1

        entry = parsed.entries[0]
        assert entry.title == "SIGMA Rule for Lateral Movement"
        assert entry.link == "https://blog.example.com/sigma-lateral"
        assert entry.id == "urn:uuid:entry-001"
        assert "SIGMA" in entry.summary
        assert entry.author == "Detection Engineer"
        assert entry.updated_parsed is not None


class TestParseEmptyFeed:
    def test_parse_empty_feed(self):
        """feedparser handles an RSS feed with no items."""
        empty_rss = """\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Empty Feed</title>
    <link>https://example.com</link>
    <description>No items here</description>
  </channel>
</rss>
"""
        parsed = feedparser.parse(empty_rss)

        assert parsed.bozo == 0
        assert parsed.feed.title == "Empty Feed"
        assert len(parsed.entries) == 0

    def test_parse_empty_atom_feed(self):
        """feedparser handles an Atom feed with no entries."""
        empty_atom = """\
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Empty Atom Feed</title>
  <id>urn:uuid:empty-feed</id>
  <updated>2024-01-01T00:00:00Z</updated>
</feed>
"""
        parsed = feedparser.parse(empty_atom)

        assert parsed.bozo == 0
        assert parsed.feed.title == "Empty Atom Feed"
        assert len(parsed.entries) == 0

    def test_parse_empty_string(self):
        """feedparser handles a completely empty string without crashing."""
        parsed = feedparser.parse("")

        # feedparser sets bozo=1 for unparseable content
        assert len(parsed.entries) == 0


class TestParseInvalidXml:
    def test_parse_invalid_xml(self):
        """feedparser handles malformed XML gracefully (bozo flag set)."""
        invalid_xml = "<rss><channel><title>Broken</title><item><title>Unclosed"
        parsed = feedparser.parse(invalid_xml)

        # feedparser is lenient but should flag it as bozo
        assert parsed.bozo == 1

    def test_parse_non_xml_content(self):
        """feedparser handles non-XML content (e.g. HTML page) gracefully."""
        html_page = """\
<!DOCTYPE html>
<html><head><title>Not a feed</title></head>
<body><p>This is a regular web page, not a feed.</p></body>
</html>
"""
        parsed = feedparser.parse(html_page)

        # feedparser should not produce valid feed entries
        assert len(parsed.entries) == 0

    def test_parse_random_text(self):
        """feedparser handles random text without raising exceptions."""
        parsed = feedparser.parse("just some random text that is not XML at all")

        assert parsed.bozo == 1
        assert len(parsed.entries) == 0
