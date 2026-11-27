"""Tests for app.services.link_preview — what a pasted link is, before subscribing.

Every outbound request goes through an httpx.MockTransport, so nothing here
touches the network or the database.
"""

from unittest.mock import patch

import httpx
import pytest

from app.services import link_preview
from app.services.link_preview import PreviewError, _identify, normalize_link

RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>{title}</title>
<link>https://blog.example.com</link><description>d</description></channel></rss>"""

SITE_TWO_FEEDS = """<html><head><title>Example Blog</title>
<link rel="alternate" type="application/rss+xml" href="/feed/" title="Example Blog">
<link rel="alternate" type="application/rss+xml" href="/comments/feed/" title="Comments">
</head><body></body></html>"""

PAGE_NO_FEED = """<html><head><title>Research | Example</title></head><body><main>
<article><h2><a href="/research/one">One</a></h2></article>
<article><h2><a href="/research/two">Two</a></h2></article>
<article><h2><a href="/research/three">Three</a></h2></article>
</main></body></html>"""


def _mock(routes: dict):
    """Patch both modules' safe_async_client with a transport answering ``routes``.

    Keys are full URLs (query string ignored) and values are
    ``(status, body, content_type)``; anything unrouted is a 404.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        key = str(request.url.copy_with(query=None))
        status, body, ctype = routes.get(key, (404, "", "text/plain"))
        if isinstance(body, (dict, list)):
            return httpx.Response(status, json=body)
        return httpx.Response(status, text=body, headers={"content-type": ctype})

    def factory(**kwargs):
        kwargs.pop("allow_private", None)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    return (
        patch.object(link_preview, "safe_async_client", factory),
        patch("app.services.feed_discovery.safe_async_client", factory),
    )


async def _run(url: str, routes: dict):
    a, b = _mock(routes)
    with a, b, patch("app.adapters.github_repo._get_token", return_value=""):
        return await _identify(normalize_link(url))


class TestNormalize:
    def test_adds_https(self):
        assert normalize_link("thedfirreport.com") == "https://thedfirreport.com"

    def test_rejects_words(self):
        with pytest.raises(PreviewError):
            normalize_link("ransomware")

    def test_rejects_empty(self):
        with pytest.raises(PreviewError):
            normalize_link("   ")


class TestSites:
    async def test_site_with_two_feeds_lists_both(self):
        p = await _run(
            "https://blog.example.com",
            {
                "https://blog.example.com": (200, SITE_TWO_FEEDS, "text/html"),
                "https://blog.example.com/feed/": (200, RSS.format(title="Example Blog"), "application/rss+xml"),
                "https://blog.example.com/comments/feed/": (
                    200,
                    RSS.format(title="Comments on Example Blog"),
                    "application/rss+xml",
                ),
            },
        )
        assert p.kind == "feed"
        assert [f.url for f in p.feeds] == [
            "https://blog.example.com/feed/",
            "https://blog.example.com/comments/feed/",
        ]
        assert p.title == "Example Blog"

    async def test_page_with_no_feed_counts_article_links(self):
        p = await _run(
            "https://example.com/research",
            {"https://example.com/research": (200, PAGE_NO_FEED, "text/html")},
        )
        assert p.kind == "page"
        assert p.feed_type == "web_scraper"
        assert p.page["article_links"] == 3

    async def test_unreachable_link_is_an_error(self):
        with pytest.raises(PreviewError):
            await _run("https://nowhere.example.com", {})


class TestGitHub:
    async def test_known_rule_repo_uses_its_template_paths(self):
        p = await _run(
            "https://github.com/SigmaHQ/sigma",
            {
                "https://api.github.com/repos/SigmaHQ/sigma": (
                    200,
                    {"owner": {"login": "SigmaHQ"}, "name": "sigma", "default_branch": "master"},
                    "",
                ),
                "https://api.github.com/repos/SigmaHQ/sigma/releases": (200, [{"id": 1}], ""),
            },
        )
        assert p.kind == "github"
        assert p.github["rules"]["label"] == "Sigma rules"
        assert p.github["rules"]["paths"] == ["rules/**/*.yml"]
        assert p.github["rules"]["folders"] == ["rules/"]
        assert p.github["has_releases"] is True

    async def test_unknown_repo_with_yara_files_is_found_by_the_tree(self):
        p = await _run(
            "github.com/acme/sigs",
            {
                "https://api.github.com/repos/acme/sigs": (
                    200,
                    {"owner": {"login": "acme"}, "name": "sigs", "default_branch": "main"},
                    "",
                ),
                "https://api.github.com/repos/acme/sigs/git/trees/main": (
                    200,
                    {
                        "tree": [
                            {"path": "yara/apt/a.yar", "type": "blob"},
                            {"path": "yara/b.yar", "type": "blob"},
                            {"path": "README.md", "type": "blob"},
                        ]
                    },
                    "",
                ),
                "https://api.github.com/repos/acme/sigs/releases": (200, [], ""),
            },
        )
        assert p.github["rules"]["label"] == "YARA rules"
        assert p.github["rules"]["paths"] == ["yara/**/*.yar"]
        assert p.github["has_releases"] is False

    async def test_repo_without_rules_says_so(self):
        p = await _run(
            "https://github.com/owner/project/tree/main/src",
            {
                "https://api.github.com/repos/owner/project": (
                    200,
                    {"owner": {"login": "owner"}, "name": "project", "default_branch": "main"},
                    "",
                ),
                "https://api.github.com/repos/owner/project/git/trees/main": (
                    200,
                    {"tree": [{"path": "src/app.py", "type": "blob"}]},
                    "",
                ),
            },
        )
        assert p.title == "owner/project"
        assert p.url == "https://github.com/owner/project"
        assert p.github["rules"] is None

    async def test_missing_repo_is_an_error(self):
        with pytest.raises(PreviewError):
            await _run(
                "https://github.com/owner/gone",
                {"https://api.github.com/repos/owner/gone": (404, {"message": "Not Found"}, "")},
            )

    async def test_github_atom_link_is_a_feed_not_a_repo(self):
        atom = '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Recent Commits</title></feed>'
        p = await _run(
            "https://github.com/owner/project/commits/main.atom",
            {"https://github.com/owner/project/commits/main.atom": (200, atom, "application/atom+xml")},
        )
        assert p.kind == "feed"


class TestSocial:
    async def test_bluesky_profile_uses_display_name(self):
        p = await _run(
            "https://bsky.app/profile/alice.bsky.social",
            {
                "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile": (
                    200,
                    {"handle": "alice.bsky.social", "displayName": "Alice"},
                    "",
                ),
            },
        )
        assert (p.kind, p.title) == ("bluesky", "Alice")
        assert p.bluesky == {"mode": "author", "handle": "alice.bsky.social", "display_name": "Alice"}

    async def test_bluesky_search_link(self):
        p = await _run("https://bsky.app/search?q=ransomware", {})
        assert p.kind == "bluesky_search"
        assert p.bluesky == {"mode": "search", "query": "ransomware"}

    async def test_telegram_warns_when_not_connected(self):
        page = '<meta property="og:title" content="Breach Intel">'
        with patch.object(link_preview, "telegram_ready", return_value=False):
            p = await _run("https://t.me/s/breachintel", {"https://t.me/breachintel": (200, page, "text/html")})
        assert (p.kind, p.title) == ("telegram", "Breach Intel")
        assert p.telegram == {"channel": "breachintel"}
        assert p.warning and "isn't connected" in p.warning

    async def test_telegram_no_warning_when_connected(self):
        with patch.object(link_preview, "telegram_ready", return_value=True):
            p = await _run("https://t.me/breachintel", {})
        assert p.warning is None

    async def test_mastodon_hashtag(self):
        p = await _run(
            "https://infosec.exchange/tags/threatintel",
            {"https://infosec.exchange/api/v1/instance": (200, {"uri": "infosec.exchange"}, "")},
        )
        assert p.kind == "mastodon_tag"
        assert p.mastodon == {"instance_url": "https://infosec.exchange", "hashtag": "threatintel"}
