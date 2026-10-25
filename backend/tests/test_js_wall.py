"""looks_like_js_wall: JavaScript-only and bot-check pages vs. real article text."""

import pytest

from app.services.js_wall import looks_like_js_wall

# Bodies stored before the extractor guard (taken from the dev DB).
WALLS = [
    # NCSC (UK)
    '<div><p class="c-wysiwyg"> Please enable JavaScript in your web browser to get the best experience.</p></div>',
    # Europol (double-escaped noscript markup)
    '<div><div id="root"><p>&lt;h2&gt;You need to enable JavaScript to run this app.&lt;/h2&gt;'
    "Loading application.<br>Please wait.</p></div></div>",
    # MSRC
    ' You need to enable JavaScript to run this app. <p id="root"></p> ',
    # FortiGuard
    "Loading domain...\n Just a moment — verifying connection security.\n\n"
    "We are checking that your connection to this site is secure.",
    # Cloudflare challenges
    "Just a moment... Enable JavaScript and cookies to continue",
    "Checking your browser before accessing example.com. DDoS protection by Cloudflare",
    "Attention Required! | Cloudflare. Please complete the security check to access example.com",
    "JavaScript is required to view this page.",
    "<noscript>This site requires JavaScript.</noscript>",
]

NOT_WALLS = [
    "",
    None,
    # A user post that happens to say "just a moment"
    "So just a moment ago I had a user interrupt what I was doing with an urgent issue. "
    "They couldn't get into their email.",
    # A short real description
    "Key findings and full report from the 6th year of the Active Cyber Defence (ACD) programme.",
    # A long article that discusses enabling JavaScript
    "Attackers lure victims into a PDF that asks them to enable JavaScript in the reader. " * 20,
]


@pytest.mark.parametrize("content", WALLS)
def test_detects_wall_pages(content):
    assert looks_like_js_wall(content)


@pytest.mark.parametrize("content", NOT_WALLS)
def test_leaves_real_content_alone(content):
    assert not looks_like_js_wall(content)
