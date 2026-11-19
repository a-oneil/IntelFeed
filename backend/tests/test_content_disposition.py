"""Content-Disposition values stay well-formed for any filename."""

import re

import pytest

from app.core.content_disposition import attachment

_FALLBACK = re.compile(r'^attachment; filename="([^"\\/\r\n]*)"; filename\*=UTF-8\'\'(\S+)$')


@pytest.mark.parametrize(
    "name",
    [
        "report＂name.txt",  # full-width quote: NFKD folds it to "
        "report＼name.txt",  # full-width backslash
        "report／name.txt",  # full-width solidus
        'plain "quoted" \\ back/slash.md',
        "line\r\nbreak.md",
        "Microsoft’s patch — 漏洞.md",
    ],
)
def test_fallback_has_no_quote_slash_or_control(name: str):
    value = attachment(name)
    assert _FALLBACK.match(value), value
    value.encode("latin-1")  # Starlette's header encoding must not raise


def test_exact_name_survives_in_filename_star():
    assert attachment("Microsoft’s patch.md").endswith("filename*=UTF-8''Microsoft%E2%80%99s%20patch.md")


def test_unencodable_name_falls_back_to_download():
    assert attachment("漏洞").startswith('attachment; filename="download";')
