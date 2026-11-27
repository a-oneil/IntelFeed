"""Content-Disposition values that survive any filename (RFC 6266 / RFC 5987)."""

import re
import unicodedata
from urllib.parse import quote

# Path separators, quotes and control characters: none belongs in a header value.
_UNSAFE = re.compile(r'[/\\"\r\n\x00-\x1f\x7f]+')


def attachment(filename: str) -> str:
    """``attachment`` with an ASCII ``filename=`` fallback and the exact name in ``filename*``.

    Starlette sends header values as latin-1, so a raw title carrying ’, — or a
    non-Latin script would raise UnicodeEncodeError and turn the download into a
    500. Browsers prefer ``filename*`` and keep the real name; the ASCII form is
    for clients that don't read it.
    """
    clean = _UNSAFE.sub("-", filename).strip()
    # NFKD folds full-width ＂ ＼ ／ into plain " \ /, so strip again after it.
    ascii_name = unicodedata.normalize("NFKD", clean).encode("ascii", "ignore").decode("ascii")
    fallback = _UNSAFE.sub("-", ascii_name).strip() or "download"
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(clean, safe='')}"
