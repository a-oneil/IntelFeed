"""Indicator-aware prompt window for the one-pass entry analysis.

The analysis prompt carries at most ``ai_analysis_content_max_chars`` of
article text. Threat-research write-ups (Talos, Unit 42, Huntress, Datadog,
Bitdefender, DFIR Report) run 20k–80k characters and put the part a detection
engineer wants — the indicator appendix, the hash table, the command-line
code blocks — at the very end. A plain head slice never shows the model any
of it, which is why the ``iocs`` array stayed empty for exactly the feeds
that publish indicators.

Two fixes live here:

* ``html_to_analysis_text`` renders article HTML with structure the model
  can use: table rows become ``cell | cell`` lines (so a hash stays next to
  its "loader" description), headings land on their own line, ``<pre>``
  blocks keep their line breaks. nh3's tag strip (``content_text``) flattens
  a table to one cell per line and glues headings onto the previous
  sentence.
* ``analysis_content_window`` composes head + indicator appendix when the
  body exceeds the cap: the appendix is the article's own IOC section
  (found by heading) or, failing that, the trailing region that carries
  hash/IP/defanged candidates. A marker line tells the model text was cut.
"""

from __future__ import annotations

import html as html_mod
import re

# ---------------------------------------------------------------------------
# HTML → analysis text
# ---------------------------------------------------------------------------

_BLOCK_CLOSE_RE = re.compile(
    r"</(?:p|div|li|ul|ol|tr|table|thead|tbody|blockquote|figure|figcaption|dl|dd|dt|details|summary|section|article|h[1-6])\s*>",
    re.IGNORECASE,
)
#: Opening block tags also break the line: an unclosed <p> or a <div> that
#: follows inline text must not glue onto it.
_BLOCK_OPEN_RE = re.compile(
    r"<(?:p|div|ul|ol|table|blockquote|figure|figcaption|caption|dl|dd|dt|details|summary|section|article)(?:\s[^>]*)?>",
    re.IGNORECASE,
)
#: A cell left over after row rendering (nested tables, a stray <td> outside
#: any <tr>) still ends at its boundary.
_CELL_CLOSE_RE = re.compile(r"</t[dh]\s*>", re.IGNORECASE)
_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_HR_RE = re.compile(r"<hr\s*/?>", re.IGNORECASE)
_H_OPEN_RE = re.compile(r"<h([1-6])(?:\s[^>]*)?>", re.IGNORECASE)
_EMPTY_H_WITH_ID_RE = re.compile(r"<h([1-6])\s[^>]*\bid=\"([^\"]{3,80})\"[^>]*>\s*</h\1\s*>", re.IGNORECASE)
_LI_OPEN_RE = re.compile(r"<li(?:\s[^>]*)?>", re.IGNORECASE)
_TR_OPEN_RE = re.compile(r"<tr(?:\s[^>]*)?>", re.IGNORECASE)
_TR_RE = re.compile(r"<tr(?:\s[^>]*)?>(.*?)</tr\s*>", re.IGNORECASE | re.DOTALL)
_CELL_RE = re.compile(r"<t[dh](?:\s[^>]*)?>(.*?)</t[dh]\s*>", re.IGNORECASE | re.DOTALL)


def _render_row(m: re.Match) -> str:
    cells = []
    for cell in _CELL_RE.findall(m.group(1)):
        flat = html_mod.unescape(_TAG_RE.sub(" ", _BR_RE.sub(" ", cell))).replace("\xa0", " ")
        cells.append(re.sub(r"\s+", " ", flat).strip())
    cells = [c for c in cells if c]
    return "\n" + " | ".join(cells) + "\n" if cells else "\n"


_PRE_RE = re.compile(r"<pre(?:\s[^>]*)?>(.*?)</pre\s*>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_PRE_TOKEN = "\x00PRE{}\x00"


def html_to_analysis_text(html: str | None) -> str:
    """Flatten sanitized article HTML into prompt text that keeps structure.

    Tables → ``cell | cell`` rows; headings → ``## Heading`` on their own
    line; list items → ``- item``; ``<pre>`` content kept verbatim (tags
    inside stripped); everything else → paragraphs separated by blank lines.
    """
    if not html:
        return ""
    text = _SCRIPT_STYLE_RE.sub("", html)

    # Lift <pre> blocks out so later whitespace collapsing can't touch them.
    pre_blocks: list[str] = []

    def _stash_pre(m: re.Match) -> str:
        body = html_mod.unescape(_TAG_RE.sub("", _BR_RE.sub("\n", m.group(1))))
        pre_blocks.append("\n".join(line.rstrip() for line in body.strip("\n").splitlines()))
        return "\n\n" + _PRE_TOKEN.format(len(pre_blocks) - 1) + "\n\n"

    text = _PRE_RE.sub(_stash_pre, text)

    # Table rows: cells joined by " | ", one row per line. Rows are rendered
    # as a unit first so block tags *inside* a cell (<td><p>…</p></td>, the
    # MSO export shape) can't split a row across lines.
    text = _TR_RE.sub(_render_row, text)

    # An empty heading whose only content is its anchor id (<h2
    # id="indicators-of-compromise"></h2>, Datadog's sanitized shape) still
    # names the section: render the id as the heading text.
    text = _EMPTY_H_WITH_ID_RE.sub(
        lambda m: f"<h{m.group(1)}>{m.group(2).replace('-', ' ').replace('_', ' ')}</h{m.group(1)}>", text
    )
    text = _H_OPEN_RE.sub("\n\n## ", text)
    text = _LI_OPEN_RE.sub("\n- ", text)
    text = _BR_RE.sub("\n", text)
    text = _HR_RE.sub("\n\n", text)
    text = _BLOCK_CLOSE_RE.sub("\n\n", text)
    text = _BLOCK_OPEN_RE.sub("\n", text)
    text = _CELL_CLOSE_RE.sub(" | ", text)
    text = _TAG_RE.sub("", text)
    text = html_mod.unescape(text).replace("\xa0", " ")

    # Per-line whitespace collapse, then paragraph normalisation.
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    # A table row rendered as " | cell | cell | " → "cell | cell".
    lines = [re.sub(r"^\|\s*|\s*\|$", "", line) for line in lines]
    out = "\n".join(lines)
    # A block opened inside a list item or heading (<li><p>…) left the
    # marker on a line of its own: pull the text back up.
    out = re.sub(r"(?m)^(-|##)\n+(?=\S)", r"\1 ", out)
    out = re.sub(r"\n{3,}", "\n\n", out).strip()

    def _restore_pre(m: re.Match) -> str:
        return pre_blocks[int(m.group(1))]

    return re.sub(r"\x00PRE(\d+)\x00", _restore_pre, out)


# ---------------------------------------------------------------------------
# Indicator appendix
# ---------------------------------------------------------------------------

#: A line that is (only) an indicator-section heading. Tolerates the glued
#: form nh3 produces ("…reduce the risk.IoCs") via the sentence-end
#: lookbehind, markdown ``##`` from html_to_analysis_text, and the
#: "<FAMILY> indicators of compromise" / "Indicators of compromise (IOCs)" /
#: "Appendix A: Indicators" variants the publishers use.
IOC_HEADING_RE = re.compile(
    r"(?im)"
    r"(?:^|(?<=[.!?:)\]]))[ \t]*"
    r"(?:#{1,6}[ \t]*)?"
    r"(?:appendix[ \t]*[a-z0-9]?[ \t]*[:.\-–—]?[ \t]*)?"
    r"(?:[a-z0-9][a-z0-9 .\-_]{0,40}[ \t]+)?"
    r"(?:"
    r"indicators?(?:[ \t]+of[ \t]+compromise)?(?:[ \t]*\((?:iocs?)\))?"
    r"|iocs?"
    r"|atomic[ \t]+indicators?"
    r"|network[ \t]+indicators?"
    r"|host(?:-based)?[ \t]+indicators?"
    r")"
    r"[ \t]*:?[ \t]*$"
)

#: Headings that end the appendix: vendor-product and footer material.
STOP_HEADING_RE = re.compile(
    r"(?im)^(?:#{1,6}[ \t]*)?(?:"
    r"coverage|protections?(?:[ \t]+and[ \t]+mitigations?)?|"
    r"(?:additional[ \t]+)?references|further[ \t]+reading|"
    r"about(?:[ \t]+(?:the[ \t]+author|us|[a-z0-9 ]{1,30}))?|"
    r"share(?:[ \t]+this)?|related(?:[ \t]+(?:posts|articles|content))?|tags|subscribe|"
    r"acknowledg(?:e)?ments?|disclaimer|"
    r"this[ \t]+article[ \t]+is[ \t]+published[ \t]+for[ \t]+informational.*"
    r")[ \t]*:?[ \t]*$"
)

#: A rendered table header row that marks an indicator table even when the
#: publisher's heading was an empty anchor (Datadog) or absent (Huntress):
#: one cell names the indicator column, another the description column.
IOC_TABLE_HEADER_RE = re.compile(
    r"(?im)^(?=.*\|)(?=.*\b(?:indicator|ioc|item|artifact|hash|sha-?256|sha-?1|md5|domain|url|ip(?:v4)?|address|value)s?\b)"
    r"(?=.*\b(?:context|description|notes?|type|purpose|role|comment|first seen|details?)\b)"
    r"[a-z0-9 \-/()|]{5,120}$"
)

#: Earliest point in the body where an IOC heading counts as the appendix
#: (an intro that says "IOCs are at the end" must not start it).
_MIN_HEADING_FRACTION = 0.2
#: After the heading, a stop heading only trims when at least this much
#: section text precedes it (a "References" line right under the heading is
#: part of a link-only IOC section, not the end of it).
_MIN_SECTION_CHARS = 200
TRUNCATION_MARKER = "[… article truncated here; its indicator appendix follows …]"


def find_indicator_section(text: str) -> tuple[int, int] | None:
    """(start, end) of the article's own indicator section, or None.

    The start is the first IOC heading at or past 20% of the body; the end is
    the first stop heading after it (if at least 200 chars in), else the
    body's end.
    """
    if not text:
        return None
    floor = int(len(text) * _MIN_HEADING_FRACTION)
    start: int | None = None
    for m in IOC_HEADING_RE.finditer(text):
        if m.start() >= floor:
            start = m.start()
            break
    if start is None:
        # No heading: an indicator table's header row is as good a marker.
        for m in IOC_TABLE_HEADER_RE.finditer(text):
            if m.start() >= floor:
                # Include the (possibly empty) heading line just above it.
                prev = text.rfind("\n\n", 0, m.start())
                start = prev + 2 if prev >= 0 else m.start()
                break
    if start is None:
        return None
    end = len(text)
    for m in STOP_HEADING_RE.finditer(text, start + 1):
        if m.start() - start >= _MIN_SECTION_CHARS:
            end = m.start()
            break
    return start, end


def _tail_candidate_start(text: str, from_offset: int) -> int | None:
    """Start offset of the trailing region that carries indicator candidates,
    when the article has no recognisable IOC heading. Precision-first: needs
    at least three hash/IP/defanged nominations past ``from_offset``."""
    from app.intelligence.observables import scan_candidates

    tail = text[from_offset:]
    if not tail.strip():
        return None
    cands = scan_candidates(tail, max_candidates=50)
    if len(cands) < 3:
        return None
    positions = [tail.find(c.surface_form) for c in cands]
    positions = [pos for pos in positions if pos >= 0]
    if not positions:
        return None
    first = min(positions)
    # Back up to the start of the paragraph so the heading/intro line comes along.
    para = tail.rfind("\n\n", 0, first)
    return from_offset + (para + 2 if para >= 0 else 0)


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: max(0, n - 2)].rstrip() + " …"


_BARE_HASH_LINE_RE = re.compile(
    r"^\s*(?:(?:md5|sha-?1|sha-?256)\s*[:|]\s*)?([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE
)
#: Per-kind quota of indicator-only lines kept when the appendix is over
#: budget. Ten hashes and fifteen of each network kind are plenty for the
#: model to judge role and attribution; the publisher's full list is a feed
#: concern, not a prompt concern — and an unbounded list makes the model emit
#: an array that overflows its output budget and loses the whole analysis.
_LINE_QUOTAS = {"md5": 10, "sha1": 10, "sha256": 10, "url": 15, "domain": 15, "ipv4": 15, "ipv6": 15, "email": 15}
_LINE_QUOTA_NAMES = {
    "md5": "MD5 hashes",
    "sha1": "SHA1 hashes",
    "sha256": "SHA256 hashes",
    "url": "URLs",
    "domain": "domains",
    "ipv4": "IPs",
    "ipv6": "IPv6 addresses",
    "email": "email addresses",
}


def _indicator_line_kind(line: str) -> str | None:
    """The kind of an indicator-only line (value plus optional label/cells), or None."""
    from app.intelligence.observables import classify_value

    m = _BARE_HASH_LINE_RE.match(line)
    if m:
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(m.group(1))]
    stripped = line.strip().lstrip("-•*| ").strip()
    if not stripped:
        return None
    # Typed table rows: "Domain | cdnorigin.net | TLS-fronted C2" → second cell.
    cells = [c.strip() for c in stripped.split("|")]
    for cell in cells[:2]:
        first = cell.split()[0] if cell.split() else ""
        classified = classify_value(first) if first else None
        if classified:
            return classified[0]
    return None


def compress_appendix(appendix: str, budget: int) -> str:
    """Fit an indicator section into ``budget`` without losing its variety.

    Publishers list sixty hashes and seventy URLs before the three C2 domains.
    When the section is over budget, lines that are *only* an indicator (plus
    an optional label) are kept up to a per-kind quota and the rest are
    replaced by one count line, so every kind the article names survives and
    the model's output stays bounded. Only then is the text clipped."""
    if len(appendix) <= budget:
        return appendix
    kept: list[str] = []
    dropped: dict[str, int] = {}
    seen: dict[str, int] = {}
    for line in appendix.splitlines():
        kind = _indicator_line_kind(line)
        if kind in _LINE_QUOTAS:
            seen[kind] = seen.get(kind, 0) + 1
            if seen[kind] > _LINE_QUOTAS[kind]:
                dropped[kind] = dropped.get(kind, 0) + 1
                continue
        kept.append(line)
    if dropped:
        note = ", ".join(f"{n} more {_LINE_QUOTA_NAMES[k]}" for k, n in sorted(dropped.items()))
        kept.append(f"[… {note} omitted from this excerpt …]")
    compact = re.sub(r"\n{3,}", "\n\n", "\n".join(kept))
    return _clip(compact, budget)


def analysis_content_window(text: str, max_chars: int, *, tail_reserve: float = 0.4) -> str:
    """Head + indicator appendix within ``max_chars``.

    * Body fits → unchanged.
    * The article's IOC section (found by heading) runs past the cap → the
      head is shortened by up to ``tail_reserve`` of the budget and the
      section is appended after a marker line. When the section already
      starts inside the head, the head is cut at the heading and the rest of
      the budget is spent on the section (no marker: contiguous text).
    * No heading, but the trailing text carries ≥3 indicator candidates →
      same head + marker + tail treatment from the first candidate's paragraph.
    * Otherwise → plain head slice (today's behaviour).
    """
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    reserve_cap = int(max_chars * max(0.0, min(tail_reserve, 0.8)))
    if reserve_cap < 200:
        return text[:max_chars]
    head_limit = max_chars - reserve_cap

    appendix_start: int | None = None
    appendix_end = len(text)
    section = find_indicator_section(text)
    if section is not None and section[1] > max_chars:
        start, end = section
        if start < head_limit:
            # Contiguous: the head already reaches the heading, so cut there
            # and let the section take the remaining budget.
            return text[:start].rstrip() + "\n\n" + compress_appendix(text[start:end], max_chars - start)
        appendix_start, appendix_end = start, end
    else:
        appendix_start = _tail_candidate_start(text, head_limit)
    if appendix_start is None:
        return text[:max_chars]

    appendix = text[appendix_start:appendix_end].strip()
    if not appendix:
        return text[:max_chars]
    reserve = min(len(appendix) + len(TRUNCATION_MARKER) + 4, reserve_cap)
    head_end = min(max_chars - reserve, appendix_start)
    head = text[:head_end].rstrip()
    body = compress_appendix(appendix, max_chars - head_end - len(TRUNCATION_MARKER) - 4)
    marker = TRUNCATION_MARKER if head_end < appendix_start else "[… indicator section continues …]"
    return f"{head}\n\n{marker}\n\n{body}"


# ---------------------------------------------------------------------------
# Candidate hints for the prompt
# ---------------------------------------------------------------------------

#: Scan-origin kinds that never belong in the hint block: the code-block
#: scanner nominates them from <pre> text and a bulletin's preformatted prose
#: used to fill all 40 slots with "Patch Instructions:"-shaped lines.
_HINT_EXCLUDED_SCAN_KINDS = frozenset({"cmdline", "path", "registry"})
_HINT_KIND_CAP = 15


def rank_candidate_hints(candidates: list[dict] | None, limit: int = 40) -> list[dict]:
    """Order entry candidates for the prompt's CANDIDATE OBSERVABLES block.

    AI-origin stagings first (the previous judge's own confirmations), then
    author-defanged tokens, then hashes, public IPs and the rest; scan-origin
    host kinds are excluded; no kind takes more than 15 slots so a hash dump
    leaves room for the domain the article actually called C2.
    """
    if not candidates:
        return []

    def _tier(c: dict) -> int:
        if c.get("origin") == "ai":
            return 0
        if c.get("was_defanged"):
            return 1
        kind = c.get("kind") or ""
        if kind in ("sha256", "sha1", "md5"):
            return 2
        if kind in ("ipv4", "ipv6"):
            return 3
        return 4

    eligible = [
        c
        for c in candidates
        if isinstance(c, dict) and not (c.get("origin") != "ai" and (c.get("kind") or "") in _HINT_EXCLUDED_SCAN_KINDS)
    ]
    eligible.sort(key=_tier)
    out: list[dict] = []
    per_kind: dict[str, int] = {}
    for c in eligible:
        kind = c.get("kind") or ""
        if per_kind.get(kind, 0) >= _HINT_KIND_CAP:
            continue
        per_kind[kind] = per_kind.get(kind, 0) + 1
        out.append(c)
        if len(out) >= limit:
            break
    return out
